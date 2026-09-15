"""
Sigma rule evaluation on JOCKY's own pattern engine.

Why this exists: the detection content already written by the industry is
Sigma rules — thousands of them, maintained by the community. A tool that
speaks Sigma inherits that corpus instead of asking every analyst to rewrite
it. Velociraptor and Dissect make you convert rules into their own syntax;
``jocky sigma`` runs the rule as written.

The second reason matters more for a forensic tool. Sigma rules are
*regex-heavy*, and the engines that evaluate them (Python ``re`` in Zircolite,
.NET regex in Chainsaw and Hayabusa) backtrack: one crafted log line — the kind
an adversary controls — turns a hunt into a hang. Every string comparison here
goes through :mod:`jocky.rt.pattern`, whose cost is
``O(len(text) x len(pattern))`` whatever the rule looks like, with a step
budget that raises instead of stalling.

Supported subset (documented, and *rejected* rather than reinterpreted when
outside it):

    detection:
      selection:                  # mapping of field -> value(s)
        Field|modifier: value     # contains startswith endswith re all cased base64
      keywords:                   # bare list = match the record text
        - 'suspicious'
      condition: selection and not filter

``condition`` supports ``and``, ``or``, ``not``, parentheses, ``N of them``,
``all of them`` and ``N of selection*`` wildcards. Aggregations
(``| count() > 5``), ``|cidr``, ``|lt``/``|gt``/``|fieldref`` and correlation
rules are out of scope: they need state across events, and a rule that silently
degrades to "match everything" is worse than one that refuses to load.
"""
from __future__ import annotations

import base64
import re as _stdlib_re          # only for the YAML/condition tokenizer, never for matching
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Tuple

from jocky.errors import JockyRuntimeError
from jocky.rt.pattern import compile_pattern

#: Modifiers this evaluator implements. Anything else is an error at load time.
SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cased",
                       "base64"}

MISSING = object()


# --------------------------------------------------------------------- YAML subset
def _strip_comment(line: str) -> str:
    """Drop a trailing ``#`` comment, respecting quotes.

    A ``#`` inside a quoted scalar is data (``title: 'a # b'``), and a ``#`` not
    preceded by whitespace is data too (``a#b``) — both are YAML's rules and both
    bite a rule whose value contains a hash.
    """
    out: List[str] = []
    quote = ""
    for index, char in enumerate(line):
        if quote:
            out.append(char)
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
            out.append(char)
        elif char == "#" and (index == 0 or line[index - 1] in " \t"):
            break
        else:
            out.append(char)
    return "".join(out).rstrip()


def _scalar(text: str) -> Any:
    """One YAML scalar: quoted string, int, bool, null or plain string."""
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        body = text[1:-1]
        if text[0] == "'":
            return body.replace("''", "'")
        return (body.replace("\\n", "\n").replace("\\t", "\t")
                .replace('\\"', '"').replace("\\\\", "\\"))
    lowered = text.lower()
    if lowered in ("true", "yes"):
        return True
    if lowered in ("false", "no"):
        return False
    if lowered in ("null", "~", ""):
        return None
    if _stdlib_re.fullmatch(r"-?\d+", text):
        return int(text)
    if _stdlib_re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    return text


def _flow_list(text: str) -> List[Any]:
    """``[a, 'b c', 3]`` — the inline form Sigma authors use constantly."""
    body = text.strip()[1:-1].strip()
    if not body:
        return []
    items: List[Any] = []
    current: List[str] = []
    quote = ""
    for char in body:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            current.append(char)
        elif char == ",":
            items.append(_scalar("".join(current)))
            current = []
        else:
            current.append(char)
    items.append(_scalar("".join(current)))
    return items


class _YamlSubset:
    """Indentation-driven parser for the YAML Sigma rules actually use.

    Deliberately small: block mappings, block sequences, inline lists, scalars
    and comments. Anchors, multi-line scalars, flow mappings and tags are
    rejected with a line number, because a rule that half-parses is a rule that
    half-matches.
    """

    def __init__(self, text: str):
        self.lines: List[Tuple[int, str]] = []
        for number, raw in enumerate(text.splitlines(), start=1):
            if raw.strip() in ("---", "..."):
                continue
            stripped = _strip_comment(raw)
            if not stripped.strip():
                continue
            if "\t" in stripped[:len(stripped) - len(stripped.lstrip())]:
                raise JockyRuntimeError(
                    f"sigma rule line {number}: tabs are not valid YAML indentation")
            self.lines.append((number, stripped))
        self.index = 0

    def parse(self) -> Any:
        if not self.lines:
            raise JockyRuntimeError("sigma rule is empty")
        value = self._block(self.lines[0][1])
        if self.index != len(self.lines):
            number, _ = self.lines[self.index]
            raise JockyRuntimeError(f"sigma rule line {number}: unexpected indentation")
        return value

    def _indent(self, line: str) -> int:
        return len(line) - len(line.lstrip(" "))

    def _block(self, head: str) -> Any:
        indent = self._indent(head)
        if head.strip().startswith("- "):
            return self._sequence(indent)
        return self._mapping(indent)

    def _sequence(self, indent: int) -> List[Any]:
        items: List[Any] = []
        while self.index < len(self.lines):
            number, line = self.lines[self.index]
            if self._indent(line) < indent or not line.strip().startswith("- "):
                break
            body = line.strip()[2:].strip()
            self.index += 1
            if not body:
                if self.index < len(self.lines) and self._indent(self.lines[self.index][1]) > indent:
                    items.append(self._block(self.lines[self.index][1]))
                else:
                    items.append(None)
                continue
            if ":" in body and not body.startswith(("\"", "'")):
                # An inline mapping inside a sequence item: `- field: value`.
                key, _, rest = body.partition(":")
                entry = {key.strip(): self._value_or_block(rest, indent + 2, number)}
                while self.index < len(self.lines):
                    next_line = self.lines[self.index][1]
                    if self._indent(next_line) <= indent:
                        break
                    if next_line.strip().startswith("- "):
                        break
                    sub_key, _, sub_rest = next_line.strip().partition(":")
                    self.index += 1
                    entry[sub_key.strip()] = self._value_or_block(sub_rest, indent + 2,
                                                                  number)
                items.append(entry)
                continue
            items.append(self._value_or_block(body, indent + 2, number))
        return items

    def _value_or_block(self, rest: str, child_indent: int, number: int) -> Any:
        rest = rest.strip()
        if rest:
            if rest.startswith("[") and rest.endswith("]"):
                return _flow_list(rest)
            if rest.startswith("{"):
                raise JockyRuntimeError(
                    f"sigma rule line {number}: flow mappings are not supported")
            if rest in ("|", ">"):
                raise JockyRuntimeError(
                    f"sigma rule line {number}: block scalars are not supported")
            return _scalar(rest)
        if self.index < len(self.lines) and self._indent(self.lines[self.index][1]) >= child_indent:
            return self._block(self.lines[self.index][1])
        return None

    def _mapping(self, indent: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        while self.index < len(self.lines):
            number, line = self.lines[self.index]
            if self._indent(line) != indent:
                break
            key, sep, rest = line.strip().partition(":")
            if not sep:
                raise JockyRuntimeError(f"sigma rule line {number}: expected 'key: value'")
            self.index += 1
            result[key.strip()] = self._value_or_block(rest, indent + 2, number)
        return result


def parse_rule(text: str) -> Dict[str, Any]:
    """Parse a Sigma rule (YAML subset) into a mapping."""
    parsed = _YamlSubset(text).parse()
    if not isinstance(parsed, dict):
        raise JockyRuntimeError("sigma rule must be a mapping at the top level")
    if "detection" not in parsed:
        raise JockyRuntimeError("sigma rule has no 'detection' section")
    return parsed


# ---------------------------------------------------------------- conditions
_CONDITION_TOKEN = _stdlib_re.compile(r"\s*(\(|\)|\*|[A-Za-z_][A-Za-z0-9_]*|\d+)")


def _condition_tokens(condition: str) -> List[str]:
    tokens: List[str] = []
    position = 0
    while position < len(condition):
        match = _CONDITION_TOKEN.match(condition, position)
        if not match or match.start() != position:
            if condition[position:].strip() == "":
                break
            raise JockyRuntimeError(
                f"sigma condition: cannot parse {condition[position:position + 12]!r}")
        tokens.append(match.group(1))
        position = match.end()
    return tokens


class _Condition:
    """Recursive-descent parser for the Sigma condition grammar."""

    def __init__(self, tokens: Sequence[str], selections: Sequence[str]):
        self.tokens = list(tokens)
        self.pos = 0
        self.selections = list(selections)

    def peek(self) -> str:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else ""

    def take(self) -> str:
        token = self.peek()
        self.pos += 1
        return token

    def parse(self) -> Any:
        node = self._or()
        if self.pos != len(self.tokens):
            raise JockyRuntimeError(f"sigma condition: trailing input {self.peek()!r}")
        return node

    def _or(self) -> Any:
        node = self._and()
        while self.peek().lower() == "or":
            self.take()
            node = ("or", node, self._and())
        return node

    def _and(self) -> Any:
        node = self._not()
        while self.peek().lower() == "and":
            self.take()
            node = ("and", node, self._not())
        return node

    def _not(self) -> Any:
        if self.peek().lower() == "not":
            self.take()
            return ("not", self._not())
        return self._atom()

    def _atom(self) -> Any:
        token = self.peek()
        if token == "(":
            self.take()
            node = self._or()
            if self.take() != ")":
                raise JockyRuntimeError("sigma condition: missing ')'")
            return node
        if not token:
            raise JockyRuntimeError("sigma condition: unexpected end of expression")
        # `N of them` / `all of selection*` / `any of them`
        if token.isdigit() or token.lower() in ("all", "any"):
            count = self.take()
            if self.peek().lower() != "of":
                raise JockyRuntimeError(
                    f"sigma condition: expected 'of' after {count!r}")
            self.take()
            pattern = self.take()
            if self.peek() == "*":                # `1 of sel_*` arrives as two tokens
                self.take()
                pattern += "*"
            names = self._of_names(pattern)
            number = len(names) if count.lower() == "all" else (
                1 if count.lower() == "any" else int(count))
            if number > len(names):
                raise JockyRuntimeError(
                    f"sigma condition: '{count} of {pattern}' cannot be satisfied "
                    f"({len(names)} selection(s) available)")
            return ("of", number, names)
        self.take()
        if token not in self.selections:
            raise JockyRuntimeError(
                f"sigma condition: unknown selection {token!r} "
                f"(have {', '.join(self.selections) or 'none'})")
        return ("sel", token)

    def _of_names(self, pattern: str) -> List[str]:
        if pattern == "them":
            return list(self.selections)
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            names = [name for name in self.selections if name.startswith(prefix)]
            if not names:
                raise JockyRuntimeError(
                    f"sigma condition: '{pattern}' matches no selection")
            return names
        if pattern in self.selections:
            return [pattern]
        raise JockyRuntimeError(f"sigma condition: unknown selection {pattern!r}")


# ------------------------------------------------------------------- matching
@dataclass
class Selection:
    """One named selection: field patterns, keyword patterns, or a list of both."""

    name: str
    fields: List[Tuple[str, bool, Any]] = field(default_factory=list)
    keywords: List[Any] = field(default_factory=list)
    alternatives: List["Selection"] = field(default_factory=list)


def _wildcard_body(value: str) -> str:
    """Sigma's wildcards as a pattern *body*: ``*`` any run, ``?`` one char.

    Escaped for the engine, so a value full of regex punctuation (paths, IPs,
    ``$`` refs) is literal. Anchoring is the caller's decision: a plain value
    describes the whole field, ``contains`` describes a substring.
    """
    out: List[str] = []
    for char in value:
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(_stdlib_re.escape(char))
    return "".join(out)


def _compile_value(value: Any, modifiers: Sequence[str], field_name: str) -> Any:
    """A matcher closure for one rule value under its modifiers.

    Modifier composition follows the specification: `|base64` transforms the
    value first, then `|contains`/`|startswith`/`|endswith` decide how the
    transformed value is compared, and `|all` is handled by the caller (it is a
    property of the value *list*, not of one value).
    """
    all_required = "all" in modifiers
    ignore_case = "cased" not in modifiers and "re" not in modifiers
    text = value if isinstance(value, str) else str(value)
    if "base64" in modifiers:
        # Sigma's `|base64`: the *rule* value is encoded before matching, because
        # the log holds the encoded form (`echo Y3VybA== | base64 -d`).
        try:
            text = base64.b64encode(text.encode("utf-8")).decode("latin-1")
        except (UnicodeEncodeError, ValueError) as exc:
            raise JockyRuntimeError(
                f"sigma rule: field {field_name!r} has |base64 but the value cannot "
                f"be encoded ({exc})")

    if "re" in modifiers:
        matcher: Any = ("re", compile_pattern(text, False))
    else:
        body = _wildcard_body(text)
        if "contains" in modifiers:
            matcher = ("re", compile_pattern(body, ignore_case))
        elif "startswith" in modifiers:
            matcher = ("re", compile_pattern("^" + body, ignore_case))
        elif "endswith" in modifiers:
            matcher = ("re", compile_pattern(body + "$", ignore_case))
        elif "*" in text or "?" in text:
            matcher = ("re", compile_pattern("^" + body + "$", ignore_case))
        else:
            matcher = ("exact", text.lower() if ignore_case else text)

    def matches(candidate: Any) -> bool:
        if candidate is MISSING or candidate is None:
            return False
        if isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
            candidate = str(candidate)
        if not isinstance(candidate, str):
            candidate = str(candidate)
        if matcher[0] == "exact":
            needle = candidate.lower() if ignore_case else candidate
            return needle == matcher[1]
        return matcher[1].test(candidate)

    matches.requires_all = all_required        # type: ignore[attr-defined]
    return matches


def _selection_from(name: str, spec: Any) -> Selection:
    selection = Selection(name=name)
    if isinstance(spec, list):
        for item in spec:
            if isinstance(item, dict):
                selection.alternatives.append(_selection_from(name, item))
            else:
                # A bare list is Sigma's "keywords": each entry hits when the
                # record *contains* it, which is why they compile as contains
                # rather than as an equality test.
                selection.keywords.append(_compile_value(item, ["contains"], name))
        return selection
    if isinstance(spec, dict):
        for raw_key, value in spec.items():
            parts = [part.strip() for part in str(raw_key).split("|")]
            field_name, modifiers = parts[0], [part.lower() for part in parts[1:]]
            unknown = [m for m in modifiers if m not in SUPPORTED_MODIFIERS]
            if unknown:
                raise JockyRuntimeError(
                    f"sigma rule: modifier |{unknown[0]} on {field_name!r} is not "
                    f"supported (known: {', '.join(sorted(SUPPORTED_MODIFIERS))})")
            values = value if isinstance(value, list) else [value]
            matcher = [_compile_value(item, modifiers, field_name) for item in values]
            require_all = "all" in modifiers
            selection.fields.append((field_name, require_all, matcher))
        return selection
    if spec is None:
        return selection
    selection.keywords.append(_compile_value(spec, [], name))
    return selection


def _record_value(record: Any, field_name: str) -> Any:
    """Field lookup with Sigma's case-insensitive field naming."""
    if isinstance(record, dict):
        if field_name in record:
            return record[field_name]
        lowered = field_name.lower()
        for key, value in record.items():
            if str(key).lower() == lowered:
                return value
        return MISSING
    return MISSING


def _record_text(record: Any) -> str:
    if isinstance(record, str):
        return record
    if isinstance(record, dict):
        return " ".join(str(value) for value in record.values() if not isinstance(value, dict))
    if isinstance(record, list):
        return " ".join(_record_text(item) for item in record)
    return "" if record is None else str(record)


def _selection_matches(selection: Selection, record: Any) -> bool:
    text = _record_text(record)
    for matcher in selection.keywords:
        if matcher(text):
            return True
    for alternative in selection.alternatives:
        if _selection_matches(alternative, record):
            return True
    if not selection.fields:
        return False
    for field_name, require_all, matchers in selection.fields:
        value = _record_value(record, field_name)
        if require_all:
            if not all(matcher(value) for matcher in matchers):
                return False
        elif not any(matcher(value) for matcher in matchers):
            return False
    return True


class Rule:
    """A parsed Sigma rule: selections, a condition, and the metadata to report."""

    def __init__(self, parsed: Dict[str, Any], source: str = ""):
        self.parsed = parsed
        self.source = source
        detection = parsed["detection"]
        self.selections: Dict[str, Selection] = {}
        for name, spec in detection.items():
            if name == "condition":
                continue
            self.selections[name] = _selection_from(name, spec)
        if not self.selections:
            raise JockyRuntimeError("sigma rule has no selections")
        condition = detection.get("condition")
        if condition is None:
            raise JockyRuntimeError("sigma rule has no 'condition'")
        if isinstance(condition, list):
            raise JockyRuntimeError(
                "sigma rule: a list of conditions is a correlation rule "
                "(unsupported: it needs state across events)")
        self.condition_text = str(condition)
        self.condition = _Condition(_condition_tokens(self.condition_text),
                                    sorted(self.selections)).parse()
        self.title = str(parsed.get("title") or "untitled sigma rule")
        self.rule_id = str(parsed.get("id") or "")
        self.level = str(parsed.get("level") or "medium").lower()
        self.tags = [str(tag) for tag in (parsed.get("tags") or [])]

    # ------------------------------------------------------------------ match
    def matches(self, record: Any) -> bool:
        """Does ``record`` (a map of fields, or plain text) satisfy the rule?"""
        results: Dict[str, bool] = {}

        def evaluate(node: Any) -> bool:
            kind = node[0]
            if kind == "sel":
                name = node[1]
                if name not in results:
                    results[name] = _selection_matches(self.selections[name], record)
                return results[name]
            if kind == "and":
                return evaluate(node[1]) and evaluate(node[2])
            if kind == "or":
                return evaluate(node[1]) or evaluate(node[2])
            if kind == "not":
                return not evaluate(node[1])
            if kind == "of":
                number, names = node[1], node[2]
                hits = 0
                for name in names:
                    if evaluate(("sel", name)):
                        hits += 1
                        if hits >= number:
                            return True
                return False
            raise JockyRuntimeError(f"sigma: internal condition node {kind!r}")

        return evaluate(self.condition)

    def summary(self) -> Dict[str, Any]:
        """Rule metadata for a finding (never the whole parsed document)."""
        return {
            "title": self.title,
            "id": self.rule_id,
            "level": self.level,
            "tags": self.tags,
            "condition": self.condition_text,
            "selections": sorted(self.selections),
            "source": self.source,
        }


_CACHE: Dict[str, Rule] = {}


def load_rule(text: str, source: str = "") -> Rule:
    """Parse a rule, caching by text (a hunt reuses one rule for every line)."""
    key = text
    rule = _CACHE.get(key)
    if rule is None:
        if len(_CACHE) >= 64:
            _CACHE.clear()
        rule = Rule(parse_rule(text), source=source)
        _CACHE[key] = rule
    return rule
