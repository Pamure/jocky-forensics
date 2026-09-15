"""
YARA-subset rule matching on JOCKY's own pattern engine.

YARA is the industry's byte-pattern language: shellcode signatures, packed
malware markers, PE/ELF heuristics and the whole ``apt_*`` rule corpus are
written in it. A forensic tool that cannot read those rules makes an analyst
retype them; this module reads the subset that matters for triage and compiles
it into the same linear-time NFA that ``re.*`` uses.

Two properties are deliberate:

* **Nothing is reinterpreted.** A construct outside the subset (``xor``,
  ``base64``, modules, ``for`` loops, counts, ``~``) raises with the offset
  instead of quietly matching something else. A signature that silently stops
  matching is worse than one that refuses to load.
* **Nothing can hang.** Every string compiles to the bounded engine, so a
  hostile rule cannot wedge a hunt the way a backtracking engine can.

Supported subset::

    rule Name {
        meta:      author = "…"  description = "…"      # read, never matched
        strings:
            $a = "text"                    nocase wide ascii
            $b = { 4D 5A ?? [4-6] ( 50 45 | 45 4C ) ?A }
            $c = /regex/                   nocase
        condition:
            $a and not $b or all of them
            any of them | 2 of them | $a at 0 | filesize < 4096
    }

``??`` matches any byte, ``[n-m]`` a jump of n..m bytes, ``(a|b)`` an
alternative, ``?A`` a nibble wildcard, and ``wide`` the UTF-16LE form.
"""
from __future__ import annotations

import re as _stdlib_re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from jocky.errors import JockyRuntimeError
from jocky.rt.pattern import compile_pattern

#: A class that matches *any* byte, including newline (the engine's ``.`` does
#: not cross one, and a byte scanner must not care).
ANY_BYTE = "[\x00-\xff]"

#: Modifiers this loader understands. Anything else is refused by name.
SUPPORTED_MODIFIERS = {"nocase", "wide", "ascii", "fullword"}


# ------------------------------------------------------------------- lexing
class _Scanner:
    def __init__(self, text: str):
        self.text = text
        self.index = 0

    def error(self, message: str) -> JockyRuntimeError:
        return JockyRuntimeError(f"yara rule at offset {self.index}: {message}")

    def skip_space(self) -> None:
        while self.index < len(self.text) and self.text[self.index] in " \t\r\n":
            self.index += 1

    def skip_junk(self) -> None:
        """Whitespace plus ``//`` and ``/* */`` comments."""
        while self.index < len(self.text):
            char = self.text[self.index]
            if char in " \t\r\n":
                self.index += 1
                continue
            if self.text.startswith("//", self.index):
                end = self.text.find("\n", self.index)
                self.index = len(self.text) if end < 0 else end + 1
                continue
            if self.text.startswith("/*", self.index):
                end = self.text.find("*/", self.index + 2)
                if end < 0:
                    raise self.error("unterminated comment")
                self.index = end + 2
                continue
            return

    def take(self, expected: str) -> None:
        self.skip_junk()
        if not self.text.startswith(expected, self.index):
            raise self.error(f"expected {expected!r}")
        self.index += len(expected)

    def maybe(self, expected: str) -> bool:
        self.skip_junk()
        if self.text.startswith(expected, self.index):
            self.index += len(expected)
            return True
        return False

    def word(self) -> str:
        self.skip_junk()
        match = _stdlib_re.match(r"[A-Za-z_][A-Za-z0-9_]*", self.text[self.index:])
        if not match:
            raise self.error("expected an identifier")
        self.index += match.end()
        return match.group(0)

    def peek_word(self) -> str:
        saved = self.index
        try:
            return self.word()
        except JockyRuntimeError:
            return ""
        finally:
            self.index = saved

    def number(self) -> int:
        self.skip_junk()
        match = _stdlib_re.match(r"0x[0-9a-fA-F]+|\d+", self.text[self.index:])
        if not match:
            raise self.error("expected a number")
        self.index += match.end()
        return int(match.group(0), 0)

    def string_literal(self) -> str:
        self.skip_junk()
        quote = self.text[self.index:self.index + 1]
        if quote != '"':
            raise self.error("expected a quoted string")
        self.index += 1
        out: List[str] = []
        while True:
            if self.index >= len(self.text):
                raise self.error("unterminated string")
            char = self.text[self.index]
            self.index += 1
            if char == "\\":
                if self.index >= len(self.text):
                    raise self.error("trailing backslash")
                escaped = self.text[self.index]
                self.index += 1
                mapping = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"',
                           "0": "\0"}
                if escaped == "x":
                    digits = self.text[self.index:self.index + 2]
                    if len(digits) != 2:
                        raise self.error("\\x needs two hex digits")
                    self.index += 2
                    out.append(chr(int(digits, 16)))
                elif escaped in mapping:
                    out.append(mapping[escaped])
                else:
                    raise self.error(f"unsupported escape \\{escaped}")
                continue
            if char == quote:
                return "".join(out)
            out.append(char)


def _hex_token_bytes(token: str) -> List[str]:
    """One hex-string token as the set of characters it can match."""
    if token == "??":
        return [ANY_BYTE]
    if "?" in token:
        # A nibble wildcard is 16 concrete bytes; spelling them out keeps the
        # engine honest (no new instruction, no new semantics).
        options = []
        for nibble in "0123456789abcdefABCDEF":
            candidate = token.replace("?", nibble, 1)
            options.append("\\x" + candidate.lower())
        return ["(?:" + "|".join(options) + ")"]
    return ["\\x" + token.lower()]


class _HexString:
    """Parser for YARA hex strings: ``{ 4D 5A ?? [4-6] ( 50 | 45 ) }``.

    Recursive descent over whitespace-separated tokens; the result is a pattern
    for the byte-string engine, where one character is one byte.
    """

    def __init__(self, body: str):
        self.tokens = body.split()
        self.index = 0

    def parse(self) -> str:
        parts = self._sequence(top_level=True)
        if self.index != len(self.tokens):
            raise JockyRuntimeError(
                f"yara hex string: unexpected token {self.tokens[self.index]!r}")
        if not parts:
            raise JockyRuntimeError("yara hex string is empty")
        return "".join(parts)

    def _sequence(self, top_level: bool = False) -> List[str]:
        parts: List[str] = []
        while self.index < len(self.tokens):
            token = self.tokens[self.index]
            if token in ("|", ")"):
                if top_level:
                    raise JockyRuntimeError(
                        f"yara hex string: unexpected {token!r}")
                return parts
            if token == "(":
                self.index += 1
                alternatives = []
                while True:
                    alternatives.append("".join(self._sequence()))
                    if self.index < len(self.tokens) and self.tokens[self.index] == "|":
                        self.index += 1
                        continue
                    break
                if self.index >= len(self.tokens) or self.tokens[self.index] != ")":
                    raise JockyRuntimeError("yara hex string: unbalanced parenthesis")
                self.index += 1
                parts.append("(?:" + "|".join(alternatives) + ")")
                continue
            if token.startswith("["):
                parts.append(self._jump(token))
                self.index += 1
                continue
            if token.startswith("~"):
                raise JockyRuntimeError("yara: '~' (not-byte) is not supported")
            if not _stdlib_re.fullmatch(r"[0-9a-fA-F?]{2}", token):
                raise JockyRuntimeError(f"yara hex string: bad token {token!r}")
            parts.append("".join(_hex_token_bytes(token)))
            self.index += 1
        if not top_level:
            raise JockyRuntimeError("yara hex string: unbalanced parenthesis")
        return parts

    @staticmethod
    def _jump(token: str) -> str:
        body = token.strip("[]")
        if "-" in body:
            low, _, high = body.partition("-")
            low_value = int(low, 0) if low else 0
            if not high:
                raise JockyRuntimeError(
                    "yara hex string: open-ended jumps are not supported")
            high_value = int(high, 0)
        else:
            low_value = high_value = int(body, 0)
        if low_value > high_value:
            raise JockyRuntimeError("yara hex string: inverted jump range")
        if low_value == high_value:
            return f"(?:{ANY_BYTE}){{{low_value}}}" if low_value else ""
        return f"(?:{ANY_BYTE}){{{low_value},{high_value}}}"


# --------------------------------------------------------------------- rules
@dataclass
class Pattern:
    """One compiled string: its identifier, pattern and modifiers."""

    identifier: str
    source: str
    pattern: Any
    nocase: bool = False
    fullword: bool = False

    def find(self, data: str, start: int = 0) -> Optional[Any]:
        return self.pattern.search(data, start)


@dataclass
class Rule:
    name: str
    meta: Dict[str, Any] = field(default_factory=dict)
    patterns: List[Pattern] = field(default_factory=list)
    condition_text: str = ""
    condition: Any = None
    tags: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------ match
    def matches(self, data: str) -> bool:
        """``data`` is a byte string (``fs.read_bytes``) or plain text."""
        cache: Dict[str, Optional[Any]] = {}
        hits: Dict[str, bool] = {}

        def string_hit(identifier: str, at: Optional[int] = None) -> bool:
            pattern = next((p for p in self.patterns if p.identifier == identifier), None)
            if pattern is None:
                raise JockyRuntimeError(f"yara rule: unknown string ${identifier}")
            if identifier not in cache:
                cache[identifier] = pattern.find(data)
            found = cache[identifier]
            if found is None:
                return False
            if at is None:
                return True
            # `search(data, at)` seeds a thread at that offset, so a match that
            # starts anywhere else means the string is not *at* the offset.
            if found.start == at:
                return True
            anchored = pattern.find(data, at)
            return anchored is not None and anchored.start == at

        def evaluate(node: Any) -> bool:
            kind = node[0]
            if kind == "str":
                return string_hit(node[1], node[2])
            if kind == "and":
                return evaluate(node[1]) and evaluate(node[2])
            if kind == "or":
                return evaluate(node[1]) or evaluate(node[2])
            if kind == "not":
                return not evaluate(node[1])
            if kind == "of":
                count, identifiers = node[1], node[2]
                hits_count = 0
                for identifier in identifiers:
                    if string_hit(identifier):
                        hits_count += 1
                        if hits_count >= count:
                            return True
                return False
            if kind == "filesize":
                operator, value = node[1], node[2]
                size = len(data)
                return {"<": size < value, "<=": size <= value,
                        ">": size > value, ">=": size >= value,
                        "==": size == value}.get(operator, False)
            raise JockyRuntimeError(f"yara: internal condition node {kind!r}")

        return evaluate(self.condition)

    def summary(self) -> Dict[str, Any]:
        return {
            "rule": self.name,
            "tags": self.tags,
            "meta": self.meta,
            "strings": [p.source for p in self.patterns],
            "condition": self.condition_text,
        }


class _RuleParser:
    def __init__(self, text: str):
        self.scanner = _Scanner(text)

    def parse(self) -> Rule:
        scanner = self.scanner
        scanner.skip_junk()
        if scanner.peek_word() != "rule":
            raise scanner.error("expected 'rule'")
        scanner.word()
        name = scanner.word()
        rule = Rule(name=name)
        scanner.take("{")
        while True:
            scanner.skip_junk()
            keyword = scanner.peek_word()
            if keyword == "meta":
                scanner.word()
                scanner.take(":")
                rule.meta = self._meta()
            elif keyword == "strings":
                scanner.word()
                scanner.take(":")
                self._strings(rule)
            elif keyword == "condition":
                scanner.word()
                scanner.take(":")
                rule.condition_text = self._condition_text()
                break
            else:
                raise scanner.error(f"unexpected section {keyword!r}")
        scanner.skip_junk()
        scanner.take("}")
        scanner.skip_junk()
        if scanner.index != len(scanner.text):
            raise scanner.error("trailing input after the rule")
        rule.condition = _ConditionParser(
            rule.condition_text, [p.identifier for p in rule.patterns]).parse()
        return rule

    def _meta(self) -> Dict[str, Any]:
        scanner = self.scanner
        meta: Dict[str, Any] = {}
        while True:
            scanner.skip_junk()
            saved = scanner.index
            word = scanner.peek_word()
            if word in ("strings", "condition") or word == "":
                scanner.index = saved
                return meta
            key = scanner.word()
            scanner.take("=")
            scanner.skip_junk()
            if scanner.text[scanner.index:scanner.index + 1] == '"':
                meta[key] = scanner.string_literal()
            elif scanner.text[scanner.index:scanner.index + 1] in "-0123456789":
                negative = scanner.maybe("-")
                value = scanner.number()
                meta[key] = -value if negative else value
            else:
                meta[key] = scanner.word()
            scanner.skip_junk()
            if scanner.maybe("="):
                raise scanner.error("expected a newline between meta entries")

    def _strings(self, rule: Rule) -> None:
        scanner = self.scanner
        while True:
            scanner.skip_junk()
            if not scanner.text.startswith("$", scanner.index):
                return
            scanner.take("$")
            identifier = scanner.word()
            scanner.take("=")
            scanner.skip_junk()
            modifiers: List[str] = []
            start = scanner.index
            if scanner.text.startswith("{", scanner.index):
                end = scanner.text.index("}", scanner.index)
                body = scanner.text[scanner.index + 1:end]
                scanner.index = end + 1
                source = "{ " + " ".join(body.split()) + " }"
                try:
                    pattern_text = _HexString(body).parse()
                except JockyRuntimeError as exc:
                    raise scanner.error(str(exc))
                kind = "hex"
            elif scanner.text.startswith("/", scanner.index):
                end = scanner.index + 1
                while end < len(scanner.text) and scanner.text[end] != "/":
                    if scanner.text[end] == "\\":
                        end += 1
                    end += 1
                body = scanner.text[scanner.index + 1:end]
                scanner.index = end + 1
                source = "/" + body + "/"
                pattern_text = body
                kind = "regex"
            else:
                literal = scanner.string_literal()
                source = '"' + literal + '"'
                pattern_text = literal
                kind = "literal"
            while True:
                scanner.skip_junk()
                modifier = scanner.peek_word()
                if modifier in SUPPORTED_MODIFIERS:
                    scanner.word()
                    modifiers.append(modifier)
                    continue
                if modifier in ("xor", "base64", "base64wide", "private", "wide_ascii"):
                    raise scanner.error(f"modifier {modifier!r} is not supported")
                break
            if "private" in modifiers:
                raise scanner.error("modifier 'private' is not supported")
            if not (start < scanner.index):
                raise scanner.error("empty string definition")
            try:
                rule.patterns.append(_build_pattern(identifier, source, pattern_text,
                                                    kind, modifiers, scanner))
            except JockyRuntimeError as exc:
                raise scanner.error(str(exc))

    def _condition_text(self) -> str:
        """Everything up to the closing brace of the rule body."""
        scanner = self.scanner
        depth = 0
        out: List[str] = []
        while scanner.index < len(scanner.text):
            char = scanner.text[scanner.index]
            if char == "{" :
                depth += 1
            elif char == "}":
                if depth == 0:
                    break
                depth -= 1
            out.append(char)
            scanner.index += 1
        return "".join(out).strip()


def _wide_body(text: str, kind: str) -> str:
    r"""The UTF-16LE form of a pattern body.

    Each *character* is escaped and then followed by a NUL, in that order:
    interleaving into an already-escaped body turns `cmd\.exe` into
    `c\x00m\x00d\x00\` + NUL + `.` … which is why a `wide` string never
    matched anything.
    """
    if kind == "hex":
        raise JockyRuntimeError("yara: 'wide' cannot be applied to a hex string")
    if kind == "regex" and _stdlib_re.search(r"[\\.*+?()\[\]{}|^$]", text):
        raise JockyRuntimeError(
            "yara: 'wide' on a regular expression is only supported when the pattern "
            "is literal text")
    return "".join(_stdlib_re.escape(character) + "\x00" for character in text)


def _build_pattern(identifier: str, source: str, body: str, kind: str,
                   modifiers: Sequence[str], scanner: _Scanner) -> Pattern:
    nocase = "nocase" in modifiers
    wide = "wide" in modifiers
    ascii_flag = "ascii" in modifiers or not wide
    if kind == "literal":
        ascii_body = _stdlib_re.escape(body)
    else:
        ascii_body = body
    if "fullword" in modifiers:
        ascii_body = r"\b" + ascii_body + r"\b"
    forms = [compile_pattern(ascii_body, nocase)]
    if wide:
        wide_body = _wide_body(body, kind)
        if "fullword" in modifiers:
            wide_body = r"\b" + wide_body + r"\b"
        wide_forms = [compile_pattern(wide_body, nocase)]
        forms = forms + wide_forms if ascii_flag else wide_forms
    first = forms[0]

    class _Alternatives:
        def __init__(self, patterns: List[Any]):
            self.patterns = patterns

        def search(self, data: str, start: int = 0):
            best = None
            for pattern in self.patterns:
                found = pattern.search(data, start)
                if found is not None and (best is None or found.start() < best.start()):
                    best = found
            return best

    return Pattern(identifier=identifier, source=source,
                   pattern=_Alternatives(forms) if len(forms) > 1 else first,
                   nocase=nocase, fullword="fullword" in modifiers)


# ---------------------------------------------------------------- conditions
_CONDITION_TOKEN = _stdlib_re.compile(
    r"\s*(\(|\)|[<>=!]=?|\$[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*|\d+)")


class _ConditionParser:
    """Recursive descent over the YARA condition subset that triage uses."""

    def __init__(self, text: str, identifiers: Sequence[str]):
        self.text = text
        self.identifiers = list(identifiers)
        self.tokens: List[str] = []
        position = 0
        while position < len(text):
            match = _CONDITION_TOKEN.match(text, position)
            if not match:
                if text[position:].strip():
                    raise JockyRuntimeError(
                        f"yara condition: cannot parse {text[position:position + 12]!r}")
                break
            self.tokens.append(match.group(1))
            position = match.end()
        self.pos = 0

    def peek(self) -> str:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else ""

    def take(self) -> str:
        token = self.peek()
        self.pos += 1
        return token

    def parse(self) -> Any:
        if not self.tokens:
            raise JockyRuntimeError("yara rule has an empty condition")
        node = self._or()
        if self.pos != len(self.tokens):
            raise JockyRuntimeError(f"yara condition: trailing input {self.peek()!r}")
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
                raise JockyRuntimeError("yara condition: missing ')'")
            return node
        if token.lower() == "filesize":
            self.take()
            operator = self.take()
            if operator not in ("<", "<=", ">", ">=", "=="):
                raise JockyRuntimeError(
                    f"yara condition: unsupported filesize comparison {operator!r}")
            return ("filesize", operator, int(self.take(), 0))
        if token.lower() in ("all", "any") or token.isdigit():
            count_token = self.take()
            if self.peek().lower() != "of":
                raise JockyRuntimeError(
                    f"yara condition: expected 'of' after {count_token!r}")
            self.take()
            if self.peek().lower() != "them":
                raise JockyRuntimeError(
                    "yara condition: only 'of them' is supported (string sets are not)")
            self.take()
            names = [identifier.lstrip("$") for identifier in self.identifiers]
            count = len(names) if count_token.lower() == "all" else (
                1 if count_token.lower() == "any" else int(count_token))
            if count > len(names):
                raise JockyRuntimeError(
                    f"yara condition: '{count_token} of them' cannot be satisfied "
                    f"({len(names)} string(s) defined)")
            return ("of", count, names)
        if token.startswith("$"):
            identifier = self.take().lstrip("$")
            if identifier not in [i.lstrip("$") for i in self.identifiers]:
                raise JockyRuntimeError(f"yara condition: unknown string ${identifier}")
            if self.peek().lower() == "at":
                self.take()
                offset = int(self.take(), 0)
                return ("str", identifier, offset)
            if self.peek().lower() == "in":
                raise JockyRuntimeError(
                    "yara condition: '$a in (…)' (range matching) is not supported")
            return ("str", identifier, None)
        if token.lower() in ("for", "uint8", "uint16", "uint32", "entrypoint", "pe",
                             "math", "hash"):
            raise JockyRuntimeError(
                f"yara condition: module or loop construct {token!r} is not supported")
        raise JockyRuntimeError(f"yara condition: unexpected token {token!r}")


_CACHE: Dict[str, Rule] = {}


def load_rule(text: str) -> Rule:
    """Parse a YARA rule (single rule per text), cached by text."""
    rule = _CACHE.get(text)
    if rule is None:
        if len(_CACHE) >= 64:
            _CACHE.clear()
        rule = _RuleParser(text).parse()
        _CACHE[text] = rule
    return rule
