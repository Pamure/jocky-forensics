"""
A small, linear-time pattern engine for forensic scripts.

Why not Python's ``re``: a backtracking engine is exponential on adversarial
patterns, and the text a triage script matches is attacker-controlled (command
lines, filenames, log fields). ``(a+)+b`` against a few kilobytes of ``a`` hangs
``re``; this engine compiles the pattern to an NFA and simulates it with a
Pike VM, so the cost is O(len(text) x len(pattern)) whatever the pattern looks
like. A step budget turns even a pathological combination into a catchable
error instead of a wedged collection run.

Supported syntax (deliberate subset, and a syntax error otherwise — never a
silently different meaning)::

    literal characters, ``.``
    escapes            \\d \\D \\w \\W \\s \\S \\b \\B
                       \\n \\t \\r \\f \\v \\0 \\a \\xNN  (\\b = backspace in a class)
    classes            [abc] [^abc] [a-z0-9_] [\\x00-\\x1f] (escapes allowed both ends)
    anchors            ^ at the start, $ at the end (or before a final newline)
    quantifiers        * + ? {m} {m,} {m,n}      (greedy)
    alternation        a|b
    groups             (...) capturing, (?:...) non-capturing

``\\xNN`` is what byte patterns are written with (``r"\\x7fELF"`` against the
byte string ``fs.read_bytes`` returns). An unknown letter escape (``\\q``) is an
error rather than a literal ``q``, because a typo that turns a rule into
something that matches nothing is the worst failure mode a detection engine can
have.

Matching is **leftmost-longest** (POSIX), not Perl's leftmost-first: for ``a|ab``
against ``ab`` the match is ``ab``. That is the predictable choice for detection
work where the question is "does this line look like X", and it keeps the engine
free of thread-priority subtleties that are easy to get subtly wrong.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from jocky.errors import JockyRuntimeError

#: Instruction ceiling for a compiled pattern: a bound on absurd input.
MAX_PROGRAM = 4000
#: Simulation step ceiling per call: len(text) x len(pattern) is bounded here so
#: a huge file cannot turn one match into an unbounded pause.
DEFAULT_STEP_BUDGET = 4_000_000
#: Ceiling for explicit {n} / {n,m} repeat counts.
MAX_REPEAT = 100_000

_DIGIT = "0123456789"
_WORD = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
_SPACE = " \t\n\r\f\v"
_HEX_DIGITS = "0123456789abcdefABCDEF"

#: Single-character escapes, `\b` included: inside a class it is the backspace
#: that byte patterns need, outside it is the word boundary (see `_escape`).
_ESCAPE_CHARS = {"n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v",
                 "0": "\0", "a": "\a", "b": "\b"}


def _is_word_char(char: str) -> bool:
    """``char in _WORD`` is true for the empty string — check length first."""
    return bool(char) and char in _WORD


# --------------------------------------------------------------------- parsing
@dataclass
class _Node:
    pass


@dataclass
class _Empty(_Node):
    pass


@dataclass
class _Char(_Node):
    value: str = ""


@dataclass
class _Any(_Node):
    pass


@dataclass
class _Class(_Node):
    ranges: List[Tuple[str, str]] = field(default_factory=list)
    literals: str = ""
    negated: bool = False


@dataclass
class _Anchor(_Node):
    kind: str = ""            # bol | eol | word | nonword


@dataclass
class _Seq(_Node):
    items: List[_Node] = field(default_factory=list)


@dataclass
class _Alt(_Node):
    branches: List[_Node] = field(default_factory=list)


@dataclass
class _Repeat(_Node):
    node: _Node = None
    low: int = 0
    high: Optional[int] = None


@dataclass
class _Group(_Node):
    node: _Node = None
    index: int = 0            # 0 = non-capturing


class _Parser:
    def __init__(self, source: str, ignore_case: bool):
        self.src = source
        self.i = 0
        self.ignore_case = ignore_case
        self.groups = 0

    # ------------------------------------------------------------- utilities
    def _peek(self) -> str:
        return self.src[self.i] if self.i < len(self.src) else ""

    def _next(self) -> str:
        char = self._peek()
        self.i += 1
        return char

    def _error(self, message: str) -> JockyRuntimeError:
        return JockyRuntimeError(f"pattern error at offset {self.i}: {message} in {self.src!r}")

    # ---------------------------------------------------------------- grammar
    def parse(self) -> _Node:
        node = self._alternation()
        if self.i != len(self.src):
            raise self._error("unexpected character")
        return node

    def _alternation(self) -> _Node:
        branches = [self._sequence()]
        while self._peek() == "|":
            self._next()
            branches.append(self._sequence())
        return branches[0] if len(branches) == 1 else _Alt(branches=branches)

    def _sequence(self) -> _Node:
        items: List[_Node] = []
        while self._peek() not in ("", "|", ")"):
            items.append(self._repetition())
        if not items:
            return _Empty()
        return items[0] if len(items) == 1 else _Seq(items=items)

    def _repetition(self) -> _Node:
        node = self._atom()
        char = self._peek()
        if char == "*":
            self._next()
            node = _Repeat(node=node, low=0, high=None)
        elif char == "+":
            self._next()
            node = _Repeat(node=node, low=1, high=None)
        elif char == "?":
            self._next()
            node = _Repeat(node=node, low=0, high=1)
        elif char == "{":
            node = self._braces(node)
        if self._peek() == "?":
            raise self._error("lazy quantifiers are not supported; matching is greedy")
        return node

    def _braces(self, node: _Node) -> _Node:
        self._next()                                    # '{'
        digits = ""
        while self._peek().isdigit():
            digits += self._next()
        if not digits:
            raise self._error("expected a repeat count after '{'")
        low = int(digits)
        high: Optional[int] = low
        if self._peek() == ",":
            self._next()
            more = ""
            while self._peek().isdigit():
                more += self._next()
            high = int(more) if more else None
        if self._peek() != "}":
            raise self._error("unterminated repeat")
        self._next()
        if high is not None and high < low:
            raise self._error("repeat range is inverted")
        cap = high if high is not None else low
        if cap > MAX_REPEAT:
            raise JockyRuntimeError(
                f"repeat count {cap} exceeds the 100,000 ceiling"
            )
        return _Repeat(node=node, low=low, high=high)

    def _atom(self) -> _Node:
        char = self._peek()
        if char == "":
            raise self._error("unexpected end of pattern")
        if char == "(":
            self._next()
            index = 0
            if self._peek() == "?":
                if self.src[self.i:self.i + 2] == "?:":
                    self.i += 2
                elif self.src[self.i:self.i + 2] == "?i":
                    raise self._error("use the ignore_case flag instead of (?i)")
                else:
                    raise self._error("unsupported group prefix")
            else:
                self.groups += 1
                index = self.groups
            inner = self._alternation()
            if self._peek() != ")":
                raise self._error("unterminated group")
            self._next()
            return _Group(node=inner, index=index)
        if char == "[":
            return self._class()
        if char == ".":
            self._next()
            return _Any()
        if char == "^":
            self._next()
            return _Anchor(kind="bol")
        if char == "$":
            self._next()
            return _Anchor(kind="eol")
        if char in "*+?":
            raise self._error(f"quantifier {char!r} has nothing to repeat")
        if char == "\\":
            self._next()
            return self._escape()
        self._next()
        return _Char(value=char)

    def _escape(self) -> _Node:
        char = self._peek()
        if char == "":
            raise self._error("trailing backslash")
        self._next()
        if char in "dDwWsS":
            node = _Class(literals=_DIGIT if char in "dD" else
                          (_WORD if char in "wW" else _SPACE))
            node.negated = char.isupper()
            return node
        if char in "bB":
            return _Anchor(kind="word" if char == "b" else "nonword")
        if char == "x":
            return _Char(value=self._hex_escape())
        mapped = _ESCAPE_CHARS
        if char in mapped:
            return _Char(value=mapped[char])
        if char.isalpha():
            # `\q` reading as a literal `q` turns a typo into a rule that never
            # matches — in a tool whose verdicts people act on. Python's `re`
            # errors here too, and a byte pattern has `\xNN` for everything else.
            raise self._error(f"unsupported escape \\{char}")
        if char.isdigit():
            # `\1` is a back-reference in Perl-style syntax. Compiling it to the
            # literal digit is the worst possible outcome: `(\w+)-\1` would match
            # "a-1" and never match "a-a", which is the opposite of the intent.
            raise self._error(
                f"back-references (\\{char}) are not supported: group captures are "
                "available through re.captures()")
        return _Char(value=char)

    def _hex_escape(self) -> str:
        """``\\xNN`` — the one escape a byte pattern cannot do without."""
        digits = self.src[self.i:self.i + 2]
        if len(digits) != 2 or any(digit not in _HEX_DIGITS for digit in digits):
            raise self._error("\\x needs exactly two hex digits")
        self.i += 2
        return chr(int(digits, 16))

    def _class(self) -> _Node:
        self._next()                                     # '['
        node = _Class()
        if self._peek() == "^":
            self._next()
            node.negated = True
        first = True
        while True:
            char = self._peek()
            if char == "":
                raise self._error("unterminated character class")
            if char == "]" and not first:
                self._next()
                return node
            first = False
            nxt = self.src[self.i + 1:self.i + 2]
            if char == "\\" and nxt in "dDwWsS":
                esc = nxt
                if esc.isupper():
                    raise self._error("negated shorthand classes are not supported inside []")
                self._next()
                self._next()
                node.literals += _DIGIT if esc in "dD" else (_WORD if esc in "wW" else _SPACE)
                continue
            low = self._class_atom()
            if self._peek() == "-" and self.src[self.i + 1:self.i + 2] not in ("]", ""):
                self._next()
                high = self._class_atom()
                if ord(high) < ord(low):
                    raise self._error("inverted character range")
                node.ranges.append((low, high))
            else:
                node.literals += low

    def _class_atom(self) -> str:
        """One character inside ``[…]``, including ``\\xNN`` endpoints.

        A byte class like ``[\\x00-\\x1f]`` is the reason this exists: escaping
        only the *first* endpoint would have made the range unparseable, so both
        ends go through the same decoder.
        """
        char = self._peek()
        if char == "":
            raise self._error("unterminated character class")
        if char != "\\":
            self._next()
            return char
        self._next()
        esc = self._peek()
        if esc == "":
            raise self._error("trailing backslash in character class")
        self._next()
        if esc == "x":
            return self._hex_escape()
        if esc in _ESCAPE_CHARS:
            return _ESCAPE_CHARS[esc]
        if esc.isalpha():
            raise self._error(f"unsupported escape \\{esc} inside []")
        return esc


# -------------------------------------------------------------------- compiler
_I_CHAR, _I_ANY, _I_CLASS, _I_SPLIT, _I_JMP, _I_SAVE, _I_MATCH, _I_ANCHOR = range(8)


@dataclass
class _Inst:
    op: int
    payload: object = None
    x: int = 0
    y: int = 0


def _fold(char: str, ignore_case: bool) -> str:
    return char.lower() if ignore_case else char


class _Compiler:
    def __init__(self, ignore_case: bool):
        self.program: List[_Inst] = []
        self.ignore_case = ignore_case

    def emit(self, inst: _Inst) -> int:
        self.program.append(inst)
        if len(self.program) > MAX_PROGRAM:
            raise JockyRuntimeError("pattern is too large to compile")
        return len(self.program) - 1

    def compile(self, node: _Node) -> List[_Inst]:
        self.emit(_Inst(_I_SAVE, 0))
        self.walk(node)
        self.emit(_Inst(_I_SAVE, 1))
        self.emit(_Inst(_I_MATCH))
        return self.program

    def walk(self, node: _Node) -> None:
        if isinstance(node, _Empty):
            return
        if isinstance(node, _Char):
            self.emit(_Inst(_I_CHAR, _fold(node.value, self.ignore_case)))
            return
        if isinstance(node, _Any):
            self.emit(_Inst(_I_ANY))
            return
        if isinstance(node, _Class):
            ranges = [(_fold(low, self.ignore_case), _fold(high, self.ignore_case))
                      for low, high in node.ranges]
            literals = "".join(_fold(char, self.ignore_case) for char in node.literals)
            self.emit(_Inst(_I_CLASS, (literals, ranges, node.negated)))
            return
        if isinstance(node, _Anchor):
            self.emit(_Inst(_I_ANCHOR, node.kind))
            return
        if isinstance(node, _Seq):
            for item in node.items:
                self.walk(item)
            return
        if isinstance(node, _Group):
            if node.index:
                self.emit(_Inst(_I_SAVE, node.index * 2))
                self.walk(node.node)
                self.emit(_Inst(_I_SAVE, node.index * 2 + 1))
            else:
                self.walk(node.node)
            return
        if isinstance(node, _Alt):
            jumps: List[int] = []
            for position, branch in enumerate(node.branches):
                last = position == len(node.branches) - 1
                if last:
                    self.walk(branch)
                    break
                split = self.emit(_Inst(_I_SPLIT))
                here = len(self.program)
                self.walk(branch)
                jumps.append(self.emit(_Inst(_I_JMP)))
                self.program[split].x = here
                self.program[split].y = len(self.program)
            for jump in jumps:
                self.program[jump].x = len(self.program)
            return
        if isinstance(node, _Repeat):
            self.repeat(node)
            return
        raise JockyRuntimeError(f"internal: unsupported pattern node {type(node).__name__}")

    def repeat(self, node: _Repeat) -> None:
        low, high = node.low, node.high or 0
        # `a{1000000000000000000}` must not be a compile-time loop. Two guards:
        # a repeat of an *empty* body is a no-op however large the count (the
        # instruction bound would never see it — that was a hang, reachable from
        # an untrusted Sigma rule), and the total number of copies is capped the
        # same way the program size is.
        expansions = low + (0 if node.high is None else high - low)
        if expansions > MAX_PROGRAM:
            raise JockyRuntimeError(
                f"pattern repeat count is too large to compile ({expansions} copies; "
                f"limit {MAX_PROGRAM})")
        if low:
            before = len(self.program)
            self.walk(node.node)
            if len(self.program) == before:
                # Body emits nothing: `(?:){n}` is `(?:)`, not n copies of nothing.
                return
            for _ in range(low - 1):
                self.walk(node.node)
        if node.high is None:
            split = self.emit(_Inst(_I_SPLIT))
            start = len(self.program)
            self.walk(node.node)
            # Loop back to the *split*, not to the body: otherwise the exit
            # branch is only considered once and `\d+` can never stop matching.
            # Control-flow targets live in `x`/`y` for every instruction that
            # jumps; `payload` carries data only (a mismatch here silently sent
            # every loop-back to instruction 0).
            self.emit(_Inst(_I_JMP, x=split))
            self.program[split].x = start
            self.program[split].y = len(self.program)
            return
        for _ in range(high - low):
            split = self.emit(_Inst(_I_SPLIT))
            start = len(self.program)
            self.walk(node.node)
            self.program[split].x = start
            self.program[split].y = len(self.program)


# ------------------------------------------------------------------ simulation
@dataclass
class Match:
    """A match with its capture groups (``groups[0]`` is the whole match)."""

    start: int = 0
    end: int = 0
    groups: List[Optional[str]] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.groups[0] or ""

    def group(self, index: int = 0) -> Optional[str]:
        return self.groups[index] if 0 <= index < len(self.groups) else None


class Pattern:
    """A compiled pattern. Immutable and safe to reuse across calls."""

    def __init__(self, source: str, ignore_case: bool = False):
        self.source = source
        self.ignore_case = ignore_case
        parser = _Parser(source, ignore_case)
        node = parser.parse()
        self.group_count = parser.groups
        compiler = _Compiler(ignore_case)
        self.program: List[_Inst] = compiler.compile(node)

    # ------------------------------------------------------------- matching
    def search(self, text: str, start: int = 0,
               step_budget: int = DEFAULT_STEP_BUDGET) -> Optional[Match]:
        """Leftmost-longest match at or after ``start``.

        Threads are seeded at every position until a match is found; afterwards
        only the threads already running may extend it, which is what makes the
        result leftmost-longest rather than first-found.
        """
        length = len(text)
        width = self.group_count * 2 + 2
        best: Optional[Match] = None
        current: List[Tuple[int, List[Optional[int]]]] = []
        # Two `seen` sets, one per position: the seeding walk belongs to the
        # position being processed, the transition closures belong to the next
        # one. Sharing a single set made a loop-back into a split that seeding
        # had already visited (`\s*,\s*` on " , ") vanish.
        seen_now = [False] * len(self.program)
        seen_next = [False] * len(self.program)
        steps = 0
        position = start
        while position <= length:
            if best is None or position <= best.start:
                self._add(current, 0, [None] * width, position, text, seen_now)
            nxt: List[Tuple[int, List[Optional[int]]]] = []
            for pc, caps in current:
                steps += 1
                if steps > step_budget:
                    raise JockyRuntimeError(
                        f"pattern match exceeded its step budget ({step_budget}): "
                        "narrow the pattern or the text")
                inst = self.program[pc]
                if inst.op == _I_CHAR:
                    if position < length and _fold(text[position], self.ignore_case) == inst.payload:
                        self._add(nxt, pc + 1, caps, position + 1, text, seen_next)
                elif inst.op == _I_ANY:
                    if position < length and text[position] != "\n":
                        self._add(nxt, pc + 1, caps, position + 1, text, seen_next)
                elif inst.op == _I_CLASS:
                    if position < length and self._in_class(inst.payload, text[position]):
                        self._add(nxt, pc + 1, caps, position + 1, text, seen_next)
                elif inst.op == _I_MATCH:
                    matched = self._build_match(caps, position, text)
                    if best is None or (matched.start, -matched.end) < (best.start, -best.end):
                        best = matched
            current = nxt
            position += 1
            seen_now, seen_next = seen_next, [False] * len(self.program)
            if best is not None and not current:
                break
        return best

    def fullmatch(self, text: str) -> Optional[Match]:
        match = self.search(text, 0)
        return match if match is not None and match.start == 0 and match.end == len(text) else None

    def test(self, text: str) -> bool:
        return self.search(text) is not None

    def find_all(self, text: str, limit: Optional[int] = None) -> List[Match]:
        results: List[Match] = []
        position = 0
        while position <= len(text):
            match = self.search(text, position)
            if match is None:
                break
            results.append(match)
            if limit is not None and len(results) >= limit:
                break
            position = match.end if match.end > match.start else match.end + 1
        return results

    def sub(self, text: str, replacement: str, limit: Optional[int] = None) -> str:
        out: List[str] = []
        position = 0
        count = 0
        while position <= len(text):
            match = self.search(text, position)
            if match is None:
                break
            out.append(text[position:match.start])
            out.append(self._expand(replacement, match))
            if match.end > match.start:
                position = match.end
            else:
                # A zero-width match consumes nothing, so the character *after*
                # it belongs to the output; copying it while advancing is what
                # makes `re.replace(r"\s*", "a b c", "")` return "abc" instead of
                # deleting the text the pattern stepped over.
                if match.end < len(text):
                    out.append(text[match.end])
                position = match.end + 1
            count += 1
            if limit is not None and count >= limit:
                break
        out.append(text[position:])
        return "".join(out)

    def split(self, text: str, limit: Optional[int] = None) -> List[str]:
        parts: List[str] = []
        position = 0                 # where the next search starts
        last = 0                     # where the current piece starts
        while position <= len(text):
            match = self.search(text, position)
            if match is None or (limit is not None and len(parts) >= limit - 1):
                break
            # The two roles differ exactly when a match is empty: it consumes
            # nothing, so the character it stepped over belongs to the *next*
            # piece. Sharing one variable here made `re.split("", "ab")` return
            # ['', '', '', ''] instead of ['', 'a', 'b', ''].
            parts.append(text[last:match.start])
            last = match.end
            position = match.end if match.end > match.start else match.end + 1
        parts.append(text[last:])
        return parts

    # ------------------------------------------------------------- internals
    @staticmethod
    def _match_start(caps: List[Optional[int]]) -> int:
        return caps[0] if caps[0] is not None else 0

    def _build_match(self, caps: List[Optional[int]], end: int, text: str) -> Match:
        start = caps[0] or 0
        groups: List[Optional[str]] = [text[start:end]]
        for index in range(1, self.group_count + 1):
            low, high = caps[index * 2], caps[index * 2 + 1]
            groups.append(text[low:high] if low is not None and high is not None else None)
        return Match(start=start, end=end, groups=groups)

    def _expand(self, replacement: str, match: Match) -> str:
        out: List[str] = []
        index = 0
        while index < len(replacement):
            char = replacement[index]
            if char in "\\$" and index + 1 < len(replacement) and replacement[index + 1].isdigit():
                group = int(replacement[index + 1])
                out.append(match.group(group) or "")
                index += 2
                continue
            out.append(char)
            index += 1
        return "".join(out)

    def _add(self, threads: List[Tuple[int, List[Optional[int]]]], pc: int,
             caps: List[Optional[int]], position: int, text: str,
             seen: List[bool]) -> None:
        """Follow epsilon transitions and record the thread if it is new."""
        stack = [(pc, caps)]
        while stack:
            pc, caps = stack.pop()
            if pc < 0 or pc >= len(self.program) or seen[pc]:
                continue
            seen[pc] = True
            inst = self.program[pc]
            if inst.op == _I_JMP:
                stack.append((inst.x, caps))
            elif inst.op == _I_SPLIT:
                stack.append((inst.y, caps))
                stack.append((inst.x, caps))
            elif inst.op == _I_SAVE:
                slot = int(inst.payload)
                saved = list(caps)
                if slot < len(saved):
                    saved[slot] = position
                stack.append((pc + 1, saved))
            elif inst.op == _I_ANCHOR:
                if self._anchor_ok(inst.payload, text, position):
                    stack.append((pc + 1, caps))
            else:
                threads.append((pc, caps))

    @staticmethod
    def _anchor_ok(kind: str, text: str, position: int) -> bool:
        if kind == "bol":
            return position == 0
        if kind == "eol":
            return position == len(text) or (position == len(text) - 1 and text[position] == "\n")
        before = text[position - 1] if position > 0 else ""
        after = text[position] if position < len(text) else ""
        # An empty text has no word character on either side, and the host engine
        # reports *neither* boundary there: `\B` must not match where `\b` cannot.
        if not text:
            return False
        at_boundary = _is_word_char(before) != _is_word_char(after)
        return at_boundary if kind == "word" else not at_boundary

    def _in_class(self, spec: object, char: str) -> bool:
        literals, ranges, negated = spec              # type: ignore[misc]
        folded = _fold(char, self.ignore_case)
        hit = folded in literals or any(low <= folded <= high for low, high in ranges)
        return not hit if negated else hit


_CACHE: Dict[Tuple[str, bool], Pattern] = {}


def compile_pattern(source: str, ignore_case: bool = False) -> Pattern:
    """Compile (with a small cache: triage loops reuse the same pattern)."""
    key = (source, ignore_case)
    pattern = _CACHE.get(key)
    if pattern is None:
        pattern = Pattern(source, ignore_case)
        if len(_CACHE) < 256:
            _CACHE[key] = pattern
    return pattern
