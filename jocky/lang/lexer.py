"""
JOCKY lexer — source text to tokens.

Design notes
------------
* Newlines are insignificant; the grammar has no terminator requirement.
* Strings carry their interpolation segments: the lexer decodes escape
  sequences in the literal parts and leaves the embedded expressions as
  raw source for the parser to sub-parse. Interpolation uses ``{expr}``;
  ``{{`` and ``}}`` are literal braces.
* Token kinds are ``int``, ``float``, ``str``, ``ident``, ``kw``, ``op``
  and ``eof``.  For operators the kind *is* the operator text, which keeps
  the parser free of an operator enum.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Tuple

from jocky.errors import JockySyntaxError

KEYWORDS = frozenset({
    "let", "set", "if", "elif", "else", "while", "for", "in", "fn",
    "return", "break", "continue", "emit", "try", "catch",
    "true", "false", "nil", "and", "or", "not",
})

_TWO_CHAR_OPS = ("==", "!=", "<=", ">=")
_ONE_CHAR_OPS = "+-*/%<>=:;,.()[]{}"

_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "0": "\0",
    "\\": "\\", '"': '"', "{": "{", "}": "}",
}

# A string token value is a list of segments:
#   ("t", text)      literal text (escapes already decoded)
#   ("e", src, line, col)   interpolation expression, raw source
Segment = Tuple


@dataclass(frozen=True)
class Token:
    kind: str
    value: Any
    line: int
    col: int

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"{self.kind}:{self.value!r}@{self.line}:{self.col}"


class Lexer:
    """Turns JOCKY source into a flat token list."""

    def __init__(self, source: str):
        self.src = source or ""
        self.i = 0
        self.line = 1
        self.col = 1

    # ------------------------------------------------------------------ utils
    def _peek(self, k: int = 0) -> str:
        j = self.i + k
        return self.src[j] if j < len(self.src) else ""

    def _adv(self, n: int = 1) -> None:
        for _ in range(n):
            if self.i >= len(self.src):
                return
            if self.src[self.i] == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1
            self.i += 1

    def _error(self, msg: str, line: int = 0, col: int = 0) -> "JockySyntaxError":
        raise JockySyntaxError(msg, line or self.line, col or self.col)

    # --------------------------------------------------------------- scanners
    def _number(self, line: int, col: int) -> Token:
        start = self.i
        text = ""
        if self._peek() == "0" and self._peek(1).lower() in ("x", "b", "o"):
            base = {"x": 16, "b": 2, "o": 8}[self._peek(1).lower()]
            self._adv(2)
            digits = ""
            while self._peek().isalnum() or self._peek() == "_":
                digits += self._peek()
                self._adv()
            digits = digits.replace("_", "")
            if not digits:
                self._error("malformed numeric literal", line, col)
            try:
                value = int(digits, base)
            except ValueError:
                self._error(f"malformed numeric literal {self.src[start:self.i]!r}", line, col)
            return Token("int", value, line, col)

        while self._peek().isdigit() or self._peek() == "_":
            text += self._peek()
            self._adv()
        is_float = False
        if self._peek() == "." and self._peek(1).isdigit():
            is_float = True
            text += "."
            self._adv()
            while self._peek().isdigit() or self._peek() == "_":
                text += self._peek()
                self._adv()
        if self._peek() in "eE":
            nxt = self._peek(1)
            if nxt.isdigit() or (nxt in "+-" and self._peek(2).isdigit()):
                is_float = True
                text += "e"
                self._adv()
                if self._peek() in "+-":
                    text += self._peek()
                    self._adv()
                while self._peek().isdigit():
                    text += self._peek()
                    self._adv()
        clean = text.replace("_", "")
        try:
            return Token("float" if is_float else "int", float(clean) if is_float else int(clean), line, col)
        except ValueError:
            self._error(f"malformed numeric literal {clean!r}", line, col)

    def _string(self, line: int, col: int, raw: bool = False) -> Token:
        self._adv()  # opening quote
        segments: List[Segment] = []
        buf: List[str] = []

        def flush() -> None:
            if buf:
                segments.append(("t", "".join(buf)))
                buf.clear()

        if raw:
            # ``r"…"`` is literal text: no escapes, no interpolation. Detection
            # patterns are full of backslashes and repeat counts (`^\d{2}:\d{2}$`),
            # and spelling those inside a normal string means doubling the
            # backslashes and escaping every brace — a rule that reads nothing
            # like the pattern it encodes.
            while True:
                ch = self._peek()
                if ch == "":
                    self._error("unterminated raw string literal", line, col)
                if ch == '"':
                    self._adv()
                    break
                buf.append(ch)
                self._adv()
            flush()
            if not segments:
                segments.append(("t", ""))
            return Token("str", segments, line, col)

        while True:
            ch = self._peek()
            if ch == "":
                self._error("unterminated string literal", line, col)
            if ch == '"':
                self._adv()
                break
            if ch == "\\":
                self._adv()
                esc = self._peek()
                if esc == "":
                    self._error("unterminated escape sequence", line, col)
                if esc == "x" and self._peek(1) and self._peek(2):
                    hex2 = self._peek(1) + self._peek(2)
                    try:
                        buf.append(chr(int(hex2, 16)))
                    except ValueError:
                        self._error(f"bad hex escape \\x{hex2}", line, col)
                    self._adv(3)
                    continue
                if esc in _ESCAPES:
                    buf.append(_ESCAPES[esc])
                else:
                    # Unknown escape: keep the backslash. Detection patterns such
                    # as "\d+" must survive verbatim — silently dropping it turns
                    # a rule into something that never matches.
                    buf.append("\\" + esc)
                self._adv()
                continue
            if ch == "{":
                if self._peek(1) == "{":
                    buf.append("{")
                    self._adv(2)
                    continue
                self._adv()
                expr_line, expr_col = self.line, self.col
                depth = 1
                expr_src: List[str] = []
                while depth:
                    c = self._peek()
                    if c == "":
                        self._error("unterminated interpolation", expr_line, expr_col)
                    if c == '"':
                        # skip a nested string literal verbatim
                        expr_src.append(c)
                        self._adv()
                        while self._peek() not in ('"', ""):
                            if self._peek() == "\\":
                                expr_src.append(self._peek())
                                self._adv()
                            expr_src.append(self._peek())
                            self._adv()
                        expr_src.append('"')
                        self._adv()
                        continue
                    if c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            self._adv()
                            break
                    expr_src.append(c)
                    self._adv()
                flush()
                code = "".join(expr_src).strip()
                if not code:
                    self._error("empty interpolation", expr_line, expr_col)
                segments.append(("e", code, expr_line, expr_col))
                continue
            if ch == "}" and self._peek(1) == "}":
                buf.append("}")
                self._adv(2)
                continue
            buf.append(ch)
            self._adv()
        flush()
        if not segments:
            segments.append(("t", ""))
        return Token("str", segments, line, col)

    def _ident(self, line: int, col: int) -> Token:
        text = ""
        while self._peek().isalnum() or self._peek() == "_":
            text += self._peek()
            self._adv()
        return Token("kw" if text in KEYWORDS else "ident", text, line, col)

    # ------------------------------------------------------------------ entry
    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []
        while self.i < len(self.src):
            ch = self._peek()
            if ch in " \t\r\n":
                self._adv()
                continue
            if ch == "#":
                while self._peek() not in ("\n", ""):
                    self._adv()
                continue
            line, col = self.line, self.col
            if ch.isdigit() or (ch == "." and self._peek(1).isdigit()):
                tokens.append(self._number(line, col))
                continue
            if ch == '"':
                tokens.append(self._string(line, col))
                continue
            if ch in "rR" and self._peek(1) == '"':
                # Raw-string prefix. `r` immediately before a quote used to be an
                # identifier followed by a string, which never parsed — so this
                # costs no existing program its meaning.
                self._adv()
                tokens.append(self._string(line, col, raw=True))
                continue
            if ch.isalpha() or ch == "_":
                tokens.append(self._ident(line, col))
                continue
            two = self.src[self.i:self.i + 2]
            if two in _TWO_CHAR_OPS:
                self._adv(2)
                tokens.append(Token("op", two, line, col))
                continue
            if ch in _ONE_CHAR_OPS:
                self._adv()
                tokens.append(Token("op", ch, line, col))
                continue
            self._error(f"unexpected character {ch!r}")
        tokens.append(Token("eof", None, self.line, self.col))
        return tokens


def tokenize(source: str) -> List[Token]:
    """Convenience wrapper used by tests and tooling."""
    return Lexer(source).tokenize()
