"""
Pygments lexer for JOCKY source — ``.jky`` highlighting for editors, wikis and
static-site renderers.

The token vocabulary mirrors ``jocky/lang/lexer.py`` rather than inventing one:
the same ``KEYWORDS``, the same string rules, and therefore the same reading of
a file by reader and interpreter.  Four details are easy to get wrong and are
deliberate here:

* ``#`` starts a comment **only outside a string**.  Detection rules carry
  shell-style patterns such as ``"grep -v '^#' /etc/passwd"`` verbatim, so a
  lexer that fires comments inside strings paints half a script as a comment.
* ``{expr}`` inside a string is *code*: it is tokenized with the normal
  keyword/number/operator rules, and its braces are ``String.Interpol`` rather
  than punctuation, so a theme cannot render interpolation as a map literal.
* ``\\d`` (an unknown escape) must keep its backslash — ``\\\\.`` matches any
  escape, which is what the interpreter does (``_ESCAPES`` in ``jocky/lang``).
* ``r"…"`` is *raw*: no escape decoding and no interpolation, so the pattern
  ``r"^\\d{2}:\\d{2}$"`` shows its backslashes and braces as the characters they
  are (``String.Affix`` prefix, body up to the first ``"``).

Nothing else in ``jocky`` is imported: highlighting must work on a machine with
no procfs, and Pygments is an optional extra
(``pip install 'jocky-forensics[pygments]'``).
"""
from __future__ import annotations

from pygments.lexer import RegexLexer, bygroups, words
from pygments.token import (
    Comment,
    Keyword,
    Name,
    Number,
    Operator,
    Punctuation,
    String,
    Text,
    Whitespace,
)

__all__ = ["JockyLexer", "KEYWORDS", "NAMESPACES", "BUILTINS"]

#: Reserved words — kept identical to ``jocky/lang/lexer.py`` (``KEYWORDS``).
KEYWORDS = (
    "and", "break", "catch", "continue", "elif", "else", "emit", "false",
    "fn", "for", "if", "in", "let", "nil", "not", "or", "return", "set",
    "true", "try", "while",
)

#: Host namespaces a script can call into (``jocky/rt/builtins.py:namespaces``).
NAMESPACES = ("proc", "net", "fs", "sys", "det", "ioc", "mem", "time", "tl", "re",
              "sigma", "yara")

#: Value/collection natives from ``jocky/rt/builtins.py:core_builtins``.
BUILTINS = (
    "print", "assert", "expect", "expect_throws", "fail", "skip",
    "len", "str", "int", "float", "type", "range", "transform", "filter",
    "sort", "sort_by", "count", "join", "keys", "values", "contains",
    "dict", "now", "sleep", "json_encode", "json_decode", "hex", "error",
)

# Statement and expression level rules shared by the top level and by
# interpolation inside a string.  Order is significant: literal words are tried
# before the generic identifier rule, and the ``Text`` fallback last, so an
# unexpected byte degrades to plain text instead of an Error token.
_CODE_RULES = (
    (r"\s+", Whitespace),
    (r"#[^\n]*", Comment.Single),
    # numbers: hex/bin/octal, floats with exponent, decimals; ``_`` separators
    (r"0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*", Number.Hex),
    (r"0[bB][01](?:_?[01])*", Number.Bin),
    (r"0[oO][0-7](?:_?[0-7])*", Number.Oct),
    (r"(?:\d[\d_]*\.[\d_]+|\.\d[\d_]*)(?:[eE][+-]?\d+)?", Number.Float),
    (r"\d[\d_]*[eE][+-]?\d+", Number.Float),
    (r"\d[\d_]*", Number.Integer),
    (words(KEYWORDS, suffix=r"\b"), Keyword),
    (words(NAMESPACES, suffix=r"\b"), Name.Namespace),
    (words(BUILTINS, suffix=r"\b"), Name.Builtin),
    # ``r"…"`` / ``R"…"``: the prefix and its opening quote are claimed before
    # the identifier rule can swallow the ``r``, then the body is literal text.
    # Detection patterns live in raw literals so that a backslash and a ``{2}``
    # repeat count need no escaping.
    (r'([rR])(")', bygroups(String.Affix, String.Double), "raw-string"),
    (r"[A-Za-z_][A-Za-z0-9_]*", Name),
    (r'"', String.Double, "string"),
    # ``obj.member``: the attribute after a dot is not a variable, and a bare
    # ``.5`` float is excluded because the pattern cannot start with a digit.
    (r"(\.)([A-Za-z_][A-Za-z0-9_]*)", bygroups(Punctuation, Name.Attribute)),
    (r"==|!=|<=|>=|[+\-*/%<>]", Operator),
    (r"[=:;,]", Punctuation),
    (r"[()\[\]{}]", Punctuation),
    (r".", Text),
)

_STRING_RULES = (
    (r'"', String.Double, "#pop"),
    # ``{{`` / ``}}`` are literal braces, not interpolation; ``\xNN`` and any
    # other escape keep their backslash, matching the interpreter's decoder.
    (r"\{\{|\}\}", String.Escape),
    (r"\\x[0-9a-fA-F]{2}", String.Escape),
    (r"\\.", String.Escape),
    (r"\{", String.Interpol, "interp"),
    # A lone ``}`` is ordinary text (only ``}}`` is special), but it needs its
    # own rule so that ``}}`` above is still seen as an escape.
    (r"\}", String.Double),
    (r'[^\\"{}]+', String.Double),
    (r".", String.Double),
)

# ``r"…"`` is literal text up to the first ``"``: no escapes to decode and no
# interpolation to open, so ``\d`` and ``{2}`` are just characters — matching
# ``Lexer._string(raw=True)`` in ``jocky/lang/lexer.py``.
_RAW_STRING_RULES = (
    (r'"', String.Double, "#pop"),
    (r'[^"]+', String.Double),
)


class JockyLexer(RegexLexer):
    """Syntax highlighter for JOCKY scripts.

    Interpolation is tracked with an explicit state stack: ``interp`` pushes
    itself for every ``{`` and pops on ``}``, so nested map literals or lambdas
    inside ``"{…}"`` close in the right order and the string resumes afterwards.
    """

    name = "JOCKY"
    aliases = ["jocky", "jky"]
    filenames = ["*.jky"]
    mimetypes = ["text/x-jocky"]
    url = "https://jocky.vercel.app"

    tokens = {
        "root": [*_CODE_RULES],
        "string": [*_STRING_RULES],
        "raw-string": [*_RAW_STRING_RULES],
        "interp": [
            (r"\{", String.Interpol, "interp"),
            (r"\}", String.Interpol, "#pop"),
            *_CODE_RULES,
        ],
    }
