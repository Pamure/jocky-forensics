"""
Pygments lexer tests (``jocky/contrib/pygments_lexer.py``).

Pygments is an *optional* extra (``pip install 'jocky-forensics[pygments]'``), so
this module skips cleanly when it is missing.  When it is present the lexer is
run over every ``.jky`` file in the repository — the project's own scripts are
the widest real input the lexer has, and an editor integration that paints them
as ``Token.Error`` is worse than no integration.

Assertions are about what a reader sees — keywords, string bodies, interpolation
braces, comments, numbers — not about the rule table, so they survive any
rewrite of the patterns that keeps the same reading of a file.
"""
from __future__ import annotations

import importlib
import pathlib
import re
import sys
import tomllib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

pytest.importorskip("pygments",
                    reason="pygments is an optional extra: pip install 'jocky-forensics[pygments]'")

from jocky.contrib.pygments_lexer import (  # noqa: E402
    BUILTINS,
    JockyLexer,
    KEYWORDS,
    NAMESPACES,
)
from jocky.rt.builtins import core_builtins, default_natives  # noqa: E402
from pygments.token import Comment, Keyword, Name, Number, Operator, Punctuation, String, Text  # noqa: E402

CORPUS_PATTERNS = ("tests/lang/*.jky", "scripts/*.jky", "jocky/examples/*.jky")
CORPUS = tuple(sorted(path for pattern in CORPUS_PATTERNS for path in REPO.glob(pattern)))

# A raw literal, a normal literal, or a ``#`` comment, scanned left to right:
# whichever comes first wins, so a ``#`` *inside* a literal is text (detection
# rules are full of shell fragments) while a ``"`` inside a comment is just a
# character.  The raw form is listed first because backslashes in it are not
# escapes — `r"C:\"` ends at the quote, it is not an escaped quote.
_LITERAL_OR_COMMENT = re.compile(r'[rR]"[^"]*"|"(?:\\.|[^"\\])*"|#[^\n]*')

_IDS = [str(path.relative_to(REPO)) for path in CORPUS]


def string_literals(source: str):
    """The literal matches of ``source``, i.e. ``"…"``/``r"…"`` that are not comments."""
    return [match for match in _LITERAL_OR_COMMENT.finditer(source)
            if not match.group().startswith("#")]


def lex(source: str):
    """Tokenize ``source`` without Pygments' newline normalisation.

    ``ensurenl`` would append a ``\\n`` that is not in the file and ``stripnl``
    would remove whitespace, which would hide exactly the off-by-one mistakes
    these tests look for.
    """
    return list(JockyLexer(ensurenl=False, stripnl=False).get_tokens(source))


def lex_file(path: pathlib.Path):
    return lex(path.read_text(encoding="utf-8"))


def types_at(source: str):
    """Map every character offset to the type of the token covering it."""
    pairs = JockyLexer(ensurenl=False, stripnl=False).get_tokens_unprocessed(source)
    return {offset + i: ttype
            for offset, ttype, value in pairs
            for i in range(len(value))}


def code_only(source: str) -> str:
    """Blank out literals and comments, keeping offsets and newlines.

    Keyword detection must not fire on text inside ``"…"`` (detection rules are
    full of shell fragments such as ``grep -v '^#'``) nor inside ``#`` comments,
    so those regions are removed before asking "does this file use ``while``?".
    """
    return _LITERAL_OR_COMMENT.sub(lambda match: " " * len(match.group()), source)


# --------------------------------------------------------------------- corpus
def test_corpus_covers_the_repository():
    for pattern in CORPUS_PATTERNS:
        assert list(REPO.glob(pattern)), f"no sources matched {pattern}"


@pytest.mark.parametrize("path", CORPUS, ids=_IDS)
def test_sources_lex_without_error_tokens(path):
    source = path.read_text(encoding="utf-8")
    tokens = lex(source)
    assert [value for ttype, value in tokens if ttype is Text.Error] == []
    # Every character is accounted for exactly once: nothing was silently
    # dropped by a rule that stopped short, nothing was emitted twice.
    assert "".join(value for _, value in tokens) == source


@pytest.mark.parametrize("path", CORPUS, ids=_IDS)
def test_keywords_of_the_corpus_are_keyword_tokens(path):
    keyword_values = {value for ttype, value in lex_file(path) if ttype in Keyword}
    assert keyword_values <= set(KEYWORDS), f"non-keyword painted as keyword: {keyword_values - set(KEYWORDS)}"
    used = {word for word in KEYWORDS
            if re.search(rf"\b{re.escape(word)}\b", code_only(path.read_text(encoding="utf-8")))}
    if used:  # a keyword in the code region must have been recognised as one
        assert used <= keyword_values, f"unrecognised keywords: {used - keyword_values}"


@pytest.mark.parametrize("path", CORPUS, ids=_IDS)
def test_string_literals_are_highlighted_as_strings(path):
    """String bodies must not leak into ``Token.Text`` (or, worse, comments).

    A dropped ``"`` rule shows up immediately: the body would lex as identifiers
    and any ``#`` in it would open a comment, painting the rest of the line.
    """
    source = path.read_text(encoding="utf-8")
    types = types_at(source)
    for match in string_literals(source):
        literal, start = match.group(), match.start()
        raw = literal[0] in "rR"
        body = literal[2:-1] if raw else literal[1:-1]
        for offset in range(start, match.end()):
            ttype = types[offset]
            assert ttype is not Text, f"{literal!r}: {source[offset]!r} at {offset} lexed as Text"
            assert ttype not in Comment, f"{literal!r}: {source[offset]!r} at {offset} lexed as a comment"
            # a raw literal has no interpolation either: every character of it,
            # prefix included, is a string token
            if raw or "{" not in body:
                assert ttype in String, f"{literal!r}: {source[offset]!r} at {offset} lexed as {ttype}"


def test_keyword_tokens_are_produced_for_the_corpus():
    """Guards the per-file test above against a corpus that lost its keywords."""
    with_keywords = [path for path in CORPUS
                     if any(ttype in Keyword for ttype, _ in lex_file(path))]
    assert len(with_keywords) == len(CORPUS)


# ------------------------------------------------------------------- literals
def test_string_bodies_do_not_leak_as_text():
    source = 'let msg = "pid={p.pid} # literals stay literal"\n'
    tokens = lex(source)
    assert all(ttype is not Text for ttype, _ in tokens), tokens
    assert String.Double in {ttype for ttype, _ in tokens}


def test_interpolation_braces_are_not_punctuation():
    source = 'let s = "a{x + 1}b"'
    types = types_at(source)
    assert types[source.index("{")] is String.Interpol
    assert types[source.index("}")] is String.Interpol
    # the interpolation body is code, not string text
    assert types[source.index("+")] is Operator
    assert types[source.index("1")] is Number.Integer
    assert types[source.index('"')] is String.Double


def test_map_braces_outside_strings_are_punctuation():
    """Contrast with the test above: ``{}`` is only interpolation inside a string."""
    source = 'let m = {"k": 1}'
    types = types_at(source)
    assert types[source.index("{")] is Punctuation
    assert types[source.index("}")] is Punctuation


def test_nested_braces_in_interpolation_close_in_order():
    """A lambda inside ``{…}``: its braces must pop before the interpolation ends."""
    source = 'let s = "{ fn(x) { return x }(1) }"'
    tokens = lex(source)
    assert "".join(value for _, value in tokens) == source
    assert [value for ttype, value in tokens if ttype is String.Interpol] == ["{", "{", "}", "}"]
    assert [value for ttype, value in tokens if ttype is Keyword] == ["let", "fn", "return"]


def test_doubled_braces_are_escapes_not_interpolation():
    source = 'let s = "{{literal}}"'
    tokens = lex(source)
    assert [value for ttype, value in tokens if ttype is String.Interpol] == []
    assert [value for ttype, value in tokens if ttype is String.Escape] == ["{{", "}}"]
    assert "{{literal}}" in "".join(value for _, value in tokens)


def test_unknown_escapes_keep_their_backslash():
    """``"\\d+"`` is a detection pattern; the lexer must not eat the backslash."""
    tokens = lex(r'let p = "\d+ \w*"')
    escapes = [value for ttype, value in tokens if ttype is String.Escape]
    assert escapes == ["\\d", "\\w"]
    assert "".join(value for _, value in tokens) == r'let p = "\d+ \w*"'


def test_raw_string_body_is_one_literal_token():
    """``r"^\\d{2}$"`` is the pattern and nothing else: no escape, no interpolation."""
    source = r'let p = r"^\d{2}$"'
    tokens = lex(source)
    assert "".join(value for _, value in tokens) == source
    assert [ttype for ttype, _ in tokens if ttype in String.Interpol] == []
    assert [ttype for ttype, _ in tokens if ttype in String.Escape] == []
    # prefix, delimiter, body, delimiter — the body verbatim, backslash and
    # repeat count included
    assert [(ttype, value) for ttype, value in tokens if ttype in String] == [
        (String.Affix, "r"),
        (String.Double, '"'),
        (String.Double, "^\\d{2}$"),
        (String.Double, '"'),
    ]
    # contrast: the same text as an ordinary literal *is* escapes + interpolation
    plain = lex(r'let p = "^\\d{2}$"')
    assert [value for ttype, value in plain if ttype is String.Interpol] == ["{", "}"]
    assert [value for ttype, value in plain if ttype is String.Escape] == ["\\\\"]


def test_raw_string_braces_do_not_open_interpolation():
    """``{``/``}`` inside a raw literal are characters, not a state change."""
    source = r'let p = r"\d{2}#not-a-comment"'
    tokens = lex(source)
    assert [value for ttype, value in tokens if ttype is String.Interpol] == []
    assert [value for ttype, value in tokens if ttype in Comment] == []
    assert (String.Double, r"\d{2}#not-a-comment") in tokens
    # ... while the same characters in a normal literal *would* interpolate
    assert (String.Interpol, "{") in lex('let p = "\\d{2}"')


def test_capital_r_prefix_is_raw_too():
    source = r'let p = R"a\b{1}"'
    tokens = lex(source)
    assert (String.Affix, "R") in tokens
    assert (String.Double, r"a\b{1}") in tokens
    assert [value for ttype, value in tokens if ttype in (String.Escape, String.Interpol)] == []


def test_raw_string_ends_at_the_first_quote():
    """``r"C:\\"`` is a two-character body: a backslash escapes nothing."""
    tokens = lex(r'let p = r"C:\" + "x"')
    assert (String.Double, "C:\\") in tokens
    assert [value for ttype, value in tokens if ttype is String.Escape] == []
    assert (String.Double, '"x"') not in tokens  # the trailing literal is separate
    assert [value for ttype, value in tokens if ttype is String.Double] == [
        '"', "C:\\", '"', '"', "x", '"',
    ]


def test_r_is_still_a_variable_when_not_before_a_quote():
    assert (Name, "r") in lex("let r = 1")
    assert (Name.Builtin, "range") in lex("range(1)")


def test_hash_starts_a_comment_outside_a_string_only():
    commented = "# bash-style comment\nlet x = 1\n"
    comments = [(ttype, value) for ttype, value in lex(commented) if ttype in Comment]
    assert comments == [(Comment.Single, "# bash-style comment")]

    in_string = 'let s = "# not a comment"'
    assert all(ttype not in Comment for ttype, _ in lex(in_string))


@pytest.mark.parametrize("literal,expected", [
    ("0x1f", Number.Hex),
    ("0XFF", Number.Hex),
    ("0b101", Number.Bin),
    ("0o17", Number.Oct),
    ("1_000", Number.Integer),
    ("42", Number.Integer),
    ("1.5", Number.Float),
    (".5", Number.Float),
    ("1e3", Number.Float),
    ("1.5e-3", Number.Float),
])
def test_number_literals(literal, expected):
    assert lex(literal) == [(expected, literal)]


# ------------------------------------------------------------- runtime wiring
def test_runtime_names_are_covered_by_the_lexer():
    """A native or namespace the runtime exposes must not lex as plain keyword/text."""
    natives = default_natives()
    runtime_namespaces = {name for name, value in natives.items() if isinstance(value, dict)}
    assert set(core_builtins()) >= set(BUILTINS), \
        f"lexer lists builtins the runtime no longer has: {set(BUILTINS) - set(core_builtins())}"
    assert runtime_namespaces <= set(NAMESPACES), \
        f"lexer does not know namespaces: {runtime_namespaces - set(NAMESPACES)}"
    for name in set(core_builtins()) | runtime_namespaces:
        assert {ttype for ttype, _ in lex(name)} <= {Name, Name.Builtin, Name.Namespace}, name


def test_namespaces_builtins_and_members_get_their_token_types():
    for namespace in NAMESPACES:
        assert lex(namespace) == [(Name.Namespace, namespace)]
    for builtin in BUILTINS:
        assert lex(builtin) == [(Name.Builtin, builtin)]
    assert types_at("det.fileless")[4] is Name.Attribute
    assert types_at("det.fileless")[3] is Punctuation


def test_lexer_is_discoverable_by_editors():
    """The published entry point and file glob are what makes highlighting fire."""
    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    assert "*.jky" in JockyLexer.filenames
    assert "jocky" in JockyLexer.aliases

    extra = data["project"]["optional-dependencies"]["pygments"]
    assert any(spec.split(">=")[0].strip().lower() == "pygments" for spec in extra), extra

    target = data["project"]["entry-points"]["pygments.lexers"]["jocky"]
    module_name, _, attribute = target.partition(":")
    assert target == "jocky.contrib.pygments_lexer:JockyLexer"
    assert getattr(importlib.import_module(module_name), attribute) is JockyLexer
