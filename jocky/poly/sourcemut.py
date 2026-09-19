"""Per-build token aliasing: every deployment spells keywords differently.

The problem statement requires token generation to differ per build. The
encoder already permutes the compiled bytes; this module closes the remaining
gap at the *source* layer: ``choose_alias_map`` derives a fresh spelling for
every keyword from a build seed, ``mutate_source`` rewrites the keyword spans
of a script to those spellings, and ``mutated_lexer_kwargs`` produces the
``keyword_table`` the lexer needs to read the result back.

Two decisions matter:

* Spans come from the lexer, never from text search. A keyword that occurs
  inside a string literal, a raw string or a comment is data, not syntax, and
  must survive unchanged; only a ``kw`` token's reported line/column locates
  text that is safe to rewrite.
* Interpolation segments are *not* rewritten. The parser re-lexes ``{expr}``
  fragments with a keyword-table-free lexer, so an alias placed there would
  not be read back. Leaving them alone is semantics-preserving either way:
  the canonical spellings still tokenize as keywords when a table is active.
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, Iterator, Mapping

from jocky.lang.lexer import KEYWORDS, Lexer

__all__ = ["choose_alias_map", "mutate_source", "mutated_lexer_kwargs"]

_IDENT_START = "_abcdefghijklmnopqrstuvwxyz"
_IDENT_BODY = _IDENT_START + "0123456789"
_IDENT_RE = re.compile(r"[_A-Za-z][_A-Za-z0-9]*\Z")


def _byte_stream(seed: bytes) -> Iterator[int]:
    """Endless deterministic byte stream keyed by ``seed`` (SHA-256 chain)."""
    counter = 0
    while True:
        digest = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        yield from digest
        counter += 1


def choose_alias_map(seed: bytes) -> Dict[str, str]:
    """Derive a per-build ``{keyword: alias}`` table from ``seed``.

    Every alias is an identifier-shaped spelling (``_``/letter start, 2–8
    chars) that is neither a canonical keyword nor another alias. The same
    seed always yields the same table; different seeds yield different ones.
    Collision with the script's *identifiers* cannot be decided here (the
    seed knows no source) and is rejected by :func:`mutate_source` instead.
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    stream = _byte_stream(bytes(seed))
    aliases: Dict[str, str] = {}
    for keyword in sorted(KEYWORDS):
        while True:
            length = 2 + next(stream) % 7
            chars = [_IDENT_START[next(stream) % len(_IDENT_START)]]
            for _ in range(length - 1):
                chars.append(_IDENT_BODY[next(stream) % len(_IDENT_BODY)])
            candidate = "".join(chars)
            if candidate not in KEYWORDS and candidate not in aliases.values():
                aliases[keyword] = candidate
                break
    return aliases


def _validate_alias_map(alias_map: Mapping[str, str]) -> None:
    """Reject tables that the lexer could never honour.

    An alias that is not identifier-shaped would tokenize as several tokens;
    an alias that shadows a keyword would never be read back (keywords win
    over the table); duplicate aliases collapse the reverse mapping. All
    three fail *here*, loudly, rather than as a parse error downstream.
    """
    for keyword, alias in alias_map.items():
        if keyword not in KEYWORDS:
            raise ValueError(f"{keyword!r} is not a JOCKY keyword")
        if not _IDENT_RE.fullmatch(alias):
            raise ValueError(f"alias {alias!r} is not an identifier spelling")
        if alias in KEYWORDS:
            raise ValueError(f"alias {alias!r} shadows a keyword")
    if len(set(alias_map.values())) != len(alias_map):
        raise ValueError("alias spellings must be unique")


def _line_starts(source: str) -> list[int]:
    starts = [0]
    for i, ch in enumerate(source):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def mutate_source(source: str, alias_map: Mapping[str, str]) -> str:
    """Rewrite the keyword spans of ``source`` according to ``alias_map``.

    ``alias_map`` maps canonical keyword -> alias spelling. Keyword text
    inside string literals, raw strings, interpolation fragments and comments
    is left byte-identical. Raises ``ValueError`` if the map is malformed or
    if an alias would collide with an identifier the script already uses
    (such a collision would silently re-bind the identifier to a keyword;
    reseeding is the fix).
    """
    _validate_alias_map(alias_map)
    starts = _line_starts(source)
    edits = []
    idents = set()
    for token in Lexer(source).tokenize():
        if token.kind == "kw" and token.value in alias_map:
            offset = starts[token.line - 1] + token.col - 1
            end = offset + len(token.value)
            assert source[offset:end] == token.value, (
                f"lexer span drifted at {token.line}:{token.col}"
            )
            edits.append((offset, end, alias_map[token.value]))
        elif token.kind == "ident":
            idents.add(token.value)
    # The whole table is active during lexing, so an unused alias that
    # matches a source identifier would still re-bind it to a keyword.
    collisions = idents & set(alias_map.values())
    if collisions:
        raise ValueError(
            f"alias(es) {sorted(collisions)} collide with identifiers already "
            "in the source; choose another seed"
        )
    out = []
    cursor = 0
    for offset, end, alias in edits:
        out.append(source[cursor:offset])
        out.append(alias)
        cursor = end
    out.append(source[cursor:])
    return "".join(out)


def mutated_lexer_kwargs(alias_map: Mapping[str, str]) -> Dict[str, Mapping[str, str]]:
    """Keyword arguments that make a Lexer read source mutated with this map.

    The lexer wants alias -> canonical keyword, the reverse of the mutation
    direction, so the table is inverted here.
    """
    _validate_alias_map(alias_map)
    return {"keyword_table": {alias: kw for kw, alias in alias_map.items()}}
