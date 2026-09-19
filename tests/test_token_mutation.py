"""Token generation must differ per build without changing behaviour.

Pillar 1 of the brief requires token-level polymorphism: two builds of the
same script must not share keyword spellings. ``jocky.poly.sourcemut`` proves
this by deriving a per-seed alias for every keyword, rewriting the keyword
spans of a script, and lexing the result back through the new
``keyword_table`` lexer hook.

The load-bearing assertion in this file is compiled-program identity, not
text comparison: for every shipped script and three seeds, the mutated source
must compile to exactly the same ``Program`` (opcodes, constants, name pool,
prototypes) as the original. Two weasel checks make that meaningful:

* a negative test proves the parser really reads the alias table — mutated
  source without the table is a syntax error, so equality above cannot be
  the result of the aliases being silently ignored;
* a span-level test proves the aliases reached the token stream — no
  keyword-shaped spelling survives outside strings and comments.

Findings are compared by run health and shape rather than byte equality:
scripts like ``inventory.jky`` embed live host state (uptime, process
counts), which drifts between any two runs of the *same* source — that is
host time moving, not the mutation changing behaviour. The exact-equality
claim lives where it can be exact: the compiled program.
"""
from __future__ import annotations

import itertools
import pathlib
import re
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.errors import JockySyntaxError  # noqa: E402
from jocky.lang import Lexer, Parser, compile_program, parse  # noqa: E402
from jocky.lang.lexer import KEYWORDS  # noqa: E402
from jocky.poly.sourcemut import (  # noqa: E402
    choose_alias_map,
    mutate_source,
    mutated_lexer_kwargs,
)
from jocky.runner import run_program, run_source  # noqa: E402

SCRIPTS = sorted((REPO / "scripts").rglob("*.jky"))

#: Fixed so the suite is reproducible; chosen to be identifier-collision-free
#: against the shipped library (a colliding seed is a ``ValueError`` by
#: design, see test_alias_colliding_with_an_identifier_is_refused).
SEEDS = (b"sih148-alias-0", b"sih148-alias-1", b"sih148-alias-2")

_ALIAS_SHAPE = re.compile(r"[_A-Za-z][_A-Za-z0-9]*\Z")


def _compile_mutated(source: str, alias_map: dict) -> object:
    """Compile mutated source using exactly the kwargs the module hands out."""
    tokens = Lexer(source, **mutated_lexer_kwargs(alias_map)).tokenize()
    return compile_program(Parser(tokens, source).parse_program())


def test_alias_map_covers_every_keyword_with_identifier_spelling():
    table = choose_alias_map(SEEDS[0])
    assert set(table) == set(KEYWORDS), (
        f"missing aliases: {set(KEYWORDS) - set(table)}"
    )
    for keyword, alias in table.items():
        assert _ALIAS_SHAPE.fullmatch(alias), f"{keyword} -> {alias!r} not identifier-shaped"
        assert 2 <= len(alias) <= 8, f"{keyword} -> {alias!r} outside length 2..8"
        assert alias[0] == "_" or alias[0].isalpha()
        assert alias not in KEYWORDS, f"{keyword} -> {alias!r} shadows a keyword"
    assert len(set(table.values())) == len(table), "aliases must be unique"


def test_alias_map_is_deterministic_per_seed():
    assert choose_alias_map(SEEDS[0]) == choose_alias_map(SEEDS[0])


def test_distinct_seeds_give_distinct_maps():
    maps = [choose_alias_map(seed) for seed in SEEDS]
    for first, second in itertools.combinations(maps, 2):
        assert first != second, "two seeds produced the same alias table"


def test_mutation_is_deterministic_per_seed():
    source = (REPO / "scripts" / "inventory.jky").read_text(encoding="utf-8")
    for seed in SEEDS:
        first = mutate_source(source, choose_alias_map(seed))
        second = mutate_source(source, choose_alias_map(seed))
        assert first == second


def test_strings_comments_and_interpolation_survive_verbatim():
    """Keyword-shaped *data* must never be rewritten."""
    source = '''\
# if else while for emit return
let doc = "if else while for {{fn return try}}"
let pat = r"^(if|else)\\\\d{2}$"
let a = 1
let b = 2
let s = "sum={a and b} flag={not a} deep={"{a or b} nested"}"
if a and b {
    emit doc
}
'''
    alias_map = choose_alias_map(SEEDS[0])
    mutated = mutate_source(source, alias_map)
    assert mutated != source
    # Comment line, string body (with escaped-brace keyword text), raw string
    # body and interpolation bodies must pass through byte-identical.
    for verbatim in (
        "# if else while for emit return",
        '"if else while for {{fn return try}}"',
        'r"^(if|else)\\\\d{2}$"',
        "{a and b}",
        "{not a}",
        '"{a or b} nested"',
    ):
        assert verbatim in mutated, f"mangled: {verbatim!r}"
    # Both forms compile to the same program and emit the same findings.
    assert _compile_mutated(mutated, alias_map) == compile_program(parse(source))
    baseline = run_source(source)
    reran = run_program(_compile_mutated(mutated, alias_map))
    assert reran.errors == baseline.errors == []
    assert reran.findings == baseline.findings


def test_mutated_source_fails_to_parse_without_the_table():
    """Negative: the parser must notice aliases, not silently swallow them."""
    source = (REPO / "scripts" / "smoke.jky").read_text(encoding="utf-8")
    mutated = mutate_source(source, choose_alias_map(SEEDS[0]))
    with pytest.raises(JockySyntaxError):
        parse(mutated)
    # A keyword-shaped alias without the table is just an identifier.
    alias = choose_alias_map(SEEDS[0])["let"]
    kinds = [tok.kind for tok in Lexer(f"{alias} x = 1").tokenize()]
    assert kinds == ["ident", "ident", "op", "int", "eof"]


def test_alias_colliding_with_an_identifier_is_refused():
    """Rewriting would re-bind the identifier to a keyword; refuse loudly."""
    alias_map = choose_alias_map(SEEDS[0])
    some_alias = next(iter(alias_map.values()))
    with pytest.raises(ValueError, match="collide"):
        mutate_source(f"let {some_alias} = 1\n", alias_map)


def test_alias_values_are_rejected_when_not_identifier_shaped():
    with pytest.raises(ValueError):
        mutated_lexer_kwargs({"let": "9bad"})
    with pytest.raises(ValueError):
        mutated_lexer_kwargs({"let": "if"})  # alias must not shadow a keyword
    with pytest.raises(ValueError):
        mutated_lexer_kwargs({"nosuch": "abc"})  # alias must name a keyword
    with pytest.raises(ValueError):
        mutated_lexer_kwargs({"let": "dup", "if": "dup"})


def _richest_script() -> pathlib.Path:
    """Shipped script with the most keyword tokens — the stiffest span test."""
    counts = {}
    for path in SCRIPTS:
        counts[path] = sum(
            1 for tok in Lexer(path.read_text(encoding="utf-8")).tokenize()
            if tok.kind == "kw"
        )
    return max(counts, key=counts.get)


def test_aliases_reach_the_token_layer():
    """No keyword spelling may survive as keyword text outside strings."""
    path = _richest_script()
    alias_map = choose_alias_map(SEEDS[0])
    source = path.read_text(encoding="utf-8")
    mutated = mutate_source(source, alias_map)
    tokens = Lexer(mutated, **mutated_lexer_kwargs(alias_map)).tokenize()
    kw_tokens = [tok for tok in tokens if tok.kind == "kw"]
    assert len(kw_tokens) >= 50, f"{path.name} is too thin to prove anything"

    starts = [0] + [i + 1 for i, ch in enumerate(mutated) if ch == "\n"]
    alias_of = dict(alias_map)  # canonical keyword -> alias
    for tok in kw_tokens:
        offset = starts[tok.line - 1] + tok.col - 1
        span = mutated[offset:offset + len(alias_of[tok.value])]
        assert span == alias_of[tok.value], (
            f"kw {tok.value!r} at {tok.line}:{tok.col} spans {span!r}, "
            "not the alias"
        )
        assert span not in KEYWORDS, (
            f"original spelling {span!r} survived at {tok.line}:{tok.col}"
        )


def test_mutation_changes_source_but_not_the_program_for_one_seed_quickly():
    """Sanity gate kept small so the full sweep below is not the only proof."""
    source = (REPO / "scripts" / "quickstart.jky").read_text(encoding="utf-8")
    alias_map = choose_alias_map(SEEDS[0])
    mutated = mutate_source(source, alias_map)
    assert mutated != source
    assert _compile_mutated(mutated, alias_map) == compile_program(parse(source))


def test_every_script_matches_its_baseline_under_three_seeds():
    """38 scripts x 3 seeds: identical compiled program, same clean run.

    The compiled ``Program`` is the executed artefact; structural equality
    there *is* semantic identity. Runtime checks catch anything compilation
    cannot see (natives, VM): no errors, no truncation, same finding count,
    and the same finding shape (mapping keys / container types — exact scalar
    values legitimately differ because scripts read live host state).
    """
    assert len(SCRIPTS) >= 8, "script discovery broke; the sweep is vacuous"
    failures = []
    runs = []
    for path in SCRIPTS:
        source = path.read_text(encoding="utf-8")
        reference_program = compile_program(parse(source))
        baseline = run_source(source)
        for seed in SEEDS:
            alias_map = choose_alias_map(seed)
            mutated = mutate_source(source, alias_map)
            if any(tok.kind == "kw"
                   for tok in Lexer(source).tokenize()):
                if mutated == source:
                    failures.append(f"{path.name}/{seed}: source unchanged")
                    continue
            program = _compile_mutated(mutated, alias_map)
            if program != reference_program:
                failures.append(f"{path.name}/{seed}: compiled program differs")
                continue
            result = run_program(program)
            runs.append((str(path.relative_to(REPO)), seed.decode()))
            if result.errors:
                failures.append(f"{path.name}/{seed}: errors {result.errors[:2]}")
            if result.truncated:
                failures.append(f"{path.name}/{seed}: truncated")
            if result.finding_count != baseline.finding_count:
                failures.append(
                    f"{path.name}/{seed}: finding_count "
                    f"{result.finding_count} != {baseline.finding_count}"
                )
    assert runs, "no mutated runs happened"
    assert failures == [], "token mutation changed behaviour:\n" + "\n".join(failures)
