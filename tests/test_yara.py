"""YARA-subset matching: the constructs that carry real rules, and the refusals.

YARA is where the byte-signature corpus lives, so this engine has to read the
common shapes exactly (hex wildcards, jumps, alternatives, `wide`) and refuse
the rest *by name*. A signature that silently stops matching is worse than one
that refuses to load — that is the property most of these tests pin.
"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky import cli, runner  # noqa: E402
from jocky.errors import JockyRuntimeError  # noqa: E402
from jocky.rt.yararules import load_rule  # noqa: E402

ELF_HEAD = "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def rule_for(definition: str, identifier: str = "$a", condition: str = "$a") -> str:
    return f"rule T {{\n strings:\n  {identifier} = {definition}\n condition: {condition}\n}}"


# ---------------------------------------------------------------- constructs
def test_hex_string_matches_bytes():
    rule = load_rule(rule_for("{ 7F 45 4C 46 }"))
    assert rule.matches(ELF_HEAD)
    assert not rule.matches("MZ\x90\x00")


def test_hex_wildcards_jumps_and_alternatives():
    rule = load_rule(rule_for("{ 4D 5A ?? [2-4] ( 50 45 | 45 4C ) }"))
    assert rule.matches("MZ\x00\x00\x00PE"), "?=1 byte + 2..4 jump bytes + PE"
    assert rule.matches("MZ" + "\x00" * 5 + "EL"), "the alternative branch matches too"
    assert not rule.matches("MZ\x00\x00PE"), "below the jump floor"
    assert not rule.matches("MZ" + "\x00" * 7 + "PE"), "above the jump ceiling"


def test_nibble_wildcard():
    rule = load_rule(rule_for("{ 4D 5? }"))
    assert rule.matches("MZ")
    assert rule.matches("M\x5a")      # 0x50..0x5F
    assert not rule.matches("M\xa0")   # 0xa0 is outside the 0x50..0x5F range
    assert not rule.matches("M\x60")   # 0x60 is outside the 0x50..0x5F range


def test_text_strings_and_nocase():
    assert load_rule(rule_for('"cmd.exe"')).matches("run cmd.exe now")
    assert not load_rule(rule_for('"cmd.exe"')).matches("run CMD.EXE now"), \
        "uncased strings are case-sensitive, as in YARA"
    assert load_rule(rule_for('"cmd.exe" nocase')).matches("run CMD.EXE now")


def test_wide_and_ascii_forms():
    wide = "\x00".join("cmd.exe") + "\x00"
    assert load_rule(rule_for('"cmd.exe" wide')).matches(wide)
    assert not load_rule(rule_for('"cmd.exe" wide')).matches("cmd.exe"), \
        "wide alone does not match the ASCII form"
    both = load_rule(rule_for('"cmd.exe" wide ascii'))
    assert both.matches(wide) and both.matches("cmd.exe")


def test_regex_strings_and_fullword():
    assert load_rule(rule_for("/[a-z]+@[a-z]+/")).matches("mail me a@b now")
    fullword = load_rule(rule_for('"cat" fullword'))
    assert fullword.matches("a cat sat")
    assert not fullword.matches("concatenate"), "fullword respects word boundaries"


def test_conditions_and_of_them():
    body = ("rule T {\n strings:\n  $a = \"one\"\n  $b = \"two\"\n  $c = \"three\"\n"
            " condition: %s\n}")
    assert load_rule(body % "$a and $b").matches("one two")
    assert not load_rule(body % "$a and $b").matches("one")
    assert load_rule(body % "$a or $b").matches("two")
    assert load_rule(body % "not $a").matches("other")
    assert load_rule(body % "all of them").matches("one two three")
    assert not load_rule(body % "all of them").matches("one two")
    assert load_rule(body % "2 of them").matches("one two")
    assert load_rule(body % "any of them").matches("three")


def test_at_offset_and_filesize():
    at_zero = load_rule(rule_for("{ 7F 45 4C 46 }", condition="$a at 0"))
    assert at_zero.matches(ELF_HEAD)
    assert not at_zero.matches("padpad" + ELF_HEAD), "`at 0` means offset 0"

    sized = load_rule(rule_for('"abc"', condition="$a and filesize < 16"))
    assert sized.matches("abc")
    assert not sized.matches("abc" + "x" * 32)


def test_meta_and_summary():
    rule = load_rule("""
rule Named {
    meta:
        author = "unit"
        description = "a rule with metadata"
    strings:
        $a = "x"
    condition:
        $a
}
""")
    summary = rule.summary()
    assert summary["rule"] == "Named"
    assert summary["meta"]["author"] == "unit"
    assert summary["strings"] == ['"x"']
    assert summary["condition"] == "$a"


def test_comments_are_ignored():
    rule = load_rule("""
// a line comment
rule T {
    strings:
        $a = "x"   // trailing comment
        /* block
           comment */
        $b = { 4D 5A }
    condition:
        $a or $b
}
""")
    assert rule.matches("x")
    assert rule.matches("MZ")


# ----------------------------------------------------------------- refusals
@pytest.mark.parametrize("definition, fragment", [
    ("{ 4D 5A } xor", "xor"),
    ("{ 4D 5A } base64", "base64"),
    ("{ 4D 5A } wide", "wide"),
    ('"abc" xor(1-255)', "xor"),
])
def test_unsupported_modifiers_are_refused(definition, fragment):
    with pytest.raises(JockyRuntimeError) as excinfo:
        load_rule(rule_for(definition))
    assert fragment in str(excinfo.value)


@pytest.mark.parametrize("source, fragment", [
    ('rule T { strings: $a = { 4D ~5A } condition: $a }', "not-byte"),
    ('rule T { strings: $a = { 4D ?? [4-] } condition: $a }', "open-ended"),
    ('rule T { strings: $a = "x" condition: for any of them : ( $a ) }', "cannot parse"),
    ('rule T { strings: $a = "x" condition: uint16(0) == 0x5A4D }', "uint16"),
])
def test_unsupported_constructs_are_refused(source, fragment):
    with pytest.raises(JockyRuntimeError) as excinfo:
        load_rule(source)
    assert fragment in str(excinfo.value)


def test_unknown_string_in_a_condition_is_refused():
    with pytest.raises(JockyRuntimeError, match="unknown string"):
        load_rule('rule T { strings: $a = "x" condition: $a and $b }')


def test_the_step_budget_covers_hostile_rules():
    """A rule is untrusted content; the engine's budget must bound it."""
    rule = load_rule(rule_for('/(a+)+b/', identifier="$a"))
    with pytest.raises(JockyRuntimeError, match="step budget"):
        rule.matches("\x00" + "a" * 2_000_000)


# ------------------------------------------------------------------ natives
def test_yara_namespace_in_the_language():
    result = runner.run_source(r'''
let rule = join([r"rule T {", r"  strings:", r"    $a = { 7F 45 4C 46 }",
                 r"  condition: $a", r"}"], "\n")
emit yara.check(rule, fs.read_bytes("/proc/self/exe", 0, 4))
emit yara.check(rule, "no magic here")
emit yara.summary(rule).rule
''')
    assert not result.errors, result.errors
    assert result.findings == [True, False, "T"], result.findings


# ---------------------------------------------------------------------- CLI
RULE = """
rule Elf_or_PE {
    meta:
        author = "unit"
    strings:
        $elf = { 7F 45 4C 46 }
        $pe  = { 4D 5A }
    condition:
        any of them
}
"""


def test_cli_scans_a_file(tmp_path, capsys):
    rule_path = tmp_path / "rule.yar"
    rule_path.write_text(RULE, encoding="utf-8")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x7fELF" + b"\x00" * 32 + b"MZ payload")

    assert cli.main(["yara", str(rule_path), str(target), "--json",
                     "--stamp-findings"]) == 1, "a match is an exit code 1, like grep"
    payload = json.loads(capsys.readouterr().out)
    assert payload["matched"] is True
    assert payload["findings"][0]["path"] == str(target)
    assert payload["findings"][0]["scanned_bytes"] == 46
    assert "ts" in payload["findings"][0], "the stamp option reaches yara findings"


def test_cli_reports_no_match_without_a_finding(tmp_path, capsys):
    rule_path = tmp_path / "rule.yar"
    rule_path.write_text(RULE, encoding="utf-8")
    target = tmp_path / "plain.bin"
    target.write_bytes(b"nothing to see here")

    assert cli.main(["yara", str(rule_path), str(target), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["matched"] is False and payload["findings"] == []


def test_cli_refuses_a_rule_it_cannot_evaluate(tmp_path, capsys):
    rule_path = tmp_path / "bad.yar"
    rule_path.write_text('rule T { strings: $a = { 4D 5A } xor condition: $a }',
                         encoding="utf-8")
    target = tmp_path / "any.bin"
    target.write_bytes(b"MZ")
    assert cli.main(["yara", str(rule_path), str(target)]) == 2
    assert "xor" in capsys.readouterr().err


def test_a_real_binary_matches_an_elf_signature():
    """The end-to-end claim: a rule from the wild matches a real file."""
    rule = load_rule(RULE)
    data = pathlib.Path("/proc/self/exe").read_bytes()[:4096].decode("latin-1")
    assert rule.matches(data)
