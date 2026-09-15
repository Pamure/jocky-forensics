"""Streaming findings out of the VM.

`--ndjson` used to be a claim rather than a behaviour: findings accumulated in
the VM and were printed after the run, so memory grew with the result set — the
exact shape (a per-file finding from a filesystem sweep) where a triage host has
least memory to spare. These tests pin the streaming path: a sink receives every
finding as it is emitted, the VM keeps none, and the summary still counts them.
"""
from __future__ import annotations

import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky import cli, runner  # noqa: E402


def test_sink_receives_every_finding_and_the_vm_keeps_none():
    seen = []
    result = runner.run_source(
        'for i in range(5) { emit {"i": i} }',
        emit_sink=seen.append)
    assert [finding["i"] for finding in seen] == [0, 1, 2, 3, 4]
    assert result.findings == [], "a streamed run must not retain findings"
    assert result.finding_count == 5
    assert result.to_dict()["finding_count"] == 5
    assert "5 finding" in runner.result_summary(result), runner.result_summary(result)


def test_without_a_sink_findings_are_kept_as_before():
    result = runner.run_source('for i in range(3) { emit i }')
    assert result.findings == [0, 1, 2]
    assert result.finding_count == 3
    assert "3 finding" in runner.result_summary(result)


def test_sink_is_used_for_every_emit_form():
    """`emit` inside functions, loops and try/catch must all reach the sink."""
    seen = []
    result = runner.run_source('''
fn report(n) { emit {"n": n} }
for i in range(3) { report(i) }
try { emit {"kind": "after_error"} } catch e { emit {"kind": "unreachable"} }
emit "bare string"
''', emit_sink=seen.append)
    assert result.finding_count == 5, seen
    assert result.findings == []
    assert seen[-1] == "bare string", "non-map findings stream too"


def test_cli_ndjson_streams_and_still_reports_the_count(tmp_path, capsys):
    script = tmp_path / "many.jky"
    script.write_text("for i in range(50) { emit {\"i\": i} }\n", encoding="utf-8")

    assert cli.main(["run", str(script), "--ndjson"]) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]
    findings = [line for line in lines if line["kind"] == "finding"]
    summary = [line for line in lines if line["kind"] == "summary"]
    assert len(findings) == 50
    assert summary and summary[0]["findings"] == 50, summary


def test_cli_json_still_materialises_everything(tmp_path, capsys):
    """The `--json` path is deliberately the "hold it all" one."""
    script = tmp_path / "many.jky"
    script.write_text("for i in range(5) { emit {\"i\": i} }\n", encoding="utf-8")

    assert cli.main(["run", str(script), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["findings"]) == 5
    assert payload["finding_count"] == 5


def test_streamed_run_reports_errors_and_truncation_normally():
    """A sink must not change error or limit semantics."""
    seen = []
    result = runner.run_source("emit 1\nemit 1 / 0\nemit 2", emit_sink=seen.append)
    assert result.finding_count == 1 and seen == [1]
    assert result.errors and "division by zero" in result.errors[0]

    limited = runner.run_source("while true { emit 1 }", emit_sink=seen.append,
                                max_steps=50_000)
    assert limited.truncated, "the step budget still applies while streaming"
