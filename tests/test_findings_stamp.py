"""Timestamps on findings: the `--stamp-findings` contract.

A finding has no time of its own, so a run cannot be lined up against
journald/auditd output. The rules that make stamping safe are the thing worth
testing: only maps, only when the field is absent, and one shared value per run.
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


# ------------------------------------------------------------------ the helper
def test_stamps_only_maps_that_lack_the_field():
    findings = [{"kind": "a"}, {"kind": "b", "ts": 5.0}, "bare string", 7, ["list"]]
    stamped = runner.stamp_findings(findings, now=1234.5)
    assert stamped == 1
    assert findings[0] == {"kind": "a", "ts": 1234.5}
    assert findings[1]["ts"] == 5.0, "a script's own event time must win"
    assert findings[2:] == ["bare string", 7, ["list"]], "non-maps are left alone"


def test_one_value_per_run_and_rounded():
    findings = [{"i": 1}, {"i": 2}, {"i": 3}]
    runner.stamp_findings(findings, now=1704110445.123456)
    assert {f["ts"] for f in findings} == {1704110445.123}


def test_default_is_epoch_seconds_near_now():
    findings = [{"kind": "x"}]
    runner.stamp_findings(findings)
    assert abs(findings[0]["ts"] - __import__("time").time()) < 5


def test_field_name_is_overridable():
    findings = [{}]
    runner.stamp_findings(findings, now=1.0, field="collected_at")
    assert findings[0] == {"collected_at": 1.0}


def test_empty_and_none_input_are_harmless():
    assert runner.stamp_findings([]) == 0
    assert runner.stamp_findings(None) == 0


# ------------------------------------------------------------------- the flag
SCRIPT = """
emit {"kind": "own_time", "ts": 1000.0}
emit {"kind": "no_time"}
emit "not a map"
"""


@pytest.fixture()
def script(tmp_path):
    path = tmp_path / "stamp.jky"
    path.write_text(SCRIPT, encoding="utf-8")
    return str(path)


def test_run_without_the_flag_leaves_findings_alone(script, capsys):
    assert cli.main(["run", script, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] == [{"kind": "own_time", "ts": 1000.0},
                                   {"kind": "no_time"}, "not a map"]


def test_run_with_the_flag_stamps_every_map(script, capsys):
    assert cli.main(["run", script, "--json", "--stamp-findings"]) == 0
    payload = json.loads(capsys.readouterr().out)
    own, fresh, bare = payload["findings"]
    assert own["ts"] == 1000.0, "the script's own timestamp is preserved"
    assert fresh["kind"] == "no_time"
    assert abs(fresh["ts"] - __import__("time").time()) < 30
    assert bare == "not a map", "a finding that is not a map is left as it is"


def test_ndjson_lines_carry_the_stamp(script, capsys):
    assert cli.main(["run", script, "--ndjson", "--stamp-findings"]) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.strip()]
    findings = [entry["value"] for entry in lines if entry.get("kind") == "finding"]
    assert len(findings) == 3, findings
    assert all(isinstance(entry, dict) and "ts" in entry
               for entry in findings if not isinstance(entry, str)), findings
    assert findings[0]["ts"] == 1000.0


def test_exec_stamps_too(tmp_path, capsys):
    script_path = tmp_path / "one.jky"
    script_path.write_text('emit {"kind": "from_artifact"}\n', encoding="utf-8")
    artifact_path = tmp_path / "one.jky.build"
    artifact, _ = runner.build_artifact(script_path.read_text(encoding="utf-8"),
                                        deterministic=True)
    artifact_path.write_bytes(artifact)

    assert cli.main(["exec", str(artifact_path), "--json", "--stamp-findings"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"] and all("ts" in f for f in payload["findings"])


def test_fileless_stamps_the_childs_findings(monkeypatch, capsys):
    """The memfd child reports its findings through `JKY_RESULT`; the flag has to
    reach those too, or the one mode that lives in memory would be the only one
    that cannot be correlated."""
    outcome = {"ok": True, "exit_code": 0, "stderr": "",
               "result": {"findings": [{"kind": "from_memfd"}]},
               "evidence": {"exe": "/memfd:python3 (deleted)", "memfd_map_count": 4}}
    monkeypatch.setattr(runner, "fileless_run_file", lambda *a, **k: outcome)

    assert cli.main(["memfd", "unused.jky", "--json", "--stamp-findings"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert abs(payload["result"]["findings"][0]["ts"] - __import__("time").time()) < 30


def test_triage_stamps_the_check_findings(capsys):
    """`triage` findings are built by the runtime, not by a script, so they are
    the ones that most need an anchor for correlation."""
    assert cli.main(["triage", "--json", "--stamp-findings"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"], "a host with no findings at all cannot verify this"
    assert all("ts" in finding for finding in payload["findings"])
