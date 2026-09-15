"""
The in-language corpus (`tests/lang/*.jky`) is part of the test surface.

Two contracts are pinned here: the corpus passes on this host, and the runner
*fails* when a script's expectation does not hold — a test facility that cannot
report failure is decoration. The failure paths are exercised against temporary
corpora so the real one stays green.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky import testrunner  # noqa: E402

CORPUS = REPO / "tests" / "lang"


def _run(args, cwd=REPO):
    return subprocess.run([sys.executable, "-m", "jocky", "test", *args],
                          cwd=str(cwd), capture_output=True, text=True, timeout=300)


def test_corpus_exists_and_is_substantial():
    files = testrunner.discover(str(CORPUS))
    assert len(files) >= 10, f"expected a real corpus, found {files}"
    assert all(path.endswith(".jky") for path in files)


def test_corpus_passes_on_this_host():
    summary = testrunner.run(str(CORPUS))
    assert summary["ok"], [r for r in summary["results"] if not r["ok"]]
    assert summary["checks"] >= 300, summary["checks"]
    assert summary["errors"] == 0


def test_cli_reports_success_and_exit_code_zero():
    finished = _run([str(CORPUS), "--json"])
    assert finished.returncode == 0, finished.stdout[-400:]
    payload = json.loads(finished.stdout)
    assert payload["ok"] is True
    assert payload["files"] >= 10
    assert payload["checks"] >= 300


def test_corpus_runs_under_confinement():
    """Landlock must not break the language or the collectors it tests."""
    probe = subprocess.run(
        [sys.executable, "-m", "jocky", "test", str(CORPUS), "--sandbox=ro", "--json"],
        cwd=str(REPO), capture_output=True, text=True, timeout=300)
    if probe.returncode == 2 and "Landlock" in probe.stderr:
        pytest.skip("kernel has no Landlock")
    payload = json.loads(probe.stdout or "{}")
    if not payload:
        pytest.skip(f"confinement unavailable: {probe.stderr.strip()[:120]}")
    assert payload["ok"], [r for r in payload["results"] if not r["ok"]]
    assert payload["sandbox"] == "ro"


def test_a_wrong_expectation_fails(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "wrong.jky").write_text(
        'expect(1 + 1, 3, "deliberately wrong")\nassert(false, "also wrong")\n'
        'expect(2 + 2, 4, "this one is right")\n',
        encoding="utf-8")
    summary = testrunner.run(str(corpus))
    assert summary["ok"] is False
    assert summary["failed"] == 2, summary
    assert summary["checks"] == 3
    finished = _run([str(corpus)])
    assert finished.returncode == 1
    assert "deliberately wrong" in finished.stdout


def test_a_syntax_error_is_reported_not_raised(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "broken.jky").write_text("let x = (1 + \n", encoding="utf-8")
    summary = testrunner.run(str(corpus))
    assert summary["ok"] is False
    assert summary["errors"] >= 1
    assert any(item["load_error"] for item in summary["results"])


def test_uncaught_runtime_error_fails_the_file(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "raises.jky").write_text(
        'expect(1, 1, "before the error")\nlet boom = 1 / 0\n', encoding="utf-8")
    summary = testrunner.run(str(corpus))
    assert summary["ok"] is False
    assert summary["checks"] == 1, "checks recorded before the error are kept"
    assert any("division by zero" in error for item in summary["results"]
               for error in item["errors"])


def test_limits_are_not_mistaken_for_errors(tmp_path):
    """expect_throws must not accept a budget-exhaustion as the expected error.

    The limit is absorbed by the helper (which records a failure), so the *run*
    finishes normally — what matters is that the check failed and said why.
    """
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "limit.jky").write_text(
        'expect_throws(fn() { let i = 0\n  while true { set i = i + 1 } }, "infinite loop")\n',
        encoding="utf-8")
    summary = testrunner.run(str(corpus), wall_ms=50)
    assert summary["ok"] is False, "a truncated closure must not satisfy expect_throws"
    assert summary["failed"] == 1
    detail = summary["results"][0]["failed"][0]
    assert "limit" in detail, detail


def test_expect_throws_can_require_a_message(tmp_path):
    """'Something raised' is a weak assertion; the interesting part is which error."""
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "messages.jky").write_text(
        'expect_throws(fn() { return 1 / 0 }, "right message", "division by zero")\n'
        'expect_throws(fn() { return 1 / 0 }, "wrong message", "modulo by zero")\n',
        encoding="utf-8")
    summary = testrunner.run(str(corpus))
    assert summary["checks"] == 2
    assert summary["failed"] == 1, summary
    detail = summary["results"][0]["failed"][0]
    assert "wrong message" in detail and "does not contain" in detail, detail


def test_cli_streams_ndjson(tmp_path):
    """--ndjson keeps memory flat: one object per line, summary last."""
    script = tmp_path / "many.jky"
    script.write_text('for n in range(50) { emit {"kind": "row", "n": n} }\n', encoding="utf-8")
    finished = subprocess.run(
        [sys.executable, "-m", "jocky", "run", str(script), "--ndjson"],
        cwd=str(REPO), capture_output=True, text=True, timeout=120)
    assert finished.returncode == 0, finished.stderr
    lines = [json.loads(line) for line in finished.stdout.splitlines() if line.strip()]
    assert len(lines) == 51, "50 findings plus the summary line"
    assert [line["kind"] for line in lines[:3]] == ["finding", "finding", "finding"]
    assert lines[0]["value"] == {"kind": "row", "n": 0}
    summary = lines[-1]
    assert summary["kind"] == "summary"
    assert summary["findings"] == 50
    assert summary["truncated"] is False
    assert "permissions" in summary and "denials" in summary


def test_missing_path_is_reported_by_the_cli():
    finished = _run(["/definitely/not/a/directory"])
    assert finished.returncode == 2
    assert "no such file or directory" in finished.stderr
