"""
Live detection test: a *fileless* JOCKY run must be visible to JOCKY's own
detector while it is alive.

This pins two contracts at once:

* the fileless executor really produces a memfd-backed process image
  (``/proc/<pid>/exe`` -> ``/memfd:python3 (deleted)`` with memfd mappings) —
  verified from the child's own report *and* from the parent's /proc view;
* the detector built for host triage actually reports it, so the evasion claim
  and the detection claim are both measurable rather than asserted.

It is deliberately an end-to-end test (real process, real procfs reads); it
takes a few seconds because the script under test stays alive on purpose.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "watch.jky"

if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.rt import detect, procfs  # noqa: E402  (path bootstrap above)


@pytest.fixture()
def fileless_run():
    """Start a fileless run and hand the live Popen back to the test."""
    process = subprocess.Popen(
        [sys.executable, "-m", "jocky", "fileless", str(SCRIPT), "--json"],
        cwd=str(REPO), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    yield process
    if process.poll() is None:
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=10)


def test_fileless_process_is_detected_and_self_reports(fileless_run):
    """Wait for the memfd process, detect it, then check its own report."""
    seen = []
    deadline = time.time() + 15.0
    while time.time() < deadline and not seen:
        seen = [p for p in procfs.list_processes()
                if "/memfd:" in (p.get("exe") or "")]
        if not seen:
            time.sleep(0.1)

    assert seen, "no process with a memfd-backed exe appeared while the run was live"
    target = seen[0]
    assert target["exe"].endswith("(deleted)")

    findings = detect.fileless_processes()
    assert findings, "host triage did not report the fileless process it was looking at"
    assert any("memfd" in (f["evidence"].get("exe") or "") for f in findings)
    assert any(f["evidence"]["pid"] == target["pid"] for f in findings)
    assert detect.memfd_mappings(), "no executable memfd mappings detected"

    stdout, stderr = fileless_run.communicate(timeout=90)
    report = json.loads(stdout)
    assert report["exit_code"] == 0, stderr
    assert report["ok"] is True, report["result"].get("errors")
    # the child's own view of its interpreter
    assert any(f.get("exe", "").startswith("/memfd:") for f in report["result"]["findings"])
    # the parent's /proc view, sampled after exec landed
    assert report["evidence"]["exe"].startswith("/memfd:")
    assert report["evidence"]["memfd_map_count"] >= 1
    assert report["evidence"]["in_memory"]["payload_bytes"] > 0
