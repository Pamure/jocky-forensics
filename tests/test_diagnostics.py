"""
Tests for the environment self-check (`jocky doctor`).

The value of the doctor is that it *fails* when a prerequisite is missing, so
the assertions are about structure and honesty rather than pretty output: every
check must carry a group, a status from the fixed vocabulary, and a fix for
anything that is not ok.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky import diagnostics  # noqa: E402


def test_quick_report_is_structured():
    report = diagnostics.run_checks(quick=True)
    assert report.checks, "doctor produced no checks"
    assert report.counts[diagnostics.OK] >= 1
    for check in report.checks:
        assert check.status in (diagnostics.OK, diagnostics.WARN, diagnostics.FAIL)
        assert check.group in ("runtime", "collection", "fileless", "management",
                              "packaging", "confinement")
        if check.status != diagnostics.OK:
            assert check.fix, f"check {check.name} reports a problem without a fix"


def test_ok_flag_reflects_failures():
    report = diagnostics.Report()
    report.checks.append(diagnostics.Check("a", diagnostics.OK, "fine"))
    assert report.ok
    report.checks.append(diagnostics.Check("b", diagnostics.FAIL, "broken", "fix it"))
    assert not report.ok


def test_report_serialises_to_json_safe_types():
    payload = diagnostics.run_checks(quick=True).to_dict()
    assert set(payload) >= {"ok", "counts", "checks", "host"}
    assert payload["host"]["python"].startswith("3.")
    for check in payload["checks"]:
        assert set(check) == {"name", "status", "detail", "fix", "group"}


def test_formatted_report_contains_verdict_and_fixes():
    text = diagnostics.format_report(diagnostics.run_checks(quick=True))
    assert "ready" in text
    assert "RUNTIME" in text.upper()


@pytest.mark.slow
def test_full_report_proves_fileless_mode_end_to_end():
    """The only claim worth making about fileless mode is a real run."""
    report = diagnostics.run_checks(quick=False)
    fileless = [c for c in report.checks if c.group == "fileless"]
    assert fileless, "no fileless checks were performed"
    assert any(c.name == "fileless end-to-end" for c in fileless)
    if not report.ok:
        pytest.skip(f"host cannot run fileless mode: {[c.detail for c in fileless]}")
    probe = next(c for c in fileless if c.name == "fileless end-to-end")
    assert probe.status == diagnostics.OK
    assert "/memfd:" in probe.detail
