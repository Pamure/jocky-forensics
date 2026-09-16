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
import types

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


# --------------------------------------------------------------- platforms
# The doctor has to be honest on hosts that are not Linux: reporting a Linux
# mechanism as "missing" there tells an operator to fix something unfixable,
# and the Windows backend has faults of its own worth reporting. These tests
# simulate the platform rather than the host, and each one is written so that
# deleting the platform branch turns it red.


def _fake_winapi(available: bool = True, rows=None, sockets=None) -> types.ModuleType:
    """A stand-in exposing only the ``winapi`` calls the collection check makes.

    Stubbing it this way also documents the dependency: on Windows the check is
    only allowed to need ``available``, ``list_processes`` and ``connections``.
    """
    module = types.ModuleType("jocky.rt.winapi")
    module.available = lambda: available
    module.list_processes = lambda **kw: list(rows or [])
    module.connections = lambda **kw: list(sockets or [])
    return module


def _install_fake_winapi(monkeypatch, module: types.ModuleType) -> None:
    """Install ``module`` as ``jocky.rt.winapi`` for the duration of one test.

    Both the ``sys.modules`` entry *and* the attribute on the ``jocky.rt``
    package are replaced. ``from jocky.rt import winapi`` resolves the package
    attribute first once the real module has been imported — which any earlier
    test in the session will have done — so patching only ``sys.modules`` leaves
    the real module bound, and the test silently exercises the wrong one. The
    symptom is a test that passes alone and fails in the full suite, which is
    exactly what happened here before this line was added.
    """
    import jocky.rt

    monkeypatch.setitem(sys.modules, "jocky.rt.winapi", module)
    monkeypatch.setattr(jocky.rt, "winapi", module, raising=False)
    monkeypatch.setattr(diagnostics, "_is_windows", lambda: True)


def test_windows_host_checks_the_winapi_backend_not_procfs(monkeypatch):
    """No /proc is normal on Windows; the winapi backend is what must be probed.

    ``_procfs_present`` is forced False to prove the Windows branch never asks:
    if it did, the check would report the FAIL this test forbids.
    """
    _install_fake_winapi(monkeypatch,
                         _fake_winapi(rows=[{"pid": 4}, {"pid": 900}],
                                      sockets=[{"proto": "tcp", "pid": 900}]))
    monkeypatch.setattr(diagnostics, "_procfs_present", lambda: False)
    report = diagnostics.Report()
    diagnostics._check_procfs(report)

    table = next(c for c in report.checks if "winapi" in c.name)
    assert table.status == diagnostics.OK
    assert "winapi" in table.detail, "the detail must name the backend that answered"
    assert "2 process" in table.detail
    assert not [c for c in report.checks if c.status == diagnostics.FAIL]
    assert any(c.name == "network tables" and c.status == diagnostics.OK
               for c in report.checks)


def test_windows_backend_that_did_not_load_is_a_failure(monkeypatch):
    """Collection is dead if the DLL bindings did not load — say so, do not guess."""
    _install_fake_winapi(monkeypatch, _fake_winapi(available=False))
    report = diagnostics.Report()
    diagnostics._check_procfs(report)
    check = report.checks[0]
    assert check.status == diagnostics.FAIL
    assert check.fix


def test_windows_backend_with_no_processes_is_a_failure(monkeypatch):
    """A Windows host always has processes; an empty table means the calls are denied."""
    _install_fake_winapi(monkeypatch, _fake_winapi(rows=[]))
    report = diagnostics.Report()
    diagnostics._check_procfs(report)
    assert report.checks[0].status == diagnostics.FAIL


def test_linux_host_without_procfs_still_fails(monkeypatch):
    """The Linux contract is unchanged: no /proc means collection cannot run."""
    monkeypatch.setattr(diagnostics, "_is_windows", lambda: False)
    monkeypatch.setattr(diagnostics, "_procfs_present", lambda: False)
    report = diagnostics.Report()
    diagnostics._check_procfs(report)
    check = next(c for c in report.checks if c.name == "procfs mounted")
    assert check.status == diagnostics.FAIL
    assert "Linux" in check.fix


def test_raw_syscall_check_reports_the_platform_not_an_exception(monkeypatch):
    """Off Linux the raw path is unsupported, and the WARN must say why."""
    from jocky.rt import raw

    monkeypatch.setattr(raw.sys, "platform", "win32")
    probe = raw.probe()
    assert probe["available"] is False
    assert probe["supported"] is False
    assert "Linux-only" in str(probe["error"])
    with pytest.raises(RuntimeError):   # never AttributeError from os.uname
        raw.uname()

    report = diagnostics.Report()
    diagnostics._check_raw_syscalls(report)
    check = report.checks[0]
    assert check.status == diagnostics.WARN
    assert "Linux-only" in check.detail
    assert check.fix


def test_memfd_check_names_the_platform_off_linux(monkeypatch):
    """memfd is Linux-only: the reason must be the platform, not a missing install."""
    monkeypatch.setattr(diagnostics.sys, "platform", "win32")
    report = diagnostics.Report()
    diagnostics._check_memfd(report)
    check = report.checks[0]
    assert check.status == diagnostics.FAIL
    assert "win32" in check.detail
    assert "Linux" in check.detail
