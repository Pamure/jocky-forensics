"""
Execution-lab tests — real children, real /proc walks, real fileless runs.

Everything here is observable behaviour, not plumbing: the guard spawns real
processes and the ownership decision is checked against live /proc state; the
fileless path runs a compiled artifact end-to-end in memory; the Windows
techniques are checked to *refuse loudly* rather than to have particular
internals; the BYOVD spec is checked to be a pure, side-effect-free dict.
The negative cases (foreign pid, dead pid, missing pid) are the load-bearing
half of the harness contract.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.lab import byovd, windows  # noqa: E402
from jocky.lab.errors import LabRefusal  # noqa: E402
from jocky.lab.fileless import run_prefab_fileless_files  # noqa: E402
from jocky.lab.guard import HarnessGuard, _ancestors  # noqa: E402

#: A child that stays alive until the guard cleans it up.
SLEEP = [sys.executable, "-c", "import time; time.sleep(120)"]


# --------------------------------------------------------------------- guard
def test_spawned_children_pass_ownership():
    guard = HarnessGuard()
    try:
        pid_a = guard.spawn_argv(SLEEP)
        pid_b = guard.spawn_argv(SLEEP)
        assert pid_a != pid_b
        assert {pid_a, pid_b} == set(guard.own_children())
        guard.assert_owned(pid_a)
        guard.assert_owned(pid_b)
    finally:
        guard.cleanup()
    for pid in (pid_a, pid_b):
        assert not os.path.exists(f"/proc/{pid}"), "cleanup left a child behind"


def test_cleanup_removes_workdir_and_is_idempotent():
    guard = HarnessGuard()
    workdir = guard.workdir
    assert os.path.isdir(workdir)
    guard.spawn_argv(SLEEP)
    guard.cleanup()
    guard.cleanup()  # second call must be a no-op, not an error
    assert not os.path.exists(workdir)


def test_self_is_always_owned():
    guard = HarnessGuard()
    try:
        guard.assert_owned(os.getpid())
    finally:
        guard.cleanup()


def test_own_ancestor_is_allowed():
    """The contract refuses only non-ancestors: the harness's own chain is legal."""
    guard = HarnessGuard()
    try:
        chain = _ancestors(os.getpid())
        assert chain, "expected at least one ancestor for the test process"
        guard.assert_owned(chain[-1])  # top of our chain, e.g. init
    finally:
        guard.cleanup()


def test_foreign_child_of_this_process_is_refused():
    """A live child of this process that the GUARD did not spawn is refused:
    being our descendant is necessary but not sufficient for ownership."""
    guard = HarnessGuard()
    foreign = subprocess.Popen(SLEEP, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    try:
        with pytest.raises(LabRefusal):
            guard.assert_owned(foreign.pid)
    finally:
        foreign.terminate()
        foreign.wait(timeout=5)
        guard.cleanup()


def test_foreign_live_pid_is_refused():
    """Any pid that lives in /proc, was never spawned by the guard, and is not
    an ancestor of this process must be refused.  (Which concrete pid that is
    varies by platform — on WSL2 pid 2 is the distro init, not kthreadd — so
    the test discovers one instead of hardcoding it.)"""
    guard = HarnessGuard()
    try:
        ancestors = set(_ancestors(os.getpid()) or [])
        foreign = [
            int(entry) for entry in os.listdir("/proc")
            if entry.isdigit() and int(entry) not in ancestors
            and int(entry) != os.getpid()
        ]
        assert foreign, "no foreign pid found in /proc"
        for pid in foreign:
            with pytest.raises(LabRefusal) as excinfo:
                guard.assert_owned(pid)
        assert "not" in str(excinfo.value)  # a reason, not a bare raise
    finally:
        guard.cleanup()


def test_reaped_own_child_is_refused_after_cleanup():
    guard = HarnessGuard()
    pid = guard.spawn_argv(SLEEP)
    guard.cleanup()
    with pytest.raises(LabRefusal) as excinfo:
        guard.assert_owned(pid)
    assert "/proc" in str(excinfo.value)


def test_absent_pid_is_refused():
    guard = HarnessGuard()
    try:
        with open("/proc/sys/kernel/pid_max") as fh:
            pid_max = int(fh.read().strip())
        with pytest.raises(LabRefusal):
            guard.assert_owned(pid_max + 1)  # cannot exist: above the pid range
    finally:
        guard.cleanup()


def test_nonsense_pids_are_refused():
    guard = HarnessGuard()
    try:
        for bad in (0, -7, "1234", None, True):
            with pytest.raises(LabRefusal):
                guard.assert_owned(bad)
    finally:
        guard.cleanup()


# ------------------------------------------------------------------ fileless
def test_fileless_runs_artifact_under_the_guard():
    """End-to-end: guard-validated anchor pid, real memfd execution, real result."""
    from jocky.runner import build_artifact

    artifact, _info = build_artifact('emit {"kind": "lab-smoke", "value": 40 + 2}')
    guard = HarnessGuard()
    try:
        anchor = guard.spawn_argv(SLEEP)
        result = run_prefab_fileless_files(guard, artifact, target_pid=anchor)
        assert result["ok"] is True, result["stderr"]
        assert result["result"]["findings"] == [{"kind": "lab-smoke", "value": 42}]
        # The executing child was forked from this harness and the guard knows it.
        assert result["harness"]["child_pid"] == result["pid"]
        assert result["pid"] in guard.own_children()
        # Sanity that this was the real memfd path, not an in-process shortcut.
        assert "memfd" in (result["evidence"]["exe"] or "")
    finally:
        guard.cleanup()


def test_fileless_refuses_foreign_target_before_executing():
    guard = HarnessGuard()
    try:
        with open("/proc/sys/kernel/pid_max") as fh:
            impossible = int(fh.read().strip()) + 1
        with pytest.raises(LabRefusal):
            run_prefab_fileless_files(guard, b'emit {"kind": "never-ran"}',
                                      target_pid=impossible)
    finally:
        guard.cleanup()


def test_fileless_requires_a_guard():
    with pytest.raises(LabRefusal):
        run_prefab_fileless_files(None, b"x", target_pid=os.getpid())


# ------------------------------------------------------------------- windows
TECHNIQUES = [windows.hollow_process, windows.reflective_load,
              windows.hijack_thread, windows.byovd_probe]


@pytest.mark.parametrize("technique", TECHNIQUES, ids=lambda f: f.__name__)
def test_windows_technique_refuses_on_linux(technique):
    guard = HarnessGuard()
    try:
        pid = guard.spawn_argv(SLEEP)
        with pytest.raises(LabRefusal) as excinfo:
            technique(guard, pid)
        assert "windows" in str(excinfo.value).lower()
    finally:
        guard.cleanup()


@pytest.mark.parametrize("technique", TECHNIQUES, ids=lambda f: f.__name__)
def test_enable_flag_does_not_unlock_linux(technique, monkeypatch):
    monkeypatch.setenv("JOCKY_LAB_ENABLE", "1")
    with pytest.raises(LabRefusal):
        technique(None, None)


def test_windows_docstrings_pin_the_phase0_contract():
    for technique in TECHNIQUES:
        doc = technique.__doc__ or ""
        assert "performs only inside the Hyper-V Phase-0 VM with testsigning on" in doc


# --------------------------------------------------------------------- byovd
def test_driver_spec_is_a_pure_dict_with_no_side_effects():
    before = set(os.listdir())
    spec = byovd.test_driver_spec()
    assert set(os.listdir()) == before, "spec function left files behind"

    assert isinstance(spec, dict)
    assert spec["driver_name"] == "jockyprobe.sys"
    assert spec["implemented"] is False  # a spec, never a silent success claim
    assert spec["test_signing"]["required"] is True
    assert len(spec["ioctls"]) == 1
    assert len(spec["runner_scripts"]) == 2
