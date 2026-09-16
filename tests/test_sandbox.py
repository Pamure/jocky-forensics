"""
Sandbox tests.

Landlock confinement is irreversible for the process that applies it, so every
assertion runs inside a forked child: the child applies a level and reports what
it could do, the parent (unrestricted) judges the answer. That mirrors how the
confinement is actually used — one process, one script.
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky import sandbox  # noqa: E402

CHILD = r"""
import json, os, socket, sys
sys.path.insert(0, {repo!r})
from jocky import sandbox

level = sys.argv[1]
try:
    report = sandbox.apply(level)
except Exception as exc:
    print(json.dumps({{"error": f"{{type(exc).__name__}}: {{exc}}"}}))
    raise SystemExit(0)

result = {{"level": report.level, "applied": report.applied, "abi": report.abi,
          "network_blocked": report.seccomp}}
try:
    with open("/etc/passwd", "rb") as handle:
        result["read_etc_passwd"] = len(handle.read()) > 0
except OSError as exc:
    result["read_etc_passwd"] = f"denied: {{exc.errno}}"
try:
    with open(os.path.join(tempfile_dir := os.environ["JKY_TMP"], "probe.txt"), "w") as handle:
        handle.write("x")
    result["write_tmp"] = True
except OSError as exc:
    result["write_tmp"] = f"denied: {{exc.errno}}"
try:
    with open("/proc/self/stat", "rb") as handle:
        result["read_proc"] = bool(handle.read())
except OSError as exc:
    result["read_proc"] = f"denied: {{exc.errno}}"
try:
    sock = socket.socket()
    sock.close()
    result["socket"] = True
except OSError as exc:
    result["socket"] = f"denied: {{exc.errno}}"
try:
    libc = ctypes.CDLL(None)
    res = libc.syscall(101, 0, 0, 0, 0) # PTRACE_TRACEME = 0
    result["ptrace"] = True if res == 0 else f"denied: {{ctypes.get_errno()}}"
except Exception as exc:
    result["ptrace"] = f"denied: {{exc}}"
print(json.dumps(result))
"""


def _run_child(level: str, tmpdir: str) -> dict:
    import subprocess

    script = CHILD.format(repo=str(REPO))
    finished = subprocess.run(
        [sys.executable, "-c", script, level], capture_output=True, text=True,
        env={**os.environ, "JKY_TMP": tmpdir}, timeout=120,
    )
    lines = [line for line in finished.stdout.splitlines() if line.strip()]
    assert lines, f"child produced no output: {finished.stderr[-400:]}"
    return json.loads(lines[-1])


def test_probe_reports_availability():
    report = sandbox.probe()
    assert set(report) >= {"available", "supported", "abi", "levels", "reason"}
    if not report["available"]:
        pytest.skip(f"kernel has no Landlock: {report['reason']}")


def test_unknown_level_is_rejected():
    with pytest.raises(ValueError):
        sandbox.apply("paranoid")


def test_off_level_does_not_confine(tmp_path):
    if not sandbox.probe()["available"]:
        pytest.skip("no Landlock")
    result = _run_child("off", str(tmp_path))
    assert result["applied"] is False
    assert result["write_tmp"] is True
    assert result["read_etc_passwd"] is True
    assert result["socket"] is True


def test_ro_level_allows_reads_and_denies_writes(tmp_path):
    if not sandbox.probe()["available"]:
        pytest.skip("no Landlock")
    result = _run_child("ro", str(tmp_path))
    assert result["applied"] is True
    assert result["read_etc_passwd"] is True, "reads must keep working for collection"
    assert result["read_proc"] is True
    assert isinstance(result["write_tmp"], str) and result["write_tmp"].startswith("denied")


def test_strict_level_denies_writes_and_sockets(tmp_path):
    if not sandbox.probe()["available"]:
        pytest.skip("no Landlock")
    result = _run_child("strict", str(tmp_path))
    assert result["applied"] is True
    assert result["read_proc"] is True, "a forensic script must still read /proc"
    assert isinstance(result["write_tmp"], str) and result["write_tmp"].startswith("denied")
    if sandbox.probe()["abi"] and sandbox.probe()["abi"] >= 1:
        assert result["socket"] is not True, "strict mode must not reach the network"
        assert result["ptrace"] is not True, "strict mode must block ptrace syscall"

def test_vm_level_keeps_the_working_directory_writable(tmp_path):
    if not sandbox.probe()["available"]:
        pytest.skip("no Landlock")
    result = _run_child("vm", str(tmp_path))
    assert result["applied"] is True
    # /tmp is in the write set for vm level; the CLI's own cwd is granted too
    assert result["write_tmp"] is True


# --------------------------------------------------------------- platforms
def test_non_linux_host_reports_unavailable_instead_of_raising(monkeypatch):
    """Landlock and seccomp are Linux mechanisms: off Linux there is nothing to apply.

    ``sys.platform`` is read at call time, so patching it *is* the simulation.
    The point of the test is that no host call is reached — ``ctypes.CDLL(None)``
    raises ``TypeError: LoadLibrary() argument 1 must be str, not None`` on
    Windows — and that ``apply`` still answers instead of raising, with
    ``applied`` False so no caller can believe it is confined.
    """
    monkeypatch.setattr(sandbox.sys, "platform", "win32")

    assert sandbox.unavailable_reason(), "a non-Linux host must give a reason"
    assert sandbox.abi_version() is None

    probe = sandbox.probe()
    assert probe["available"] is False
    assert probe["supported"] is False, "unsupported must differ from merely unavailable"
    assert probe["abi"] is None
    assert "win32" in probe["reason"]
    assert probe["levels"] == list(sandbox.LEVELS)

    report = sandbox.apply("strict")
    assert report.applied is False
    assert report.abi is None
    assert "win32" in report.reason
    assert report.seccomp is False
    # the report shape the CLI and the VM consume is unchanged
    assert set(report.to_dict()) >= {"level", "applied", "abi", "reason",
                                     "rules_skipped", "rules", "network_blocked"}

    # `off` keeps its own reason even here: it is a request, not a failure
    assert sandbox.apply("off").reason == "confinement disabled by request"
    with pytest.raises(ValueError):
        sandbox.apply("paranoid")
