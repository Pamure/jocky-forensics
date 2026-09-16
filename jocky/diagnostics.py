"""
Environment self-check behind ``jocky doctor``.

An investigation tool that fails halfway through a live response is worse than
one that refuses to start, so every prerequisite is probed *before* work begins
and reported as ``ok`` / ``warn`` / ``fail`` with the remediation.

Checks are grouped by what they gate: language runtime, host collection,
fileless execution, management (TLS), and packaging.
"""
from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import sqlite3
import ssl
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

OK = "ok"
WARN = "warn"
FAIL = "fail"


@dataclass
class Check:
    name: str
    status: str
    detail: str
    fix: str = ""
    group: str = "general"


@dataclass
class Report:
    checks: List[Check] = field(default_factory=list)
    started_at: float = 0.0
    duration_ms: float = 0.0

    @property
    def ok(self) -> bool:
        return not any(check.status == FAIL for check in self.checks)

    @property
    def counts(self) -> Dict[str, int]:
        return {
            OK: sum(1 for c in self.checks if c.status == OK),
            WARN: sum(1 for c in self.checks if c.status == WARN),
            FAIL: sum(1 for c in self.checks if c.status == FAIL),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "counts": self.counts,
            "duration_ms": round(self.duration_ms, 3),
            "host": {
                "platform": platform.platform(),
                "python": sys.version.split()[0],
                "machine": platform.machine(),
                "uid": os.geteuid() if hasattr(os, "geteuid") else None,
            },
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail,
                 "fix": c.fix, "group": c.group}
                for c in self.checks
            ],
        }


def _check_python(report: Report) -> None:
    version = sys.version_info
    if version >= (3, 12):
        report.checks.append(Check("python >= 3.12", OK, sys.version.split()[0], group="runtime"))
    else:
        report.checks.append(
            Check("python >= 3.12", FAIL, sys.version.split()[0],
                  "install Python 3.12+ (the runtime uses tomllib-free stdlib features and modern typing)",
                  group="runtime")
        )


def _is_windows() -> bool:
    """Whether this host's collection backend is ``jocky.rt.winapi``.

    A function rather than a constant so the platform branch can be exercised by
    a test without pretending to be Windows for the whole process.
    """
    return sys.platform == "win32"


def _procfs_present() -> bool:
    """Whether a Linux procfs is mounted and readable at ``/proc``."""
    return os.path.isdir("/proc") and os.path.exists("/proc/self/stat")


def _memfd_platform_reason() -> str:
    """Why memfd-based fileless execution cannot work here, or ``""`` if it can."""
    if sys.platform.startswith("linux"):
        return ""
    return (f"memfd_create is a Linux mechanism (sys.platform={sys.platform!r}); "
            "fileless execution has no equivalent here")


def _check_procfs(report: Report) -> None:
    """Check the collection backend this platform actually has.

    ``/proc`` proves the Linux collection path works. On Windows that path does
    not exist at all — collection goes through :mod:`jocky.rt.winapi` — so a
    missing ``/proc`` there is not a fault, and reporting one would tell an
    operator to fix something that cannot be fixed. The backend that answered is
    named in the detail, because which one produced the evidence is itself a
    fact worth recording.
    """
    if _is_windows():
        _check_windows_backend(report)
        return
    if _procfs_present():
        report.checks.append(Check("procfs mounted", OK, "/proc is readable", group="collection"))
    else:
        report.checks.append(
            Check("procfs mounted", FAIL, "/proc missing",
                  "collection requires Linux procfs; run inside a Linux host or container "
                  "with /proc mounted", group="collection")
        )
    if os.path.isdir("/proc/net"):
        report.checks.append(Check("network tables", OK, "/proc/net present", group="collection"))
    else:
        report.checks.append(
            Check("network tables", WARN, "/proc/net not readable",
                  "socket inventory will be empty; check container networking",
                  group="collection")
        )


def _check_windows_backend(report: Report) -> None:
    """Probe ``winapi`` — the Windows stand-in for procfs — without assuming it loaded.

    ``winapi`` is imported here rather than at module scope so that importing
    ``diagnostics`` on Linux (where every caller of it lives) stays cheap and
    does not pull in the Windows structure definitions.
    """
    try:
        from jocky.rt import winapi
    except Exception as exc:  # a missing backend must be reported, not raised
        report.checks.append(
            Check("process table (winapi)", FAIL,
                  f"cannot import jocky.rt.winapi: {type(exc).__name__}: {exc}",
                  "reinstall the package: python -m pip install -e .", group="collection")
        )
        return
    if not winapi.available():
        report.checks.append(
            Check("process table (winapi)", FAIL, "Windows API bindings did not load",
                  "collection needs kernel32/ntdll/advapi32/iphlpapi/psapi; "
                  "run doctor from a normal Windows session", group="collection")
        )
        return
    try:
        rows = winapi.list_processes()
    except Exception as exc:
        report.checks.append(
            Check("process table (winapi)", FAIL,
                  f"list_processes() failed: {type(exc).__name__}: {exc}",
                  "collection cannot enumerate processes on this host", group="collection")
        )
        return
    if rows:
        report.checks.append(
            Check("process table (winapi)", OK,
                  f"{len(rows)} process(es) via jocky.rt.winapi "
                  "(Toolhelp32 + NtQuerySystemInformation)", group="collection")
        )
    else:
        report.checks.append(
            Check("process table (winapi)", FAIL, "list_processes() returned no rows",
                  "a Windows host always has processes; the API call is being denied "
                  "(see winapi.access_errors())", group="collection")
        )
    try:
        sockets = winapi.connections()
        report.checks.append(
            Check("network tables", OK,
                  f"{len(sockets)} socket(s) via jocky.rt.winapi (GetExtendedTcpTable/"
                  "GetExtendedUdpTable)", group="collection")
        )
    except Exception as exc:
        report.checks.append(
            Check("network tables", WARN,
                  f"winapi.connections() failed: {type(exc).__name__}: {exc}",
                  "socket inventory will be empty", group="collection")
        )


def _check_permissions(report: Report) -> None:
    uid = os.geteuid() if hasattr(os, "geteuid") else None
    if uid is None:
        # Windows has no process-wide uid; visibility is decided per handle, so
        # there is no single number to report and no procfs to read through.
        report.checks.append(
            Check("effective uid", WARN, f"no geteuid on this platform ({sys.platform})",
                  "Windows visibility is per access, not per uid: run elevated to read "
                  "every process (denied calls are listed by winapi.access_errors())",
                  group="collection")
        )
    elif uid == 0:
        report.checks.append(Check("effective uid", OK, "0 (root)", group="collection"))
    else:
        report.checks.append(
            Check("effective uid", WARN, str(uid),
                  "reading other users' /proc entries needs root (or CAP_SYS_PTRACE for ptrace); "
                  "you will still see your own processes", group="collection")
        )


def _check_memfd(report: Report) -> None:
    """memfd is how fileless payloads get a readable, executable descriptor."""
    platform_reason = _memfd_platform_reason()
    if platform_reason:
        report.checks.append(
            Check("memfd_create", FAIL, platform_reason,
                  "fileless mode is Linux-only; use `jocky run` (source mode) on this host "
                  "instead", group="fileless")
        )
        return
    if not hasattr(os, "memfd_create"):
        report.checks.append(
            Check("memfd_create", FAIL, "not available on this interpreter/kernel",
                  "fileless mode unavailable; use `jocky run` (source mode) instead",
                  group="fileless")
        )
        return
    report.checks.append(Check("memfd_create", OK, "available", group="fileless"))
    executable = os.path.isdir("/proc/self") and os.path.exists("/proc/self/fd")
    if not executable:
        report.checks.append(
            Check("/proc/self/fd execution", FAIL, "not available",
                  "fileless mode executes through /proc/self/fd", group="fileless")
        )


def _check_raw_syscalls(report: Report) -> None:
    """Probe the raw trampoline, whose absence here may be the platform itself."""
    try:
        from jocky.rt import raw

        probe = raw.probe()
        if probe.get("available"):
            report.checks.append(
                Check("direct syscalls", OK,
                      f"{probe.get('method')} on {probe.get('arch', platform.machine())}",
                      group="runtime")
            )
        elif not probe.get("supported", True):
            # `supported` False means no configuration could help: the mechanism
            # belongs to a platform this host is not.
            report.checks.append(
                Check("direct syscalls", WARN, str(probe.get("error") or "Linux-only mechanism"),
                      "direct syscalls are a Linux-only mechanism; mem.syscall() is not "
                      "available here", group="runtime")
            )
        else:
            report.checks.append(
                Check("direct syscalls", WARN, probe.get("error") or "unavailable",
                      "mem.syscall() falls back to libc; JOCKY works, the raw path is unavailable",
                      group="runtime")
            )
    except Exception as exc:  # a broken probe must not break doctor
        report.checks.append(
            Check("direct syscalls", WARN, f"{type(exc).__name__}: {exc}",
                  "optional feature", group="runtime")
        )


def _check_fileless_end_to_end(report: Report) -> None:
    """Actually run a tiny payload from memory — the only proof that counts."""
    platform_reason = _memfd_platform_reason()
    if platform_reason:
        report.checks.append(
            Check("fileless end-to-end", FAIL, platform_reason,
                  "fileless mode is Linux-only (memfd plus /proc/self/fd); use source mode "
                  "(`jocky run`) on this host", group="fileless")
        )
        return
    try:
        from jocky.exec import fileless

        outcome = fileless.run_fileless(b'emit {"kind": "doctor-probe"}',
                                        wall_clock_ms=10_000, timeout=60)
        if outcome.get("ok"):
            evidence = outcome.get("evidence", {})
            report.checks.append(
                Check("fileless end-to-end", OK,
                      f"exe={evidence.get('exe')} memfd_maps={evidence.get('memfd_map_count')}",
                      group="fileless")
            )
        else:
            report.checks.append(
                Check("fileless end-to-end", FAIL,
                      (outcome.get("stderr") or "").strip()[:200] or "payload failed",
                      "check that executing files from /proc/self/fd is permitted "
                      "(some hardening policies block it)", group="fileless")
            )
    except Exception as exc:
        report.checks.append(
            Check("fileless end-to-end", FAIL, f"{type(exc).__name__}: {exc}",
                  "install the package and retry: python -m pip install -e .", group="fileless")
        )


def _check_management(report: Report) -> None:
    if importlib.util.find_spec("ssl") is not None:
        report.checks.append(Check("tls module", OK, ssl.OPENSSL_VERSION.split(" ")[0],
                                   group="management"))
    else:
        report.checks.append(
            Check("tls module", FAIL, "ssl unavailable",
                  "Python built without OpenSSL: `jocky serve`/`agent` cannot run",
                  group="management")
        )
    openssl = shutil.which("openssl")
    if openssl:
        report.checks.append(Check("openssl binary", OK, openssl, group="management"))
    else:
        report.checks.append(
            Check("openssl binary", WARN, "not found",
                  "certificates must be supplied with --cert/--key; `jocky serve` cannot "
                  "generate a self-signed pair without openssl", group="management")
        )
    try:
        sqlite3.connect(":memory:").execute("select 1").fetchone()
        report.checks.append(Check("sqlite3", OK, sqlite3.sqlite_version, group="management"))
    except Exception as exc:
        report.checks.append(
            Check("sqlite3", FAIL, f"{type(exc).__name__}: {exc}",
                  "the job/finding store requires sqlite3", group="management")
        )


def _check_workspace(report: Report) -> None:
    cwd = os.getcwd()
    if os.access(cwd, os.W_OK):
        report.checks.append(Check("working directory writable", OK, cwd, group="packaging"))
    else:
        report.checks.append(
            Check("working directory writable", WARN, cwd,
                  "`jocky init`, case output and the evidence harness write here",
                  group="packaging")
        )
    try:
        from jocky import __version__

        report.checks.append(Check("jocky package importable", OK, f"version {__version__}",
                                   group="packaging"))
    except Exception as exc:
        report.checks.append(
            Check("jocky package importable", FAIL, f"{type(exc).__name__}: {exc}",
                  "run from the repository root or install the package", group="packaging")
        )


def _check_sandbox(report: Report) -> None:
    """Report whether confinement is available — never assume it is."""
    try:
        from jocky import sandbox

        probe = sandbox.probe()
        if probe.get("available"):
            detail = f"Landlock ABI {probe['abi']}"
            if not probe.get("network_rights"):
                detail += " (filesystem rights only; --sandbox=strict adds seccomp)"
            report.checks.append(Check("sandbox (Landlock)", OK, detail,
                                       group="confinement"))
        elif not probe.get("supported", True):
            # Off Linux there is no LSM to reach: this is a platform fact, not a
            # kernel build option the operator left out.
            report.checks.append(
                Check("sandbox (Landlock)", WARN, str(probe.get("reason") or "Linux-only mechanism"),
                      "Landlock is a Linux-only mechanism; every sandbox level is a no-op "
                      "here and `jocky run --sandbox` reports it as unenforced",
                      group="confinement")
            )
        else:
            report.checks.append(
                Check("sandbox (Landlock)", WARN, probe.get("reason", "unavailable"),
                      "run untrusted scripts only with --sandbox=off acknowledged, or on a "
                      "kernel built with CONFIG_SECURITY_LANDLOCK", group="confinement")
            )
    except Exception as exc:  # a broken probe must not break doctor
        report.checks.append(
            Check("sandbox (Landlock)", WARN, f"{type(exc).__name__}: {exc}",
                  "confinement is optional", group="confinement")
        )


def run_checks(quick: bool = False) -> Report:
    """Probe every prerequisite. ``quick`` skips the end-to-end fileless run."""
    report = Report(started_at=time.time())
    _check_python(report)
    _check_workspace(report)
    _check_procfs(report)
    _check_permissions(report)
    _check_raw_syscalls(report)
    _check_sandbox(report)
    _check_management(report)
    if not quick:
        _check_memfd(report)
        _check_fileless_end_to_end(report)
    report.duration_ms = (time.time() - report.started_at) * 1000.0
    return report


SYMBOLS = {OK: "ok  ", WARN: "warn", FAIL: "FAIL"}


def format_report(report: Report) -> str:
    """Human-readable table, grouped, with fixes for anything not ok."""
    lines: List[str] = []
    current_group = None
    for check in report.checks:
        if check.group != current_group:
            current_group = check.group
            lines.append(f"\n{current_group.upper()}")
        lines.append(f"  [{SYMBOLS.get(check.status, '????')}] {check.name:<28} {check.detail}")
        if check.fix and check.status != OK:
            lines.append(f"          -> {check.fix}")
    counts = report.counts
    verdict = "ready" if report.ok else "NOT ready"
    lines.append(
        f"\n{verdict}: {counts[OK]} ok, {counts[WARN]} warning(s), "
        f"{counts[FAIL]} failure(s) in {report.duration_ms:.0f} ms"
    )
    return "\n".join(lines)
