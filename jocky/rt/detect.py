"""
Detection engineering over the collectors.

Each check returns ``finding`` dicts shaped as::

    {"check": str, "severity": str, "title": str,
     "evidence": {...}, "recommendation": str}

``severity`` uses an ordered scale so scripts can threshold:
``info < low < medium < high < critical``.

The checks target exactly the techniques this project also exercises
(fileless execution, in-memory payloads, LOLBin-style command lines) — the
tool must be able to see what it can do, otherwise the evasion claim would be
unverifiable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
import re
import time
from typing import Any, Dict, List, Optional

from jocky.rt import filefs, netfs, procfs, sysinfo

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: Every check this module can emit, with its data source and default severity.
#: This catalog is the single source of truth for the documentation generator
#: (`site/tools/gen_reference.py`) and is asserted against real triage output by
#: `tests/test_runtime.py`, so docs cannot drift from behaviour.
CHECK_CATALOG = (
    {
        "check": "fileless_process",
        "severity": "high",
        "source": "/proc/<pid>/exe",
        "summary": "Process image runs from anonymous memory (/memfd:…) or a deleted file.",
        "action": "copy /proc/<pid>/exe to evidence storage before the process exits",
    },
    {
        "check": "memfd_mapping",
        "severity": "high",
        "source": "/proc/<pid>/maps",
        "summary": "Executable mapping backed by a memfd object.",
        "action": "capture the mapping and correlate with the parent process",
    },
    {
        "check": "memfd_fd_holder",
        "severity": "high",
        "source": "/proc/<pid>/cmdline + /proc/<pid>/fd",
        "summary": "A memfd payload is being executed through an interpreter (/proc/self/fd/N in argv).",
        "action": "recover the payload from the referenced descriptor",
    },
    {
        "check": "injection_primitive",
        "severity": "low",
        "source": "/proc/<pid>/fd (anon_inode)",
        "summary": "Anonymous descriptors used for injection (userfaultfd, io_uring) are held open.",
        "action": "correlate with ptrace/process_vm_* activity; legitimate for some software",
    },
    {
        "check": "deleted_executable",
        "severity": "medium",
        "source": "/proc/<pid>/exe",
        "summary": "Executable was unlinked after start (loader that drops its dropper).",
        "action": "recover the binary from /proc/<pid>/exe and hash it",
    },
    {
        "check": "temp_executable",
        "severity": "high",
        "source": "/proc/<pid>/exe",
        "summary": "Execution from a world-writable drop zone (/tmp, /dev/shm, /var/tmp).",
        "action": "hash the binary and reconstruct the parent chain",
    },
    {
        "check": "rwx_memory",
        "severity": "low",
        "source": "/proc/<pid>/maps",
        "summary": "Writable+executable anonymous region — correlation input, not a verdict.",
        "action": "correlate with fileless flags rather than alerting alone",
    },
    {
        "check": "unusual_listener",
        "severity": "low",
        "source": "/proc/net/tcp{,6} + /proc/*/fd",
        "summary": "TCP listener outside the baseline port set, attributed to a process.",
        "action": "confirm the service is expected on this host",
    },
    {
        "check": "ioc_connection",
        "severity": "critical",
        "source": "/proc/net/* cross-referenced with an IOC set",
        "summary": "Live connection involving an indicator from the supplied IOC set.",
        "action": "isolate the host and capture volatile state",
    },
    {
        "check": "deleted_open_file",
        "severity": "medium",
        "source": "/proc/<pid>/fd",
        "summary": "File unlinked on disk but still held open (memfd targets excluded).",
        "action": "recover the content via /proc/<pid>/fd/<fd>",
    },
    {
        "check": "ld_preload",
        "severity": "high",
        "source": "/etc/ld.so.preload",
        "summary": "Global library preloading injects code into every process.",
        "action": "verify each listed library against the package manager",
    },
    {
        "check": "ld_env_injection",
        "severity": "medium",
        "source": "/proc/<pid>/environ",
        "summary": "Process environment carries LD_PRELOAD/LD_AUDIT/LD_LIBRARY_PATH.",
        "action": "inspect the referenced library",
    },
    {
        "check": "suspicious_cmdline",
        "severity": "varies",
        "source": "/proc/<pid>/cmdline vs pattern table",
        "summary": "Command line matches an intrusion pattern (download-and-execute, reverse shell, log tampering, …).",
        "action": "reconstruct the process tree around the PID",
    },
    {
        "check": "hidden_module",
        "severity": "critical",
        "source": "/proc/modules vs loadable /sys/module subset",
        "summary": "The two kernel views of loadable modules disagree — one was tampered with.",
        "action": "treat the kernel as compromised; acquire a memory image",
    },
    {
        "check": "byovd_known_vulnerable_module",
        "severity": "varies",
        "source": "/proc/modules vs a curated abused-driver list",
        "summary": ("A loaded module matches a driver abused in published BYOVD "
                    "research. Third-party drivers grade critical; in-tree modules "
                    "with a patched flaw grade info."),
        "action": ("third-party: treat the load as hostile. in-tree: compare the "
                   "kernel build against the vendor fix — presence is not compromise"),
    },
    {
        "check": "byovd_out_of_tree_module",
        "severity": "medium",
        "source": "/sys/module/<name>/taint (O)",
        "summary": "Module was not shipped with this kernel build (taint bit 12).",
        "action": "identify the vendor or package that installed the module",
    },
    {
        "check": "byovd_unsigned_module",
        "severity": "high",
        "source": "/sys/module/<name>/taint (E)",
        "summary": "Module carries no signature (taint bit 13) — the BYOVD precondition.",
        "action": "hash the .ko and compare it against the distribution package manifest",
    },
    {
        "check": "byovd_forced_module",
        "severity": "high",
        "source": "/sys/module/<name>/taint (F)",
        "summary": "Module was force-loaded, bypassing vermagic and version checks.",
        "action": "treat as deliberate tampering unless a maintenance action explains it",
    },
    {
        "check": "byovd_late_loaded_module",
        "severity": "info",
        "source": "/sys/module/<name> mtime vs boot time",
        "summary": ("Module appeared well after boot. Correlation input, not a "
                    "verdict: modules load on demand for ordinary reasons."),
        "action": "correlate the load time with process, cron and package-manager activity",
    },
    {
        "check": "byovd_deleted_module_file",
        "severity": "high",
        "source": "/proc/modules vs /lib/modules/<release>",
        "summary": "A loaded module's backing .ko is gone from disk.",
        "action": "dump the module from memory before the host is rebooted",
    },
    {
        "check": "byovd_deleted_driver_file",
        "severity": "high",
        "source": "kernel module list vs the driver's image path (Windows)",
        "summary": ("A loaded kernel driver's image file is missing on disk — the "
                    "Windows ghost-driver signal."),
        "action": ("dump the driver from memory and identify who loaded it before "
                   "the host is rebooted"),
    },
    {
        "check": "byovd_kernel_taint",
        "severity": "medium",
        "source": "/proc/sys/kernel/tainted",
        "summary": ("Global kernel taint bits 12/13 are set: out-of-tree and/or "
                    "unsigned code is running in ring 0. A summary — the "
                    "per-module findings carry the precise grade."),
        "action": "enumerate the offending modules before drawing conclusions from any check",
    },
    {
        "check": "hollowed_process",
        "severity": "high",
        "source": "on-disk image vs the image mapped in the process (Windows)",
        "summary": ("A process's main image differs from its file on disk — the "
                    "process-hollowing signature."),
        "action": "dump the memory image and compare entry-point bytes against a known-good copy",
    },
    {
        "check": "private_executable_memory",
        "severity": "medium",
        "source": "VirtualQueryEx region walk (Windows)",
        "summary": ("Committed private memory that is executable — where a "
                    "manually-mapped payload lives. Also where a JIT lives."),
        "action": "correlate with the process's provenance; a JIT runtime looks identical",
    },
    {
        "check": "unbacked_thread_start",
        "severity": "high",
        "source": "thread start addresses vs loaded modules (Windows)",
        "summary": ("A thread's start address lies outside every loaded module — the "
                    "thread-execution-hijacking signal."),
        "action": "capture the thread context and the memory at its start address",
    },
    {
        "check": "module_from_temp_path",
        "severity": "medium",
        "source": "loaded module paths (Windows)",
        "summary": "A module was loaded from a temporary or world-writable directory.",
        "action": "hash the module and identify what loaded it",
    },
    {
        "check": "hijackable_path",
        "severity": "low",
        "source": "$PATH resolved through symlinks + /proc/mounts",
        "summary": "PATH directory is writable (permission-opaque filesystems excluded).",
        "action": "remove it from PATH or fix permissions",
    },
    {
        "check": "persistence",
        "severity": "high",
        "source": "cron, systemd, rc.local, profile.d, authorized_keys",
        "summary": "Persistence artefact modified recently or world-writable.",
        "action": "review the file against the package manifest",
    },
    {
        "check": "partial_visibility",
        "severity": "info",
        "source": "/proc/<pid>/exe reachability across the process table",
        "summary": "Part of the process table could not be inspected, so a clean result is not conclusive.",
        "action": "re-run as root or with CAP_SYS_PTRACE before treating the host as clean",
    },
    {
        "check": "check_error",
        "severity": "info",
        "source": "internal",
        "summary": "A check raised — reported instead of aborting the whole triage.",
        "action": "treat a clean result as unknown for that check",
    },
)

# Command-line patterns seen in real intrusions. Kept as data so scripts can
# extend them; severity reflects how strongly the pattern implies execution.
CMD_PATTERNS = (
    (r"(?:curl|wget)[^|]{0,120}\|\s*(?:ba|z|da)?sh\b", "download-and-execute", "critical"),
    (r"/dev/tcp/", "bash-reverse-shell", "critical"),
    (r"\bnc(?:at)?\b[^\n]{0,60}\s-e\b", "netcat-exec", "critical"),
    (r"\bsocat\b|\bmkfifo\b", "relay-shell", "high"),
    (r"chmod\s+\+x\s+/(?:tmp|dev/shm|var/tmp)/", "temp-chmod-exec", "high"),
    (r"base64\s+(?:-d|--decode)", "base64-decode", "medium"),
    (r"python[0-9.]*\s+-c\s+.{0,60}(?:exec|eval|__import__)", "inline-interpreter-exec", "medium"),
    (r"history\s+-c|rm\s+-rf?\s+/var/log|>\s*/var/log/", "log-tampering", "high"),
    (r"\bnohup\b.*&\s*$", "backgrounded-process", "low"),
)

SUSPICIOUS_ENV_KEYS = ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")

PERSISTENCE_PATHS = (
    "/etc/ld.so.preload",
    "/etc/rc.local",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/var/spool/cron",
    "/etc/systemd/system",
    "/etc/profile.d",
    "/root/.ssh/authorized_keys",
)


def _finding(check: str, severity: str, title: str, evidence: Dict[str, Any],
             recommendation: str = "") -> Dict[str, Any]:
    return {
        "check": check,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _self_pids() -> set:
    pids = {os.getpid()}
    try:
        pids.add(os.getppid())
    except OSError:
        pass
    return pids


@dataclass
class Snapshot:
    """One pass over ``/proc``, shared by every process check.

    Each check used to walk ``/proc`` on its own, so a single triage run paid
    for roughly five sweeps of the same data. ``processes`` holds every visible
    process with its cheap fields, plus descriptors and memory maps for the
    first ``max_pids`` — the same bound the deep checks always applied, so
    ``entry.get("fds")``/``entry.get("maps")`` are absent exactly where a check
    would previously have stopped.

    The host-facing checks (network, modules, PATH) take the snapshot too and
    ignore it; the uniform signature keeps the triage call site honest.
    """

    processes: List[Dict[str, Any]] = field(default_factory=list)


def collect_snapshot(max_pids: int = 400) -> Snapshot:
    """Collect the shared process view once."""
    return Snapshot(processes=procfs.list_processes(
        detail_limit=max_pids, with_fds=True, with_maps=True))


# --------------------------------------------------------------- fileless
def fileless_processes(exclude_self: bool = True,
                       snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """Processes running from an anonymous memory file (memfd) or a
    deleted executable — the artefact both we and malware leave."""
    skip = _self_pids() if exclude_self else set()
    entries = snapshot.processes if snapshot is not None else procfs.list_processes()
    out: List[Dict[str, Any]] = []
    for entry in entries:
        if entry["pid"] in skip:
            continue
        exe = entry.get("exe") or ""
        if "/memfd:" in exe or exe.endswith("(deleted)"):
            out.append(_finding(
                "fileless_process", "high",
                f"process {entry['pid']} ({entry['name']}) runs from memory",
                {"pid": entry["pid"], "name": entry["name"], "exe": exe,
                 "cmdline": entry["cmdline"], "uid": entry.get("uid"),
                 "start_epoch": entry.get("start_epoch")},
                "dump /proc/<pid>/exe for analysis before the process exits",
            ))
    return out


def memfd_mappings(max_pids: int = 400,
                   snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """Executable mappings backed by memfd objects."""
    entries = snapshot.processes if snapshot is not None else procfs.list_processes(
        detail_limit=max_pids, with_maps=True)
    out: List[Dict[str, Any]] = []
    for entry in entries[:max_pids]:
        pid = entry["pid"]
        for mapping in entry.get("maps") or []:
            if mapping["memfd"] and "x" in mapping["perms"]:
                out.append(_finding(
                    "memfd_mapping", "high",
                    f"executable memfd mapping in pid {pid}",
                    {"pid": pid, "path": mapping["path"], "perms": mapping["perms"],
                     "size_kb": mapping["size_kb"], "inode": mapping["inode"]},
                    "capture the mapping with dd/if=/proc/<pid>/mem before it vanishes",
                ))
    return out


def memfd_fd_holders(max_pids: int = 400,
                     snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """Processes that handed a memfd to an interpreter through argv.

    Executing a *script* from a memfd does not produce a memfd-backed
    ``/proc/<pid>/exe``: the kernel starts the on-disk interpreter and passes
    ``/proc/self/fd/N`` as an argument, so the generic fileless test misses it
    entirely (verified in research/findings/res-fileless-state-of-art.md). What
    survives is the pair — an argv token pointing at ``/proc/self/fd/N`` and a
    descriptor N that really is a memfd.
    """
    entries = snapshot.processes if snapshot is not None else procfs.list_processes(
        detail_limit=max_pids, with_fds=True)
    out: List[Dict[str, Any]] = []
    for entry in entries[:max_pids]:
        pid = entry["pid"]
        argv = entry.get("argv") or procfs.read_cmdline(pid)
        referenced = {
            int(token.rsplit("/", 1)[-1])
            for token in argv
            if ("/proc/self/fd/" in token or "/dev/fd/" in token)
            and token.rsplit("/", 1)[-1].isdigit()
        }
        if not referenced:
            continue
        memfds = {
            fd["fd"]: fd["target"]
            for fd in entry.get("fds") or procfs.read_fds(pid)
            if isinstance(fd.get("fd"), int) and "memfd:" in fd.get("target", "")
        }
        hits = {fd: memfds[fd] for fd in referenced if fd in memfds}
        if not hits:
            continue
        out.append(_finding(
            "memfd_fd_holder", "high",
            f"pid {pid} is running a memfd payload through an interpreter",
            {"pid": pid, "argv": argv[:4], "memfd_descriptors": hits,
             "exe": entry.get("exe")},
            "recover the payload from /proc/<pid>/fd/<N> before the process exits",
        ))
    return out


def injection_primitives(max_pids: int = 400,
                         snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """Anonymous kernel objects used for cross-process injection.

    ``userfaultfd`` and ``io_uring`` descriptors are how modern Linux injectors
    stage memory. Both are legitimate for some software, so this is reported as
    ``low``: it is a correlation input, not a verdict.
    """
    markers = ("userfaultfd", "io_uring", "udmabuf", "pidfd")
    entries = snapshot.processes if snapshot is not None else procfs.list_processes(
        detail_limit=max_pids, with_fds=True)
    out: List[Dict[str, Any]] = []
    for entry in entries[:max_pids]:
        pid = entry["pid"]
        hits = [
            fd for fd in entry.get("fds") or procfs.read_fds(pid)
            if any(marker in fd.get("target", "") for marker in markers)
        ]
        if not hits:
            continue
        out.append(_finding(
            "injection_primitive", "low",
            f"pid {pid} holds {len(hits)} injection-capable descriptor(s)",
            {"pid": pid, "descriptors": [fd["target"] for fd in hits][:4],
             "exe": entry.get("exe")},
            "correlate with ptrace/process_vm_* activity before alerting",
        ))
    return out


def deleted_executables(max_pids: int = 400,
                        snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """Processes whose on-disk image was unlinked after start."""
    entries = snapshot.processes if snapshot is not None else procfs.list_processes()
    out: List[Dict[str, Any]] = []
    for entry in entries[:max_pids]:
        exe = entry.get("exe")
        if exe and exe.endswith("(deleted)") and "/memfd:" not in exe:
            out.append(_finding(
                "deleted_executable", "medium",
                f"pid {entry['pid']} runs a deleted executable",
                {"pid": entry["pid"], "exe": exe, "cmdline": entry.get("cmdline", "")},
                "copy /proc/<pid>/exe to evidence storage",
            ))
    return out


def temp_executables(max_pids: int = 400,
                     snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """Executables launched from world-writable temporary directories."""
    entries = snapshot.processes if snapshot is not None else procfs.list_processes()
    out: List[Dict[str, Any]] = []
    for entry in entries[:max_pids]:
        exe = entry.get("exe")
        if exe and exe.startswith(filefs.TEMP_PREFIXES):
            out.append(_finding(
                "temp_executable", "high",
                f"pid {entry['pid']} executes from {exe}",
                {"pid": entry["pid"], "exe": exe,
                 "cmdline": entry.get("cmdline", "")},
                "hash the binary and correlate with the parent process",
            ))
    return out


def rwx_regions(max_pids: int = 400, anonymous_only: bool = True,
                snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """Writable+executable memory regions — injection / JIT shells.

    Reported as ``low``: JIT runtimes (Python, Electron, JVM) legitimately own
    anonymous rwx regions, so this is a correlation input, not a verdict.
    """
    entries = snapshot.processes if snapshot is not None else procfs.list_processes(
        detail_limit=max_pids, with_maps=True)
    out: List[Dict[str, Any]] = []
    for entry in entries[:max_pids]:
        pid = entry["pid"]
        name = entry.get("name", "?")
        for mapping in entry.get("maps") or []:
            if not mapping["rwx"]:
                continue
            if anonymous_only and not mapping["anonymous"]:
                continue
            out.append(_finding(
                "rwx_memory", "low",
                f"rwx region in pid {pid} ({name}), {mapping['size_kb']} KiB",
                {"pid": pid, "process": name, "start": hex(mapping["start"]),
                 "size_kb": mapping["size_kb"], "path": mapping["path"] or "[anon]"},
                "correlate with the process's child/parent chain and fileless flags",
            ))
    return out


# --------------------------------------------------------------- network
def unusual_listeners(snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for conn in netfs.unusual_listeners():
        owner = conn.get("process") or "unattributed"
        out.append(_finding(
            "unusual_listener", "low",
            f"{conn['proto']} listener on port {conn['local_port']} ({owner})",
            {"proto": conn["proto"], "addr": conn["local_addr"],
             "port": conn["local_port"], "pid": conn.get("pid"),
             "process": conn.get("process")},
            "confirm the service is expected on this host",
        ))
    return out


def remote_connections_to(addresses: List[str]) -> List[Dict[str, Any]]:
    wanted = set(addresses)
    out: List[Dict[str, Any]] = []
    for conn in netfs.established():
        if conn["remote_addr"] in wanted or conn["local_addr"] in wanted:
            out.append(_finding(
                "ioc_connection", "critical",
                f"connection involving {conn['remote_addr']}",
                {"proto": conn["proto"], "local": f"{conn['local_addr']}:{conn['local_port']}",
                 "remote": f"{conn['remote_addr']}:{conn['remote_port']}",
                 "pid": conn.get("pid"), "process": conn.get("process")},
                "isolate the host and capture the associated process memory",
            ))
    return out


# --------------------------------------------------------------- host
def deleted_open_files(snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    if snapshot is None:
        items = procfs.deleted_open_files()
    else:
        grouped: Dict[tuple, Dict[str, Any]] = {}
        for entry in snapshot.processes:
            for fd in entry.get("fds") or []:
                target = fd.get("target", "")
                if not fd.get("deleted") or fd.get("kind") != "file" or "/memfd:" in target:
                    continue
                row = grouped.setdefault((entry["pid"], target),
                                         {"pid": entry["pid"], "path": target,
                                          "fds": [], "count": 0})
                row["fds"].append(fd["fd"])
                row["count"] += 1
        items = list(grouped.values())
    out: List[Dict[str, Any]] = []
    for item in items:
        out.append(_finding(
            "deleted_open_file", "medium",
            f"pid {item['pid']} holds deleted file {item['path']}",
            item,
            "recover the content via /proc/<pid>/fd/<fd>",
        ))
    return out


def ld_preload_check(snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """``/etc/ld.so.preload`` and LD_* variables: userland rootkit surface."""
    out: List[Dict[str, Any]] = []
    preload = filefs.ld_preload()
    if preload.get("exists") and preload.get("entries"):
        out.append(_finding(
            "ld_preload", "high",
            "/etc/ld.so.preload injects libraries into every process",
            preload,
            "verify each library hash against the package manager",
        ))
    # `environ` is not part of the shared snapshot (it is the only check that
    # wants it) and reading it costs a fraction of a millisecond per process.
    entries = snapshot.processes if snapshot is not None else procfs.list_processes()
    for entry in entries:
        for var in procfs.read_environ(entry["pid"]):
            key = var.split("=", 1)[0]
            if key in SUSPICIOUS_ENV_KEYS:
                out.append(_finding(
                    "ld_env_injection", "medium",
                    f"pid {entry['pid']} has {key} set",
                    {"pid": entry["pid"], "name": entry["name"], "env": var},
                    "inspect the referenced library",
                ))
    return out


def suspicious_cmdline(max_pids: int = 400,
                       snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """Command lines matching known intrusion patterns."""
    compiled = [(re.compile(pattern), label, severity)
                for pattern, label, severity in CMD_PATTERNS]
    skip = _self_pids()
    entries = snapshot.processes if snapshot is not None else procfs.list_processes()
    out: List[Dict[str, Any]] = []
    for entry in entries[:max_pids]:
        if entry["pid"] in skip:
            continue
        cmdline = entry.get("cmdline") or ""
        if not cmdline:
            continue
        for regex, label, severity in compiled:
            if regex.search(cmdline):
                out.append(_finding(
                    "suspicious_cmdline", severity,
                    f"pid {entry['pid']} matches {label}",
                    {"pid": entry["pid"], "pattern": label, "cmdline": cmdline[:400]},
                    "reconstruct the full process tree around this PID",
                ))
                break
    return out


def hidden_modules(snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """Module-view mismatch between /proc/modules and /sys/module."""
    diff = sysinfo.hidden_modules()
    out: List[Dict[str, Any]] = []
    for name in diff["in_proc_not_sys"]:
        out.append(_finding(
            "hidden_module", "critical",
            f"module {name} is loaded but hidden from /sys/module",
            {"module": name, "visible_in": "/proc/modules"},
            "treat the kernel as compromised; acquire memory image",
        ))
    for name in diff["in_sys_not_proc"]:
        out.append(_finding(
            "hidden_module", "high",
            f"module {name} exists in /sys/module but not /proc/modules",
            {"module": name, "visible_in": "/sys/module"},
            "verify whether a rootkit filters /proc/modules",
        ))
    return out


def byovd(snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """Kernel-module integrity: the BYOVD-shaped checks, as one callable.

    Grouped behind a single function so ``triage`` can run it alongside the
    others and pay for the ``/proc/modules`` + ``/sys/module`` walk once
    (``byovd.byovd_findings`` shares that view across every per-module check),
    and so a script can ask for just this class with ``det.byovd()``.

    Kept out of the process ``Snapshot`` on purpose: this reads kernel module
    state, not ``/proc/<pid>``, and folding it in would put a second, unrelated
    sweep behind a name that promises process facts.
    """
    from jocky.rt import byovd as _byovd
    return _byovd.byovd_findings()


def winject(snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """Windows process-injection detection, as one callable.

    The mirror of the techniques pillar 3 names — process hollowing, reflective
    injection, thread hijacking — implemented as *detection* only. The execution
    side is deliberately absent (see ``docs/DESIGN.md`` §10); what an analyst
    needs on Windows is to find these, and until now the runtime could only do
    that on Linux.

    Exposed separately from ``triage`` because it reads other processes' memory:
    bounded, but heavier than the default checks, so triage runs it in ``deep``
    mode the same way it gates ``persistence`` and the memfd mapping walk.
    """
    from jocky.rt import winject as _winject
    if not _winject.available():
        return []
    findings: List[Dict[str, Any]] = []
    for detector in (_winject.hollowed_processes,
                     _winject.executable_private_memory,
                     _winject.unbacked_executable_threads,
                     _winject.modules_from_temp_paths):
        try:
            findings.extend(detector())
        except Exception as exc:  # a failed detector must not stop the sweep
            findings.append(_finding("check_error", "info",
                                     f"{detector.__name__} failed",
                                     {"error": repr(exc)}))
    return findings


def world_writable_path(snapshot: Optional[Snapshot] = None) -> List[Dict[str, Any]]:
    """PATH directories the current user could plant a binary in."""
    out: List[Dict[str, Any]] = []
    for entry in filefs.path_dirs():
        if entry.get("hijackable"):
            out.append(_finding(
                "hijackable_path", "low",
                f"PATH entry {entry['path']} is writable ({entry.get('resolved')})",
                entry,
                "remove the directory from PATH or fix its permissions",
            ))
    return out


def persistence(limit: int = 200) -> List[Dict[str, Any]]:
    """Recently modified persistence locations."""
    out: List[Dict[str, Any]] = []
    cutoff = time.time() - 30 * 24 * 3600        # last 30 days
    for path in PERSISTENCE_PATHS:
        if not os.path.exists(path):
            continue
        entries = filefs.scan(path, max_files=limit, max_depth=3) if os.path.isdir(path) \
            else [filefs.stat_entry(path)]
        for entry in entries:
            if entry is None or entry["is_dir"]:
                continue
            if entry["mtime"] >= cutoff or entry["world_writable"]:
                out.append(_finding(
                    "persistence", "high",
                    f"persistence artefact modified: {entry['path']}",
                    {"path": entry["path"], "mtime": entry["mtime"],
                     "mode": entry["mode"], "size": entry["size"]},
                    "review the file content against the package manifest",
                ))
    return out



# Checks that should never be deduplicated by (check, pid) — they originate
# from ``ioc_match`` or have no meaningful per-process identity.
_NO_DEDUP_CHECKS = frozenset({"ioc_connection", "ioc_hash", "ioc_filename"})


def _dedup_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse findings that share the same ``(check, evidence.pid)`` tuple.

    When a single process triggers multiple findings from the same check
    (e.g. a fileless binary that also has a deleted executable entry), only
    the highest-severity finding is kept.  Findings without a ``pid`` in
    their evidence or belonging to ``_NO_DEDUP_CHECKS`` pass through
    untouched.
    """
    best: Dict[tuple, Dict[str, Any]] = {}
    passthrough: List[Dict[str, Any]] = []
    for f in findings:
        pid = f.get("evidence", {}).get("pid")
        check = f.get("check", "")
        if pid is None or check in _NO_DEDUP_CHECKS:
            passthrough.append(f)
            continue
        key = (check, pid)
        existing = best.get(key)
        if existing is None or SEVERITY_ORDER.get(
                f["severity"], -1) > SEVERITY_ORDER.get(
                existing["severity"], -1):
            best[key] = f
    return list(best.values()) + passthrough


# --------------------------------------------------------------- aggregation
def triage(deep: bool = False, max_pids: int = 400) -> Dict[str, Any]:
    """Run every check and return findings plus counters."""
    started = time.perf_counter()
    findings: List[Dict[str, Any]] = []
    # One pass over /proc for every check that needs process state: the
    # per-check sweeps this replaces were most of a triage run's syscalls.
    snapshot = collect_snapshot(max_pids=max_pids)
    for check in (fileless_processes, memfd_fd_holders, deleted_executables,
                  temp_executables, rwx_regions, unusual_listeners,
                  deleted_open_files, ld_preload_check, suspicious_cmdline,
                  hidden_modules, world_writable_path, injection_primitives,
                  byovd):
        try:
            findings.extend(check(snapshot=snapshot))   # type: ignore[call-arg]
        except Exception as exc:                # a failed check must not stop triage
            findings.append(_finding("check_error", "info",
                                     f"{check.__name__} failed", {"error": repr(exc)}))
    if deep:
        findings.extend(memfd_mappings(max_pids=max_pids, snapshot=snapshot))
        findings.extend(persistence())
        # Windows-only, and the heaviest check here: each of these reads another
        # process's image or address space. Deep mode is where the Linux side
        # puts its expensive walks too, so it sits with them.
        findings.extend(winject())
    findings = _dedup_findings(findings)
    counts: Dict[str, int] = {level: 0 for level in SEVERITY_ORDER}
    processes = procfs.list_processes()
    unreadable = [entry for entry in processes if entry.get("exe") is None]
    coverage = round(1.0 - (len(unreadable) / len(processes)), 3) if processes else 0.0
    if processes and coverage < 0.95:
        # A clean verdict from a blind scan is the most dangerous result this
        # function can return, so partial visibility is reported as a finding
        # rather than hidden in a counter.
        findings.append(_finding(
            "partial_visibility", "info",
            f"only {coverage:.0%} of processes were inspectable "
            f"({len(unreadable)} of {len(processes)} unreadable)",
            {"unreadable_processes": len(unreadable), "total_processes": len(processes),
             "coverage": coverage, "uid": os.getuid() if hasattr(os, "getuid") else None},
            "re-run as root (or with CAP_SYS_PTRACE) before treating a clean "
            "result as conclusive for fileless/deleted-executable checks",
        ))
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    return {
        "findings": findings,
        "counts": counts,
        "scanned": {"processes": len(processes),
                    "sockets": len(netfs.connections(with_process=False)),
                    "unreadable_processes": len(unreadable),
                    "coverage": coverage},
        "host": {"hostname": os.uname().nodename,
                 "kernel": os.uname().release,
                 "boot_time": procfs.boot_time()},
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def ioc_match(indicators: Dict[str, Any], scan_root: Optional[str] = None,
              max_files: int = 2000) -> Dict[str, Any]:
    """Match IOCs against live processes, sockets and (optionally) files."""
    ips = {str(i) for i in (indicators.get("ips") or [])}
    names = {str(n).lower() for n in (indicators.get("names") or [])}
    paths = {str(p) for p in (indicators.get("paths") or [])}
    domains = {str(d).lower() for d in (indicators.get("domains") or [])}
    hashes = {str(h).lower() for h in (indicators.get("hashes") or [])}
    matches: List[Dict[str, Any]] = []

    for entry in procfs.list_processes():
        cmdline = entry.get("cmdline") or ""
        lowered = cmdline.lower()
        exe = entry.get("exe") or ""
        haystacks = {"name": entry["name"], "cmdline": cmdline, "exe": exe}
        for kind, wanted in (("ip", ips), ("name", names), ("path", paths),
                             ("domain", domains)):
            for value in wanted:
                blob = lowered if kind in ("name", "domain") else (
                    haystacks["cmdline"] + " " + exe)
                if value in blob:
                    matches.append({"where": "process", "indicator": value,
                                    "kind": kind, "pid": entry["pid"],
                                    "name": entry["name"], "detail": cmdline[:300]})
    for conn in netfs.connections(with_process=False):
        if conn["remote_addr"] in ips:
            matches.append({"where": "socket", "indicator": conn["remote_addr"],
                            "kind": "ip", "detail":
                                f"{conn['proto']} {conn['local_addr']}:{conn['local_port']}"
                                f" -> {conn['remote_addr']}:{conn['remote_port']}"})
    scanned_files = 0
    if scan_root:
        entries = filefs.scan(scan_root, max_files=max_files, with_hash=bool(hashes))
        for entry in entries:
            scanned_files += 1
            lowered_path = entry["path"].lower()
            for value in names | paths:
                if value.lower() in lowered_path:
                    matches.append({"where": "file", "indicator": value,
                                    "kind": "path", "detail": entry["path"]})
            if entry.get("hash") and entry["hash"].lower() in hashes:
                matches.append({"where": "file", "indicator": entry["hash"],
                                "kind": "hash", "detail": entry["path"]})
    return {
        "matches": matches,
        "indicators": {"ips": len(ips), "names": len(names), "paths": len(paths),
                       "domains": len(domains), "hashes": len(hashes)},
        "scanned": {"processes": len(procfs.list_pids()),
                    "sockets": len(netfs.connections(with_process=False)),
                    "files": scanned_files},
    }
