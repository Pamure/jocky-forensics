"""
/proc based process collection.

Every reader here parses kernel procfs directly.  No external binary is ever
spawned (no ``ps``, ``lsof``, ``ss``): that is what makes JOCKY collection
"living off the land" and what the evidence harness measures — a full triage
runs with zero child processes and zero disk artefacts.

Readers are defensive by design: a process can exit between two reads, so any
``OSError`` yields an empty/None result instead of aborting a scan.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional


def _sysconf(name: str, default: int) -> int:
    """``os.sysconf`` with a fallback.

    Importing this module must not fail on a platform without ``os.sysconf``
    (Windows): the collectors are Linux-only, but the language, encoder and
    agent are portable and import this package.
    """
    try:
        value = os.sysconf(name)
    except (AttributeError, ValueError, OSError):
        return default
    return int(value) if isinstance(value, int) and value > 0 else default


CLOCK_TICKS = _sysconf("SC_CLK_TCK", 100)
PAGE_SIZE = _sysconf("SC_PAGE_SIZE", 4096)

_BOOT_TIME: Optional[float] = None


def uptime_seconds() -> float:
    """Seconds since boot (``/proc/uptime``)."""
    try:
        with open("/proc/uptime") as fh:
            return float(fh.read().split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


def boot_time() -> float:
    """Epoch seconds of the last boot (cached; ``btime`` from /proc/stat)."""
    global _BOOT_TIME
    if _BOOT_TIME is None:
        value = 0.0
        try:
            with open("/proc/stat") as fh:
                for line in fh:
                    if line.startswith("btime "):
                        value = float(line.split()[1])
                        break
        except (OSError, ValueError, IndexError):
            value = 0.0
        _BOOT_TIME = value or (time.time() - uptime_seconds())
    return _BOOT_TIME


def list_pids() -> List[int]:
    """All visible PIDs, ascending."""
    pids: List[int] = []
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.append(int(entry))
    except OSError:
        return []
    pids.sort()
    return pids


def read_stat(pid: int) -> Optional[Dict[str, Any]]:
    """Parse ``/proc/<pid>/stat`` (comm may contain spaces and parentheses)."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            raw = fh.read().decode("utf-8", "replace")
    except OSError:
        return None
    rparen = raw.rfind(")")
    lparen = raw.find("(")
    if lparen < 0 or rparen < lparen:
        return None
    comm = raw[lparen + 1:rparen]
    rest = raw[rparen + 2:].split()
    if len(rest) < 22:
        return None

    def num(idx: int) -> int:
        try:
            return int(rest[idx])
        except (ValueError, IndexError):
            return 0

    start_ticks = num(19)
    return {
        "pid": pid,
        "name": comm,
        "state": rest[0],
        "ppid": num(1),
        "pgrp": num(2),
        "session": num(3),
        "tty": num(4),
        "utime_ticks": num(11),
        "stime_ticks": num(12),
        "threads": num(17),
        "start_ticks": start_ticks,
        "start_epoch": round(boot_time() + start_ticks / CLOCK_TICKS, 3),
        "vsize": num(20),
        "rss_pages": num(21),
        "rss_kb": num(21) * PAGE_SIZE // 1024,
    }


def read_cmdline(pid: int) -> List[str]:
    """Argv of a process (empty for kernel threads)."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read()
    except OSError:
        return []
    parts = raw.split(b"\0")
    return [p.decode("utf-8", "replace") for p in parts if p]


def read_status(pid: int) -> Dict[str, str]:
    """Selected fields from ``/proc/<pid>/status``."""
    wanted = ("Name", "State", "Pid", "PPid", "Uid", "Gid", "Threads",
              "VmRSS", "VmSize", "Seccomp", "NoNewPrivs", "NSpid", "CapEff",
              "CapPrm", "SigIgn", "SigBlk")
    fields: Dict[str, str] = {}
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                key, sep, value = line.partition(":")
                if sep and key in wanted:
                    fields[key] = value.strip()
    except OSError:
        return {}
    return fields


def read_exe(pid: int) -> Optional[str]:
    """Target of ``/proc/<pid>/exe`` (``/memfd:... (deleted)`` for fileless)."""
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None


def read_cwd(pid: int) -> Optional[str]:
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        return None


def read_environ(pid: int) -> List[str]:
    try:
        with open(f"/proc/{pid}/environ", "rb") as fh:
            raw = fh.read()
    except OSError:
        return []
    return [p.decode("utf-8", "replace") for p in raw.split(b"\0") if p]


def read_fds(pid: int, deleted_only: bool = False) -> List[Dict[str, Any]]:
    """Open file descriptors with their symlink targets."""
    results: List[Dict[str, Any]] = []
    fd_dir = f"/proc/{pid}/fd"
    try:
        entries = os.listdir(fd_dir)
    except PermissionError:
        # Typically root-owned processes; fd dir unreadable by current user
        return results
    except FileNotFoundError:
        # Process vanished between list_pids() and fd enumeration
        return results
    except OSError:
        # Any other I/O problem (e.g. EACCES on a FUSE mount)
        return results
    for entry in entries:
        path = f"{fd_dir}/{entry}"
        try:
            target = os.readlink(path)
        except FileNotFoundError:
            # FD closed between listdir and readlink
            continue
        except PermissionError:
            # Restricted fd (e.g. /proc/1/fd/* without CAP_SYS_PTRACE)
            continue
        except OSError:
            # Other I/O failure; skip this fd
            continue
        deleted = target.endswith(" (deleted)")
        if deleted_only and not deleted:
            continue
        item: Dict[str, Any] = {"fd": int(entry) if entry.isdigit() else entry,
                                "target": target, "deleted": deleted}
        if target.startswith("socket:["):
            item["kind"] = "socket"
            item["inode"] = int(target[8:-1])
        elif target.startswith("pipe:["):
            item["kind"] = "pipe"
        elif target.startswith("anon_inode:"):
            item["kind"] = "anon"
        else:
            item["kind"] = "file"
        results.append(item)
    return results


def read_cgroups(pid: int) -> Dict[str, str]:
    """Extract cgroup hierarchies from ``/proc/<pid>/cgroup`` (container detection)."""
    cgroups: Dict[str, str] = {}
    try:
        with open(f"/proc/{pid}/cgroup") as fh:
            for line in fh:
                parts = line.strip().split(":", 2)
                if len(parts) == 3:
                    cgroups[parts[1] or "unified"] = parts[2]
    except OSError:
        pass
    return cgroups


def read_namespaces(pid: int) -> Dict[str, str]:
    """Resolve namespace inode links from ``/proc/<pid>/ns/*``."""
    ns_dir = f"/proc/{pid}/ns"
    namespaces: Dict[str, str] = {}
    try:
        for entry in os.listdir(ns_dir):
            try:
                namespaces[entry] = os.readlink(f"{ns_dir}/{entry}")
            except OSError:
                pass
    except OSError:
        pass
    return namespaces


def read_maps(pid: int) -> List[Dict[str, Any]]:
    """Parsed ``/proc/<pid>/maps`` with forensic flags."""
    out: List[Dict[str, Any]] = []
    try:
        with open(f"/proc/{pid}/maps") as fh:
            lines = fh.readlines()
    except OSError:
        return out
    for line in lines:
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        addr, perms, offset, dev, inode = parts[:5]
        path = parts[5].strip() if len(parts) > 5 else ""
        try:
            start_s, end_s = addr.split("-")
            start, end = int(start_s, 16), int(end_s, 16)
            inode_no = int(inode)
        except ValueError:
            continue
        out.append({
            "start": start,
            "end": end,
            "size_kb": (end - start) // 1024,
            "perms": perms,
            "offset": int(offset, 16) if offset.isalnum() else 0,
            "inode": inode_no,
            "path": path,
            "rwx": perms[:3] == "rwx",
            "memfd": "memfd:" in path,
            "deleted": path.endswith("(deleted)"),
            "anonymous": path == "",
        })
    return out


def read_io(pid: int) -> Dict[str, int]:
    """``/proc/<pid>/io`` counters (empty when permission denied)."""
    fields: Dict[str, int] = {}
    try:
        with open(f"/proc/{pid}/io") as fh:
            for line in fh:
                key, sep, value = line.partition(":")
                if sep:
                    try:
                        fields[key] = int(value.strip())
                    except ValueError:
                        continue
    except OSError:
        return {}
    return fields


def read_threads(pid: int) -> List[int]:
    try:
        return sorted(int(t) for t in os.listdir(f"/proc/{pid}/task") if t.isdigit())
    except OSError:
        return []


def info(pid: int, with_fds: bool = False, with_maps: bool = False,
         with_environ: bool = False, with_io: bool = False) -> Optional[Dict[str, Any]]:
    """Aggregated view of one process (cheap by default)."""
    stat = read_stat(pid)
    if stat is None:
        return None
    cmdline = read_cmdline(pid)
    status = read_status(pid)
    uid = gid = None
    if status.get("Uid"):
        try:
            uid = int(status["Uid"].split()[0])
        except (ValueError, IndexError):
            uid = None
    if status.get("Gid"):
        try:
            gid = int(status["Gid"].split()[0])
        except (ValueError, IndexError):
            gid = None
    entry: Dict[str, Any] = {
        **stat,
        "cmdline": " ".join(cmdline),
        "argv": cmdline,
        "exe": read_exe(pid),
        "cwd": read_cwd(pid),
        "uid": uid,
        "gid": gid,
        "vmrss_kb": _kb(status.get("VmRSS")),
        "vmsize_kb": _kb(status.get("VmSize")),
        # ---- evasion-relevant flags -------------------------------------
        "memfd_exe": bool(read_exe(pid) and "/memfd:" in (read_exe(pid) or "")),
        "nspid": [int(x) for x in status.get("NSpid", "").split() if x.isdigit()],
        "capeff": status.get("CapEff", ""),
    }
    cgroups = read_cgroups(pid)
    entry["cgroup"] = cgroups.get("unified") or next(iter(cgroups.values()), "")
    entry["is_container"] = bool(len(entry["nspid"]) > 1 or any(
        marker in entry["cgroup"] for marker in ("docker", "kubepods", "containerd", "lxc")
    ))
    exe = entry["exe"] or ""
    entry["deleted_exe"] = exe.endswith("(deleted)")
    entry["suspicious_path"] = any(
        exe.startswith(p) for p in ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/")
    )
    if with_fds:
        entry["fds"] = read_fds(pid)
    if with_maps:
        entry["maps"] = read_maps(pid)
    if with_environ:
        entry["environ"] = read_environ(pid)
    if with_io:
        entry["io"] = read_io(pid)
    return entry


def _kb(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(value.split()[0])
    except (ValueError, IndexError):
        return None


def list_processes(limit: Optional[int] = None, detail_limit: Optional[int] = None,
                   **kwargs: Any) -> List[Dict[str, Any]]:
    """Aggregate every visible process; extra kwargs go to :func:`info`.

    ``detail_limit`` applies those kwargs to the first *N* processes only, so a
    caller that wants deep state (fds, maps) for a bounded sample still sees
    every process's cheap fields without paying for a deep read of each one.
    """
    out: List[Dict[str, Any]] = []
    for index, pid in enumerate(list_pids()):
        detailed = detail_limit is None or index < detail_limit
        entry = info(pid, **(kwargs if detailed else {}))
        if entry is not None:
            out.append(entry)
            if limit is not None and len(out) >= limit:
                break
    return out


def process_tree() -> Dict[str, Any]:
    """Parent/child index plus roots and orphan detection."""
    entries = {e["pid"]: e for e in list_processes()}
    children: Dict[int, List[int]] = {}
    for pid, entry in entries.items():
        children.setdefault(entry["ppid"], []).append(pid)
    roots = [pid for pid, entry in entries.items() if entry["ppid"] not in entries]
    return {"processes": entries, "children": children, "roots": sorted(roots)}


def deleted_open_files() -> List[Dict[str, Any]]:
    """Files unlinked from disk but still held open (payload hiding).

    ``memfd:`` targets are excluded: they are anonymous memory objects, not
    deleted disk files, and are covered by the fileless/memfd checks.  Multiple
    descriptors of the same file are collapsed into one finding with a count.
    """
    grouped: Dict[tuple, Dict[str, Any]] = {}
    for pid in list_pids():
        for fd in read_fds(pid, deleted_only=True):
            target = fd["target"]
            if fd.get("kind") != "file" or "/memfd:" in target:
                continue
            key = (pid, target)
            entry = grouped.setdefault(key, {"pid": pid, "path": target,
                                             "fds": [], "count": 0})
            entry["fds"].append(fd["fd"])
            entry["count"] += 1
    return list(grouped.values())


def socket_inode_map() -> Dict[int, Dict[str, Any]]:
    """socket inode -> owning process (built from /proc/*/fd sweeps)."""
    mapping: Dict[int, Dict[str, Any]] = {}
    for pid in list_pids():
        for fd in read_fds(pid):
            if fd.get("kind") == "socket":
                mapping.setdefault(fd["inode"], {
                    "pid": pid,
                    "fd": fd["fd"],
                    "name": (read_stat(pid) or {}).get("name", "?"),
                })
    return mapping
