"""
System inventory from ``/proc`` and ``/sys``: kernel, memory, mounts, modules.

The module cross-check is the interesting one: a kernel module that appears in
``/proc/modules`` but has no ``/sys/module/<name>`` directory (or vice versa)
is a classic sign of a rootkit tampering with one of the two views.
"""
from __future__ import annotations

import os
import platform
import time
from typing import Any, Dict, List, Optional

from jocky.rt import procfs


def kernel() -> Dict[str, Any]:
    uname = platform.uname()
    version_text = ""
    try:
        with open("/proc/version") as fh:
            version_text = fh.read().strip()
    except OSError:
        pass
    return {
        "sysname": uname.system,
        "release": uname.release,
        "version": uname.version,
        "machine": uname.machine,
        "hostname": uname.node,
        "wsl": "microsoft" in version_text.lower(),
        "container": container(),
        "kernel_string": version_text,
    }


def container() -> Dict[str, Any]:
    markers = {"docker": os.path.exists("/.dockerenv"),
               "podman": os.path.exists("/run/.containerenv")}
    cgroup = ""
    try:
        with open("/proc/1/cgroup") as fh:
            cgroup = fh.read().strip()
    except OSError:
        pass
    markers["cgroup_hint"] = cgroup[:200]
    markers["namespaced"] = bool(cgroup and cgroup.strip() not in ("", "0::/"))
    return markers


def distro() -> Dict[str, str]:
    fields: Dict[str, str] = {}
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                key, sep, value = line.partition("=")
                if sep:
                    fields[key.strip()] = value.strip().strip('"')
    except OSError:
        pass
    return fields


def uptime() -> Dict[str, float]:
    return {"seconds": procfs.uptime_seconds(), "boot_time": procfs.boot_time()}


def loadavg() -> List[float]:
    try:
        return [float(x) for x in open("/proc/loadavg").read().split()[:3]]
    except (OSError, ValueError):
        return []


def memory() -> Dict[str, int]:
    wanted = ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached",
              "SwapTotal", "SwapFree", "Dirty", "Writeback")
    out: Dict[str, int] = {}
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                key, sep, value = line.partition(":")
                if sep and key in wanted:
                    try:
                        out[key] = int(value.split()[0]) * 1024
                    except (ValueError, IndexError):
                        continue
    except OSError:
        pass
    return out


def cpu() -> Dict[str, Any]:
    model = None
    count = 0
    try:
        with open("/proc/cpuinfo") as fh:
            for line in fh:
                if line.startswith("model name") and model is None:
                    model = line.partition(":")[2].strip()
                elif line.startswith("processor"):
                    count += 1
    except OSError:
        pass
    return {"model": model, "cpus": count or os.cpu_count()}


def mounts() -> List[Dict[str, Any]]:
    """Mounted filesystems with the flags an analyst cares about."""
    out: List[Dict[str, Any]] = []
    try:
        with open("/proc/mounts") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 4:
                    continue
                device, mountpoint, fstype, options = parts[:4]
                opt_set = set(options.split(","))
                out.append({
                    "device": device,
                    "mountpoint": mountpoint,
                    "fstype": fstype,
                    "options": options,
                    "noexec": "noexec" in opt_set,
                    "nosuid": "nosuid" in opt_set,
                    "nodev": "nodev" in opt_set,
                    "readonly": "ro" in opt_set,
                })
    except OSError:
        return out
    return out


def modules() -> List[Dict[str, Any]]:
    """Loaded kernel modules from ``/proc/modules``."""
    out: List[Dict[str, Any]] = []
    try:
        with open("/proc/modules") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 6:
                    continue
                out.append({
                    "name": parts[0],
                    "size": int(parts[1]) if parts[1].isdigit() else 0,
                    "refcount": int(parts[2]) if parts[2].isdigit() else 0,
                    "dependencies": [d for d in parts[3].split(",") if d],
                    "state": parts[4],
                    "address": parts[5],
                })
    except OSError:
        return out
    return out


def sys_module_names() -> List[str]:
    try:
        return sorted(os.listdir("/sys/module"))
    except OSError:
        return []


def loadable_module_names() -> List[str]:
    """Modules that can actually be loaded/unloaded.

    ``/sys/module`` also lists built-in kernel subsystems, which have no
    ``initstate`` attribute.  Only ``initstate``-bearing entries correspond to
    entries in ``/proc/modules`` — without this filter every built-in (xen,
    workqueue, tpm, ...) would be reported as a hidden module.
    """
    out: List[str] = []
    try:
        for name in os.listdir("/sys/module"):
            if os.path.exists(f"/sys/module/{name}/initstate"):
                out.append(name)
    except OSError:
        return []
    return sorted(out)


def hidden_modules() -> Dict[str, List[str]]:
    """Modules visible in one kernel view but missing from the other.

    Compares ``/proc/modules`` against the *loadable* subset of
    ``/sys/module``; a mismatch means one of the two views was tampered with.
    """
    proc_names = {m["name"].replace("-", "_") for m in modules()}
    sys_names = {n.replace("-", "_") for n in loadable_module_names()}
    return {
        "in_proc_not_sys": sorted(proc_names - sys_names),
        "in_sys_not_proc": sorted(sys_names - proc_names),
    }


def kallsyms_visible() -> bool:
    """True when ``/proc/kallsyms`` exposes real addresses (privileged)."""
    try:
        address = open("/proc/kallsyms").readline().split()[0]
    except (OSError, IndexError):
        return False
    return bool(address) and set(address) != {"0"}


def logged_in_users() -> List[Dict[str, Any]]:
    """Sessions from ``/proc``: tty ownership is enough for a quick view."""
    users: List[Dict[str, Any]] = []
    for pid in procfs.list_pids():
        stat = procfs.read_stat(pid)
        if not stat or not stat.get("tty"):
            continue
        users.append({
            "pid": pid,
            "name": stat["name"],
            "tty": stat.get("tty", 0),
            "uid": (procfs.info(pid) or {}).get("uid"),
            "start_epoch": stat["start_epoch"],
        })
    return users


def env_snapshot(keys: Optional[List[str]] = None) -> Dict[str, str]:
    keys = keys or ["PATH", "HOME", "USER", "SHELL", "LD_PRELOAD", "HOSTNAME"]
    return {k: os.environ[k] for k in keys if k in os.environ}


def info() -> Dict[str, Any]:
    """One-call host inventory used by scripts and the agent."""
    return {
        "kernel": kernel(),
        "distro": distro(),
        "uptime": uptime(),
        "loadavg": loadavg(),
        "memory": memory(),
        "cpu": cpu(),
        "env": env_snapshot(),
        "kallsyms_visible": kallsyms_visible(),
        "collected_at": time.time(),
    }
