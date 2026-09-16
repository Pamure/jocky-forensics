"""BYOVD triage: vulnerable, unsigned, out-of-tree and runtime-loaded modules.

Why this module exists
----------------------
"Bring your own vulnerable driver" is the pillar-3 technique whose Linux form
is a *kernel module* rather than a userland binary: a module the distribution
never shipped is dropped in, or a distribution module carrying a publicly
exploited privilege-escalation flaw is loaded, and the attacker then lives
inside the kernel.  This project's rule is that detection is deliberately the
mirror image of the execution side, so the observation surface is exactly the
same one an operator would need: ``/proc/modules``, ``/proc/sys/kernel/tainted``
and ``/sys/module/<name>/``.

Nothing in this module loads, unloads, writes to, or otherwise touches a
module, its parameters or its backing file.  Every function is a read-only
observation of ``/proc`` and ``/sys``; the tool must never change the state it
is describing.

Checks emitted by :func:`byovd_findings`
----------------------------------------
``byovd_known_vulnerable_module``   loaded module matches a curated list of
                                    drivers/modules exploited in published
                                    research — ``critical``/``high`` for a
                                    third-party driver, ``info`` for a module
                                    that ships with the distribution kernel
``byovd_out_of_tree_module``        module taint ``O`` — not shipped by the
                                    distribution kernel (medium)
``byovd_unsigned_module``           module taint ``E`` — no usable signature
                                    (high)
``byovd_forced_module``             module taint ``F`` — force loaded, which
                                    bypasses version/vermagic checks (high)
``byovd_late_loaded_module``        module stamped materially after boot, i.e.
                                    loaded at runtime (info — correlation input,
                                    like ``rwx_memory``)
``byovd_deleted_module_file``       module stays loaded while its ``.ko`` is
                                    gone from ``/lib/modules`` (high)
``byovd_deleted_driver_file``       the same question on Windows: a resident
                                    driver whose image file is not on disk (high)
``byovd_kernel_taint``              global taint bits 12/13 set (medium)
``partial_visibility``              reused from :mod:`jocky.rt.detect`: part of
                                    the module view could not be read, or the
                                    platform has no such concept, so a clean
                                    result is not conclusive (info)

Platform scope: the module list comes from the platform backend — ``/proc/modules``
plus ``/sys/module`` on Linux, the kernel's ``SystemModuleInformation`` driver
list through :mod:`jocky.rt.winapi` on Windows.  The taint-derived checks
(out-of-tree, unsigned, forced) and the load-time check exist only where the
kernel exposes per-module taint data, i.e. Linux; elsewhere they are reported as
*not applicable* rather than as clean, because "no unsigned drivers" and "this
platform has no such notion" must never look the same in a report.

Check metadata (source, summary, remediation) is not repeated here: it lives in
:data:`jocky.rt.detect.CHECK_CATALOG`, the single source of truth the test suite
asserts against real triage output and the documentation generator reads.

Design notes
------------
* ``/sys`` is frequently root-only (``taint``, ``sections/.text``).  An
  unprivileged analyst must still get a usable answer, so every attribute read
  returns ``(value, error)`` and the failure is *reported* in the result (per
  entry, or as a ``partial_visibility`` finding) instead of raising or being
  dropped.  A permission denial is a finding about the collection, not an
  exception.
* Kernel module names are normalised inconsistently: ``/proc/modules`` and
  ``modules.dep`` use underscores, ``modprobe`` accepts dashes, and users type
  either.  Every lookup here tries both spellings — getting that wrong is the
  single largest source of false "deleted module file" positives.
* The load time of a module is the mtime of ``/sys/module/<name>``: kernfs
  stamps that directory when the module is inserted (verified: boot-loaded
  modules land 2-7 s after ``btime``).  Individual attributes are weaker
  evidence because an attribute inode can be instantiated on first lookup, so
  ``coresize`` is only consulted when the directory cannot be stat'd.
"""
from __future__ import annotations

import errno
import os
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from jocky.rt import procfs

PROC_MODULES = "/proc/modules"
SYS_MODULE_ROOT = "/sys/module"
KERNEL_TAINTED = "/proc/sys/kernel/tainted"
MODULES_ROOT = "/lib/modules"

#: A module stamped within this window of ``btime`` is part of the boot
#: sequence: initramfs hand-off, udev coldplug and the module auto-loader can
#: all lag ``btime`` by up to about a minute.  Anything materially later was
#: loaded by something running on the host.
LATE_LOAD_GRACE_SECONDS = 120.0

#: Upper bound for the fallback walk of ``/lib/modules/<release>``.  A tree
#: with more entries than this is not indexed by walks at all, because a
#: truncated index would produce false "the .ko is deleted" conclusions.
MODULE_WALK_LIMIT = 20000

#: Compression suffixes a module file may carry, longest first.
_KO_SUFFIXES = (".ko.zst", ".ko.xz", ".ko.gz", ".ko")

#: ``/proc/sys/kernel/tainted`` bit meanings.  This is a stable kernel ABI
#: (``Documentation/admin-guide/tainted-kernels.rst``) and the letters are the
#: ones the kernel prints in oops headers, so the decoding can be quoted in a
#: report verbatim.  Bits 12 (out-of-tree, ``O``) and 13 (unsigned, ``E``) are
#: the ones that matter for BYOVD triage: they are the kernel's own admission
#: that code it cannot vouch for is running.
TAINT_BITS: Tuple[Tuple[int, str, str], ...] = (
    (0, "P", "proprietary module was loaded"),
    (1, "F", "module was force loaded"),
    (2, "S", "kernel running on an out-of-specification CPU/system"),
    (3, "R", "module was force unloaded"),
    (4, "M", "processor reported a machine check exception"),
    (5, "B", "bad page referenced or unexpected page flags"),
    (6, "U", "taint requested by a userspace application"),
    (7, "D", "kernel died recently (oops or panic)"),
    (8, "A", "an ACPI table was overridden by the user"),
    (9, "W", "kernel issued a warning"),
    (10, "C", "staging driver was loaded"),
    (11, "I", "workaround for a bug in platform firmware applied"),
    (12, "O", "out-of-tree module was loaded"),
    (13, "E", "unsigned module was loaded"),
    (14, "L", "soft lockup occurred"),
    (15, "K", "kernel has been live patched"),
    (16, "X", "auxiliary taint (distribution defined)"),
    (17, "T", "kernel was built with the struct randomization plugin"),
    (18, "N", "an in-kernel test has been run"),
)

TAINT_BIT_OUT_OF_TREE = 12
TAINT_BIT_UNSIGNED = 13

#: Per-module taint letters from ``/sys/module/<name>/taint``.  The attribute
#: reports the flags *this* module contributed, which is what makes per-module
#: attribution possible at all.
MODULE_TAINT_MEANINGS: Dict[str, str] = {
    "P": "proprietary module (no source available for review)",
    "O": "out-of-tree module (not shipped by the distribution kernel)",
    "F": "module was force loaded (version/vermagic checks bypassed)",
    "E": "module is unsigned",
    "R": "module was force unloaded",
    "C": "staging driver",
    "S": "kernel running on an out-of-specification CPU/system",
    "I": "workaround for a platform firmware bug",
    "X": "auxiliary (distribution defined) taint",
}

#: The checks this module emits.  Their documentation lives in
#: :data:`jocky.rt.detect.CHECK_CATALOG` — the project's single source of truth
#: for check metadata, asserted against real triage output by the test suite and
#: used by the documentation generator — so no second copy is kept here: two
#: catalogs are two things to drift.
EMITTED_CHECKS: Tuple[str, ...] = (
    "byovd_known_vulnerable_module",
    "byovd_out_of_tree_module",
    "byovd_unsigned_module",
    "byovd_forced_module",
    "byovd_late_loaded_module",
    "byovd_deleted_module_file",
    "byovd_deleted_driver_file",
    "byovd_kernel_taint",
    "partial_visibility",
)


# --------------------------------------------------------------------- known
#: Drivers and kernel modules with a *published*, exploited-in-the-wild
#: vulnerability.  Accuracy beats length: every entry below was checked against
#: the CVE record (and, for the Linux entries, against the CISA Known Exploited
#: Vulnerabilities catalog), and entries whose only evidence is "a scanner
#: flagged it" were deliberately left out.
#:
#: ``scope`` matters for grading.  ``third_party`` entries are the classic BYOVD
#: shape: a signed driver the attacker brings with them, so a match keeps the
#: entry's ``severity`` (``critical``, or ``high`` where the primitive is
#: narrower) and is reported as hostile.  ``in_tree`` entries are modules shipped
#: by the distribution kernel — loading ``overlay`` or ``nf_tables`` is normal,
#: so a match is "a module with a publicly exploited flaw is present", a
#: patching question answered by correlating the running kernel build with the
#: vendor fix; :func:`byovd_findings` reports those at ``info`` and carries the
#: entry's ``severity`` in the evidence rather than acting on it.  The field is
#: the entry's own grading, which the Windows collector reusing this table also
#: relies on.
KNOWN_VULNERABLE: Tuple[Dict[str, Any], ...] = (
    # ----------------------------------------------------------- linux (in-tree)
    {
        "name": "nf_tables",
        "aliases": (),
        "cve": "CVE-2024-1086",
        "why": ("use-after-free/double-free in nft_verdict_init(); exploited in "
                "the wild through unprivileged user namespaces for local root, "
                "including in ransomware campaigns"),
        "severity": "high",
        "platform": "linux",
        "scope": "in_tree",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2024-1086",
    },
    {
        "name": "nf_tables",
        "aliases": ("nftables",),
        "cve": "CVE-2022-2586",
        "why": ("use-after-free in nft_object batch processing giving arbitrary "
                "kernel read/write to a local attacker"),
        "severity": "high",
        "platform": "linux",
        "scope": "in_tree",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2022-2586",
    },
    {
        "name": "x_tables",
        "aliases": ("ip_tables", "iptables"),
        "cve": "CVE-2021-22555",
        "why": ("heap out-of-bounds write in the netfilter 32-bit compat path "
                "(xt_compat_target_from_user); publicly exploited for container "
                "escape and local root"),
        "severity": "high",
        "platform": "linux",
        "scope": "in_tree",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2021-22555",
    },
    {
        "name": "overlay",
        "aliases": ("overlayfs",),
        "cve": "CVE-2023-0386",
        "why": ("OverlayFS ownership/UID-mapping flaw that lets a setuid-capable "
                "file be copied out of a nosuid mount; exploited in the wild"),
        "severity": "high",
        "platform": "linux",
        "scope": "in_tree",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2023-0386",
    },
    {
        "name": "overlay",
        "aliases": ("overlayfs",),
        "cve": "CVE-2021-3493",
        "why": ("OverlayFS does not validate file capabilities against user "
                "namespaces on Ubuntu kernels, yielding local root"),
        "severity": "high",
        "platform": "linux",
        "scope": "in_tree",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2021-3493",
    },
    {
        "name": "af_packet",
        "aliases": ("packet",),
        "cve": "CVE-2021-22600",
        "why": ("AF_PACKET socket option handling frees memory incorrectly; local "
                "denial of service and possible privilege escalation"),
        "severity": "medium",
        "platform": "linux",
        "scope": "in_tree",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2021-22600",
    },
    {
        "name": "rds",
        "aliases": (),
        "cve": "CVE-2010-3904",
        "why": ("Reliable Datagram Sockets sendmsg() input validation flaw — the "
                "classic local-root primitive delivered by a loadable module; the "
                "module is normally not required on a server"),
        "severity": "medium",
        "platform": "linux",
        "scope": "in_tree",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2010-3904",
    },
    {
        "name": "snd",
        "aliases": ("snd_ctl",),
        "cve": "CVE-2023-0266",
        "why": ("ALSA control-interface use-after-free giving ring0 access; "
                "exploited in the wild as part of commercial spyware chains"),
        "severity": "high",
        "platform": "linux",
        "scope": "in_tree",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2023-0266",
    },
    {
        "name": "uvcvideo",
        "aliases": ("uvc",),
        "cve": "CVE-2024-53104",
        "why": ("USB Video Class driver out-of-bounds write in uvc_parse_streaming; "
                "exploited in the wild, requires attaching a malicious USB device"),
        "severity": "medium",
        "platform": "linux",
        "scope": "in_tree",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2024-53104",
    },
    {
        "name": "snd_usb_audio",
        "aliases": (),
        "cve": "CVE-2024-53197",
        "why": ("USB-audio driver out-of-bounds access exploitable by a malicious "
                "USB device; exploited in the wild"),
        "severity": "medium",
        "platform": "linux",
        "scope": "in_tree",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2024-53197",
    },
    {
        "name": "binder",
        "aliases": ("binder_linux",),
        "cve": "CVE-2019-2215",
        "why": ("Android Binder use-after-free giving kernel privilege from an "
                "application; exploited in the wild by commercial spyware"),
        "severity": "high",
        "platform": "linux",
        "scope": "in_tree",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2019-2215",
    },
    # ------------------------------------------------- windows (third-party)
    # Kept here, in one table with a ``platform`` key, so the Windows collector
    # reuses the same data instead of maintaining a second list.
    {
        "name": "RTCore64.sys",
        "aliases": ("RTCore32.sys", "rtcore64"),
        "cve": "CVE-2019-16098",
        "why": ("MSI Afterburner driver allowing any authenticated user to read and "
                "write arbitrary memory, I/O ports and MSRs; abused by BlackByte "
                "ransomware and by most EDR-killer tooling"),
        "severity": "critical",
        "platform": "windows",
        "scope": "third_party",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2019-16098",
    },
    {
        "name": "gdrv.sys",
        "aliases": ("gdrv", "GDrv.sys"),
        "cve": "CVE-2018-19320",
        "why": ("GIGABYTE App Center/OC GURU ring0 memcpy-like primitive "
                "(CVE-2018-19321/19322/19323 as well); used by RobbinHood ransomware"),
        "severity": "critical",
        "platform": "windows",
        "scope": "third_party",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2018-19320",
    },
    {
        "name": "dbutil_2_3.sys",
        "aliases": ("DBUtilDrv2.sys", "dbutil"),
        "cve": "CVE-2021-21551",
        "why": ("Dell BIOS utility driver with insufficient access control giving "
                "kernel memory read/write; one of the most widely abused BYOVD "
                "drivers"),
        "severity": "critical",
        "platform": "windows",
        "scope": "third_party",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2021-21551",
    },
    {
        "name": "iqvw64e.sys",
        "aliases": ("iQVW64.SYS", "IQVW32.sys", "NalDrv.sys"),
        "cve": "CVE-2015-2291",
        "why": ("Intel Ethernet diagnostics driver with kernel-privileged IOCTLs; "
                "used by the Slingshot APT and in Scattered Spider BYOVD tooling"),
        "severity": "critical",
        "platform": "windows",
        "scope": "third_party",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2015-2291",
    },
    {
        "name": "WinRing0x64.sys",
        "aliases": ("WinRing0.sys", "OpenHardwareMonitorLib.sys"),
        "cve": "CVE-2020-14979",
        "why": ("OpenLibSys hardware-access driver: any user can map \\Device"
                "\\PhysicalMemory and read/write MSRs, then load unsigned drivers"),
        "severity": "critical",
        "platform": "windows",
        "scope": "third_party",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2020-14979",
    },
    {
        "name": "mhyprot2.sys",
        "aliases": ("mhyprot.sys", "mhyprot3.sys"),
        "cve": "CVE-2020-36603",
        "why": ("Genshin Impact anti-cheat driver that does not restrict unprivileged "
                "calls; weaponised by ransomware operators to terminate AV/EDR "
                "processes before encryption"),
        "severity": "critical",
        "platform": "windows",
        "scope": "third_party",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2020-36603",
    },
    {
        "name": "speedfan.sys",
        "aliases": ("speedfan",),
        "cve": "CVE-2007-5633",
        "why": ("MSR read/write IOCTLs on \\Device\\speedfan, which also allow "
                "unsigned drivers to be loaded; a long-standing BYOVD primitive"),
        "severity": "high",
        "platform": "windows",
        "scope": "third_party",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2007-5633",
    },
    {
        "name": "ATSZIO64.sys",
        "aliases": ("ATSZIO.sys",),
        "cve": "CVE-2024-33222",
        "why": ("ASUS ATSZIO driver exposes MSR access through crafted IOCTLs, "
                "allowing privilege escalation and kernel code execution"),
        "severity": "high",
        "platform": "windows",
        "scope": "third_party",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2024-33222",
    },
    {
        "name": "ene.sys",
        "aliases": ("ENE.sys",),
        "cve": None,
        "why": ("ENE Technology hardware-access driver with unrestricted physical "
                "memory/IOCTL access; on Microsoft's vulnerable driver blocklist "
                "and named by EDR-killer tooling, though no CVE is assigned"),
        "severity": "medium",
        "platform": "windows",
        "scope": "third_party",
        "reference": "https://learn.microsoft.com/en-us/windows/security/application-security/"
                    "application-control/windows-defender-application-control/"
                    "microsoft-recommended-driver-block-rules",
    },
)


# ----------------------------------------------------------------- utilities
def _detect() -> Any:
    """Return :mod:`jocky.rt.detect` imported on demand.

    Why not a module-level import: ``detect`` is the module that will aggregate
    these findings, so it imports this one.  Importing it here at import time
    would be circular; doing it on first use cannot be, because by then the
    caller's module object already exists.
    """
    from jocky.rt import detect

    return detect


def _finding(check: str, severity: str, title: str, evidence: Dict[str, Any],
             recommendation: str = "") -> Dict[str, Any]:
    """Build a finding through :func:`jocky.rt.detect._finding`.

    Going through the shared helper rather than rebuilding the dict keeps the
    evidence shape identical to every other check in the tool.
    """
    return _detect()._finding(check, severity, title, evidence, recommendation)


def _worst_severity(severities: Iterable[str]) -> str:
    """Highest severity in ``severities`` (``info`` if the input is empty)."""
    order = _detect().SEVERITY_ORDER
    return max(severities, key=lambda s: order.get(s, 0), default="info")


def _error_name(exc: OSError) -> str:
    """``"EACCES: Permission denied"`` — small, quotable, no traceback."""
    code = errno.errorcode.get(exc.errno, exc.errno)
    return f"{code}: {exc.strerror}" if exc.strerror else f"{code}"


def _read_attr(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Read one sysfs/procfs attribute.

    Returns ``(value, error)``.  ``error`` is ``None`` on success and a short
    ``"EACCES: Permission denied"``-style string otherwise: the caller decides
    whether an unreadable attribute is a finding, but it is never raised (an
    unprivileged analyst must still get a report) and never silently dropped.
    """
    try:
        with open(path, "r", errors="replace") as handle:
            return handle.read().strip(), None
    except OSError as exc:
        return None, _error_name(exc)


def _list_dir(path: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """List a directory as ``(sorted_entries, error)``; same contract as above."""
    try:
        return sorted(os.listdir(path)), None
    except OSError as exc:
        return None, _error_name(exc)


def _stat(path: str) -> Tuple[Optional[float], Optional[str]]:
    """``(mtime, error)`` for ``path``."""
    try:
        return os.stat(path).st_mtime, None
    except OSError as exc:
        return None, _error_name(exc)


def _absent(error: Optional[str]) -> bool:
    """True when an error only means the attribute does not exist.

    Plenty of sysfs attributes are optional (``srcversion`` is missing on many
    modules), so an ``ENOENT`` is normal absence, not a coverage gap.  Keeping it
    out of ``read_errors`` is what makes the list actionable: everything left in
    it is a real failure — almost always ``EACCES`` for an unprivileged analyst.
    """
    return bool(error) and error.startswith("ENOENT")


def _note(errors: List[str], path: str, error: Optional[str]) -> None:
    """Record ``path``'s read failure unless the attribute is simply not there."""
    if error and not _absent(error):
        errors.append(f"{path}: {error}")


def _name_spellings(name: str) -> Tuple[str, ...]:
    """Both spellings of a module name, dashes first-free.

    ``/proc/modules`` and ``modules.dep`` normalise dashes to underscores while
    ``modprobe``/``insmod`` accept either; a lookup that only tries one spelling
    reports ordinary modules as missing.
    """
    dashed = name.replace("_", "-")
    return (name,) if dashed == name else (name, dashed)


def _kernel_release() -> Optional[str]:
    """The running kernel's release, or ``None`` on a platform without one.

    ``os.uname`` is Unix-only, and BYOVD is not: on Windows there is no
    ``/lib/modules/<release>`` and therefore no on-disk module tree to compare
    against.  Callers must treat ``None`` as "this platform has no such notion"
    and say so, never as an empty release name.
    """
    uname = getattr(os, "uname", None)
    if uname is None:
        return None
    try:
        return uname().release or None
    except OSError:
        return None


def _disk_index_label() -> str:
    """Cache key and evidence label for the module-tree index of this host."""
    return _kernel_release() or f"platform:{sys.platform}"


def _win_backend() -> Any:
    """``jocky.rt.winapi`` when this host is Windows and it is usable, else ``None``.

    Imported lazily because the module is large and only meaningful on Windows,
    and because a Linux collector must never need it.  ``available()`` is itself
    cached and reports whether the Windows DLL bindings loaded, so a Windows
    host missing a library degrades to a reported gap rather than an exception.
    """
    if sys.platform != "win32":
        return None
    from jocky.rt import winapi

    return winapi if winapi.available() else None


def _sysfs_module_view() -> bool:
    """True when this platform exposes per-module taint and load timestamps.

    Only Linux does (``/sys/module/<name>`` plus ``/proc/sys/kernel/tainted``),
    so the platform check comes first: on Windows those mechanics do not exist
    and a path that happens to be present must not be allowed to pretend
    otherwise.  The checks built on those sources are not "clean" elsewhere,
    they are *undefined*: Windows has no per-driver taint flag, and reporting no
    out-of-tree drivers while the concept does not exist would be the
    blind-scan failure this project treats as a defect.  The aggregate says so
    instead.
    """
    if sys.platform == "win32":
        return False
    return os.path.isdir(SYS_MODULE_ROOT) and os.path.exists(KERNEL_TAINTED)


# ------------------------------------------------------------ module view
def _proc_modules_rows() -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Parse ``/proc/modules`` into raw rows plus a read error, if any.

    Field order is ``name size refcount deps state address``.  ``deps`` is ``-``
    when the module has none.
    """
    rows: List[Dict[str, Any]] = []
    try:
        with open(PROC_MODULES, "r", errors="replace") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) < 6:
                    continue
                rows.append({
                    "name": parts[0],
                    "size": int(parts[1]) if parts[1].isdigit() else 0,
                    "refcount": int(parts[2]) if parts[2].isdigit() else 0,
                    "dependencies": [d for d in parts[3].split(",") if d and d != "-"],
                    "state": parts[4],
                    "address": parts[5],
                })
    except OSError as exc:
        return rows, f"{PROC_MODULES}: {_error_name(exc)}"
    return rows, None


def _module_sysfs_dir(name: str) -> Optional[str]:
    """``/sys/module/<name>`` for either spelling, or ``None`` if absent."""
    for spelling in _name_spellings(name):
        path = os.path.join(SYS_MODULE_ROOT, spelling)
        if os.path.isdir(path):
            return path
    return None


def _adapt_windows_rows(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Give Windows driver rows the same record shape as the Linux view.

    ``jocky.rt.winapi.modules()`` already supplies the ``/proc/modules`` fields
    (``name``, ``size``, ``refcount``, ``dependencies``, ``state``, ``address``)
    plus ``path``, ``base``, ``load_order`` and ``file_exists``.  The
    sysfs-derived keys are added as ``None``/empty on purpose: Windows has no
    per-driver taint flag and no module directory, so they must read as "not
    determined" — the aggregate then reports the platform limitation instead of
    letting the missing data look like a clean result.
    """
    out: List[Dict[str, Any]] = []
    for row in rows:
        entry = dict(row)
        entry.update({
            "sysfs_present": False,
            "sysfs_path": None,
            "initstate": None,
            "coresize": None,
            "srcversion": None,
            "holders": [],
            "has_executable_code": None,
            "taint": None,
            "taint_available": False,
            "taint_flags": [],
            "proprietary": None,
            "out_of_tree": None,
            "unsigned": None,
            "forced": None,
            "load_mtime": None,
            "load_mtime_source": None,
            "read_errors": [],
        })
        out.append(entry)
    return out


def _loaded_module_view() -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Loaded modules in one record shape, taken from the platform backend.

    Linux reads ``/proc/modules`` and enriches it from ``/sys/module``; Windows
    asks the kernel through ``jocky.rt.winapi`` (``SystemModuleInformation``,
    the only driver inventory that answers a non-elevated caller truthfully).
    Returns ``(records, error)``; a backend that is present but failed yields an
    error string so :func:`byovd_findings` reports a gap instead of an empty,
    innocent-looking host.
    """
    backend = _win_backend()
    if backend is not None:
        rows = backend.modules()
        if not rows:
            return [], "winapi.modules(): the kernel reported no loaded drivers"
        return _adapt_windows_rows(rows), None
    if sys.platform == "win32":
        return [], ("winapi unavailable (Windows DLL bindings did not load); the "
                    "driver list could not be read")
    rows, error = _proc_modules_rows()
    return _enrich(rows), error


def _module_flags(sysfs_dir: Optional[str]) -> Tuple[Dict[str, Any], List[str]]:
    """Enrich one module from ``/sys/module/<name>/``.

    Returns ``(attributes, read_errors)``.  ``attributes`` carries the decoded
    taint flags plus the raw attributes an analyst pivots on; ``read_errors``
    lists ``"<path>: <errno>"`` strings for attributes that exist but could not
    be read (typically ``EACCES`` for an unprivileged analyst).  Attributes the
    kernel does not provide at all are not errors, so they stay out of the list.
    """
    attrs: Dict[str, Any] = {
        "coresize": None,
        "initstate": None,
        "srcversion": None,
        "holders": [],
        "has_executable_code": None,
        "taint": None,
        "taint_flags": [],
        "taint_available": False,
        "proprietary": None,
        "out_of_tree": None,
        "unsigned": None,
        "forced": None,
    }
    errors: List[str] = []
    if sysfs_dir is None:
        return attrs, errors

    coresize_path = os.path.join(sysfs_dir, "coresize")
    coresize, coresize_error = _read_attr(coresize_path)
    _note(errors, coresize_path, coresize_error)
    if coresize_error is None and coresize is not None and coresize.isdigit():
        attrs["coresize"] = int(coresize)

    for key, attribute in (("initstate", "initstate"), ("srcversion", "srcversion")):
        attribute_path = os.path.join(sysfs_dir, attribute)
        value, error = _read_attr(attribute_path)
        _note(errors, attribute_path, error)
        if error is None and value:
            attrs[key] = value

    holders_path = os.path.join(sysfs_dir, "holders")
    holders, holders_error = _list_dir(holders_path)
    _note(errors, holders_path, holders_error)
    if holders_error is None:
        attrs["holders"] = holders or []

    # Presence of .text means the module mapped executable code; the files
    # themselves are root-only on most kernels, so the directory listing is the
    # best an unprivileged analyst can do, and its failure is reported rather
    # than silently recorded as "no executable code".
    sections_path = os.path.join(sysfs_dir, "sections")
    sections, sections_error = _list_dir(sections_path)
    _note(errors, sections_path, sections_error)
    if sections_error is None:
        attrs["has_executable_code"] = any(s.startswith(".text") for s in sections)

    taint_path = os.path.join(sysfs_dir, "taint")
    taint, taint_error = _read_attr(taint_path)
    _note(errors, taint_path, taint_error)
    if taint_error is None:
        attrs["taint_available"] = True
        attrs["taint"] = taint or ""
        flags = sorted({c for c in attrs["taint"] if c in MODULE_TAINT_MEANINGS})
        attrs["taint_flags"] = flags
        attrs["proprietary"] = "P" in flags
        attrs["out_of_tree"] = "O" in flags
        attrs["unsigned"] = "E" in flags
        attrs["forced"] = "F" in flags
    return attrs, errors


def _load_time(sysfs_dir: str) -> Tuple[Optional[float], Optional[str], Optional[str]]:
    """``(mtime, source, error)`` for a module's load time.

    The module directory is the authoritative stamp; ``coresize`` is only a
    fallback for kernels/filesystems where the directory cannot be stat'd,
    because a single attribute inode may be instantiated on first lookup and
    therefore drift later than the load.
    """
    mtime, error = _stat(sysfs_dir)
    if mtime is not None:
        return mtime, "sysfs_dir", None
    fallback, fallback_error = _stat(os.path.join(sysfs_dir, "coresize"))
    if fallback is not None:
        return fallback, "coresize", None
    return None, None, error or fallback_error


def _enrich(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Turn parsed ``/proc/modules`` rows into full module records."""
    out: List[Dict[str, Any]] = []
    for row in rows:
        sysfs_dir = _module_sysfs_dir(row["name"])
        attrs, errors = _module_flags(sysfs_dir)
        mtime, mtime_source, mtime_error = (None, None, None)
        if sysfs_dir is not None:
            mtime, mtime_source, mtime_error = _load_time(sysfs_dir)
            if mtime_error:
                errors.append(f"{sysfs_dir}: {mtime_error}")
        entry: Dict[str, Any] = dict(row)
        entry.update({
            "sysfs_present": sysfs_dir is not None,
            "sysfs_path": sysfs_dir,
            "initstate": attrs["initstate"],
            "coresize": attrs["coresize"],
            "srcversion": attrs["srcversion"],
            "holders": attrs["holders"],
            "has_executable_code": attrs["has_executable_code"],
            "taint": attrs["taint"],
            "taint_available": attrs["taint_available"],
            "taint_flags": attrs["taint_flags"],
            "proprietary": attrs["proprietary"],
            "out_of_tree": attrs["out_of_tree"],
            "unsigned": attrs["unsigned"],
            "forced": attrs["forced"],
            "load_mtime": mtime,
            "load_mtime_source": mtime_source,
            "read_errors": errors,
        })
        out.append(entry)
    return out


def loaded_modules() -> List[Dict[str, Any]]:
    """Every module the platform reports loaded, in one record shape.

    Every record carries the module-list fields (``name``, ``size``,
    ``refcount``, ``dependencies``, ``state``, ``address``) plus:

    ``sysfs_present`` / ``sysfs_path``
        Whether a ``/sys/module/<name>`` entry exists (Linux).  A module the
        kernel lists as loaded but that has no sysfs entry is the hidden-module
        case worth surfacing, so it is recorded rather than raised.
    ``initstate``, ``coresize``, ``srcversion``, ``holders``,
    ``has_executable_code``
        Raw sysfs attributes; ``has_executable_code`` is ``None`` when
        ``sections`` could not be listed (it is root-only on some kernels).
    ``taint``, ``taint_flags``, ``taint_available``
        The module's own taint string and the decoded letters.
        ``taint_flags`` is empty and the classification booleans below are
        ``None`` when the attribute is unreadable or not provided by the kernel.
    ``proprietary`` / ``out_of_tree`` / ``unsigned`` / ``forced``
        Convenience booleans for the taint letters ``P``/``O``/``E``/``F``.
    ``load_mtime`` / ``load_mtime_source``
        When the module was inserted (``sysfs_dir`` or the ``coresize``
        fallback) and which source answered.
    ``read_errors``
        ``"<path>: <errno>"`` for every attribute that exists but could not be
        read — a permission denial is visible, not fatal.

    On Windows the rows come from :func:`jocky.rt.winapi.modules` (kernel
    drivers via ``SystemModuleInformation``) and keep its ``path``, ``base``,
    ``load_order`` and ``file_exists`` keys; the sysfs-derived keys above are
    then ``None``/empty, because the platform has no equivalent and inventing
    one would make "no unsigned drivers" indistinguishable from "no such
    concept here".

    Returns an empty list when the module view cannot be read at all (the
    reason is then reported by :func:`byovd_findings` as a coverage finding).
    """
    records, _error = _loaded_module_view()
    return records


# ------------------------------------------------------------------- taint
def taint_state() -> Dict[str, Any]:
    """Decode ``/proc/sys/kernel/tainted`` into named bits.

    The value is a bitmask: the kernel sets a bit the moment it accepts
    something it cannot vouch for, and the mask is sticky until reboot, which
    makes it the cheapest host-wide integrity signal available.  Returns::

        {"value": int | None, "flags": ["O", "E", ...],
         "bits": [{"bit": 12, "flag": "O", "meaning": "..."}],
         "unknown_bits": [int], "proprietary": bool, "forced": bool,
         "out_of_tree": bool, "unsigned": bool, "source": str, "errors": [...]}

    ``value``/``out_of_tree``/``unsigned`` are ``None`` when the file cannot be
    read or parsed, and ``errors`` explains why.
    """
    raw, error = _read_attr(KERNEL_TAINTED)
    state: Dict[str, Any] = {
        "value": None,
        "flags": [],
        "bits": [],
        "unknown_bits": [],
        "proprietary": None,
        "forced": None,
        "out_of_tree": None,
        "unsigned": None,
        "source": KERNEL_TAINTED,
        "errors": [],
    }
    if error:
        state["errors"].append(f"{KERNEL_TAINTED}: {error}")
        return state
    try:
        value = int(raw or "", 0)
    except ValueError:
        state["errors"].append(f"{KERNEL_TAINTED}: unparsable value {raw!r}")
        return state

    known = {bit for bit, _flag, _meaning in TAINT_BITS}
    state.update({
        "value": value,
        "bits": [{"bit": bit, "flag": flag, "meaning": meaning}
                 for bit, flag, meaning in TAINT_BITS if value >> bit & 1],
        "flags": [flag for bit, flag, _meaning in TAINT_BITS if value >> bit & 1],
        "unknown_bits": [bit for bit in range(value.bit_length())
                         if bit not in known and value >> bit & 1],
        "proprietary": bool(value >> 0 & 1),
        "forced": bool(value >> 1 & 1),
        "out_of_tree": bool(value >> TAINT_BIT_OUT_OF_TREE & 1),
        "unsigned": bool(value >> TAINT_BIT_UNSIGNED & 1),
    })
    return state


# ------------------------------------------------- taint-derived module sets
def _taint_errors(module: Dict[str, Any]) -> List[str]:
    """Read failures recorded for a module's ``taint`` attribute.

    Used to turn "we could not read the flag" into an explicit entry instead of
    an absent one: an unreadable attribute must not look like a clean module.
    """
    return [error for error in (module.get("read_errors") or []) if "/taint:" in error]


def _unsigned_of(modules: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Modules with taint ``E`` (unsigned), plus the ones we could not decide."""
    out: List[Dict[str, Any]] = []
    for module in modules:
        if module.get("unsigned"):
            out.append({
                "module": module["name"],
                "unsigned": True,
                "taint": module.get("taint") or "",
                "taint_flags": module.get("taint_flags") or [],
                "source": f"{module.get('sysfs_path')}/taint",
                "error": None,
            })
        elif module.get("unsigned") is None and module.get("taint_available") is False:
            for error in _taint_errors(module):
                out.append({
                    "module": module["name"],
                    "unsigned": None,
                    "taint": None,
                    "taint_flags": [],
                    "source": error.split(":", 1)[0],
                    "error": error,
                })
    return out


def unsigned_modules() -> List[Dict[str, Any]]:
    """Modules whose signature could not be established (taint ``E``).

    One entry per module::

        {"module", "unsigned": True | None, "taint", "taint_flags",
         "source", "error"}

    ``unsigned`` is ``True`` for a confirmed match and ``None`` when the module
    level taint attribute exists but could not be read (``error`` carries the
    ``errno``).  Kernels that do not provide ``/sys/module/<name>/taint`` at all
    are not listed here — the global :func:`taint_state` bit 13 still reports
    that *some* unsigned module is loaded, and :func:`byovd_findings` raises a
    coverage finding saying attribution was impossible.
    """
    return _unsigned_of(loaded_modules())


def _out_of_tree_of(modules: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Modules with taint ``O`` (not shipped by the running kernel)."""
    out: List[Dict[str, Any]] = []
    for module in modules:
        if module.get("out_of_tree"):
            out.append({
                "module": module["name"],
                "out_of_tree": True,
                "taint": module.get("taint") or "",
                "taint_flags": module.get("taint_flags") or [],
                "coresize": module.get("coresize"),
                "source": f"{module.get('sysfs_path')}/taint",
                "error": None,
            })
        elif module.get("out_of_tree") is None and module.get("taint_available") is False:
            for error in _taint_errors(module):
                out.append({
                    "module": module["name"],
                    "out_of_tree": None,
                    "taint": None,
                    "taint_flags": [],
                    "coresize": module.get("coresize"),
                    "source": error.split(":", 1)[0],
                    "error": error,
                })
    return out


def out_of_tree_modules() -> List[Dict[str, Any]]:
    """Modules the kernel does not consider part of itself (taint ``O``).

    Same shape as :func:`unsigned_modules`, with ``out_of_tree`` instead of
    ``unsigned`` and the module's ``coresize`` included as a pivot.  Legitimate
    sources exist (dkms, NVIDIA, VirtualBox, storage vendors), so this is a
    triage input rather than a verdict.
    """
    return _out_of_tree_of(loaded_modules())


# ------------------------------------------------------------ load timing
def _late_of(modules: Sequence[Dict[str, Any]], boot_time: float
             ) -> List[Dict[str, Any]]:
    """Modules stamped materially after ``boot_time``."""
    if not boot_time or boot_time <= 0:
        return []
    out: List[Dict[str, Any]] = []
    for module in modules:
        mtime = module.get("load_mtime")
        if mtime is None:
            continue
        delta = mtime - boot_time
        if delta <= LATE_LOAD_GRACE_SECONDS:
            continue
        out.append({
            "module": module["name"],
            "loaded_at": mtime,
            "loaded_at_local": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(mtime)),
            "boot_time": boot_time,
            "delta_seconds": round(delta, 1),
            "instantiated": module.get("load_mtime_source"),
            "sysfs_path": module.get("sysfs_path"),
            "out_of_tree": module.get("out_of_tree"),
            "read_errors": module.get("read_errors") or [],
        })
    return sorted(out, key=lambda entry: entry["delta_seconds"], reverse=True)


def late_loaded_modules(boot_time: float,
                        snapshot: Optional[List[Dict[str, Any]]] = None
                        ) -> List[Dict[str, Any]]:
    """Modules loaded at runtime rather than during the boot sequence.

    ``boot_time`` is epoch seconds (``jocky.rt.procfs.boot_time()``).  A module
    directory whose mtime is more than :data:`LATE_LOAD_GRACE_SECONDS` after
    boot was inserted by something that ran later — a package install, a
    service, or an operator.  The grace window exists because initramfs
    hand-off, ``udev`` coldplug and the module auto-loader legitimately lag
    ``btime`` by tens of seconds.

    Each entry::

        {"module", "loaded_at", "loaded_at_local", "boot_time",
         "delta_seconds", "instantiated": "sysfs_dir" | "coresize",
         "sysfs_path", "out_of_tree", "read_errors"}

    Returns an empty list when ``boot_time`` is unknown (``<= 0``): without a
    boot timestamp every module would look late-loaded.
    """
    if snapshot is None:
        snapshot = loaded_modules()
    return _late_of(snapshot, boot_time)


# ------------------------------------------------- module files on disk
_DISK_INDEX_CACHE: Dict[str, Tuple[Dict[str, str], List[str], bool]] = {}


def _index_key(filename: str) -> Optional[str]:
    """Module name a ``.ko`` filename provides, normalised to underscores."""
    base = os.path.basename(filename)
    for suffix in _KO_SUFFIXES:
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    else:
        return None
    return base.replace("-", "_")


def _index_from_depmod(root: str) -> Tuple[Dict[str, str], List[str]]:
    """Index a module tree from ``modules.dep`` (authoritative and cheap)."""
    index: Dict[str, str] = {}
    errors: List[str] = []
    dep_path = os.path.join(root, "modules.dep")
    try:
        with open(dep_path, "r", errors="replace") as handle:
            for line in handle:
                relative = line.split(":", 1)[0].strip()
                if not relative:
                    continue
                key = _index_key(relative)
                if key is None:
                    continue
                index.setdefault(key, os.path.join(root, relative))
    except OSError as exc:
        errors.append(f"{dep_path}: {_error_name(exc)}")
    return index, errors


def _index_from_walk(root: str) -> Tuple[Dict[str, str], List[str], bool]:
    """Index a module tree by walking it; ``modules.dep`` may not exist.

    Returns ``(index, errors, complete)``.  ``complete`` is ``False`` when the
    walk hit :data:`MODULE_WALK_LIMIT`; a truncated index would make ordinary
    modules look deleted, so callers must not use it to raise findings.
    """
    index: Dict[str, str] = {}
    errors: List[str] = []
    seen = 0
    complete = True
    for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda exc: errors.append(
            f"{getattr(exc, 'filename', root)}: {_error_name(exc)}")):
        for filename in filenames:
            key = _index_key(filename)
            if key is None:
                continue
            seen += 1
            if seen > MODULE_WALK_LIMIT:
                complete = False
                break
            index.setdefault(key, os.path.join(dirpath, filename))
        if not complete:
            break
    return index, errors, complete


def _module_disk_index(release: Optional[str] = None
                       ) -> Tuple[Dict[str, str], List[str], bool]:
    """``(index, errors, complete)`` mapping module names to ``.ko`` paths.

    Keys are underscore-normalised names *and* the dashed spelling, so callers
    can look up whatever they have.  Built from ``modules.dep`` when present and
    from a bounded walk otherwise (a custom firmware image may ship the tree
    without the depmod files).  ``complete`` is ``False`` when the tree is
    missing or the walk was truncated — in that state no deletion claim may be
    made, because the absence of an entry would say nothing about the module.

    On a platform without ``/lib/modules`` (Windows) there is no tree at all,
    so this returns the same "no index available" shape as a missing release —
    an empty index plus an error note and ``complete=False`` — rather than
    touching ``os.uname``, which does not exist there.
    """
    release = release or _kernel_release()
    if release is None:
        label = _disk_index_label()
        cached = _DISK_INDEX_CACHE.get(label)
        if cached is None:
            cached = ({},
                      [f"no kernel module tree on this platform ({sys.platform}): "
                       "the on-disk module comparison does not apply"],
                      False)
            _DISK_INDEX_CACHE[label] = cached
        return cached
    cached = _DISK_INDEX_CACHE.get(release)
    if cached is not None:
        return cached

    root = os.path.join(MODULES_ROOT, release)
    index: Dict[str, str] = {}
    errors: List[str] = []
    complete = True
    if not os.path.isdir(root):
        complete = False
        errors.append(f"{root}: missing (no module tree for the running kernel)")
    else:
        index, errors = _index_from_depmod(root)
        if not index:
            index, walk_errors, complete = _index_from_walk(root)
            errors.extend(walk_errors)
        if not index:
            complete = False

    for key in list(index):
        dashed = key.replace("_", "-")
        if dashed != key:
            index.setdefault(dashed, index[key])
    result = (index, errors, complete)
    _DISK_INDEX_CACHE[release] = result
    return result


def _resolve_elsewhere(name: str, release: str) -> Optional[str]:
    """Look for ``name`` in another installed kernel tree.

    A host can run a kernel whose tree was removed while another release's tree
    is still installed (containers, WSL, freshly pruned images).  A module found
    there is not a deleted file, and saying otherwise would be exactly the false
    positive this check must avoid.
    """
    try:
        candidates = sorted(os.listdir(MODULES_ROOT))
    except OSError:
        return None
    for other in candidates:
        if other == release or not os.path.isdir(os.path.join(MODULES_ROOT, other)):
            continue
        index, _errors, _complete = _module_disk_index(other)
        for spelling in _name_spellings(name):
            if spelling in index:
                return index[spelling]
    return None


def _deleted_of(modules: Sequence[Dict[str, Any]], index: Dict[str, str],
                complete: bool, release: str) -> List[Dict[str, Any]]:
    """Modules that are loaded while their ``.ko`` is absent from disk."""
    if not complete or not index:
        return []
    out: List[Dict[str, Any]] = []
    for module in modules:
        name = module["name"]
        indexed = next((index[s] for s in _name_spellings(name) if s in index), None)
        if indexed is not None:
            if os.path.exists(indexed):
                continue
            out.append({
                "module": name,
                "kernel_release": release,
                "indexed_path": indexed,
                "expected_path": indexed,
                "indexed_file_missing": True,
                "sysfs_path": module.get("sysfs_path"),
                "state": module.get("state"),
                "reason": "modules.dep lists this path but the file is gone",
            })
            continue
        if _resolve_elsewhere(name, release) is not None:
            continue
        out.append({
            "module": name,
            "kernel_release": release,
            "indexed_path": None,
            "expected_path": os.path.join(MODULES_ROOT, release),
            "indexed_file_missing": False,
            "sysfs_path": module.get("sysfs_path"),
            "state": module.get("state"),
            "reason": ("loaded module resolves to no .ko under "
                       f"{MODULES_ROOT}/{release} (both - and _ spellings tried)"),
        })
    return out


def deleted_module_files(snapshot: Optional[List[Dict[str, Any]]] = None
                         ) -> List[Dict[str, Any]]:
    """Loaded modules whose backing file is gone from disk (Linux).

    Deleting the ``.ko`` after loading is a classic anti-forensic step: the
    module keeps running, but nothing on disk can be hashed or attributed.
    Each entry::

        {"module", "kernel_release", "indexed_path", "expected_path",
         "indexed_file_missing", "sysfs_path", "state", "reason"}

    ``indexed_path`` is the path ``modules.dep`` promised (``None`` when the
    module is not indexed at all) and ``indexed_file_missing`` distinguishes
    "listed but repackaged away" from "never on disk".

    Returns an empty list when the module tree for the running kernel is
    incomplete or missing, and on platforms that have no module tree at all:
    without a trustworthy index, "not found" would be a statement about the
    index rather than about the module, and reporting it would flood a normal
    host with false positives.  That reduced coverage is surfaced by
    :func:`byovd_findings` as a ``partial_visibility`` finding.  Windows instead
    uses the per-driver ``file_exists`` flag from
    :func:`jocky.rt.winapi.modules`, reported as ``byovd_deleted_driver_file``.
    """
    if snapshot is None:
        snapshot = loaded_modules()
    index, _errors, complete = _module_disk_index()
    return _deleted_of(snapshot, index, complete, _disk_index_label())


# ------------------------------------------------------- known vulnerable
def known_vulnerable_drivers(platform: Optional[str] = None) -> List[Dict[str, Any]]:
    """Curated BYOVD table from :data:`KNOWN_VULNERABLE`, optionally filtered.

    ``platform`` is ``"linux"`` or ``"windows"`` (``None`` returns everything),
    so the Windows collector can reuse exactly the same table::

        {"name", "aliases": tuple, "cve": str | None, "why",
         "severity", "platform", "scope", "reference"}

    Copies are returned so a caller cannot mutate the module-level table.
    """
    entries = [dict(entry) for entry in KNOWN_VULNERABLE]
    if platform is None:
        return entries
    return [entry for entry in entries if entry["platform"] == platform]


def _match_known_vulnerable(names: Iterable[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Map loaded module names to the table entries they match.

    Matching is case-insensitive on the module name and on every alias, with
    dashes and underscores treated as equivalent (a Linux module name has to
    match ``nf_tables`` whether it was typed with a dash or not, and a Windows
    collector will pass ``RTCore64.sys``).
    """
    loaded: Dict[str, str] = {}
    for name in names:
        loaded[name.replace("-", "_").lower()] = name
    hits: Dict[str, List[Dict[str, Any]]] = {}
    for entry in KNOWN_VULNERABLE:
        keys = {entry["name"], *entry.get("aliases", ())}
        for key in keys:
            module = loaded.get(key.replace("-", "_").lower())
            if module is not None:
                hits.setdefault(module, []).append(entry)
    return hits


# --------------------------------------------------------------- aggregate
#: Driver-name prefix Windows uses for the crash-dump stack. These are loaded
#: into a reserved region at boot so a bugcheck can write the dump; the image
#: is resident while absent from the filesystem, on every healthy host.
_DUMP_STACK_PREFIX = "dump_"


def _is_dump_stack_driver(name: str) -> bool:
    """True for a Windows crash-dump stack driver (``dump_*.sys``).

    Exists so the ghost-driver check can tell "resident by design" from
    "resident and its image was removed", which is the difference between a
    finding an analyst acts on and one they learn to scroll past. The test is
    the documented prefix and nothing else — a driver merely *resembling* one is
    still reported at full severity.
    """
    return bool(name) and name.lower().startswith(_DUMP_STACK_PREFIX)


def byovd_findings(boot_time: Optional[float] = None,
                   snapshot: Optional[List[Dict[str, Any]]] = None
                   ) -> List[Dict[str, Any]]:
    """Run every BYOVD check and return ``detect``-shaped findings.

    The module list comes from the platform backend (:func:`_loaded_module_view`):
    ``/proc/modules`` enriched from ``/sys/module`` on Linux, the kernel's
    ``SystemModuleInformation`` driver list through :mod:`jocky.rt.winapi` on
    Windows.  ``snapshot`` accepts an already-built :func:`loaded_modules`
    result so a caller that needs both the view and the findings pays for the
    walk once; ``boot_time`` defaults to :func:`jocky.rt.procfs.boot_time`.

    One finding is emitted per hit for: a known-vulnerable module, an
    out-of-tree module, an unsigned module, a force-loaded module, a module
    loaded well after boot, a module or driver whose image file is gone from
    disk, and the global taint bits 12/13.  Checks the platform cannot support
    are reported as not applicable, and coverage gaps (unreadable module list,
    unrunnable per-module taint attribution, no module tree to compare against)
    are reported as ``partial_visibility`` findings instead of being swallowed —
    a clean result that quietly skipped a check is worse than no result at all.
    """
    if boot_time is None:
        boot_time = procfs.boot_time()

    rows_error = None
    modules = snapshot
    if modules is None:
        modules, rows_error = _loaded_module_view()

    findings: List[Dict[str, Any]] = []
    sysfs_view = _sysfs_module_view()
    
    # -- known vulnerable drivers/modules
    #
    # Grading splits on ``scope`` because the two cases ask different things of
    # the analyst. A ``third_party`` driver is the BYOVD shape — a signed binary
    # the attacker brought with them — so a match *is* the finding. An ``in_tree``
    # module ships with the distribution kernel: ``ip_tables`` loads on any host
    # that uses iptables, so reporting it at high severity would place an
    # unactionable item in every triage result on every machine, which is how a
    # detector trains its operator to ignore it. It is still reported — at
    # ``info``, CVE intact — because "this kernel build exposes a publicly
    # exploited module" is worth knowing. It is a patching question, not
    # evidence of compromise.
    for module_name, entries in sorted(
            _match_known_vulnerable([m["name"] for m in modules]).items()):
        cves = sorted({e["cve"] for e in entries if e["cve"]})
        scopes = sorted({e["scope"] for e in entries})
        cve_text = ", ".join(cves) if cves else "no CVE assigned"
        third_party = [e for e in entries if e["scope"] == "third_party"]
        if third_party:
            severity = _worst_severity(e["severity"] for e in third_party)
            title = (f"loaded module {module_name} matches a driver abused in "
                     f"BYOVD research ({cve_text})")
            recommendation = ("treat the load as hostile: identify the vendor, hash "
                              "the driver and check it against the published "
                              "driver blocklist")
        else:
            severity = "info"
            title = (f"loaded module {module_name} has a publicly exploited flaw "
                     f"({cve_text}); it ships with the distribution kernel")
            recommendation = ("compare the running kernel build against the vendor "
                              f"fix for {cve_text}; presence alone is not evidence "
                              "of compromise")
        findings.append(_finding(
            "byovd_known_vulnerable_module",
            severity,
            title,
            {
                "module": module_name,
                "cves": cves,
                "scope": scopes[0] if len(scopes) == 1 else scopes,
                "platform": sorted({e["platform"] for e in entries}),
                "matches": [
                    {"name": e["name"], "cve": e["cve"], "why": e["why"],
                     "severity": e["severity"], "scope": e["scope"],
                     "reference": e["reference"]}
                    for e in entries
                ],
                "out_of_tree": next(
                    (m.get("out_of_tree") for m in modules if m["name"] == module_name),
                    None),
            },
            recommendation,
        ))

    # -- per-module taint classes (Linux only: Windows has no taint flag, and
    #    saying "no unsigned drivers" there would be a claim about nothing)
    for entry in _out_of_tree_of(modules) if sysfs_view else ():
        if entry["out_of_tree"] is None:
            continue                        # reported as a coverage gap below
        findings.append(_finding(
            "byovd_out_of_tree_module", "medium",
            f"module {entry['module']} is out-of-tree (taint 'O')",
            {"module": entry["module"], "taint_flags": entry["taint_flags"],
             "coresize": entry["coresize"], "source": entry["source"]},
            "identify the vendor or package that installed this module",
        ))
    for entry in _unsigned_of(modules) if sysfs_view else ():
        if entry["unsigned"] is None:
            continue                        # reported as a coverage gap below
        findings.append(_finding(
            "byovd_unsigned_module", "high",
            f"module {entry['module']} is unsigned (taint 'E')",
            {"module": entry["module"], "taint": entry["taint"],
             "source": entry["source"]},
            "hash the .ko and compare it against the distribution package manifest",
        ))
    for module in modules if sysfs_view else ():
        if not module.get("forced"):
            continue
        findings.append(_finding(
            "byovd_forced_module", "high",
            f"module {module['name']} was force loaded (taint 'F')",
            {"module": module["name"], "taint": module.get("taint"),
             "taint_flags": module.get("taint_flags"),
             "sysfs_path": module.get("sysfs_path")},
            "force loading bypasses vermagic/version checks; treat as deliberate "
            "tampering unless a maintenance action explains it",
        ))

    # -- runtime load timing
    #
    # ``info``, not ``medium``: modules load on demand for entirely ordinary
    # reasons (the first mount of a filesystem type, a USB device, a TLS socket
    # enabling kTLS). The signal is the *correlation* — a load timestamp has to
    # line up with suspicious process or package-manager activity — so this is
    # graded the way ``detect.py`` grades ``rwx_memory``: correlation input, not
    # a verdict. Reporting it higher would fire on most long-lived hosts.
    for entry in _late_of(modules, boot_time) if sysfs_view else ():
        findings.append(_finding(
            "byovd_late_loaded_module", "info",
            (f"module {entry['module']} was loaded "
             f"{entry['delta_seconds']:.0f}s after boot"),
            {"module": entry["module"], "loaded_at": entry["loaded_at"],
             "loaded_at_local": entry["loaded_at_local"],
             "boot_time": entry["boot_time"],
             "delta_seconds": entry["delta_seconds"],
             "instantiated": entry["instantiated"],
             "sysfs_path": entry["sysfs_path"]},
            "correlate the load time with process, cron and package-manager activity",
        ))

    # -- backing file removed from disk
    index, index_errors, index_complete = _module_disk_index()
    for entry in _deleted_of(modules, index, index_complete, _disk_index_label()):
        findings.append(_finding(
            "byovd_deleted_module_file", "high",
            f"module {entry['module']} is loaded but its .ko is not on disk",
            entry,
            "acquire a memory image and recover the module image before the host "
            "reboots; hash the file if a copy still exists",
        ))

    # -- resident driver whose image file is gone (the Windows counterpart of
    #    the .ko check: the record carries a per-driver path and a stat result,
    #    while Linux answers the same question from the module tree above)
    #
    # Windows loads its crash-dump stack drivers (dump_*.sys) into a reserved
    # area at boot for dump support; they are resident by design and their image
    # is not on the filesystem. Measured on a healthy Windows 11 host: exactly 3
    # of 244 drivers — dump_diskdump.sys, dump_iaStorVD.sys, dump_dumpfve.sys —
    # and the same is true of dump_storahci.sys. Reporting those at ``high`` puts
    # three permanent, unactionable findings in every triage result on every
    # Windows machine, which is how an operator is trained to ignore the check
    # that is supposed to catch a real ghost driver. They stay reported, at
    # ``info``, with the reason stated — the same split this module applies to
    # in-tree CVEs, and the same reasoning ``detect.py`` uses for ``rwx_memory``.
    unresolved_paths: List[str] = []
    for module in modules:
        exists = module.get("file_exists")
        if exists is None and "file_exists" in module:
            unresolved_paths.append(module["name"])
            continue
        if exists is not False:
            continue
        expected = _is_dump_stack_driver(module.get("name") or "")
        findings.append(_finding(
            "byovd_deleted_driver_file", "info" if expected else "high",
            (f"driver {module['name']} is resident but its image file is not on "
             "disk"
             + (" (crash-dump stack driver: expected)" if expected else "")),
            {"module": module["name"], "path": module.get("path"),
             "size": module.get("size"), "address": module.get("address"),
             "load_order": module.get("load_order"), "file_exists": False,
             "dump_stack_driver": expected},
            ("no action: Windows loads dump_*.sys into the crash-dump stack at "
             "boot, so the image is resident while absent from the filesystem"
             if expected else
             "acquire a memory image and recover the driver image before the host "
             "reboots; hash the file from a known-good package if one exists"),
        ))

    # -- global taint
    taint = taint_state()
    if sysfs_view and taint["value"] is None:
        findings.append(_finding(
            "partial_visibility", "info",
            "the kernel taint mask could not be read, so the taint-derived checks "
            "are inconclusive",
            {"source": taint["source"], "errors": taint["errors"],
             "platform": sys.platform},
            "re-run with permission to read /proc/sys/kernel/tainted; treat the "
            "taint checks as unknown rather than clean",
        ))
    for label, bit, modules_attr in (
            ("out-of-tree", TAINT_BIT_OUT_OF_TREE, "out_of_tree"),
            ("unsigned", TAINT_BIT_UNSIGNED, "unsigned")):
        if not taint.get(modules_attr):
            continue
        attributed = [m["name"] for m in modules if m.get(modules_attr)]
        findings.append(_finding(
            "byovd_kernel_taint", "medium",
            f"kernel taint bit {bit} is set: an {label} module was loaded",
            {"bit": bit, "taint_value": taint["value"], "taint_flags": taint["flags"],
             "modules": attributed,
             "attribution": ("per-module taint flags" if attributed
                             else "no module reported this taint flag; it was set "
                                  "earlier in this boot")},
            "attribute the taint and review the provenance of the modules involved",
        ))

    # -- coverage: never let a skipped read look like a clean host
    if rows_error:
        findings.append(_finding(
            "partial_visibility", "info",
            "the loaded module/driver list could not be read",
            {"source": rows_error, "modules_seen": len(modules),
             "platform": sys.platform},
            "re-run with the rights the platform requires (root/CAP_SYS_MODULE on "
            "Linux); treat the module results as unknown rather than clean",
        ))
    if not sysfs_view:
        windows = sys.platform == "win32"
        missing = [] if windows else [path for path in (SYS_MODULE_ROOT, KERNEL_TAINTED)
                                      if not os.path.exists(path)]
        findings.append(_finding(
            "partial_visibility", "info",
            "per-module taint and module load-time checks do not apply on this "
            "platform",
            {"platform": sys.platform, "missing": missing,
             "checks_not_applicable": [
                 "byovd_out_of_tree_module", "byovd_unsigned_module",
                 "byovd_forced_module", "byovd_late_loaded_module",
                 "byovd_kernel_taint"],
             "note": ("Windows exposes no per-driver taint flag and no module "
                      "directory, so these checks report nothing because the "
                      "concept is absent, not because the host is clean")},
            "do not read the absence of those findings as a clean result; "
            "correlate driver provenance against the platform's own mechanisms "
            "(WDAC or the vulnerable-driver blocklist) instead",
        ))
    # A platform without a module tree at all is already explained by the finding
    # above; only report the missing index where one was expected.
    if (index_errors or not index_complete) and _kernel_release() is not None:
        findings.append(_finding(
            "partial_visibility", "info",
            "the on-disk module tree for this kernel could not be indexed",
            {"release": _disk_index_label(), "errors": index_errors[:5],
             "error_count": len(index_errors),
             "entries_indexed": len(index),
             "platform": sys.platform},
            "install the matching kernel modules package before trusting the "
            "deleted-module check",
        ))
    if unresolved_paths:
        findings.append(_finding(
            "partial_visibility", "info",
            (f"{len(unresolved_paths)} loaded driver(s) have no stat-able image "
             "path, so the missing-file check did not cover them"),
            {"drivers": unresolved_paths[:20], "driver_count": len(unresolved_paths),
             "note": ("a device path (\\Device\\...) has no user-mode name and a "
                      "UNC path is not stat'ed; unknown is not the same as missing")},
            "resolve the paths offline against a memory image or an offline disk",
        ))
    unattributed = [m["name"] for m in modules
                    if sysfs_view and (not m.get("sysfs_present")
                                       or not m.get("taint_available"))]
    if unattributed:
        unreadable = {error for m in modules for error in (m.get("read_errors") or [])}
        findings.append(_finding(
            "partial_visibility", "info",
            f"{len(unattributed)} loaded module(s) could not be attributed to a "
            "sysfs entry or a taint flag",
            {"modules": unattributed[:20], "module_count": len(unattributed),
             "read_errors": sorted(unreadable)[:5],
             "read_error_count": len(unreadable)},
            "re-run as root so /sys/module/<name>/taint and /sys/module/<name>/"
            "sections are readable",
        ))
    return findings
