"""Windows process-injection **detection** through pure ``ctypes``.

Why this module exists
----------------------
Pillar 3 of the problem statement names the Windows injection family — process
hollowing, reflective DLL injection, API unhooking, thread execution hijacking —
and those techniques dominate on Windows the way memfd/fileless execution
dominates on Linux.  This project implements none of them: ``docs/DESIGN.md`` §10
puts kernel-mode evasion and the offensive half of that list out of scope, and
that line does not move.  What was missing is the *detection* half, so this
module is the mirror image of :mod:`jocky.rt.detect`: whatever state an injection
technique leaves behind on a Windows host, there is a read-only check here that
names it, grades it and hands the analyst somewhere to pivot.

Nothing here writes, allocates, patches, suspends, resumes or injects.  Every
call is a query (``ReadProcessMemory``/``VirtualQueryEx``/``EnumProcessModulesEx``
/``NtQueryInformationThread``) against an already-running process, and no handle
is opened with a right above ``PROCESS_VM_READ`` — the same rule
:mod:`jocky.rt.winapi` follows, for the same reason: a forensic collector must not
look like the attacker it is describing.

Checks emitted
--------------
``hollowed_process``            the image mapped in the process is not the image
                                on disk: PE headers, section table or the bytes of
                                a section disagree.  Structural mismatch (headers
                                / section table) is ``high``; a content-only
                                mismatch is ``medium`` — see *False positives*
                                below for why those two are graded apart.
``private_executable_memory``   committed ``MEM_PRIVATE`` pages that carry an
                                execute protection, i.e. where a manually mapped
                                payload lives.  ``medium``: JIT runtimes look
                                identical, so this is correlation input.
``unbacked_thread_start``       a thread whose start address lies outside every
                                loaded module of its process — the shape thread
                                execution hijacking and ``CreateRemoteThread``
                                leave behind.  ``high``.
``module_from_temp_path``       a loaded image whose file sits under a
                                temp/world-writable directory, or whose file is
                                not on disk at all.  ``medium``.
``partial_visibility``          part of the process table could not be read, so a
                                clean result is not conclusive (``info``).  Reused
                                from :mod:`jocky.rt.detect`; a denial is a fact
                                about the collection, never an exception.

Check metadata (source, summary, remediation) is not duplicated here: it belongs
in :data:`jocky.rt.detect.CHECK_CATALOG`, the project's single source of truth
for check metadata, and :data:`EMITTED_CHECKS` is the list to add there.

Scope, stated plainly.  The four checks cover the *state* the named techniques
leave behind: a hollowed or doppelgänged process (``hollowed_process``), a
manually mapped or reflectively loaded payload (``private_executable_memory``),
a thread pointed at code that no image accounts for
(``unbacked_thread_start``), and an image loaded from somewhere an attacker
could write (``module_from_temp_path``).  Two boundaries are deliberate.
**Main-module only**: the disk/memory comparison examines the process's own
image, so a *patched system DLL* (``ntdll`` hook removal or a rogue hook) is not
covered — and a check that simply compared every mapped DLL against its file
would fire on every host running an EDR, because hooking one is what an EDR
does, so it would need a baseline this module does not have.  **Address, not
verdict**: ``ThreadQuerySetWin32StartAddress`` is the address the thread was
created with, and a few runtimes do start threads outside the module list, so
the finding names what it measured and leaves the judgement to the analyst.

How to read the output
----------------------
A finding is a map — ``{"check", "severity", "title", "evidence",
"recommendation"}`` — with the pivots in ``evidence``: the pid and process name,
the module base/size, the compared byte counts, the mismatching fields, and each
region's base, size and protection.  Every finding is a *lead with its
measurement attached*, not a verdict: the counts are there so an analyst can tell
a 40-byte relocation artefact from a replaced ``.text``.

False positives are treated as defects, and this module has three specific
guards worth knowing about:

* **The disk image is compared only when it is older than the process.**  A
  browser that updated itself five minutes after launch has a newer file than
  the process, so the comparison is meaningless and is skipped (and reported as
  skipped, never silently dropped).
* **Relocated pages are excluded from the content comparison.**  Windows rebases
  images (ASLR) by patching addresses in place, so a relocated ``.text`` differs
  from its file even when nothing hostile happened.  The ``.reloc`` table names
  exactly the pages the loader will rewrite, so those pages are skipped rather
  than counted as a mismatch.
* **Discardable sections are skipped.**  The loader is allowed to drop
  ``IMAGE_SCN_MEM_DISCARDABLE`` sections (``.reloc``, debug) under memory
  pressure; their absence proves nothing.

Reading is bounded throughout: a scan never reads more than the module's own
declared size, and never more than a fixed budget per section and per image.

Off-platform contract
---------------------
``ctypes.windll`` does not exist off Windows, so :func:`available` is ``False``
and every detector returns ``[]`` without raising and without touching a Windows
API.  The pure helpers — PE header/section parsing, relocation-page extraction,
protection decoding, page-wise mismatch counting, address-range coverage and the
path grading — are module-level functions over plain ``int``/``bytes``, which is
what makes the parts that are easy to get wrong testable on Linux with synthetic
buffers (``tests/test_winject.py``).
"""
from __future__ import annotations

import ctypes
import os
import struct
import sys
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from jocky.rt import winapi

__all__ = [
    "EMITTED_CHECKS",
    "available",
    "executable_private_memory",
    "hollowed_processes",
    "modules_from_temp_paths",
    "unbacked_executable_threads",
]

#: The checks this module emits.  Their documentation lives in
#: :data:`jocky.rt.detect.CHECK_CATALOG` — one catalog, because two catalogs are
#: two things to drift.
EMITTED_CHECKS: Tuple[str, ...] = (
    "hollowed_process",
    "private_executable_memory",
    "unbacked_thread_start",
    "module_from_temp_path",
    "partial_visibility",
)

# ------------------------------------------------------------------ constants
_IS_WINDOWS = sys.platform == "win32"
_POINTER_SIZE = ctypes.sizeof(ctypes.c_void_p)

#: Access rights.  ``PROCESS_VM_READ`` is the one right ``winapi`` never asks
#: for, and the only extra one this module needs: every check here is a read of
#: another process's memory, so there is no stronger right to accidentally hold.
_PROCESS_VM_READ = 0x0010
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_THREAD_QUERY_INFORMATION = 0x0040
_THREAD_QUERY_LIMITED_INFORMATION = 0x0800

_TH32CS_SNAPTHREAD = 0x00000004
_LIST_MODULES_ALL = 0x0003
#: ``THREADINFOCLASS.ThreadQuerySetWin32StartAddress``.
_THREAD_QUERY_SET_WIN32_START_ADDRESS = 9

#: ``MEMORY_BASIC_INFORMATION.State`` / ``.Type``.
_MEM_COMMIT = 0x1000
_MEM_PRIVATE = 0x20000
#: ``MEMORY_BASIC_INFORMATION.Protect``.
_PAGE_NOACCESS = 0x01
_PAGE_GUARD = 0x100
_PAGE_NOCACHE = 0x200
_PAGE_WRITECOMBINE = 0x400
_PAGE_EXECUTE = 0x10
_PAGE_EXECUTE_READ = 0x20
_PAGE_EXECUTE_READWRITE = 0x40
_PAGE_EXECUTE_WRITECOPY = 0x80
_PROTECT_MASK = 0xFF

_PROTECTION_NAMES = {
    _PAGE_NOACCESS: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    _PAGE_EXECUTE: "PAGE_EXECUTE",
    _PAGE_EXECUTE_READ: "PAGE_EXECUTE_READ",
    _PAGE_EXECUTE_READWRITE: "PAGE_EXECUTE_READWRITE",
    _PAGE_EXECUTE_WRITECOPY: "PAGE_EXECUTE_WRITECOPY",
}
_EXECUTE_PROTECTIONS = frozenset((
    _PAGE_EXECUTE, _PAGE_EXECUTE_READ, _PAGE_EXECUTE_READWRITE,
    _PAGE_EXECUTE_WRITECOPY,
))

_MEMORY_TYPES = {
    _MEM_COMMIT: "MEM_COMMIT",
    0x2000: "MEM_RESERVE",
    0x10000: "MEM_FREE",
    _MEM_PRIVATE: "MEM_PRIVATE",
    0x40000: "MEM_MAPPED",
    0x1000000: "MEM_IMAGE",
}

#: ``IMAGE_SCN_MEM_DISCARDABLE``: the loader may unmap the section once it has
#: done its job, so a difference there is not evidence of anything.
_IMAGE_SCN_MEM_DISCARDABLE = 0x02000000

_PAGE_SIZE = 0x1000
_PAGE_MASK = ~(_PAGE_SIZE - 1)
#: The user-mode address ceiling for *this interpreter's* bitness.  A single
#: 64-bit constant was wrong under a 32-bit Python: the walk would step from
#: 0x7FFF0000 to 0x7FFFFFFF0000, every query past the real ceiling would fail,
#: and every process would report its address-space walk as truncated — a
#: coverage gap indistinguishable from a hostile process.  This mirrors the
#: ``_MBI`` choice below.
_USER_SPACE_TOP = 0x7FFFFFFF0000 if _POINTER_SIZE == 8 else 0x7FFF0000

#: Read budgets.  A scan reads a bounded slice of each image, and always less
#: than the module's own declared size.  The per-image budget is what keeps a
#: sweep of a few hundred processes to a few seconds of ``ReadProcessMemory``
#: instead of gigabytes: the entry-point section is first in the table and is
#: therefore compared first and in full, and any section the budget cannot reach
#: is listed in ``skipped_sections`` rather than passed off as a match.
_MAX_HEADER_BYTES = 0x10000          # PE headers + section table
_MAX_SECTION_BYTES = 1 * 1024 * 1024  # per-section content comparison
_MAX_TOTAL_COMPARE = 4 * 1024 * 1024  # per-image content comparison
_MAX_IMAGE_BYTES = 64 * 1024 * 1024   # refuse to compare anything larger
_MAX_RELOC_BYTES = 8 * 1024 * 1024    # .reloc read bound
_MAX_RELOC_BLOCKS = 1 << 16           # relocation blocks honoured
_READ_CHUNK = 0x10000
_PE_PROBE_BYTES = 0x1000

#: Bounds on the scan itself, so one hostile process cannot wedge a triage.
_MAX_REGIONS = 4096                   # VirtualQueryEx steps per process
_MAX_MODULES = 4096                   # EnumProcessModulesEx sanity ceiling
_MAX_PROBED_REGIONS = 64              # ReadProcessMemory probes per process
_MAX_PIDS = 4096
_MAX_EVIDENCE_ITEMS = 16

#: Fraction of a compared section that must differ before a content-only
#: mismatch is reported.  Tuned against the relocation guard above: what is left
#: after excluding relocated pages is noise at the byte level (a hot patch, an
#: in-place self-update), while a replaced ``.text`` differs wholesale.
_MISMATCH_FRACTION = 0.05
#: A file replaced *during* the process's lifetime is a normal software update,
#: so only a clearly newer file invalidates the comparison.
_MTIME_GRACE = 1.0

#: Directory fragments under which a *loaded module* is never a normal system
#: image.  ``winapi._SUSPICIOUS_DIRS`` is the list the process collector already
#: grades an image path with; reusing it keeps one definition of "drop zone".
_MODULE_DROP_ZONES = tuple(winapi._SUSPICIOUS_DIRS) + (
    "\\tmp\\",
    "\\downloads\\",
    "\\perflogs\\",
)

_COFF_HEADER = struct.Struct("<HHIIIHH")
_SECTION_HEADER = struct.Struct("<8sIIIIIIHHI")
_RELOC_BLOCK = struct.Struct("<II")

#: PE fields compared between the disk image and the mapped image.  ``checksum``
#: is deliberately absent: build tooling rewrites it on disk, and a mismatch
#: there is a build artefact rather than evidence.  ``timestamp`` stays in — two
#: different binaries essentially never share it.
_PE_FIELDS = (
    "magic",
    "machine",
    "number_of_sections",
    "timestamp",
    "size_of_image",
    "size_of_headers",
    # ``image_base`` is deliberately NOT compared. The loader rewrites it in the
    # mapped image to the address the module actually landed on when ASLR moved
    # it, so on a real host it differs for every relocated process. Measured on
    # a healthy Windows 11 box: comparing it produced 107 high-severity
    # "hollowed process" findings for brave.exe, RuntimeBroker.exe, taskhostw.exe
    # and every other normal binary — 4 differing bytes each, at exactly this
    # field and nowhere else. A detector that flags every ASLR process is not
    # detecting anything; the value is still reported as context, it just does
    # not decide the verdict.
    "entry_point",
    "characteristics",
)

#: Section fields compared position by position.
_SECTION_FIELDS = (
    "name",
    "virtual_address",
    "virtual_size",
    "size_of_raw_data",
    "pointer_to_raw_data",
    "characteristics",
)

# ------------------------------------------------------------------- win types
# Fixed-width aliases, for the same reason ``winapi`` uses them: the structures
# must have identical size and offsets here and on Windows, which is what makes
# ``tests/test_winject.py`` able to assert the layout on Linux.
_DWORD = ctypes.c_uint32
_LONG = ctypes.c_int32
_BOOL = ctypes.c_int32
_ULONGLONG = ctypes.c_uint64
_SIZE_T = ctypes.c_size_t
_HANDLE = ctypes.c_void_p


class _MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    """``MEMORY_BASIC_INFORMATION`` as a 64-bit caller sees it (48 bytes)."""

    _fields_ = [
        ("BaseAddress", _ULONGLONG),
        ("AllocationBase", _ULONGLONG),
        ("AllocationProtect", _DWORD),
        ("__alignment1", _DWORD),
        ("RegionSize", _ULONGLONG),
        ("State", _DWORD),
        ("Protect", _DWORD),
        ("Type", _DWORD),
        ("__alignment2", _DWORD),
    ]


class _MEMORY_BASIC_INFORMATION32(ctypes.Structure):
    """The same structure for a 32-bit caller (28 bytes, no padding)."""

    _fields_ = [
        ("BaseAddress", _DWORD),
        ("AllocationBase", _DWORD),
        ("AllocationProtect", _DWORD),
        ("RegionSize", _DWORD),
        ("State", _DWORD),
        ("Protect", _DWORD),
        ("Type", _DWORD),
    ]


class _MODULEINFO(ctypes.Structure):
    """``MODULEINFO``: base, mapped size and entry point of one loaded image."""

    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", _DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


class _THREADENTRY32(ctypes.Structure):
    """``THREADENTRY32`` from ``tlhelp32.h`` (28 bytes)."""

    _fields_ = [
        ("dwSize", _DWORD),
        ("cntUsage", _DWORD),
        ("th32ThreadID", _DWORD),
        ("th32OwnerProcessID", _DWORD),
        ("tpBasePri", _LONG),
        ("tpDeltaPri", _LONG),
        ("dwFlags", _DWORD),
    ]


_MBI = _MEMORY_BASIC_INFORMATION64 if _POINTER_SIZE == 8 \
    else _MEMORY_BASIC_INFORMATION32


# ------------------------------------------------------------------ findings
def _finding(check: str, severity: str, title: str, evidence: Dict[str, Any],
             recommendation: str = "") -> Dict[str, Any]:
    """One finding, in the shape :mod:`jocky.rt.detect` emits."""
    return {
        "check": check,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _partial_finding(detector: str, scanned: int, denied: Sequence[Dict[str, Any]],
                     skipped: Sequence[Dict[str, Any]] = (),
                     extra: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """The ``partial_visibility`` note for a sweep that could not see everything.

    Returns ``None`` when the sweep was complete, so a clean result on a host
    this account can fully read stays quiet — and anything else says so.
    """
    if not denied and not skipped:
        return None
    evidence: Dict[str, Any] = {
        "detector": detector,
        "processes_scanned": scanned,
        "denied_count": len(denied),
        "denied_processes": list(denied)[:_MAX_EVIDENCE_ITEMS],
        "skipped_count": len(skipped),
        "skipped_processes": list(skipped)[:_MAX_EVIDENCE_ITEMS],
        "platform": sys.platform,
    }
    if extra:
        evidence.update(extra)
    parts = []
    if denied:
        parts.append(f"{len(denied)} of {scanned} processes could not be inspected")
    if skipped:
        parts.append(f"{len(skipped)} were skipped")
    return _finding(
        "partial_visibility", "info",
        f"{detector}: " + "; ".join(parts or ["incomplete coverage"]),
        evidence,
        "re-run elevated (SeDebugPrivilege) before treating a clean result as "
        "conclusive for this check; a protected or denied process is not a clean one",
    )


# ------------------------------------------------------------------ pure: memory
def _protection_name(protect: int) -> str:
    """``PAGE_EXECUTE_READ`` for a ``Protect`` value, with modifier suffixes.

    Unknown base values keep their hex form rather than being rounded to
    ``PAGE_NOACCESS``: an unrecognised protection must not read as "harmless".
    """
    value = int(protect or 0)
    base = value & _PROTECT_MASK
    name = _PROTECTION_NAMES.get(base, "0x%02x" % base)
    for flag, label in ((_PAGE_GUARD, "PAGE_GUARD"),
                        (_PAGE_NOCACHE, "PAGE_NOCACHE"),
                        (_PAGE_WRITECOMBINE, "PAGE_WRITECOMBINE")):
        if value & flag:
            name += "|" + label
    return name


def _is_executable(protect: int) -> bool:
    """True for an execute protection that actually maps code.

    ``PAGE_GUARD`` and ``PAGE_NOACCESS`` pages can carry an execute bit in the
    low byte and still be unreadable, so they are excluded — reporting one as
    "executable memory" would be a finding about nothing.
    """
    value = int(protect or 0)
    if value & (_PAGE_GUARD | _PAGE_NOACCESS):
        return False
    return (value & _PROTECT_MASK) in _EXECUTE_PROTECTIONS


def _is_private_executable_region(region: Dict[str, Any]) -> bool:
    """Committed, private (not file-backed) and executable — the payload shape."""
    return (int(region.get("state") or 0) == _MEM_COMMIT
            and int(region.get("type") or 0) == _MEM_PRIVATE
            and _is_executable(region.get("protect", 0)))


def _address_backed(address: int, ranges: Sequence[Tuple[int, int]]) -> bool:
    """True when ``address`` lies inside one of the half-open ``(start, end)``."""
    value = int(address)
    for start, end in ranges:
        if start <= value < end:
            return True
    return False


def _mismatch_bytes(left: bytes, right: bytes) -> int:
    """Number of positions where two buffers differ.

    Done with one big-integer XOR rather than a Python loop: a section is
    megabytes wide and the per-byte generator costs seconds per image.
    """
    first = bytes(left)
    second = bytes(right)
    if first == second:
        return 0
    width = max(len(first), len(second))
    if width == 0:
        return 0
    left_value = int.from_bytes(first.ljust(width, b"\x00"), "big")
    right_value = int.from_bytes(second.ljust(width, b"\x00"), "big")
    difference = (left_value ^ right_value).to_bytes(width, "big")
    return width - difference.count(0)


def _looks_like_pe(raw: Optional[bytes]) -> bool:
    """True when a buffer starts with a DOS stub and a PE signature.

    A truncated buffer returns ``False`` rather than "probably": the claim this
    feeds is "there is a PE image here", and an unconfirmed claim is worse than
    a missing one.
    """
    data = bytes(raw or b"")
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    entry = struct.unpack_from("<I", data, 0x3C)[0]
    if entry < 0x40 or entry + 4 > len(data):
        return False
    return data[entry:entry + 4] == b"PE\x00\x00"


def _read_all(read: Callable[[int, int], Optional[bytes]], offset: int, size: int,
              chunk: int = _READ_CHUNK) -> bytes:
    """Fetch ``size`` bytes at ``offset`` through ``read``, stopping on a gap.

    A short result is not an error: the caller compares what it has and reports
    the shortfall, because "the read stopped early" and "the bytes are equal"
    are different answers.
    """
    if size <= 0:
        return b""
    out = bytearray()
    while len(out) < size:
        part = read(offset + len(out), min(chunk, size - len(out)))
        if not part:
            break
        out += part
    return bytes(out)


# ---------------------------------------------------------------- pure: PE
def _pe_headers(raw: Optional[bytes]) -> Optional[Dict[str, Any]]:
    """Decode the DOS stub, the NT headers and the section table of a PE image.

    Returns ``None`` for anything that is not a complete, parseable PE: a
    truncated section table is rejected rather than partially parsed, because a
    half-read table would show up as "the images disagree" in the comparison
    that consumes this.
    """
    data = bytes(raw or b"")
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if lfanew < 0x40 or lfanew + 24 > len(data):
        return None
    if data[lfanew:lfanew + 4] != b"PE\x00\x00":
        return None
    (machine, section_count, timestamp, _symbols, _symbol_count,
     optional_size, characteristics) = _COFF_HEADER.unpack_from(data, lfanew + 4)
    optional = lfanew + 24
    if optional_size < 96 or optional + optional_size > len(data):
        return None
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:
        image_base = struct.unpack_from("<I", data, optional + 28)[0]
    elif magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    else:
        return None
    table = optional + optional_size
    if table + _SECTION_HEADER.size * section_count > len(data):
        return None
    sections: List[Dict[str, Any]] = []
    for index in range(section_count):
        (raw_name, virtual_size, virtual_address, raw_size, raw_pointer,
         _reloc_pointer, _line_pointer, _reloc_count, _line_count,
         section_flags) = _SECTION_HEADER.unpack_from(
            data, table + index * _SECTION_HEADER.size)
        sections.append({
            "name": raw_name.rstrip(b"\x00").decode("latin-1"),
            "virtual_size": int(virtual_size),
            "virtual_address": int(virtual_address),
            "size_of_raw_data": int(raw_size),
            "pointer_to_raw_data": int(raw_pointer),
            "characteristics": int(section_flags),
            "discardable": bool(section_flags & _IMAGE_SCN_MEM_DISCARDABLE),
        })
    return {
        "magic": magic,
        "machine": int(machine),
        "number_of_sections": int(section_count),
        "timestamp": int(timestamp),
        "characteristics": int(characteristics),
        "optional_header_size": int(optional_size),
        "image_base": int(image_base),
        "entry_point": struct.unpack_from("<I", data, optional + 16)[0],
        "section_alignment": struct.unpack_from("<I", data, optional + 32)[0],
        "file_alignment": struct.unpack_from("<I", data, optional + 36)[0],
        "size_of_image": struct.unpack_from("<I", data, optional + 56)[0],
        "size_of_headers": struct.unpack_from("<I", data, optional + 60)[0],
        "checksum": struct.unpack_from("<I", data, optional + 64)[0],
        "subsystem": struct.unpack_from("<H", data, optional + 68)[0],
        "sections": sections,
    }


def _find_section(pe: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    """The first section called ``name`` (case-insensitive), or ``None``."""
    wanted = name.lower()
    for section in pe.get("sections") or []:
        if str(section.get("name", "")).lower() == wanted:
            return section
    return None


def _relocated_pages(relocations: Optional[bytes]) -> Set[int]:
    """Page RVAs the loader will rewrite, from an ``.reloc`` blob.

    Each ``IMAGE_BASE_RELOCATION`` block names one 4 KiB page and lists the
    offsets inside it that carry a fixup, so the page is exactly the unit that
    cannot be compared byte-for-byte against the file once the image has been
    rebased.  Blocks are walked defensively: a zero page or a block smaller than
    its own header ends the walk instead of looping.
    """
    data = bytes(relocations or b"")
    pages: Set[int] = set()
    offset = 0
    while offset + _RELOC_BLOCK.size <= len(data) and len(pages) < _MAX_RELOC_BLOCKS:
        page, block_size = _RELOC_BLOCK.unpack_from(data, offset)
        if page == 0 or block_size < _RELOC_BLOCK.size:
            break
        pages.add(int(page) & _PAGE_MASK)
        offset += int(block_size)
    return pages


def _comparable_length(section: Dict[str, Any]) -> int:
    """Bytes of a section that exist both in the file and in the mapped image.

    The loader copies ``SizeOfRawData`` bytes at the section's RVA, but never
    more than ``VirtualSize``; the tail of a section with no raw data (``.bss``)
    exists only in memory and has nothing to compare against.
    """
    raw_size = int(section.get("size_of_raw_data") or 0)
    if raw_size <= 0 or not section.get("pointer_to_raw_data"):
        return 0
    virtual = int(section.get("virtual_size") or 0)
    return min(raw_size, virtual) if virtual > 0 else raw_size


def _image_mismatch(
        disk_read: Callable[[int, int], Optional[bytes]],
        memory_read: Callable[[int, int], Optional[bytes]],
        max_section_bytes: int = _MAX_SECTION_BYTES,
) -> Dict[str, Any]:
    """Compare a running image against its on-disk file. Pure, over two readers.

    Both readers take ``(offset_into_image, length)`` and return what they could
    read (``None``/short on failure), which is what makes the whole comparison
    exercisable on Linux with synthetic buffers — and what keeps the real
    implementation honest, since a short read is reported instead of being
    treated as a match.

    Returns a report, not a verdict: the caller grades it.  ``header_differences``
    and ``section_differences`` are structural (a different PE), while
    ``sections`` carries the per-section byte counts behind a content-only
    mismatch.
    """
    report: Dict[str, Any] = {
        "disk": None,
        "memory": None,
        "header_differences": [],
        "section_differences": [],
        "sections": [],
        "skipped_sections": [],
        "compared_bytes": 0,
        "mismatch_bytes": 0,
        "notes": [],
    }
    disk_pe = _pe_headers(_read_all(disk_read, 0, _MAX_HEADER_BYTES))
    memory_pe = _pe_headers(_read_all(memory_read, 0, _MAX_HEADER_BYTES))
    report["disk"] = disk_pe
    report["memory"] = memory_pe
    if memory_pe is None:
        report["notes"].append(
            "the mapped PE headers could not be read (denied or not a PE)")
        return report
    if disk_pe is None:
        report["notes"].append("the on-disk image is not a parseable PE image")
        return report

    for field in _PE_FIELDS:
        if disk_pe[field] != memory_pe[field]:
            report["header_differences"].append({
                "field": field, "disk": disk_pe[field], "memory": memory_pe[field]})

    disk_sections = disk_pe["sections"]
    memory_sections = memory_pe["sections"]
    for index in range(max(len(disk_sections), len(memory_sections))):
        left = disk_sections[index] if index < len(disk_sections) else {}
        right = memory_sections[index] if index < len(memory_sections) else {}
        changed = {
            field: {"disk": left.get(field), "memory": right.get(field)}
            for field in _SECTION_FIELDS if left.get(field) != right.get(field)
        }
        if changed:
            report["section_differences"].append({
                "index": index,
                "name": left.get("name") or right.get("name") or "?",
                "fields": changed,
            })
    if len(disk_sections) != len(memory_sections):
        report["notes"].append(
            "the section tables differ in length, so section content was not compared")
        return report

    relocations = _find_section(disk_pe, ".reloc")
    relocated: Set[int] = set()
    if relocations is not None:
        relocated = _relocated_pages(_read_all(
            disk_read, relocations["pointer_to_raw_data"],
            min(int(relocations["size_of_raw_data"]), _MAX_RELOC_BYTES)))

    entry_point = int(disk_pe["entry_point"])
    budget = _MAX_TOTAL_COMPARE
    for index, section in enumerate(disk_sections):
        memory_section = memory_sections[index]
        name = section["name"] or "?"
        if any(section[field] != memory_section[field]
               for field in _SECTION_FIELDS if field != "name"):
            report["skipped_sections"].append(
                {"name": name, "reason": "the section table entry differs"})
            continue
        if section["discardable"]:
            report["skipped_sections"].append(
                {"name": name,
                 "reason": "IMAGE_SCN_MEM_DISCARDABLE: the loader may unmap it"})
            continue
        length = _comparable_length(section)
        if length <= 0:
            report["skipped_sections"].append(
                {"name": name, "reason": "no file-backed content"})
            continue
        length = min(length, max_section_bytes, budget)
        if length <= 0:
            report["skipped_sections"].append(
                {"name": name, "reason": "comparison budget exhausted"})
            continue
        raw = _read_all(disk_read, section["pointer_to_raw_data"], length)
        span = max(int(section["virtual_size"]), int(section["size_of_raw_data"]))
        entry = {
            "name": name,
            "rva": int(section["virtual_address"]),
            "requested_bytes": length,
            "file_bytes": len(raw),
            "compared_bytes": 0,
            "mismatch_bytes": 0,
            "relocated_pages": 0,
            "unreadable_pages": 0,
            "entry_point_section": int(section["virtual_address"]) <= entry_point
            < int(section["virtual_address"]) + span,
        }
        if len(raw) < length:
            entry["truncated_disk_read"] = True
        for offset in range(0, len(raw), _PAGE_SIZE):
            step = min(_PAGE_SIZE, len(raw) - offset)
            page = (int(section["virtual_address"]) + offset) & _PAGE_MASK
            if page in relocated:
                entry["relocated_pages"] += 1
                continue
            data = memory_read(int(section["virtual_address"]) + offset, step)
            if data is None or len(data) < step:
                entry["unreadable_pages"] += 1
                continue
            entry["compared_bytes"] += step
            entry["mismatch_bytes"] += _mismatch_bytes(raw[offset:offset + step], data)
        budget -= entry["compared_bytes"]
        report["compared_bytes"] += entry["compared_bytes"]
        report["mismatch_bytes"] += entry["mismatch_bytes"]
        report["sections"].append(entry)
    return report


def _section_ratio(entry: Dict[str, Any]) -> float:
    """The mismatch fraction of one compared section, or 0.0 when nothing was
    compared.  The single definition both ``_worst_section`` and the
    entry-point precedence in :func:`_hollow_finding` grade against — section
    entries themselves do not carry the ratio, they carry the byte counts."""
    compared = int(entry.get("compared_bytes") or 0)
    if compared <= 0:
        return 0.0
    return int(entry.get("mismatch_bytes") or 0) / compared


def _worst_section(report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The compared section with the highest mismatch fraction, or ``None``."""
    worst: Optional[Dict[str, Any]] = None
    worst_ratio = 0.0
    for entry in report.get("sections") or []:
        if int(entry.get("compared_bytes") or 0) <= 0:
            continue
        ratio = _section_ratio(entry)
        if worst is None or ratio > worst_ratio:
            worst, worst_ratio = entry, ratio
    if worst is None:
        return None
    entry = dict(worst)
    entry["mismatch_ratio"] = round(_section_ratio(worst), 4)
    return entry


# -------------------------------------------------------------- pure: paths
def _module_path_kinds(path: Optional[str],
                       exists: Optional[bool]) -> List[str]:
    """Why a loaded module's path is worth a look: ``temp_path`` / ``missing_file``.

    Both signals are returned when both hold — a module in a drop zone that is
    also absent from disk is two independent reasons to look, and collapsing
    them would hide one.
    """
    kinds: List[str] = []
    if not path:
        return kinds
    lowered = path.lower()
    if any(marker in lowered for marker in _MODULE_DROP_ZONES):
        kinds.append("temp_path")
    if exists is False:
        kinds.append("missing_file")
    return kinds


def _image_newer_than_process(path: Optional[str],
                              start_epoch: Optional[float]) -> Optional[bool]:
    """``True`` when the file on disk was written after the process started.

    ``None`` means "not determined" (no start time, unreadable file), which is
    different from ``False``: the caller still compares, it just cannot rule the
    update case out.  A file replaced mid-flight is a software update far more
    often than it is an intrusion, so a newer file invalidates the comparison
    instead of producing a finding.
    """
    if not path or not start_epoch:
        return None
    try:
        modified = os.stat(path).st_mtime
    except OSError:
        return None
    return modified > float(start_epoch) + _MTIME_GRACE


# --------------------------------------------------------------- DLL plumbing
_BOUND = False


def _bind(libs: Dict[str, Any]) -> None:
    """Declare the prototypes this module uses.  Called once, on Windows.

    These are deliberately not in :mod:`jocky.rt.winapi`: that module collects a
    host, this one reads into other processes, and keeping the cross-process
    rights in one place makes them auditable in one place.
    """
    kernel32 = libs["kernel32"]
    winapi._proto(kernel32.ReadProcessMemory, _BOOL, _HANDLE, ctypes.c_void_p,
                  ctypes.c_void_p, _SIZE_T, ctypes.c_void_p)
    winapi._proto(kernel32.VirtualQueryEx, _SIZE_T, _HANDLE, ctypes.c_void_p,
                  ctypes.c_void_p, _SIZE_T)
    winapi._proto(kernel32.OpenThread, _HANDLE, _DWORD, _BOOL, _DWORD)
    winapi._proto(kernel32.Thread32First, _BOOL, _HANDLE, ctypes.c_void_p)
    winapi._proto(kernel32.Thread32Next, _BOOL, _HANDLE, ctypes.c_void_p)
    winapi._proto(libs["ntdll"].NtQueryInformationThread, _DWORD, _HANDLE, _DWORD,
                  ctypes.c_void_p, _DWORD, ctypes.c_void_p)
    winapi._proto(libs["psapi"].GetModuleInformation, _BOOL, _HANDLE, _HANDLE,
                  ctypes.c_void_p, _DWORD)


def _dlls() -> Optional[Dict[str, Any]]:
    """The libs :mod:`jocky.rt.winapi` loaded, plus this module's prototypes."""
    global _BOUND
    libs = winapi._dlls()
    if libs is None:
        return None
    if not _BOUND:
        # Order matters. Setting the flag first meant a raise inside ``_bind``
        # left it True, so every later call skipped the declaration and failed
        # at the first call on an undeclared prototype — an error a long way
        # from its cause.
        _bind(libs)
        _BOUND = True
    return libs


def available() -> bool:
    """True only on Windows, and only when every DLL this module needs loads."""
    return _dlls() is not None


# ------------------------------------------------------------ platform calls
def _open_image_process(pid: int,
                        errors: Optional[List[Dict[str, Any]]] = None) -> Optional[int]:
    """Open ``pid`` for reading, or ``None`` (the denial is reported).

    ``PROCESS_VM_READ`` is added on top of the query rights
    :func:`jocky.rt.winapi._open_process` asks for; nothing more.  A protected
    process refuses both attempts and lands in the denial log rather than being
    silently absent from the scan.
    """
    libs = _dlls()
    if libs is None:
        return None
    kernel32 = libs["kernel32"]
    for access in (_PROCESS_QUERY_LIMITED_INFORMATION | _PROCESS_VM_READ,
                   _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ):
        handle = kernel32.OpenProcess(access, False, int(pid))
        if handle:
            return int(handle)
    code, text = winapi._last_error()
    winapi._report("OpenProcess(pid=%d, VM_READ)" % int(pid),
                   text or "access denied", code, errors)
    return None


def _read_remote(handle: int, address: int, size: int,
                 errors: Optional[List[Dict[str, Any]]] = None,
                 scope: str = "ReadProcessMemory") -> Optional[bytes]:
    """A bounded ``ReadProcessMemory``; ``None`` on failure (denial recorded)."""
    libs = _dlls()
    if libs is None:
        return None
    if size <= 0:
        return b""
    buffer = ctypes.create_string_buffer(size)
    read = _SIZE_T(0)
    try:
        ok = libs["kernel32"].ReadProcessMemory(
            _HANDLE(handle), ctypes.c_void_p(int(address)), buffer, _SIZE_T(size),
            ctypes.byref(read))
    except (OSError, ValueError):
        ok = False
    if not ok:
        winapi._fail(scope, errors)
        return None
    return buffer.raw[:read.value]


def _bounded_reader(handle: int, base: int, size: int,
                    errors: Optional[List[Dict[str, Any]]] = None
                    ) -> Callable[[int, int], Optional[bytes]]:
    """A reader over one module's image, clamped to ``[0, size)``.

    The bound is the point: a comparison against attacker-influenced headers must
    never be able to ask the kernel for a read past the module it is examining.
    """
    def read(offset: int, length: int) -> Optional[bytes]:
        if length <= 0 or offset < 0 or offset >= size:
            return b""
        return _read_remote(handle, base + offset, min(length, size - offset),
                            errors, "ReadProcessMemory(module)")

    return read


def _file_reader(stream: Any) -> Callable[[int, int], bytes]:
    """A reader over an open file handle, seeking rather than buffering it all."""
    def read(offset: int, length: int) -> bytes:
        if length <= 0 or offset < 0:
            return b""
        stream.seek(offset)
        return stream.read(length)

    return read


def _regions(handle: int, errors: Optional[List[Dict[str, Any]]] = None,
             max_regions: int = _MAX_REGIONS) -> Optional[Dict[str, Any]]:
    """Walk a process's address space with ``VirtualQueryEx``.

    Returns ``{"regions": [...], "complete": bool}``, or ``None`` when the very
    first query failed — "this account cannot see the address space at all",
    which the caller reports rather than rounding down to "no regions found".
    """
    libs = _dlls()
    if libs is None:
        return None
    kernel32 = libs["kernel32"]
    info = _MBI()
    info_size = ctypes.sizeof(info)
    address = 0
    rows: List[Dict[str, Any]] = []
    complete = False
    while address < _USER_SPACE_TOP:
        if len(rows) >= max_regions:
            break
        written = kernel32.VirtualQueryEx(_HANDLE(handle), ctypes.c_void_p(address),
                                          ctypes.byref(info), _SIZE_T(info_size))
        if not written:
            winapi._fail("VirtualQueryEx", errors)
            if not rows:
                # The documented contract, and the caller depends on it: no
                # region was ever readable, so this is "cannot see the address
                # space at all", not "no private executable memory here". The
                # old code returned an empty complete=False walk instead, which
                # the caller recorded as a truncated walk and then reported
                # nothing for — a refusal reading as a clean process.
                return None
            break
        base = int(info.BaseAddress or 0)
        size = int(info.RegionSize or 0)
        rows.append({
            "base": base,
            "size": size,
            "allocation_base": int(info.AllocationBase or 0),
            "state": int(info.State),
            "type": int(info.Type),
            "protect": int(info.Protect),
            "allocation_protect": int(info.AllocationProtect),
            "protection": _protection_name(int(info.Protect)),
        })
        if size <= 0:
            break
        if base + size >= _USER_SPACE_TOP:
            complete = True
            break
        address = base + size
    else:
        complete = True
    return {"regions": rows, "complete": complete}


def _module_ranges(handle: int,
                   errors: Optional[List[Dict[str, Any]]] = None
                   ) -> Optional[Dict[str, Any]]:
    """``{"modules": [...], "complete": bool, "main": {...}|None}``.

    ``EnumProcessModulesEx`` with ``LIST_MODULES_ALL`` so a WOW64 process does not
    look empty; ``GetModuleInformation`` turns each base into the mapped extent,
    which is what a thread start address has to be tested against.

    ``complete`` is the load-bearing part for the thread check.  "This thread
    starts outside every loaded module" is only true against a *complete* module
    list, so a module whose extent could not be queried makes the answer
    incomplete — the thread check then reports the gap instead of accusing a
    thread that the missing range would have covered.  ``None`` means even the
    list itself was refused (the denial is recorded either way).
    """
    libs = _dlls()
    if libs is None:
        return None
    psapi = libs["psapi"]
    needed = _DWORD(0)
    if not psapi.EnumProcessModulesEx(_HANDLE(handle), None, 0, ctypes.byref(needed),
                                      _LIST_MODULES_ALL) and not needed.value:
        winapi._fail("EnumProcessModulesEx(size)", errors)
        return None
    count = int(needed.value) // _POINTER_SIZE
    if count <= 0 or count > _MAX_MODULES:
        winapi._report("EnumProcessModulesEx",
                       "implausible module count %d" % count, 0, errors)
        return None
    bases = (_HANDLE * count)()
    if not psapi.EnumProcessModulesEx(_HANDLE(handle), bases, int(needed.value),
                                      ctypes.byref(needed), _LIST_MODULES_ALL):
        winapi._fail("EnumProcessModulesEx", errors)
        return None
    rows: List[Dict[str, Any]] = []
    complete = True
    main: Optional[Dict[str, Any]] = None
    for index, base in enumerate(bases):
        info = _MODULEINFO()
        if not psapi.GetModuleInformation(_HANDLE(handle), _HANDLE(base),
                                          ctypes.byref(info), _DWORD(ctypes.sizeof(info))):
            winapi._fail("GetModuleInformation", errors)
            complete = False
            continue
        start = int(info.lpBaseOfDll or base or 0)
        size = int(info.SizeOfImage)
        rows.append({"base": start, "size": size, "end": start + size})
        if index == 0:
            main = rows[-1]
    # ``EnumProcessModulesEx`` lists the main executable first, so ``main`` is
    # only set when *that* first base answered — a failed query for it must not
    # silently promote the second module to "the main module", which would then
    # be compared against the process's image path and mismatch every time.
    return {"modules": rows, "complete": complete, "main": main}


def _thread_rows(errors: Optional[List[Dict[str, Any]]] = None
                 ) -> Optional[List[Dict[str, Any]]]:
    """Every thread the snapshot can see: ``{"tid", "pid"}``.

    The Toolhelp thread snapshot needs no handle on the owning process, so the
    thread inventory survives even for processes whose memory this account may
    not read — which is what turns "the threads are there but their start
    addresses are not" into a reported gap instead of an empty answer.
    """
    libs = _dlls()
    if libs is None:
        return None
    kernel32 = libs["kernel32"]
    snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
    if not snapshot or int(snapshot) == winapi._INVALID_HANDLE:
        winapi._fail("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)", errors)
        return None
    entry = _THREADENTRY32()
    entry.dwSize = ctypes.sizeof(_THREADENTRY32)
    rows: List[Dict[str, Any]] = []
    try:
        ok = kernel32.Thread32First(_HANDLE(snapshot), ctypes.byref(entry))
        while ok:
            rows.append({"tid": int(entry.th32ThreadID),
                         "pid": int(entry.th32OwnerProcessID)})
            ok = kernel32.Thread32Next(_HANDLE(snapshot), ctypes.byref(entry))
    finally:
        winapi._close(int(snapshot))
    return rows


def _open_thread(tid: int,
                 errors: Optional[List[Dict[str, Any]]] = None) -> Optional[int]:
    """Open a thread handle, query rights only, or ``None`` (reported)."""
    libs = _dlls()
    if libs is None:
        return None
    kernel32 = libs["kernel32"]
    for access in (_THREAD_QUERY_INFORMATION | _THREAD_QUERY_LIMITED_INFORMATION,
                   _THREAD_QUERY_LIMITED_INFORMATION):
        handle = kernel32.OpenThread(access, False, int(tid))
        if handle:
            return int(handle)
    code, text = winapi._last_error()
    winapi._report("OpenThread(tid=%d)" % int(tid), text or "access denied", code,
                   errors)
    return None


def _thread_start(handle: int,
                  errors: Optional[List[Dict[str, Any]]] = None) -> Optional[int]:
    """Win32 start address of an open thread (``None`` when the class is refused).

    This is the address the thread was *created* with, which is exactly what a
    hijack or ``CreateRemoteThread`` leaves pointing at its payload.  Windows
    reports zero for threads it started itself, and zero is returned as-is: the
    caller counts those separately rather than calling them unbacked.
    """
    libs = _dlls()
    if libs is None:
        return None
    value = ctypes.c_void_p(0)
    status = libs["ntdll"].NtQueryInformationThread(
        _HANDLE(handle), _THREAD_QUERY_SET_WIN32_START_ADDRESS,
        ctypes.byref(value), _DWORD(ctypes.sizeof(value)), None)
    if status != 0:
        winapi._report("NtQueryInformationThread(ThreadQuerySetWin32StartAddress)",
                       "status 0x%08X" % (int(status) & 0xFFFFFFFF), 0, errors)
        return None
    return int(value.value or 0)


# ------------------------------------------------------------------ shared
def _scan_targets(pids: Optional[Iterable[int]],
                  known: Optional[Dict[int, str]] = None
                  ) -> Tuple[List[int], int]:
    """``(pids_to_scan, dropped)`` — the second value is a reported gap.

    The cap exists so a hostile or broken host cannot make a sweep unbounded; the
    dropped count is returned rather than swallowed, because "I scanned the first
    4096 processes" and "I scanned every process" must not look the same in a
    report.
    """
    if pids is None:
        every = sorted(known) if known is not None else winapi.list_pids()
        return every[:_MAX_PIDS], max(0, len(every) - _MAX_PIDS)
    out: List[int] = []
    for pid in pids:
        try:
            value = int(pid)
        except (TypeError, ValueError):
            continue
        if value > 0 and value not in out:
            out.append(value)
    return out[:_MAX_PIDS], max(0, len(out) - _MAX_PIDS)


def _cap_gap(dropped: int, known: Optional[Dict[int, str]]) -> List[Dict[str, Any]]:
    """The ``skipped`` row for processes beyond the sweep cap, or ``()``."""
    if dropped <= 0:
        return []
    total = len(known) if known is not None else None
    return [{"pid": None, "process": None,
             "reason": "%d process(es) beyond the %d-process sweep cap%s"
                       % (dropped, _MAX_PIDS,
                          "" if total is None else " of %d visible" % total)}]


def _name_of(names: Dict[int, str], pid: int) -> str:
    """Process name for a pid, or ``"?"`` when the snapshot had no name."""
    return names.get(pid) or "?"


def _process_names() -> Optional[Dict[int, str]]:
    """``pid -> name`` for the host, or ``None`` when the snapshot failed.

    An empty snapshot on a running Windows host is a *failure*, not a host with
    no processes — ``System Idle Process`` and ``System`` always exist.
    :func:`jocky.rt.winapi._snapshot_processes` returns ``[]`` when the toolhelp
    snapshot itself cannot be taken, and the four detectors then resolved no
    names, targeted nothing through :func:`_scan_targets`, and returned ``[]``:
    a refusal that is byte-identical in shape to a clean sweep. The caller turns
    ``None`` into a ``partial_visibility`` note instead.
    """
    rows = winapi._snapshot_processes()
    if not rows:
        return None
    return {row["pid"]: row["name"] for row in rows}


def _snapshot_gap(detector: str) -> Dict[str, Any]:
    """The note for a sweep that could not list the host's processes at all."""
    return _finding(
        "partial_visibility", "info",
        f"{detector}: the process snapshot failed, so no process was inspected",
        {"detector": detector, "processes_scanned": 0,
         "snapshot_failed": True, "platform": sys.platform},
        "re-run elevated (SeDebugPrivilege) before treating this as a clean "
        "result; nothing was scanned",
    )


# ------------------------------------------------------- check: hollowing
def _hollow_finding(pid: int, name: str, image_path: str, base: int, size: int,
                    report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Grade one image comparison into a finding (or ``None`` when it matches).

    Precedence is by strength of evidence: a structural difference (a different
    PE) outranks a byte difference, and an entry-point-section difference
    outranks the same difference elsewhere, because the entry point is where a
    replaced payload has to live to run.
    """
    memory_pe = report["memory"]
    if memory_pe is None:
        return None
    disk_pe = report["disk"]
    sections = report["sections"]
    mismatch: Optional[str] = None
    severity = "medium"
    title = ""
    if disk_pe is None:
        mismatch, severity = "disk_not_pe", "high"
        title = (f"pid {pid} ({name}) is running from {image_path}, which is no "
                 f"longer a PE image")
    elif report["header_differences"]:
        mismatch, severity = "headers", "high"
        title = (f"pid {pid} ({name}) mapped PE headers do not match {image_path}")
    elif report["section_differences"]:
        mismatch, severity = "section_table", "high"
        title = (f"pid {pid} ({name}) mapped section table does not match "
                 f"{image_path}")
    else:
        truncated = [entry["name"] for entry in sections
                     if entry.get("truncated_disk_read")]
        # The entry-point section is tested FIRST and on its own ratio, not as
        # a property of whichever section happens to be noisiest. Selecting
        # `_worst_section` first meant that ordinary IAT churn in `.rdata` (the
        # module's own measurements put it at up to 70% on healthy hosts) could
        # out-noise a >5% rewrite of the entry-point section and bury it at
        # `info` — the opposite of the precedence this function documents.
        entry_section = next(
            (entry for entry in sections if entry.get("entry_point_section")), None)
        worst = _worst_section(report)
        if truncated:
            mismatch, severity = "disk_truncated", "high"
            title = (f"pid {pid} ({name}) image file is shorter than its own "
                     f"headers declare")
        elif (entry_section is not None
              and _section_ratio(entry_section) > _MISMATCH_FRACTION):
            mismatch, severity = "entry_point_content", "high"
            title = (f"pid {pid} ({name}) entry-point section "
                     f"{entry_section['name']} differs from {image_path} "
                     f"({entry_section['mismatch_bytes']} of "
                     f"{entry_section['compared_bytes']} bytes)")
        elif worst is not None and worst["mismatch_ratio"] > _MISMATCH_FRACTION:
            # ``info``, not ``medium``, and the measurement is why. On a
            # healthy Windows 11 host this comparison fires on essentially
            # every process — measured across the machine: `.fptable` 43x,
            # `fothk` 41x, `.rdata` 36x, `.data` 11x, `.idata` 3x — at a
            # median of 1.06% of section bytes and up to 70%. The loader
            # writes the resolved Import Address Table into `.rdata`/`.idata`
            # on every process that imports anything, JIT engines rewrite
            # their own code, and `.data` is writable by design. A verdict
            # cannot rest on bytes the loader and the runtime are entitled to
            # write, so the *structural* classes above keep the severity and
            # this one is context an analyst may confirm.
            mismatch, severity = "section_content", "info"
            title = (f"pid {pid} ({name}) section {worst['name']} differs from "
                     f"{image_path} ({worst['mismatch_bytes']} of "
                     f"{worst['compared_bytes']} bytes)")
        else:
            # Nothing crossed the fraction. Returning here also keeps `mismatch`
            # and `title` guaranteed-bound on every path below, which the old
            # shape did not: with no branch taken they were simply unset and the
            # `if mismatch is None` guard raised instead of returning.
            return None
    evidence = {
        "pid": pid,
        "process": name,
        "image": image_path,
        "image_base": base,
        "module_size": size,
        "mismatch": mismatch,
        "header_differences": report["header_differences"][:_MAX_EVIDENCE_ITEMS],
        "section_differences": report["section_differences"][:_MAX_EVIDENCE_ITEMS],
        "sections": sections[:_MAX_EVIDENCE_ITEMS],
        "skipped_sections": report["skipped_sections"][:_MAX_EVIDENCE_ITEMS],
        "compared_bytes": report["compared_bytes"],
        "mismatch_bytes": report["mismatch_bytes"],
        "notes": report["notes"][:_MAX_EVIDENCE_ITEMS],
        "disk_entry_point": None if disk_pe is None else disk_pe["entry_point"],
        "memory_entry_point": memory_pe["entry_point"],
        "disk_size_of_image": None if disk_pe is None else disk_pe["size_of_image"],
        "memory_size_of_image": memory_pe["size_of_image"],
    }
    if mismatch == "disk_not_pe":
        recommendation = (
            "the process is running an image whose file has been replaced or "
            "truncated since load; capture a memory image of the process and "
            "recover the mapped PE before it exits")
    elif mismatch in ("headers", "section_table", "disk_truncated"):
        recommendation = (
            "capture the process image and compare the mapped payload against a "
            "known-good copy of the file from the installation media; a mapped "
            "image that is structurally not the file on disk is the process-"
            "hollowing signature")
    else:
        recommendation = (
            "context, not a finding: the loader writes the Import Address Table "
            "into .rdata/.idata on any process that imports anything, and JIT "
            "engines rewrite their own code, so this class fires on most "
            "processes. Compare the reported range against a known-good copy "
            "only if something else about this process is already suspicious")
    return _finding("hollowed_process", severity, title, evidence, recommendation)


def hollowed_processes(pids: Optional[Iterable[int]] = None) -> List[Dict[str, Any]]:
    """Compare every process's mapped main image against its file on disk.

    The question: *is the code running in this process the code on disk?*
    Process hollowing, process doppelgänging and replacement all end with a
    process whose mapped image is not (or is no longer) the file its image path
    names, so the check reads the PE headers and the section table from both
    sides and compares the file-backed content of each section page by page.

    How to read it: ``evidence["mismatch"]`` says which class of difference was
    found. ``headers``, ``section_table`` and ``disk_truncated`` are graded
    ``high``: a mapped image that is structurally not the file on disk is the
    hollowing signature, and nothing legitimate produces it. ``section_content``
    is graded ``info`` because the loader, JIT engines and hot patches all write
    to section bytes on ordinary processes — measured on a healthy host, this
    class fires on most running processes at a median of ~1% of bytes, so it is
    context rather than a verdict. ``evidence`` carries the exact byte counts
    either way.  ``skipped_sections`` names every section the comparison declined
    to judge, with the reason.

    The comparison is skipped, and reported as skipped, when the on-disk file is
    newer than the process (a software update invalidates it) or larger than
    :data:`_MAX_IMAGE_BYTES`.
    """
    libs = _dlls()
    if libs is None:
        return []
    names = _process_names()
    if names is None:
        return [_snapshot_gap("hollowed_processes")]
    targets, dropped = _scan_targets(pids, names)
    findings: List[Dict[str, Any]] = []
    denied: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = _cap_gap(dropped, names)
    for pid in targets:
        errors: List[Dict[str, Any]] = []
        name = _name_of(names, pid)
        handle = _open_image_process(pid, errors)
        if handle is None:
            denied.append({"pid": pid, "process": name, "reason": "OpenProcess denied"})
            continue
        try:
            walk = _module_ranges(handle, errors)
            main = None if walk is None else walk["main"]
            if main is None:
                denied.append({"pid": pid, "process": name,
                               "reason": "main module extent unreadable"})
                continue
            base, size = int(main["base"]), int(main["size"])
            if base <= 0 or size <= 0:
                skipped.append({"pid": pid, "process": name,
                                "reason": "main module base or size unavailable"})
                continue
            if size > _MAX_IMAGE_BYTES:
                skipped.append({"pid": pid, "process": name,
                                "reason": "image larger than the comparison budget"})
                continue
            image_path = winapi._query_image_path(handle, errors)
            if not image_path:
                denied.append({"pid": pid, "process": name,
                               "reason": "image path unreadable"})
                continue
            started = winapi._query_times(handle, errors).get("start_epoch")
            if _image_newer_than_process(image_path, started):
                skipped.append({"pid": pid, "process": name,
                                "reason": "image file was written after the process "
                                          "started (software update)"})
                continue
            try:
                with open(image_path, "rb") as stream:
                    report = _image_mismatch(_file_reader(stream),
                                             _bounded_reader(handle, base, size, errors))
            except OSError as exc:
                skipped.append({"pid": pid, "process": name,
                                "reason": "image file unreadable: %s"
                                          % (exc.strerror or exc)})
                continue
            finding = _hollow_finding(pid, name, image_path, base, size, report)
            if finding is not None:
                findings.append(finding)
        finally:
            winapi._close(handle)
        if errors:
            denied.append({"pid": pid, "process": name,
                           "reason": errors[0].get("error", "call failed")})
    note = _partial_finding("hollowed_processes", len(targets), denied, skipped)
    if note is not None:
        findings.append(note)
    return findings


# --------------------------------------------------- check: private exec memory
def executable_private_memory(pids: Optional[Iterable[int]] = None) -> List[Dict[str, Any]]:
    """Find committed, private, executable memory — where a mapped payload lives.

    The question: *is there code in this process that no file on disk accounts
    for?*  A region that is ``MEM_COMMIT`` + ``MEM_PRIVATE`` (not an image, not a
    mapped file) and carries an execute protection is where a manually mapped
    DLL, a shellcode stage and a reflective loader all end up.  The first bytes
    of each region are probed for a PE signature, because an ``MZ``/``PE`` header
    in private memory is a much stronger statement than an executable page.

    How to read it: one finding per process, with every region's base, size and
    protection in ``evidence["regions"]`` and the PE-carrying ones listed in
    ``evidence["pe_regions"]``. A region that carries a **PE header** is graded
    ``medium`` — nothing ordinary puts an image in private memory, that is the
    manual-mapping signature. A region without one is graded ``info``: measured
    on a healthy Windows 11 host, every one of 41 such findings was the JIT heap
    of a Chromium/Electron process (25 of them `brave.exe`), and protection alone
    cannot tell that from a payload. Correlate before escalating, and start with
    any region that carries a PE header.
    """
    libs = _dlls()
    if libs is None:
        return []
    names = _process_names()
    if names is None:
        return [_snapshot_gap("executable_private_memory")]
    targets, dropped = _scan_targets(pids, names)
    findings: List[Dict[str, Any]] = []
    denied: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = _cap_gap(dropped, names)
    for pid in targets:
        errors: List[Dict[str, Any]] = []
        name = _name_of(names, pid)
        handle = _open_image_process(pid, errors)
        if handle is None:
            denied.append({"pid": pid, "process": name, "reason": "OpenProcess denied"})
            continue
        try:
            walk = _regions(handle, errors)
            if walk is None:
                denied.append({"pid": pid, "process": name,
                               "reason": "VirtualQueryEx refused"})
                continue
            if not walk["complete"]:
                skipped.append({"pid": pid, "process": name,
                                "reason": "address-space walk truncated"})
            interesting = [region for region in walk["regions"]
                           if _is_private_executable_region(region)]
            if not interesting:
                continue
            regions: List[Dict[str, Any]] = []
            pe_regions: List[str] = []
            total = 0
            for region in interesting:
                total += int(region["size"])
                entry = {
                    "base": region["base"],
                    "size": region["size"],
                    "protection": region["protection"],
                    "allocation_base": region["allocation_base"],
                }
                if len(regions) >= _MAX_PROBED_REGIONS:
                    # Not probed is not "not a PE": the count says how many
                    # regions were left, and ``region_count`` holds the total.
                    entry["probed"] = False
                    regions.append(entry)
                    continue
                probe = _read_remote(handle, region["base"],
                                     min(_PE_PROBE_BYTES, int(region["size"])), errors)
                entry["probed"] = True
                entry["readable"] = probe is not None
                if probe is not None:
                    entry["looks_like_pe"] = _looks_like_pe(probe)
                    if entry["looks_like_pe"]:
                        pe_regions.append(hex(int(region["base"])))
                regions.append(entry)
            evidence = {
                "pid": pid,
                "process": name,
                "region_count": len(interesting),
                "total_bytes": total,
                "regions": regions[:_MAX_EVIDENCE_ITEMS],
                "pe_regions": pe_regions[:_MAX_EVIDENCE_ITEMS],
                "address_space_complete": walk["complete"],
            }
            recommendation = (
                "JIT runtimes (CLR, JVM, V8/Electron) allocate executable private "
                "pages that look exactly like this; correlate with the process's "
                "module list, its thread start addresses and its parent chain before "
                "escalating, and dump the region first when it carries a PE header")
            if pe_regions:
                recommendation = (
                    "a PE header inside private memory is the manual-mapping "
                    "signature: dump each reported region, hash it, and pivot on the "
                    "thread start addresses that point into it")
            # Grading follows the discriminator the recommendation already names.
            # Measured on a healthy Windows 11 host: 41 private-executable-region
            # findings, **none** carrying a PE header, 25 of them brave.exe and the
            # rest other Chromium/Electron processes — V8 allocating its JIT heap.
            # A protect-only signal cannot distinguish that from a payload, so a
            # region without a PE header is context; one that has a header is the
            # finding.
            findings.append(_finding(
                "private_executable_memory", "medium" if pe_regions else "info",
                f"pid {pid} ({name}) has {len(interesting)} private executable "
                f"region(s), {total // 1024} KiB"
                + ("" if pe_regions else " (no PE header — JIT shape)"),
                evidence, recommendation))
        finally:
            winapi._close(handle)
        if errors:
            denied.append({"pid": pid, "process": name,
                           "reason": errors[0].get("error", "call failed")})
    note = _partial_finding("executable_private_memory", len(targets), denied, skipped)
    if note is not None:
        findings.append(note)
    return findings


# ------------------------------------------------ check: unbacked thread starts
def unbacked_executable_threads(pids: Optional[Iterable[int]] = None) -> List[Dict[str, Any]]:
    """Find threads whose start address lies outside every loaded module.

    The question: *does any thread in this process begin in memory that no image
    accounts for?*  A thread start address inside a module is the normal case
    (``kernel32!BaseThreadInitThunk`` and the image's entry point both are); an
    address in private memory means the thread was pointed at something loaded
    into the process rather than mapped from disk, which is what
    ``CreateRemoteThread``, ``NtCreateThreadEx`` and thread execution hijacking
    leave behind.

    How to read it: one finding per process, ``high``, listing each unbacked
    thread with its start address and, when the address falls inside one of the
    private executable regions from :func:`executable_private_memory`, that
    region's protection.  Threads Windows reports a start address of zero for
    (system-created) are counted as ``unknown`` rather than accused.  Correlate
    with the module list, the region protections and the process's parent chain
    before escalating — a start address outside the module list is a fact, and
    only the analyst can decide what loaded it.
    """
    libs = _dlls()
    if libs is None:
        return []
    names = _process_names()
    if names is None:
        return [_snapshot_gap("unbacked_executable_threads")]
    targets, dropped = _scan_targets(pids, names)
    wanted = set(targets)
    snapshot_errors: List[Dict[str, Any]] = []
    threads = _thread_rows(snapshot_errors)
    findings: List[Dict[str, Any]] = []
    denied: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = _cap_gap(dropped, names)
    if threads is None:
        note = _partial_finding(
            "unbacked_executable_threads", len(targets),
            [{"pid": None, "process": None, "reason": "thread snapshot failed"}],
            skipped)
        return [note] if note is not None else []
    grouped: Dict[int, List[int]] = {}
    for row in threads:
        if row["pid"] in wanted:
            grouped.setdefault(row["pid"], []).append(row["tid"])
    for pid in targets:
        tids = grouped.get(pid)
        if not tids:
            continue
        name = _name_of(names, pid)
        errors: List[Dict[str, Any]] = []
        # Query rights only: judging a start address needs the module list, not
        # the process's memory, and asking for less is what lets this check run
        # against processes the hollowing comparison cannot touch.
        handle = winapi._open_process(pid, errors)
        if handle is None:
            denied.append({"pid": pid, "process": name, "reason": "OpenProcess denied"})
            continue
        try:
            walk = _module_ranges(handle, errors)
            if walk is None or not walk["modules"]:
                denied.append({"pid": pid, "process": name,
                               "reason": "module list unreadable"})
                continue
            if not walk["complete"]:
                # A module whose extent is unknown could cover the very address
                # we are about to call unbacked, so the claim is not made.
                skipped.append({"pid": pid, "process": name,
                                "reason": "module map incomplete: a module extent "
                                          "could not be read"})
                continue
            spans = [(int(entry["base"]), int(entry["end"]))
                     for entry in walk["modules"] if int(entry["size"]) > 0]
            unbacked: List[Dict[str, Any]] = []
            unknown = 0
            for tid in tids:
                thread = _open_thread(tid, errors)
                if thread is None:
                    unknown += 1
                    continue
                try:
                    start = _thread_start(thread, errors)
                finally:
                    winapi._close(thread)
                if start is None:
                    unknown += 1
                    continue
                if start == 0:
                    unknown += 1
                    continue
                if _address_backed(start, spans):
                    continue
                unbacked.append({"tid": tid, "start": hex(start),
                                 "start_value": start})
            if not unbacked:
                continue
            private = _private_region_lookup(handle, errors)
            for entry in unbacked:
                region = _region_containing(entry["start_value"], private)
                if region is not None:
                    entry["protection"] = region["protection"]
                    entry["region_base"] = hex(int(region["base"]))
                    entry["in_private_executable_region"] = True
            findings.append(_finding(
                "unbacked_thread_start", "high",
                f"pid {pid} ({name}) has {len(unbacked)} thread(s) starting "
                f"outside every loaded module",
                {"pid": pid, "process": name, "threads": unbacked[:_MAX_EVIDENCE_ITEMS],
                 "unbacked_count": len(unbacked), "threads_listed": len(tids),
                 "unreadable_threads": unknown,
                 "modules_scanned": len(spans),
                 "modules": [hex(base) for base, _ in spans[:_MAX_EVIDENCE_ITEMS]]},
                "capture the memory at each reported start address before the "
                "process exits; a start address outside the module list belongs to "
                "code that was never mapped from disk — correlate with the private "
                "executable regions and with the parent process that created the "
                "thread"))
        finally:
            winapi._close(handle)
        if errors:
            denied.append({"pid": pid, "process": name,
                           "reason": errors[0].get("error", "call failed")})
    note = _partial_finding("unbacked_executable_threads", len(targets), denied,
                            skipped)
    if note is not None:
        findings.append(note)
    return findings


def _private_region_lookup(handle: int,
                           errors: Optional[List[Dict[str, Any]]] = None
                           ) -> List[Dict[str, Any]]:
    """The private executable regions of a process, for the thread cross-check.

    Built lazily and only when an unbacked thread was actually found, so the
    common case (every thread inside a module) pays nothing for it.  Best effort
    by construction: a refused walk returns an empty list, which means "not
    determined" — the finding is about the start address, not about the region.
    """
    walk = _regions(handle, errors)
    if walk is None:
        return []
    return [region for region in walk["regions"]
            if _is_private_executable_region(region)]


def _region_containing(address: int,
                       regions: Sequence[Dict[str, Any]]
                       ) -> Optional[Dict[str, Any]]:
    """The region a thread start address falls inside, or ``None``.

    Containment, not equality: a start address lands wherever inside the region
    the payload's entry point happens to be, so keying on the region base would
    miss every real case.
    """
    value = int(address)
    for region in regions:
        base = int(region.get("base") or 0)
        if base <= value < base + int(region.get("size") or 0):
            return region
    return None


# --------------------------------------------------- check: modules off drop zones
def modules_from_temp_paths(pids: Optional[Iterable[int]] = None) -> List[Dict[str, Any]]:
    """Find loaded modules whose file sits in a drop zone or is not on disk.

    The question: *is any image loaded into this process backed by a file an
    attacker could have written, or by no file at all?*  A DLL loaded from a temp
    directory, a user-writable share or ``ProgramData`` is the classic
    DLL-sideloading plant; a module that stays resident while its file is gone
    cannot be verified from the host at all and has to be recovered from memory.

    How to read it: one finding per (process, module, reason), ``medium``, with
    ``evidence["kind"]`` of ``temp_path`` or ``missing_file`` and the resolved
    path.  Both are reported when both hold.  Paths that cannot be resolved or
    stat'ed (device paths, refusals) are counted in the ``partial_visibility``
    note rather than guessed at — ``os.path.exists`` on a UNC path would put an
    SMB round trip inside a forensic sweep, which is why ``winapi`` only stats
    drive-letter paths.
    """
    libs = _dlls()
    if libs is None:
        return []
    names = _process_names()
    if names is None:
        return [_snapshot_gap("modules_from_temp_paths")]
    targets, dropped = _scan_targets(pids, names)
    findings: List[Dict[str, Any]] = []
    denied: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = _cap_gap(dropped, names)
    unresolved = 0
    for pid in targets:
        errors: List[Dict[str, Any]] = []
        name = _name_of(names, pid)
        modules = winapi.read_modules(pid, errors)
        if not modules:
            denied.append({"pid": pid, "process": name,
                           "reason": "module list unreadable"})
            continue
        for module in modules:
            raw_path = module.get("path") or ""
            path = winapi._normalise_driver_path(raw_path) or raw_path
            if not path:
                unresolved += 1
                continue
            exists = winapi._local_path_exists(path)
            if exists is None:
                unresolved += 1
                continue
            for kind in _module_path_kinds(path, exists):
                if kind == "temp_path":
                    title = (f"pid {pid} ({name}) loaded {module.get('name')} from "
                             f"a writable drop zone: {path}")
                    recommendation = (
                        "confirm the module against the installer or updater that "
                        "placed it there; if it is unexplained, hash the file, dump "
                        "the process and check whether the module is signed")
                else:
                    title = (f"pid {pid} ({name}) has {module.get('name')} loaded "
                             f"with no file on disk: {path}")
                    recommendation = (
                        "the module cannot be verified from the host; capture a "
                        "memory image and recover the mapped image before the "
                        "process exits or the host reboots")
                findings.append(_finding(
                    "module_from_temp_path", "medium", title,
                    {"pid": pid, "process": name, "module": module.get("name"),
                     "path": path, "raw_path": raw_path, "kind": kind,
                     "base": module.get("base"), "file_exists": exists},
                    recommendation))
        if errors:
            denied.append({"pid": pid, "process": name,
                           "reason": errors[0].get("error", "call failed")})
    if unresolved:
        skipped.append({"pid": None, "process": None,
                        "reason": "%d module path(s) could not be resolved or "
                                  "stat'ed" % unresolved})
    note = _partial_finding(
        "modules_from_temp_paths", len(targets), denied, skipped,
        extra={"unresolved_module_paths": unresolved})
    if note is not None:
        findings.append(note)
    return findings
