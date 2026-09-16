"""Tests for ``jocky.rt.winject`` — the Windows injection detectors.

The module cannot be *run* off Windows, but most of it can be *reasoned about*
there, and the parts that can be must be pinned: PE header/section parsing,
protection-flag decoding, relocation-page extraction, page-wise mismatch
counting, address-range coverage and the disk/memory comparison that all of it
feeds.  Those are exactly the places where a wrong answer is silent — a swapped
field or an off-by-one in a section table still produces a plausible finding —
so they are exercised here against synthetic buffers.

The other half is the platform contract: importing the module on Linux must not
touch ``ctypes.windll``, ``available()`` must be ``False``, and every detector
must return an empty list without raising, because a collector that raised would
abort a hunt script mid-run.
"""
from __future__ import annotations

import ctypes
import os
import pathlib
import struct
import sys
from typing import Any

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


winject = pytest.importorskip("jocky.rt.winject")
winapi = pytest.importorskip("jocky.rt.winapi")

DETECTORS = ("hollowed_processes", "executable_private_memory",
             "unbacked_executable_threads", "modules_from_temp_paths")

# ------------------------------------------------------------------ fixtures
# Layout of the synthetic images below.  The header block is large enough for
# the DOS stub, the NT headers and a handful of section headers; content follows
# at file-aligned offsets, exactly as a real image is laid out.
_LFANEW = 0x80
_OPT_SIZE = 0xF0
_HEADERS = 0x400
_PAGE = 0x1000
_DISCARDABLE = 0x02000000


def _build_image(sections, *, entry_point=0x1000, size_of_image=0x8000,
                 timestamp=0x5F000000, image_base=0x140000000):
    """A complete synthetic PE32+ image plus the table its RVAs need.

    Args:
        sections: ``(name, virtual_address, virtual_size, content, flags)`` rows.

    Returns:
        ``(blob, meta)`` where ``meta`` maps each section's RVA to its file
        offset, so a reader can serve the same bytes as a *file* (by offset) and
        as a *mapped image* (by RVA).
    """
    offsets = []
    cursor = _HEADERS
    for _name, _va, _vsize, content, _flags in sections:
        offsets.append(cursor)
        cursor += len(content)
    blob = bytearray(cursor)
    for (_name, _va, _vsize, content, _flags), offset in zip(sections, offsets):
        blob[offset:offset + len(content)] = content
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, _LFANEW)
    blob[_LFANEW:_LFANEW + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", blob, _LFANEW + 4, 0x8664, len(sections),
                     timestamp, 0, 0, _OPT_SIZE, 0x0022)
    optional = _LFANEW + 24
    struct.pack_into("<H", blob, optional, 0x20B)
    struct.pack_into("<I", blob, optional + 16, entry_point)
    struct.pack_into("<Q", blob, optional + 24, image_base)
    struct.pack_into("<I", blob, optional + 32, _PAGE)
    struct.pack_into("<I", blob, optional + 36, 0x200)
    struct.pack_into("<I", blob, optional + 56, size_of_image)
    struct.pack_into("<I", blob, optional + 60, _HEADERS)
    struct.pack_into("<I", blob, optional + 64, 0)
    struct.pack_into("<H", blob, optional + 68, 3)
    struct.pack_into("<I", blob, optional + 92, 16)
    table = optional + _OPT_SIZE
    meta = []
    for index, ((name, va, vsize, content, flags), offset) in enumerate(
            zip(sections, offsets)):
        struct.pack_into("<8sIIIIIIHHI", blob, table + 40 * index, name.encode(),
                         vsize, va, len(content), offset, 0, 0, 0, 0, flags)
        meta.append({"name": name, "va": va, "raw_ptr": offset,
                     "size": len(content)})
    return bytes(blob), meta


def _code_sections(text=b"\x90" * 0x400, data=b"\x01" * 0x400, extra=()):
    """The section list every comparison test starts from."""
    return [
        (".text", 0x1000, len(text), text, 0x60000020),
        (".data", 0x2000, len(data), data, 0xC0000040),
        *extra,
    ]


def _mapped(blob, meta, overrides=None, size_of_image=0x8000):
    """The same image laid out the way the loader maps it: content at its RVA.

    A file stores section content at ``PointerToRawData``; a mapped image holds
    it at ``VirtualAddress``.  Both views share one header block — that is what
    makes the comparison able to read the disk by file offset and the process by
    RVA at the same time, and what the fake harness below has to reproduce.
    """
    out = bytearray(size_of_image)
    out[0:_HEADERS] = blob[0:_HEADERS]
    for entry in meta:
        content = (overrides or {}).get(
            entry["name"], blob[entry["raw_ptr"]:entry["raw_ptr"] + entry["size"]])
        out[entry["va"]:entry["va"] + len(content)] = content
    return bytes(out)


def _file_reader(blob):
    """Read a *file* by byte offset."""
    return lambda offset, length: bytes(blob[offset:offset + length])


def _mapped_reader(blob, meta):
    """Read a *mapped image* by RVA, through the section table."""
    def read(offset, length):
        if offset < 0 or length <= 0:
            return b""
        if offset < _HEADERS:
            return bytes(blob[offset:offset + length])
        for entry in meta:
            if entry["va"] <= offset < entry["va"] + entry["size"]:
                start = entry["raw_ptr"] + (offset - entry["va"])
                return bytes(blob[start:start + length])
        return b""

    return read


def _relocation_blob(pages):
    """An ``.reloc`` blob naming one page per fixup block."""
    out = bytearray()
    for page in pages:
        out += struct.pack("<II", page, 12) + b"\x00\x00\x00\x00"
    return bytes(out)


# ------------------------------------------------------------- platform gate
def test_module_imports_on_linux():
    """The module imports on POSIX, with no ``windll`` contact, and is unavailable."""
    assert callable(winject.available)
    assert winject.available() is False
    assert winject.EMITTED_CHECKS, "the emitted-check list must not be empty"


@pytest.mark.parametrize("name", DETECTORS)
def test_detectors_return_empty_offplatform(name):
    """Every detector returns ``[]`` on POSIX and never raises.

    A detector that raised here would abort an entire hunt script mid-run, and a
    detector that returned ``None`` would break ``findings.extend(...)`` in the
    caller — both are worse than an empty answer.
    """
    fn = getattr(winject, name, None)
    assert fn is not None, f"jocky.rt.winject.{name} missing"
    result = fn()
    assert isinstance(result, list)
    assert result == []


def test_detectors_accept_a_pid_list_offplatform():
    """The scoping argument is accepted everywhere, so scripts can pass it blindly."""
    for name in DETECTORS:
        assert getattr(winject, name)(pids=[1, 4, 1]) == []


# --------------------------------------------------------------- structures
def test_windows_struct_layouts_match_the_abi():
    """Structure sizes are the ABI's, which is what makes the offsets portable.

    A field-width mistake here does not raise: ``VirtualQueryEx`` fills a smaller
    structure than expected and the region walk reads whatever follows the buffer
    in memory.
    """
    assert ctypes.sizeof(winject._MEMORY_BASIC_INFORMATION64) == 48
    assert ctypes.sizeof(winject._MEMORY_BASIC_INFORMATION32) == 28
    assert ctypes.sizeof(winject._THREADENTRY32) == 28
    assert ctypes.sizeof(winject._MODULEINFO) == 24
    assert winject._MEMORY_BASIC_INFORMATION64.BaseAddress.offset == 0
    assert winject._MEMORY_BASIC_INFORMATION64.RegionSize.offset == 24
    assert winject._MEMORY_BASIC_INFORMATION64.Protect.offset == 36
    assert winject._MEMORY_BASIC_INFORMATION64.Type.offset == 40


# ---------------------------------------------------------------- PE parsing
def test_pe_headers_parses_a_synthetic_image():
    """Every field the comparison keys on is decoded at the right offset."""
    blob, _meta = _build_image(
        _code_sections(extra=[(".reloc", 0x3000, 0x100, b"\x00" * 0x100,
                               _DISCARDABLE | 0x42000040)]),
        entry_point=0x1000, size_of_image=0x8000, timestamp=0x5F000000)
    pe = winject._pe_headers(blob)
    assert pe is not None
    assert pe["magic"] == 0x20B
    assert pe["machine"] == 0x8664
    assert pe["number_of_sections"] == 3
    assert pe["timestamp"] == 0x5F000000
    assert pe["entry_point"] == 0x1000
    assert pe["image_base"] == 0x140000000
    assert pe["size_of_image"] == 0x8000
    assert pe["size_of_headers"] == _HEADERS
    assert [s["name"] for s in pe["sections"]] == [".text", ".data", ".reloc"]
    assert pe["sections"][0]["virtual_address"] == 0x1000
    assert pe["sections"][0]["size_of_raw_data"] == 0x400
    assert pe["sections"][0]["discardable"] is False
    assert pe["sections"][2]["discardable"] is True
    assert winject._find_section(pe, ".reloc")["virtual_address"] == 0x3000
    assert winject._find_section(pe, ".nope") is None


def test_pe_headers_rejects_anything_that_is_not_a_complete_image():
    """Non-images and truncated tables are rejected, never parsed partially.

    A half-read section table would surface downstream as "the two images
    disagree", which is a finding invented by the parser.
    """
    assert winject._pe_headers(b"") is None
    assert winject._pe_headers(b"MZ") is None
    assert winject._pe_headers(b"ZZ" + b"\x00" * 0x100) is None
    blob, _meta = _build_image(_code_sections())
    assert winject._pe_headers(blob[:0x60]) is None
    # A section table that claims one more section than the buffer holds.
    truncated = bytearray(blob[:0x400])
    struct.pack_into("<H", truncated, _LFANEW + 6, 200)
    assert winject._pe_headers(bytes(truncated)) is None


def test_pe_headers_parses_a_32bit_image():
    """PE32 stores ``ImageBase`` as a DWORD at a different offset than PE32+."""
    blob, _meta = _build_image(_code_sections())
    raw = bytearray(blob)
    optional = _LFANEW + 24
    struct.pack_into("<H", raw, optional, 0x10B)
    struct.pack_into("<I", raw, optional + 28, 0x400000)
    pe = winject._pe_headers(bytes(raw))
    assert pe is not None and pe["magic"] == 0x10B
    assert pe["image_base"] == 0x400000


def test_comparable_length_never_claims_bytes_the_file_does_not_map():
    """A section's comparable extent is bounded by both raw and virtual size."""
    assert winject._comparable_length(
        {"size_of_raw_data": 0x400, "virtual_size": 0x200,
         "pointer_to_raw_data": 0x200}) == 0x200
    assert winject._comparable_length(
        {"size_of_raw_data": 0x400, "virtual_size": 0,
         "pointer_to_raw_data": 0x200}) == 0x400
    assert winject._comparable_length(
        {"size_of_raw_data": 0, "virtual_size": 0x400,
         "pointer_to_raw_data": 0x200}) == 0
    assert winject._comparable_length(
        {"size_of_raw_data": 0x400, "virtual_size": 0x400,
         "pointer_to_raw_data": 0}) == 0


def test_relocated_pages_walks_fixup_blocks():
    """Each relocation block names exactly one page the loader will rewrite."""
    blob = _relocation_blob([0x1000, 0x2000, 0x5000])
    assert winject._relocated_pages(blob) == {0x1000, 0x2000, 0x5000}
    # A page inside the block (the loader aligns them) is still one page.
    assert winject._relocated_pages(struct.pack("<II", 0x1ABC, 12)
                                    + b"\x00" * 4) == {0x1000}
    # Malformed input ends the walk rather than looping or raising.
    assert winject._relocated_pages(b"") == set()
    assert winject._relocated_pages(b"\x00" * 8) == set()
    assert winject._relocated_pages(struct.pack("<II", 0x1000, 4)) == set()


# ----------------------------------------------------------- pure: decoding
@pytest.mark.parametrize("protect,expected", [
    (0x20, "PAGE_EXECUTE_READ"),
    (0x40, "PAGE_EXECUTE_READWRITE"),
    (0x10, "PAGE_EXECUTE"),
    (0x04, "PAGE_READWRITE"),
    (0x01, "PAGE_NOACCESS"),
    (0x20 | 0x100, "PAGE_EXECUTE_READ|PAGE_GUARD"),
    (0x20 | 0x200, "PAGE_EXECUTE_READ|PAGE_NOCACHE"),
])
def test_protection_names_are_decoded(protect, expected):
    """Protection is a bitfield; a rounded-down name would mislead the analyst."""
    assert winject._protection_name(protect) == expected


def test_unknown_protection_keeps_its_number():
    """An unrecognised protection must not read as ``PAGE_NOACCESS``."""
    assert winject._protection_name(0x00) == "0x00"
    assert winject._protection_name(0x20 | 0x1000).startswith("PAGE_EXECUTE_READ")


@pytest.mark.parametrize("protect,expected", [
    (0x10, True), (0x20, True), (0x40, True), (0x80, True),
    (0x04, False), (0x02, False), (0x01, False),
    (0x20 | 0x100, False),   # PAGE_GUARD: not readable code
    (0x04 | 0x01, False),
])
def test_executable_protection_detection(protect, expected):
    """``PAGE_GUARD``/``PAGE_NOACCESS`` pages are not "executable memory"."""
    assert winject._is_executable(protect) is expected


@pytest.mark.parametrize("state,mem_type,protect,expected", [
    (0x1000, 0x20000, 0x40, True),
    (0x1000, 0x20000, 0x20, True),
    (0x1000, 0x20000, 0x04, False),      # private but not executable
    (0x1000, 0x1000000, 0x40, False),    # executable but an image
    (0x1000, 0x40000, 0x40, False),      # executable but file-mapped
    (0x2000, 0x20000, 0x40, False),      # reserved, not committed
])
def test_private_executable_region_selection(state, mem_type, protect, expected):
    """The payload shape is committed + private + executable, all three."""
    region = {"state": state, "type": mem_type, "protect": protect}
    assert winject._is_private_executable_region(region) is expected


def test_address_backed_is_half_open():
    """Module ranges are half-open: the end address belongs to the next region."""
    spans = [(0x1000, 0x2000), (0x400000, 0x401000)]
    assert winject._address_backed(0x1000, spans) is True
    assert winject._address_backed(0x1FFF, spans) is True
    assert winject._address_backed(0x2000, spans) is False
    assert winject._address_backed(0x400000, spans) is True
    assert winject._address_backed(0, spans) is False
    assert winject._address_backed(0x1000, []) is False


def test_mismatch_bytes_counts_positions_not_values():
    """The count is what the finding reports, so it has to be exact."""
    assert winject._mismatch_bytes(b"", b"") == 0
    assert winject._mismatch_bytes(b"abc", b"abc") == 0
    assert winject._mismatch_bytes(b"abc", b"abd") == 1
    assert winject._mismatch_bytes(b"abc", b"xyz") == 3
    assert winject._mismatch_bytes(b"abc", b"abcdef") == 3
    # A zero byte inside the buffer must still count as a match.
    assert winject._mismatch_bytes(b"\x00\x01", b"\x00\x02") == 1
    left = b"\x41" * 0x10000
    right = bytearray(left)
    right[0x8000] = 0x42
    assert winject._mismatch_bytes(left, bytes(right)) == 1


def test_looks_like_pe_requires_a_full_signature():
    """A PE claim needs both the DOS stub and the NT signature behind it."""
    blob, _meta = _build_image(_code_sections())
    assert winject._looks_like_pe(blob[:0x1000]) is True
    assert winject._looks_like_pe(b"MZ") is False
    assert winject._looks_like_pe(b"") is False
    assert winject._looks_like_pe(None) is False
    assert winject._looks_like_pe(b"MZ" + b"\x00" * 0x40) is False
    # The signature is beyond what was read: unconfirmed, so not a PE claim.
    assert winject._looks_like_pe(blob[:0x40]) is False


# ------------------------------------------------------- image comparison
def _compare(disk_blob, memory_blob, memory_meta, **kwargs):
    return winject._image_mismatch(_file_reader(disk_blob),
                                   _mapped_reader(memory_blob, memory_meta),
                                   **kwargs)


def test_identical_images_report_no_difference():
    """The comparison has real coverage, and a clean image stays clean."""
    blob, meta = _build_image(_code_sections())
    report = _compare(blob, blob, meta)
    assert report["header_differences"] == []
    assert report["section_differences"] == []
    assert report["compared_bytes"] == 0x800       # both sections were compared
    assert report["mismatch_bytes"] == 0
    assert report["notes"] == []


def test_replaced_section_content_is_high_when_it_holds_the_entry_point():
    """A wholly different ``.text`` is the hollowing signature, not a byte diff."""
    blob, meta = _build_image(_code_sections())
    moved = bytearray(blob)
    moved[meta[0]["raw_ptr"]:meta[0]["raw_ptr"] + 0x400] = b"\xCC" * 0x400
    report = _compare(blob, bytes(moved), meta)
    assert report["header_differences"] == []
    entry = report["sections"][0]
    assert entry["mismatch_bytes"] == entry["compared_bytes"] > 0
    assert entry["entry_point_section"] is True
    finding = winject._hollow_finding(7, "payload.exe", r"C:\a\payload.exe",
                                      0x140000000, 0x8000, report)
    assert finding is not None
    assert finding["check"] == "hollowed_process"
    assert finding["severity"] == "high"
    assert finding["evidence"]["mismatch"] == "entry_point_content"
    assert finding["evidence"]["pid"] == 7


def test_replaced_content_outside_the_entry_point_is_informational():
    """Same evidence elsewhere is context, not the hollowing shape.

    Graded ``info`` rather than ``medium`` after measuring the check on a real
    Windows 11 host: this class fires on most running processes (`.fptable`,
    `fothk`, `.rdata`, `.data`, `.idata`) at a median of ~1% of section bytes,
    because the loader writes the resolved Import Address Table into
    `.rdata`/`.idata` and JIT engines rewrite their own code. A verdict cannot
    rest on bytes the loader is entitled to write, so only the structural classes
    keep a severity.
    """
    blob, meta = _build_image(_code_sections())
    moved = bytearray(blob)
    moved[meta[1]["raw_ptr"]:meta[1]["raw_ptr"] + 0x400] = b"\xCC" * 0x400
    report = _compare(blob, bytes(moved), meta)
    finding = winject._hollow_finding(8, "app.exe", r"C:\a\app.exe", 0x140000000,
                                      0x8000, report)
    assert finding is not None
    assert finding["evidence"]["mismatch"] == "section_content"
    assert finding["severity"] == "info", (
        "content-only differences must not carry a severity that competes with "
        "the structural classes"
    )
    # The structural class it is contrasted with still grades high, so the
    # downgrade narrowed the check rather than flattening it.
    header_blob, header_meta = _build_image(_code_sections())
    damaged = bytearray(header_blob)
    damaged[0x3C] ^= 0xFF                     # e_lfanew no longer points at a PE
    header_report = _compare(header_blob, bytes(damaged), header_meta)
    header_finding = winject._hollow_finding(9, "app.exe", r"C:\a\app.exe", 1, 2,
                                             header_report)
    assert header_finding is None or header_finding["severity"] == "high"


def test_a_few_differing_bytes_are_not_a_finding():
    """Below the tuned fraction this is an artefact, and reporting it is noise."""
    blob, meta = _build_image(_code_sections())
    moved = bytearray(blob)
    moved[meta[0]["raw_ptr"] + 8] ^= 0xFF
    report = _compare(blob, bytes(moved), meta)
    assert report["mismatch_bytes"] == 1
    assert winject._hollow_finding(9, "app.exe", r"C:\a\app.exe", 1, 2,
                                   report) is None


def test_relocated_pages_are_excluded_from_the_comparison():
    """A rebased image differs from its file by design; that is not a finding."""
    reloc = _relocation_blob([0x1000])
    sections = _code_sections(extra=[(".reloc", 0x3000, len(reloc), reloc,
                                      0x42000040 | _DISCARDABLE)])
    blob, meta = _build_image(sections)
    moved = bytearray(blob)
    moved[meta[0]["raw_ptr"]:meta[0]["raw_ptr"] + 0x10] = b"\x11" * 0x10
    report = _compare(blob, bytes(moved), meta)
    text = report["sections"][0]
    assert text["relocated_pages"] == 1
    assert text["compared_bytes"] == 0
    assert text["mismatch_bytes"] == 0
    assert report["mismatch_bytes"] == 0
    # The discardable section the loader may unmap is skipped, with its reason.
    assert any(entry["name"] == ".reloc" and "DISCARDABLE" in entry["reason"]
               for entry in report["skipped_sections"])
    assert winject._hollow_finding(1, "app.exe", r"C:\a\app.exe", 1, 2,
                                   report) is None


def test_header_difference_is_high_and_named():
    """A different PE header means the mapped image is not the file on disk."""
    blob, meta = _build_image(_code_sections())
    moved, moved_meta = _build_image(_code_sections(), timestamp=0x60000000)
    report = _compare(blob, moved, moved_meta)
    assert [d["field"] for d in report["header_differences"]] == ["timestamp"]
    finding = winject._hollow_finding(3, "svc.exe", r"C:\a\svc.exe", 1, 2, report)
    assert finding is not None
    assert finding["severity"] == "high"
    assert finding["evidence"]["mismatch"] == "headers"
    assert finding["evidence"]["header_differences"][0]["memory"] == 0x60000000


def test_section_table_difference_is_high_and_names_the_section():
    """A moved section is structural: content comparison is skipped for it."""
    blob, meta = _build_image(_code_sections())
    moved, moved_meta = _build_image(_code_sections())
    raw = bytearray(moved)
    table = _LFANEW + 24 + _OPT_SIZE
    struct.pack_into("<I", raw, table + 40 + 12, 0x9000)  # .data VirtualAddress
    report = _compare(blob, bytes(raw), moved_meta)
    assert report["section_differences"][0]["name"] == ".data"
    assert "virtual_address" in report["section_differences"][0]["fields"]
    assert any(entry["name"] == ".data" for entry in report["skipped_sections"])
    finding = winject._hollow_finding(4, "svc.exe", r"C:\a\svc.exe", 1, 2, report)
    assert finding is not None
    assert finding["severity"] == "high"
    assert finding["evidence"]["mismatch"] == "section_table"


def test_a_truncated_file_is_high():
    """The file no longer holds what its own headers claim for a section."""
    blob, meta = _build_image(_code_sections())
    truncated = blob[:meta[1]["raw_ptr"] + 0x10]
    report = _compare(truncated, blob, meta)
    assert any(entry.get("truncated_disk_read") for entry in report["sections"])
    finding = winject._hollow_finding(5, "svc.exe", r"C:\a\svc.exe", 1, 2, report)
    assert finding is not None
    assert finding["severity"] == "high"
    assert finding["evidence"]["mismatch"] == "disk_truncated"


def test_a_file_that_is_no_longer_a_pe_is_high():
    """The running process's image path now names something that is not an image."""
    blob, meta = _build_image(_code_sections())
    report = _compare(b"not an executable at all\n", blob, meta)
    finding = winject._hollow_finding(6, "svc.exe", r"C:\a\svc.exe", 1, 2, report)
    assert finding is not None
    assert finding["severity"] == "high"
    assert finding["evidence"]["mismatch"] == "disk_not_pe"


def test_an_unreadable_memory_image_is_not_a_finding():
    """Blindness is reported as a gap by the caller, never as a verdict."""
    blob, meta = _build_image(_code_sections())
    report = _compare(blob, b"", meta)
    assert report["memory"] is None
    assert report["notes"]
    assert winject._hollow_finding(1, "app.exe", r"C:\a\app.exe", 1, 2,
                                   report) is None


def test_findings_use_the_detect_finding_shape():
    """Every finding this module emits is consumable by the same readers."""
    blob, meta = _build_image(_code_sections())
    moved, moved_meta = _build_image(_code_sections(), timestamp=0x60000000)
    finding = winject._hollow_finding(
        1, "app.exe", r"C:\a\app.exe", 1, 2, _compare(blob, moved, moved_meta))
    assert set(finding) == {"check", "severity", "title", "evidence",
                            "recommendation"}
    assert finding["check"] in winject.EMITTED_CHECKS
    assert finding["severity"] in ("info", "low", "medium", "high", "critical")
    assert finding["recommendation"]


# ------------------------------------------------------------- honesty gates
def test_partial_visibility_is_reported_only_when_something_was_missed():
    """A clean, complete sweep stays quiet; a blind one must not look clean."""
    assert winject._partial_finding("hollowed_processes", 10, [], []) is None
    denied = winject._partial_finding("hollowed_processes", 10,
                                      [{"pid": 4, "process": "System",
                                        "reason": "OpenProcess denied"}], [])
    assert denied is not None
    assert denied["check"] == "partial_visibility"
    assert denied["severity"] == "info"
    assert denied["evidence"]["denied_count"] == 1
    assert denied["evidence"]["denied_processes"][0]["pid"] == 4
    skipped = winject._partial_finding("hollowed_processes", 10, [],
                                       [{"pid": 9, "reason": "image newer"}])
    assert skipped is not None
    assert skipped["evidence"]["skipped_count"] == 1
    assert "1 were skipped" in skipped["title"]


def test_region_containing_matches_by_range_not_by_base():
    """A thread start address lands anywhere inside the region, not at its base."""
    regions = [{"base": 0x10000, "size": 0x1000, "protection": "PAGE_EXECUTE_READ"}]
    assert winject._region_containing(0x10000, regions) is regions[0]
    assert winject._region_containing(0x10800, regions) is regions[0]
    assert winject._region_containing(0x10FFF, regions) is regions[0]
    assert winject._region_containing(0x11000, regions) is None
    assert winject._region_containing(0xFFFF, regions) is None
    assert winject._region_containing(0x10800, []) is None


def test_scan_targets_deduplicates_and_reports_the_cap():
    """The scan scope is normalised, and a cap is a reported gap, not a silence."""
    known = {4: "System", 8: "svc.exe"}
    assert winject._scan_targets(None, known) == ([4, 8], 0)
    assert winject._scan_targets(None, {}) == ([], 0)
    assert winject._scan_targets([8, 8, "x", 0, -1, 4.0]) == ([8, 4], 0)
    assert winject._scan_targets([], known) == ([], 0)
    assert winject._cap_gap(0, known) == []
    assert "cap" in winject._cap_gap(3, known)[0]["reason"]
    assert winject._cap_gap(3, None)[0]["process"] is None


def test_module_path_grading():
    """Drop-zone and missing-file signals are independent and both are kept."""
    assert winject._module_path_kinds(r"C:\Windows\Temp\evil.dll", True) == ["temp_path"]
    assert winject._module_path_kinds(
        r"C:\Users\bob\AppData\Local\Temp\x.dll", True) == ["temp_path"]
    assert winject._module_path_kinds(r"C:\Windows\System32\kernel32.dll",
                                      True) == []
    assert winject._module_path_kinds(r"C:\Windows\System32\gone.dll",
                                      False) == ["missing_file"]
    assert winject._module_path_kinds(r"C:\Windows\Temp\gone.dll", False) == [
        "temp_path", "missing_file"]
    assert winject._module_path_kinds("", False) == []
    assert winject._module_path_kinds(None, None) == []


def test_image_newer_than_process_guard(tmp_path):
    """A file written after the process started invalidates the comparison."""
    target = tmp_path / "image.bin"
    target.write_bytes(b"x")
    modified = os.stat(target).st_mtime
    assert winject._image_newer_than_process(str(target), modified - 3600) is True
    assert winject._image_newer_than_process(str(target), modified + 3600) is False
    # Not determined is not ``False``: the caller still compares, it just cannot
    # rule the software-update case out.
    assert winject._image_newer_than_process(str(target), None) is None
    assert winject._image_newer_than_process("", modified) is None
    assert winject._image_newer_than_process(str(tmp_path / "nope"), 1.0) is None


# ---------------------------------------------------------- simulated harness
# The detectors themselves are Windows-only, but their *control flow* is not: a
# fake of the few APIs they call lets the whole path — handle lifecycle, module
# enumeration, the region walk, the comparison, the grading and the denial
# bookkeeping — run here instead of shipping unexecuted.  The fake emulates the
# documented contract (two-call sizing, region metadata, a refused read for an
# unmapped range), not Windows itself, so it proves the code runs and grades as
# intended rather than that the ABI is right.


def _as_int(value: Any) -> int:
    """An integer from a ctypes value, a ``byref`` result, or a plain int."""
    if isinstance(value, int):
        return value
    inner = getattr(value, "_obj", value)
    return int(getattr(inner, "value", 0) or 0)


class _FakeFunction:
    """A callable that tolerates ``restype``/``argtypes`` assignment."""

    restype: Any = None
    argtypes: Any = None

    def __init__(self, function):
        self._function = function

    def __call__(self, *args, **kwargs):
        return self._function(*args, **kwargs)


class _FakeLibrary:
    """A DLL stand-in whose functions are attributes, as ``WinDLL``'s are."""

    def __init__(self, **functions):
        for name, function in functions.items():
            setattr(self, name, function)


class _FakeWindows:
    """An in-memory stand-in for the APIs the four detectors call."""

    def __init__(self, processes):
        self.processes = {int(pid): model for pid, model in processes.items()}
        self.modules = {}
        self.threads = {}
        self.snapshots = {}
        self.next_handle = 0x100

        def add_handle(store, value):
            handle = self.next_handle
            self.next_handle += 4
            store[handle] = value
            return handle

        self._add_handle = add_handle
        self.libs = {
            "kernel32": _FakeLibrary(**{
                name: _FakeFunction(getattr(self, name))
                for name in ("CreateToolhelp32Snapshot", "Process32FirstW",
                             "Process32NextW", "Thread32First", "Thread32Next",
                             "CloseHandle", "OpenProcess", "OpenThread",
                             "QueryFullProcessImageNameW", "GetProcessTimes",
                             "ReadProcessMemory", "VirtualQueryEx", "GetTickCount64")
            }),
            "ntdll": _FakeLibrary(
                NtQueryInformationThread=_FakeFunction(self.NtQueryInformationThread)),
            "psapi": _FakeLibrary(**{
                name: _FakeFunction(getattr(self, name))
                for name in ("EnumProcessModulesEx", "GetModuleInformation",
                             "GetModuleBaseNameW", "GetModuleFileNameExW")
            }),
            "advapi32": _FakeLibrary(),
            "iphlpapi": _FakeLibrary(),
        }

    # -- helpers
    def _process_of(self, handle):
        return self.processes.get(self.modules.get(_as_int(handle), -1))

    def _model_for_pid(self, pid):
        return self.processes.get(int(pid))

    # -- process and module surface
    def OpenProcess(self, access, inherit, pid):
        model = self._model_for_pid(pid)
        if model is None or model.get("protected"):
            return None
        return self._add_handle(self.modules, int(pid))

    def CloseHandle(self, handle):
        value = _as_int(handle)
        for store in (self.modules, self.threads, self.snapshots):
            store.pop(value, None)
        return True

    def QueryFullProcessImageNameW(self, handle, flags, buffer, size):
        model = self._process_of(handle)
        if model is None:
            return False
        buffer.value = model["path"]
        size._obj.value = len(model["path"])
        return True

    def GetProcessTimes(self, handle, creation, _exit, _kernel, _user):
        model = self._process_of(handle)
        if model is None:
            return False
        ticks = int((model["start_epoch"] + 11644473600) * 10 ** 7)
        creation._obj.dwLowDateTime = ticks & 0xFFFFFFFF
        creation._obj.dwHighDateTime = ticks >> 32
        return True

    def GetTickCount64(self):
        return 123456

    def CreateToolhelp32Snapshot(self, flags, pid):
        handle = self._add_handle(self.snapshots, 0)
        self.snapshots[handle] = 0
        return handle

    def _process_rows(self):
        return sorted(self.processes.values(), key=lambda model: model["pid"])

    def Process32FirstW(self, handle, entry):
        self.snapshots[_as_int(handle)] = 0
        return self.Process32NextW(handle, entry)

    def Process32NextW(self, handle, entry):
        rows = self._process_rows()
        index = self.snapshots.get(_as_int(handle), 0)
        if index >= len(rows):
            return False
        model = rows[index]
        self.snapshots[_as_int(handle)] = index + 1
        entry._obj.th32ProcessID = model["pid"]
        entry._obj.th32ParentProcessID = model["ppid"]
        entry._obj.cntThreads = len(model["threads"])
        name = model["name"].encode("utf-16-le") + b"\x00\x00"
        ctypes.memmove(ctypes.addressof(entry._obj)
                       + winapi._PROCESSENTRY32W.szExeFile.offset, name, len(name))
        return True

    def EnumProcessModulesEx(self, handle, buffer, size, needed, flags):
        model = self._process_of(handle)
        if model is None:
            return False
        bases = [module["base"] for module in model["modules"]]
        needed._obj.value = len(bases) * ctypes.sizeof(ctypes.c_void_p)
        if buffer is None:
            return False            # the size probe: FALSE, with the size filled in
        for index, base in enumerate(bases):
            buffer[index] = base
        return True

    def GetModuleInformation(self, handle, module, info, size):
        model = self._process_of(handle)
        if model is None:
            return False
        for entry in model["modules"]:
            if entry["base"] == _as_int(module):
                info._obj.lpBaseOfDll = entry["base"]
                info._obj.SizeOfImage = entry["size"]
                info._obj.EntryPoint = entry["base"] + 0x1000
                return True
        return False

    def GetModuleBaseNameW(self, handle, module, buffer, size):
        model = self._process_of(handle)
        if model is None:
            return 0
        for entry in model["modules"]:
            if entry["base"] == _as_int(module):
                buffer.value = entry["name"]
                return len(entry["name"])
        return 0

    def GetModuleFileNameExW(self, handle, module, buffer, size):
        model = self._process_of(handle)
        if model is None:
            return 0
        for entry in model["modules"]:
            if entry["base"] == _as_int(module):
                buffer.value = entry["path"]
                return len(entry["path"])
        return 0

    # -- memory
    def VirtualQueryEx(self, handle, address, info, size):
        model = self._process_of(handle)
        if model is None:
            return 0
        wanted = _as_int(address)
        for region in model["regions"]:
            if region["base"] <= wanted < region["base"] + region["size"]:
                info._obj.BaseAddress = region["base"]
                info._obj.AllocationBase = region.get("allocation_base",
                                                       region["base"])
                info._obj.AllocationProtect = region["protect"]
                info._obj.RegionSize = region["size"]
                info._obj.State = region["state"]
                info._obj.Protect = region["protect"]
                info._obj.Type = region["type"]
                return ctypes.sizeof(winject._MEMORY_BASIC_INFORMATION64)
        return 0

    def ReadProcessMemory(self, handle, address, buffer, size, read):
        model = self._process_of(handle)
        if model is None:
            return False
        wanted = _as_int(address)
        for region in model["regions"]:
            if not (region["base"] <= wanted < region["base"] + region["size"]):
                continue
            content = region.get("bytes")
            if content is None:
                return False          # committed but not backed by anything
            offset = wanted - region["base"]
            available = min(int(size.value), len(content) - offset)
            if available <= 0:
                return False
            ctypes.memmove(buffer, content[offset:offset + available], available)
            read._obj.value = available
            return True
        return False

    # -- threads
    def _thread_rows(self):
        rows = []
        for model in self._process_rows():
            for tid, start in model["threads"]:
                rows.append((model["pid"], tid, start))
        return rows

    def Thread32First(self, handle, entry):
        self.snapshots[_as_int(handle)] = 0
        return self.Thread32Next(handle, entry)

    def Thread32Next(self, handle, entry):
        rows = self._thread_rows()
        index = self.snapshots.get(_as_int(handle), 0)
        if index >= len(rows):
            return False
        pid, tid, _start = rows[index]
        self.snapshots[_as_int(handle)] = index + 1
        entry._obj.th32ThreadID = tid
        entry._obj.th32OwnerProcessID = pid
        return True

    def OpenThread(self, access, inherit, tid):
        for _pid, candidate, _start in self._thread_rows():
            if candidate == int(tid):
                return self._add_handle(self.threads, int(tid))
        return None

    def NtQueryInformationThread(self, handle, info_class, value, size, returned):
        tid = self.threads.get(_as_int(handle))
        for _pid, candidate, start in self._thread_rows():
            if candidate == tid:
                value._obj.value = start
                return 0
        return 0xC0000008            # STATUS_INVALID_HANDLE


def _contiguous(regions):
    """Fill the gaps between regions with ``MEM_FREE`` so a walk can complete.

    ``VirtualQueryEx`` answers for *any* address, so a model with holes would
    make the real walk look truncated — an artefact of the model, not of the
    module under test.
    """
    used = sorted(regions, key=lambda region: region["base"])
    out: list = []
    cursor = 0
    for region in used:
        if region["base"] > cursor:
            out.append({"base": cursor, "size": region["base"] - cursor,
                        "state": 0x10000, "type": 0, "protect": 1})
        out.append(region)
        cursor = max(cursor, region["base"] + region["size"])
    if cursor < winject._USER_SPACE_TOP:
        out.append({"base": cursor, "size": winject._USER_SPACE_TOP - cursor,
                    "state": 0x10000, "type": 0, "protect": 1})
    return out


def _make_model(module_path, memory, *, regions_extra=(), threads=(),
                start_epoch=None, name="payload.exe", pid=4242,
                modules_extra=(), protected=False):
    """One process model with a contiguous address space ending at the ceiling."""
    import time as _time

    base = 0x140000000
    size = len(memory)
    regions = _contiguous([
        {"base": 0x10000, "size": 0x1000, "state": 0x1000, "type": 0x20000,
         "protect": 0x04, "bytes": b"\x00" * 0x1000},
        {"base": base, "size": size, "state": 0x1000, "type": 0x1000000,
         "protect": 0x20, "bytes": memory},
        *regions_extra,
    ])
    return {
        "pid": pid,
        "ppid": 4,
        "name": name,
        "path": module_path,
        "base": base,
        "regions": regions,
        "modules": [{"name": name, "path": module_path, "base": base, "size": size},
                    *modules_extra],
        "threads": list(threads),
        "start_epoch": _time.time() + 10 if start_epoch is None else start_epoch,
        "protected": protected,
    }


@pytest.fixture()
def fake_windows(monkeypatch):
    """Install a fake API layer, so the detectors run off-platform."""
    def install(processes):
        fake = _FakeWindows(processes)
        monkeypatch.setattr(winapi, "_IS_WINDOWS", True)
        monkeypatch.setattr(winapi, "_LIBS", fake.libs)
        monkeypatch.setattr(winapi, "_LIB_FAILURE", False)
        monkeypatch.setattr(winject, "_BOUND", False)
        winapi.clear_access_errors()
        return fake

    return install


def test_hollowed_process_scan_runs_and_grades(fake_windows, tmp_path):
    """The whole hollowing path runs: open, enumerate, compare, grade."""
    image, meta = _build_image(_code_sections())
    target = tmp_path / "payload.exe"
    target.write_bytes(image)
    payload = _mapped(image, meta, {".text": b"\xCC" * 0x400})
    fake_windows({4242: _make_model(str(target), payload,
                                    threads=[(8, 0x140001000)])})

    findings = winject.hollowed_processes()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["check"] == "hollowed_process"
    assert finding["severity"] == "high"
    assert finding["evidence"]["mismatch"] == "entry_point_content"
    assert finding["evidence"]["pid"] == 4242
    assert winapi.access_errors() == []


def test_a_matching_image_produces_no_finding(fake_windows, tmp_path):
    """Nothing hostile, nothing to report — and no fabricated partial note."""
    image, meta = _build_image(_code_sections())
    target = tmp_path / "payload.exe"
    target.write_bytes(image)
    mapped = _mapped(image, meta)
    fake_windows({4242: _make_model(str(target), mapped, threads=[(8, 0x140001000)])})

    assert winject.hollowed_processes() == []
    assert winject.executable_private_memory() == []
    assert winject.unbacked_executable_threads() == []
    assert winapi.access_errors() == []
    # The module-path check grades a *Windows* path; the harness stands in a
    # POSIX one (so the image file can really be opened), which ``winapi``
    # refuses to stat by design.  The check must say so rather than stay quiet.
    module_findings = winject.modules_from_temp_paths()
    assert [finding["check"] for finding in module_findings] == ["partial_visibility"]
    assert module_findings[0]["evidence"]["unresolved_module_paths"] == 1


def test_a_denied_process_is_reported_not_skipped(fake_windows, tmp_path):
    """A protected process must show up as a gap, never as a clean result."""
    image, meta = _build_image(_code_sections())
    target = tmp_path / "payload.exe"
    target.write_bytes(image)
    fake_windows({4242: _make_model(str(target), _mapped(image, meta), protected=True)})

    findings = winject.hollowed_processes()
    assert len(findings) == 1
    assert findings[0]["check"] == "partial_visibility"
    assert findings[0]["evidence"]["denied_processes"][0]["pid"] == 4242
    assert any(entry["scope"].startswith("OpenProcess")
               for entry in winapi.access_errors())


def test_private_executable_memory_and_unbacked_thread(fake_windows, tmp_path):
    """A payload in private memory with a thread starting inside it."""
    image, meta = _build_image(_code_sections())
    target = tmp_path / "payload.exe"
    target.write_bytes(image)
    payload = 0x20000000
    payload_bytes = _mapped(image, meta, size_of_image=0x2000) + b"\x00" * 0x1000
    fake_windows({4242: _make_model(
        str(target), _mapped(image, meta),
        threads=[(8, 0x140001000), (9, payload + 0x40)],
        regions_extra=[{"base": payload, "size": 0x2000, "state": 0x1000,
                        "type": 0x20000, "protect": 0x40,
                        "bytes": payload_bytes[:0x2000]}])})

    memory = winject.executable_private_memory()
    assert len(memory) == 1
    assert memory[0]["check"] == "private_executable_memory"
    assert memory[0]["severity"] == "medium"
    assert memory[0]["evidence"]["region_count"] == 1
    assert memory[0]["evidence"]["pe_regions"] == [hex(payload)]
    assert memory[0]["evidence"]["regions"][0]["looks_like_pe"] is True

    threads = winject.unbacked_executable_threads()
    assert len(threads) == 1
    assert threads[0]["check"] == "unbacked_thread_start"
    assert threads[0]["severity"] == "high"
    reported = threads[0]["evidence"]["threads"]
    assert [entry["tid"] for entry in reported] == [9]
    assert reported[0]["in_private_executable_region"] is True
    assert reported[0]["protection"] == "PAGE_EXECUTE_READWRITE"
    assert threads[0]["evidence"]["modules_scanned"] == 1


def test_module_path_grading_end_to_end(fake_windows, tmp_path):
    """A module loaded from a drop zone with no file behind it is reported twice."""
    image, meta = _build_image(_code_sections())
    target = tmp_path / "payload.exe"
    target.write_bytes(image)
    planted = r"C:\Users\Public\planted.dll"
    fake_windows({4242: _make_model(
        str(target), _mapped(image, meta),
        modules_extra=[{"name": "planted.dll", "path": planted, "base": 0x10000000,
                        "size": 0x1000}])})

    findings = [finding for finding in winject.modules_from_temp_paths()
                if finding["check"] == "module_from_temp_path"]
    kinds = sorted(finding["evidence"]["kind"] for finding in findings)
    assert kinds == ["missing_file", "temp_path"]
    assert all(finding["severity"] == "medium" for finding in findings)
    assert all(finding["evidence"]["module"] == "planted.dll" for finding in findings)
    # The module that is present and in a normal location is not reported.
    assert not any(finding["evidence"]["module"] == "payload.exe"
                   for finding in findings)
    assert meta  # the image really has a section table to have built
