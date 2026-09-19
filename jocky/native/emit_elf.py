"""
Native ELF64 emitter — phase A of the JOCKY native backend.

SIH26148 pillar 1 requires altering "basic control-flow graphs, token
generation, and binary structure layout" of *real binaries*, and pillar 2's
"dynamic entry-point alterations / altered import tables" presuppose a PE/ELF
to alter at all.  Until now every JOCKY artifact existed only as ``JKY1``
bytecode; this module is the ELF side: it wraps a bytecode artifact in a
hand-built, fully static x86-64 Linux executable.

What this phase does:

* emits a valid ``ET_EXEC`` (non-PIE) ELF64 image with two ``PT_LOAD``
  segments and no ``PT_INTERP``/``PT_DYNAMIC`` — zero ``DT_NEEDED`` entries,
  which is the honest ELF reading of an "altered import table" (there is
  nothing to import);
* derives the ``.text`` virtual address — and therefore ``e_entry`` — from
  the build seed, so two builds of the same artifact differ in entry point;
* stores the artifact in a section whose *name* is seed-derived, and makes
  every non-essential byte (padding, overlay junk, NOP slots, register-setup
  order) a deterministic function of the seed;
* provides :func:`read_artifact` to reverse the embedding exactly, and
  :func:`inspect_elf` to describe an image.

What this phase does **not** do — and must not be read as doing:

* it does **not** translate JOCKY opcodes into native code.  The artifact is
  embedded (data), not AOT-compiled; execution of the script still happens in
  the existing bytecode VM (:class:`jocky.lang.vm.VM`).
* it does not yet *run* the artifact from the native image.  A
  ``jocky.native.runner`` that maps the image, recovers the artifact with
  :func:`read_artifact` and hands it to the VM is a separate, later phase.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict, List

__all__ = ["emit_elf", "inspect_elf", "read_artifact"]

DEFAULT_BANNER = b"jocky native image (artifact embedded)\n"

_EHDR_SIZE = 64
_PHDR_SIZE = 56
_SHDR_SIZE = 64
_PHNUM = 2

_PT_LOAD = 1
_PF_X, _PF_W, _PF_R = 1, 2, 4
_SHT_NULL, _SHT_PROGBITS, _SHT_STRTAB = 0, 1, 3
_SHF_ALLOC, _SHF_EXECINSTR = 0x2, 0x4

_TEXT_BASE = 0x400000  # canonical non-PIE text base; seed picks the page
_RODATA_BASE = 0x600000


class _Stream(object):
    """Deterministic byte stream derived from ``seed``.

    Every byte of build randomness (padding, junk, layout choices) comes from
    here, so equal seeds produce byte-identical images.
    """

    def __init__(self, seed: bytes) -> None:
        self._seed = seed
        self._counter = 0
        self._buf = b""
        self._pos = 0

    def byte(self) -> int:
        if self._pos >= len(self._buf):
            self._buf = hashlib.sha256(
                self._seed + self._counter.to_bytes(4, "little")
            ).digest()
            self._counter += 1
            self._pos = 0
        value = self._buf[self._pos]
        self._pos += 1
        return value

    def bytes(self, n: int) -> bytes:
        return bytes(self.byte() for _ in range(n))


def _asm(op: str, arg: int = 0) -> bytes:
    """Assemble one stub instruction.

    Hand-verified encodings (checked byte-for-byte in the tests):

    * ``mov eax, 1``      ``b8 01 00 00 00``  SYS_write
    * ``mov eax, 60``     ``b8 3c 00 00 00``  SYS_exit
    * ``mov edi, 1``      ``bf 01 00 00 00``  fd = stdout
    * ``xor  edi, edi``   ``31 ff``           exit status 0
    * ``mov rsi, imm64``  ``48 be + imm64``   buffer address
    * ``mov edx, imm32``  ``ba + imm32``      buffer length
    * ``syscall``         ``0f 05``
    * ``nop``             ``90``
    """
    fixed = {
        "mov_eax_1": b"\xb8\x01\x00\x00\x00",
        "mov_eax_60": b"\xb8\x3c\x00\x00\x00",
        "mov_edi_1": b"\xbf\x01\x00\x00\x00",
        "xor_edi_edi": b"\x31\xff",
        "syscall": b"\x0f\x05",
        "nop": b"\x90",
    }
    if op == "mov_rsi":
        return b"\x48\xbe" + struct.pack("<Q", arg)
    if op == "mov_edx":
        return b"\xba" + struct.pack("<I", arg & 0xFFFFFFFF)
    try:
        return fixed[op]
    except KeyError:
        raise ValueError("unknown stub op: %r" % (op,))


def _stub(buf_addr: int, buf_len: int, *, swap: bool, nops: int) -> bytes:
    """write(1, buf_addr, buf_len); exit(0) — raw syscalls, no libc.

    The syscall-number/fd group and the address/length group write disjoint
    registers, so their order — and the NOP padding between them — is free
    build entropy without any semantic effect.
    """
    group_fd = _asm("mov_eax_1") + _asm("mov_edi_1")
    group_ptr = _asm("mov_rsi", buf_addr) + _asm("mov_edx", buf_len)
    if swap:
        group_fd, group_ptr = group_ptr, group_fd
    write = group_fd + _asm("nop") * nops + group_ptr + _asm("syscall")
    return write + _asm("mov_eax_60") + _asm("xor_edi_edi") + _asm("syscall")


def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _section_name(seed: bytes) -> bytes:
    digest = hashlib.sha256(b"jocky-native-section\0" + seed).hexdigest()
    # ".jk" + 4 hex chars: seed-derived, always <= 8 characters after the dot
    return b".jk" + digest[:4].encode("ascii")


def emit_elf(artifact: bytes, *, marker: bytes = b"", seed: bytes) -> bytes:
    """A runnable x86-64 Linux executable embedding ``artifact``.

    The image is fully static and dependency-free; running it prints
    ``marker`` (or a default banner) and exits 0.  ``seed`` controls every
    non-essential byte: same seed -> identical image, different seed ->
    different entry point, section name, padding and junk.
    """
    if not seed:
        raise ValueError("emit_elf requires a non-empty seed")
    marker = marker or DEFAULT_BANNER
    payload = struct.pack("<I", len(marker)) + marker + artifact
    rnd = _Stream(seed)

    # ------------------------------------------------------------- layout
    head_end = _EHDR_SIZE + _PHDR_SIZE * _PHNUM
    text_off = head_end + rnd.byte()                      # 0..255 pad, then .text
    swap = rnd.byte() % 2 == 1
    nops = rnd.byte() % 4
    stub_len = 5 + 5 + 10 + 5 + nops + 2 + 5 + 2 + 2      # both groups + exit
    rodata_off = _align_up(text_off + stub_len + rnd.byte(), 16)

    def congruent(vaddr: int, offset: int) -> int:
        # The kernel requires p_vaddr ≡ p_offset (mod p_align).
        return vaddr + offset % 0x1000

    text_vaddr = congruent(_TEXT_BASE + 0x1000 * (seed[0] % 64), text_off)
    rodata_vaddr = congruent(_RODATA_BASE + 0x1000 * (seed[1 % len(seed)] % 64),
                             rodata_off)
    stub = _stub(rodata_vaddr + 4, len(marker), swap=swap, nops=nops)
    assert len(stub) == stub_len

    section = _section_name(seed)
    shstrtab = b"\x00.text\x00" + section + b"\x00.shstrtab\x00"
    name_text = 1
    name_jk = 1 + len(".text") + 1
    name_shstr = name_jk + len(section) + 1

    shstr_off = rodata_off + len(payload)
    shoff = _align_up(shstr_off + len(shstrtab), 8)

    entry = text_vaddr

    # ------------------------------------------------------------ headers
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr += struct.pack(
        "<HHIQQQIHHHHHH",
        2,            # ET_EXEC
        62,           # EM_X86_64
        1,            # EV_CURRENT
        entry,
        _EHDR_SIZE,   # e_phoff
        shoff,        # e_shoff
        0,            # e_flags
        _EHDR_SIZE,
        _PHDR_SIZE,
        _PHNUM,
        _SHDR_SIZE,
        4,            # shnum: NULL, .text, .jk*, .shstrtab
        3,            # shstrndx
    )

    def phdr(flags: int, offset: int, vaddr: int, size: int) -> bytes:
        return struct.pack(
            "<IIQQQQQQ",
            _PT_LOAD, flags, offset, vaddr, vaddr, size, size, 0x1000,
        )

    phdrs = (
        phdr(_PF_R | _PF_X, text_off, text_vaddr, len(stub))
        + phdr(_PF_R, rodata_off, rodata_vaddr, len(payload))
    )

    def shdr(name: int, shtype: int, flags: int, addr: int, offset: int,
             size: int, align: int) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name, shtype, flags, addr,
                           offset, size, 0, 0, align, 0)

    shdrs = (
        b"\x00" * _SHDR_SIZE
        + shdr(name_text, _SHT_PROGBITS, _SHF_ALLOC | _SHF_EXECINSTR,
               text_vaddr, text_off, len(stub), 16)
        + shdr(name_jk, _SHT_PROGBITS, _SHF_ALLOC,
               rodata_vaddr, rodata_off, len(payload), 16)
        + shdr(name_shstr, _SHT_STRTAB, 0, 0, shstr_off, len(shstrtab), 1)
    )

    # ----------------------------------------------------------- assemble
    image = bytearray()
    image += ehdr + phdrs
    image += rnd.bytes(text_off - len(image))
    image += stub
    image += rnd.bytes(rodata_off - len(image))
    image += payload
    assert len(image) == shstr_off
    image += shstrtab
    image += b"\x00" * (shoff - len(image))
    image += shdrs
    image += rnd.bytes(rnd.byte())  # trailing overlay junk (0..255 bytes)
    return bytes(image)


# -------------------------------------------------------------- inspection
def _parse_header(image: bytes) -> Dict[str, Any]:
    if len(image) < _EHDR_SIZE or image[:4] != b"\x7fELF":
        raise ValueError("not a JOCKY native image")
    if image[4] != 2 or image[5] != 1:  # ELFCLASS64, little-endian
        raise ValueError("not a JOCKY native image")
    fields = struct.unpack_from("<HHIQQQIHHHHHH", image, 16)
    (etype, machine, _version, entry, phoff, shoff, _flags,
     ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = fields
    if etype != 2 or machine != 62:
        raise ValueError("not a JOCKY native image")
    if shoff == 0 or shnum == 0 or shstrndx >= shnum:
        raise ValueError("not a JOCKY native image")
    if shoff + shnum * shentsize > len(image) or phoff + phnum * phentsize > len(image):
        raise ValueError("not a JOCKY native image")
    return {
        "entry": entry, "phoff": phoff, "shoff": shoff,
        "phentsize": phentsize, "phnum": phnum,
        "shentsize": shentsize, "shnum": shnum, "shstrndx": shstrndx,
        "ehsize": ehsize,
    }


def _sections(image: bytes, hdr: Dict[str, Any]) -> List[Dict[str, Any]]:
    shoff, shentsize, shnum = hdr["shoff"], hdr["shentsize"], hdr["shnum"]
    raw = []
    for i in range(shnum):
        fields = struct.unpack_from("<IIQQQQIIQQ", image, shoff + i * shentsize)
        name_off, shtype, flags, addr, offset, size = fields[:6]
        if offset + size > len(image) and shtype != _SHT_NULL:
            raise ValueError("not a JOCKY native image")
        raw.append({
            "name_off": name_off, "type": shtype, "flags": flags,
            "addr": addr, "offset": offset, "size": size,
        })
    strtab = raw[hdr["shstrndx"]]
    base, limit = strtab["offset"], strtab["offset"] + strtab["size"]
    sections = []
    for entry in raw:
        end = image.find(b"\x00", base + entry["name_off"], limit)
        if end < 0:
            raise ValueError("not a JOCKY native image")
        name = image[base + entry["name_off"]:end].decode("ascii", "replace")
        sections.append({
            "name": name, "type": entry["type"], "flags": entry["flags"],
            "addr": entry["addr"], "offset": entry["offset"],
            "size": entry["size"],
        })
    return sections


def inspect_elf(image: bytes) -> Dict[str, Any]:
    """Describe an emitted image: entry point, sections, sizes.

    Raises ``ValueError("not a JOCKY native image")`` for anything that is
    not a parseable JOCKY-emitter ELF64 — malformed input never surfaces as
    a bare :class:`struct.error`.
    """
    hdr = _parse_header(image)
    sections = _sections(image, hdr)
    return {
        "class": "ELF64",
        "type": "EXEC",
        "machine": "x86-64",
        "entry": hdr["entry"],
        "phnum": hdr["phnum"],
        "sections": sections,
        "size": len(image),
    }


def read_artifact(image: bytes) -> bytes:
    """Recover the embedded artifact from an emitted image (exact inverse).

    The seed-named section holds ``u32 marker_len || marker || artifact``;
    only the artifact is returned.
    """
    hdr = _parse_header(image)
    for section in _sections(image, hdr):
        if not section["name"].startswith(".jk"):
            continue
        start = section["offset"]
        body = image[start:start + section["size"]]
        if len(body) < 4:
            raise ValueError("not a JOCKY native image")
        (marker_len,) = struct.unpack_from("<I", body, 0)
        if 4 + marker_len > len(body):
            raise ValueError("not a JOCKY native image")
        return body[4 + marker_len:]
    raise ValueError("not a JOCKY native image")
