"""
Phase-A native ELF emitter contract, measured rather than assumed:

* every stub instruction encoding is pinned byte-for-byte;
* 64 seed-distinct yields produce 64 unique images with 64 distinct entry
  points, and every one of them *executes* on this host;
* ``read_artifact`` is the exact inverse of the embedding;
* a tampered entry point never reaches the marker.
"""
from __future__ import annotations

import hashlib
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.native import emit_elf, inspect_elf, read_artifact  # noqa: E402
from jocky.runner import build_artifact  # noqa: E402

assembler = sys.modules["jocky.native.emit_elf"]  # the function shadows it

SMOKE = REPO / "scripts" / "smoke.jky"
# Measured headline numbers, filled by the 64-build test for the report.
MEASURED: dict = {}


def _seed(i: int) -> bytes:
    # byte 0 is i (so distinct i -> distinct .text page, hence distinct entry)
    return bytes([i]) + hashlib.sha256(b"native-seed-%d" % i).digest()[:15]


def _smoke_artifact() -> bytes:
    artifact, _meta = build_artifact(SMOKE.read_text())
    return artifact


def _run(image: bytes, directory: str, name: str) -> subprocess.CompletedProcess:
    path = os.path.join(directory, name)
    with open(path, "wb") as fh:
        fh.write(image)
    os.chmod(path, 0o755)
    return subprocess.run([path], capture_output=True, timeout=5, cwd=directory)


# ----------------------------------------------------------------- encodings
def test_stub_instruction_encodings_are_verified():
    """Each pinned byte string is the published x86-64 encoding."""
    assert assembler._asm("mov_eax_1") == b"\xb8\x01\x00\x00\x00"
    assert assembler._asm("mov_eax_60") == b"\xb8\x3c\x00\x00\x00"
    assert assembler._asm("mov_edi_1") == b"\xbf\x01\x00\x00\x00"
    assert assembler._asm("xor_edi_edi") == b"\x31\xff"
    assert assembler._asm("mov_rsi", 0x400000) == b"\x48\xbe\x00\x00\x40\x00\x00\x00\x00\x00"
    assert assembler._asm("mov_edx", 0x1234) == b"\xba\x34\x12\x00\x00"
    assert assembler._asm("syscall") == b"\x0f\x05"
    assert assembler._asm("nop") == b"\x90"
    with pytest.raises(ValueError):
        assembler._asm("int3")


# ---------------------------------------------------------------- determinism
def test_same_seed_is_byte_identical_across_calls():
    artifact = _smoke_artifact()
    first = emit_elf(artifact, marker=b"m\n", seed=_seed(9))
    second = emit_elf(artifact, marker=b"m\n", seed=_seed(9))
    assert first == second
    assert first.startswith(b"\x7fELF")


def test_different_seeds_move_the_entry_point_and_bytes():
    artifact = _smoke_artifact()
    one = emit_elf(artifact, marker=b"m\n", seed=_seed(1))
    two = emit_elf(artifact, marker=b"m\n", seed=_seed(2))
    assert one != two
    entry_one = struct.unpack_from("<Q", one, 24)[0]
    entry_two = struct.unpack_from("<Q", two, 24)[0]
    assert entry_one != entry_two


# ------------------------------------------------------------------ big run
def test_sixty_four_builds_are_unique_have_distinct_entries_and_run():
    artifact = _smoke_artifact()
    hashes, entries = set(), set()
    start = time.monotonic()
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(64):
            marker = b"jky-native-marker-%02d\n" % i
            image = emit_elf(artifact, marker=marker, seed=_seed(i))
            hashes.add(hashlib.sha256(image).hexdigest())
            e_entry = struct.unpack_from("<Q", image, 24)[0]
            info = inspect_elf(image)
            assert info["entry"] == e_entry
            entries.add(e_entry)
            proc = _run(image, tmp, "img%02d" % i)
            assert proc.returncode == 0, (i, proc.returncode, proc.stderr)
            assert proc.stdout == marker, (i, proc.stdout)
    elapsed = time.monotonic() - start
    assert len(hashes) == 64, "seed must make every byte count"
    assert len(entries) == 64, "entry-point variation did not materialize"
    MEASURED.update(
        unique_images=len(hashes), distinct_entries=len(entries), wall_s=elapsed
    )


# ------------------------------------------------------------------- readelf
def test_readelf_parses_an_image_as_elf64():
    readelf = shutil.which("readelf")
    if readelf is None:
        pytest.skip("readelf not installed on this host")
    image = emit_elf(_smoke_artifact(), marker=b"x\n", seed=_seed(3))
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "check")
        with open(path, "wb") as fh:
            fh.write(image)
        out = subprocess.run([readelf, "-h", path], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "Class:" in out.stdout and "ELF64" in out.stdout
    assert "Entry point" in out.stdout


# ---------------------------------------------------------------- round-trip
def test_read_artifact_round_trips_random_payloads():
    rng = random.Random(0xC0DE)
    for n in range(5):
        blob = bytes(rng.getrandbits(8) for _ in range(64 + rng.randrange(512)))
        image = emit_elf(blob, marker=b"mk%d\n" % n, seed=_seed(100 + n))
        assert read_artifact(image) == blob


def test_read_artifact_rejects_non_native_blob():
    with pytest.raises(ValueError, match="not a JOCKY native image"):
        read_artifact(b"not a native image at all")
    with pytest.raises(ValueError, match="not a JOCKY native image"):
        artifact = _smoke_artifact()
        read_artifact(artifact)  # JKY1 bytecode is not an ELF
    with pytest.raises(ValueError, match="not a JOCKY native image"):
        read_artifact(b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 100)  # truncated


# ------------------------------------------------------------------ negative
def test_tampered_entry_point_never_reaches_the_marker():
    image = bytearray(emit_elf(_smoke_artifact(), marker=b"tamper-canary\n",
                               seed=_seed(7)))
    struct.pack_into("<Q", image, 24, 0x1)  # entry outside every segment
    with tempfile.TemporaryDirectory() as tmp:
        proc = _run(bytes(image), tmp, "tampered")
    assert proc.returncode != 0
    assert b"tamper-canary" not in proc.stdout


# ------------------------------------------------------------------ inspect
def test_inspect_reports_seed_named_artifact_section():
    image = emit_elf(_smoke_artifact(), marker=b"m\n", seed=_seed(11))
    info = inspect_elf(image)
    assert info["class"] == "ELF64" and info["machine"] == "x86-64"
    names = [s["name"] for s in info["sections"]]
    assert ".text" in names
    jk = [s for s in info["sections"] if s["name"].startswith(".jk")]
    assert len(jk) == 1, names
    assert jk[0]["size"] > 0 and jk[0]["addr"] != 0
