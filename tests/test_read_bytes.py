"""
Byte-level file reads — ``filefs.read_bytes`` and ``filefs.hash_bytes_raw``.

The point of a byte read is that it is *lossless*: a script scanning a binary
must get the bytes back, not a UTF-8 approximation of them (``fs.read`` decodes
with ``errors="replace"``, so every invalid sequence becomes U+FFFD and the
original value is gone).  These tests write real files with known contents —
every byte value in order, and random binary — and require the read to return
them exactly, plus the offset/limit arithmetic a pager needs and the composition
with the raw hasher.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.errors import JockyRuntimeError  # noqa: E402
from jocky.rt import filefs  # noqa: E402

ALL_BYTES = bytes(range(256))


def _write(tmp_path: pathlib.Path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_every_byte_value_survives_a_round_trip(tmp_path):
    """0..255 must each come back as themselves — that is the whole contract.

    A mapping that dropped or rewrote one value would still look correct on
    ASCII text and silently corrupt a binary, so assert the code point of every
    character, and that re-encoding gives the file's bytes back unchanged.
    """
    path = _write(tmp_path, "all-bytes.bin", ALL_BYTES)

    raw = filefs.read_bytes(path)

    assert raw == ALL_BYTES.decode("latin-1")
    assert [ord(char) for char in raw] == list(range(256))
    assert raw.encode("latin-1") == pathlib.Path(path).read_bytes()


def test_offsets_and_limits_select_exact_windows(tmp_path):
    path = _write(tmp_path, "all-bytes.bin", ALL_BYTES)

    assert filefs.read_bytes(path, 0, 16) == ALL_BYTES[:16].decode("latin-1")
    assert filefs.read_bytes(path, 200, 32) == ALL_BYTES[200:232].decode("latin-1")
    assert filefs.read_bytes(path, 128) == ALL_BYTES[128:].decode("latin-1")
    assert len(filefs.read_bytes(path)) == 256, "the default limit covers a small file"
    # A window that runs off the end is shorter, not padded and not an error.
    assert filefs.read_bytes(path, 250, 32) == ALL_BYTES[250:].decode("latin-1")


def test_offsets_at_and_beyond_eof_read_nothing(tmp_path):
    path = _write(tmp_path, "blob.bin", os.urandom(64))

    assert filefs.read_bytes(path, 64, 8) == ""
    assert filefs.read_bytes(path, 4096, 8) == ""
    assert filefs.read_bytes(path, 0, 1 << 20) == filefs.read_bytes(path)


@pytest.mark.parametrize("offset,limit", [
    (-1, 8), (-4096, 8), (-1, -1), (0, -1), (-5, -5), (-1, 0),
])
def test_negative_arguments_clamp_to_zero(tmp_path, offset, limit):
    """A negative seek would raise or wrap; a negative count would read backwards."""
    blob = os.urandom(64)
    path = _write(tmp_path, "blob.bin", blob)
    start, count = max(0, offset), max(0, limit)

    assert filefs.read_bytes(path, offset, limit) == blob[start:start + count].decode("latin-1")


def test_a_file_that_cannot_be_opened_names_the_path(tmp_path):
    missing = tmp_path / "absent.bin"

    with pytest.raises(JockyRuntimeError) as excinfo:
        filefs.read_bytes(str(missing))
    assert "cannot read" in str(excinfo.value)
    assert str(missing) in str(excinfo.value)

    # The same failure with an offset: a seek must not hide an open error.
    with pytest.raises(JockyRuntimeError, match="cannot read"):
        filefs.read_bytes(str(missing), 8, 4)

    # A directory *opens* on POSIX but cannot be read; returning an empty byte
    # string there would look like an empty file.
    with pytest.raises(JockyRuntimeError, match="cannot read"):
        filefs.read_bytes(str(tmp_path))


def test_hash_bytes_raw_hashes_the_bytes_not_a_re_encoding(tmp_path):
    """``hash_bytes_raw(read_bytes(p))`` must be the hash of ``p`` itself.

    The composition is the whole reason the hasher is separate: text hashing
    would encode this data as UTF-8 first and produce a digest of bytes that
    were never in the file.
    """
    path = _write(tmp_path, "all-bytes.bin", ALL_BYTES)
    assert filefs.hash_bytes_raw(filefs.read_bytes(path)) == hashlib.sha256(ALL_BYTES).hexdigest()
    assert filefs.hash_bytes_raw(filefs.read_bytes(path), "md5") == hashlib.md5(ALL_BYTES).hexdigest()

    noise = os.urandom(64 * 1024)
    noise_path = _write(tmp_path, "noise.bin", noise)
    assert filefs.hash_bytes_raw(filefs.read_bytes(noise_path)) == hashlib.sha256(noise).hexdigest()


def test_hash_bytes_raw_is_latin1_where_hash_bytes_is_utf8():
    """Two hashers, two questions: byte values versus the UTF-8 encoding of text."""
    assert filefs.hash_bytes_raw("é") == hashlib.sha256(b"\xe9").hexdigest()
    assert filefs.hash_bytes_raw("é") != filefs.hash_bytes("é".encode())


def test_a_megabyte_read_is_not_quadratic(tmp_path):
    """Guard the read against per-byte string building (accidental O(n²)).

    The byte read does one syscall and one decode; the baseline is the same
    file read and decoded as text (exactly what ``fs.read`` does).  The bound is
    deliberately loose — 10x with a floor — so it fails on a complexity mistake
    by orders of magnitude rather than on a busy host.
    """
    blob = os.urandom(1 << 20)
    path = _write(tmp_path, "megabyte.bin", blob)

    def fastest(call, rounds: int = 3) -> float:
        best = float("inf")
        for _ in range(rounds):
            started = time.perf_counter()
            call()
            best = min(best, time.perf_counter() - started)
        return best

    def read_as_text() -> str:
        with open(path, "rb") as fh:
            return fh.read(1 << 20).decode("utf-8", "replace")

    text_seconds = fastest(read_as_text)
    byte_seconds = fastest(lambda: filefs.read_bytes(path, 0, 1 << 20))

    assert len(filefs.read_bytes(path, 0, 1 << 20)) == 1 << 20
    assert byte_seconds < 10 * max(text_seconds, 5e-3), (byte_seconds, text_seconds)
