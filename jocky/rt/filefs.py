"""
Filesystem primitives for JOCKY: hashing, metadata, magic sniffing, scanning
and timeline construction.

All of it is plain read-only syscalls — no ``find``, ``sha256sum`` or ``file``
process is spawned, which keeps collection quiet and attributable.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import stat as stat_mod
import time
from typing import Any, Dict, Iterable, List, Optional

# Pseudo filesystems that must never be walked by a generic scan.
SKIP_DIRS = {"/proc", "/sys", "/dev", "/run"}

MAGIC_SIGNATURES = (
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\xfe\xed\xfa\xce", "mach-o"),
    (b"\xcf\xfa\xed\xfe", "mach-o-64"),
    (b"#!", "script"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"%PDF", "pdf"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"SQLite format 3", "sqlite"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
)

TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/")

#: A pattern that asks about *bytes* rather than text: a `\xNN` escape above
#: 0x7F (the escape itself is ASCII, so this reads the pattern, not the file).
_BYTE_PATTERN = re.compile(r"\\x(?:[89a-fA-F][0-9a-fA-F])")

#: Longest single read a script may request (256 MiB) and longest line ``grep``
#: will build (1 MiB). Both exist because the alternative is an allocation whose
#: size the *input* decides: `fs.read_bytes("/dev/zero", 0, 10**12)` grew until
#: the allocator refused, and a 500 MB log line cost 1 GB of RAM before the byte
#: cap was ever consulted.
MAX_READ_BYTES = 256 * 1024 * 1024
MAX_LINE_BYTES = 1 * 1024 * 1024


def hash_bytes(data: bytes, algo: str = "sha256") -> str:
    return hashlib.new(algo, data).hexdigest()


def hash_bytes_raw(data: str, algo: str = "sha256") -> str:
    """Hash a *byte string* — the latin-1 reading of the characters.

    :func:`hash_bytes` hashes text, so ``fs.hash_bytes`` encodes it as UTF-8:
    right for a string a script built itself, wrong for bytes that came out of a
    file, because re-encoding changes every value above 0x7F before it reaches
    the digest.  This is the inverse of :func:`read_bytes`, so
    ``fs.hash_bytes_raw(fs.read_bytes(path, 0, n))`` is the hash of exactly
    those ``n`` bytes on disk.

    A string that is not a byte string — any character above U+00FF — has no
    latin-1 encoding and raises rather than hashing a substituted byte.
    """
    return hashlib.new(algo, data.encode("latin-1")).hexdigest()


def strings(path: str, min_len: int = 4, limit: int = 200, offset: int = 0,
            wide: bool = False, max_bytes: int = 16 * 1024 * 1024,
            deadline: Optional[float] = None) -> List[Dict[str, Any]]:
    """Printable runs in a file — the ``strings(1)`` primitive, in-process.

    Every triage toolkit has this and scripts kept re-implementing it badly:
    reads are streamed (nothing is loaded whole), the walk is bounded by
    ``max_bytes``, and each hit carries its **offset** so it can be mapped back
    to the file with ``fs.read_bytes``.  ``wide=True`` reads UTF-16LE, where a
    printable character is followed by a NUL — the encoding that hides
    command lines inside Windows binaries, which a plain ASCII scan misses.
    """
    from jocky.errors import JockyRuntimeError

    minimum = max(1, min_len)
    start = max(0, offset)
    results: List[Dict[str, Any]] = []
    try:
        handle = open(path, "rb")
    except OSError as exc:
        raise JockyRuntimeError(f"cannot read {path}: {exc.strerror or exc}")
    with handle:
        if start:
            try:
                handle.seek(start)
            except OSError:
                return results
        consumed = 0
        current = bytearray()
        current_at = start
        try:
            while len(results) < limit and consumed < max_bytes:
                if deadline is not None and time.monotonic() > deadline:
                    from jocky.lang.vm import JockyLimitError
                    raise JockyLimitError("wall-clock budget exceeded")
                block = handle.read(min(1 << 20, max_bytes - consumed))
                if not block:
                    break
                consumed += len(block)
                for index, byte in enumerate(block):
                    if wide:
                        # UTF-16LE: a printable byte followed by NUL, or the
                        # second byte of such a pair (skip it).
                        if index % 2 == 1:
                            continue
                        printable = 0x20 <= byte <= 0x7E and block[index + 1:index + 2] == b"\x00"
                    else:
                        printable = 0x20 <= byte <= 0x7E or byte == 0x09
                    if printable:
                        if not current:
                            current_at = start + consumed - len(block) + index
                        current.append(byte)
                        continue
                    if len(current) >= minimum:
                        results.append({"offset": current_at,
                                        "text": bytes(current).decode("latin-1"),
                                        "length": len(current)})
                    current.clear()
                    if len(results) >= limit:
                        break
        except OSError:
            pass                        # partial results beat an exception mid-file
        if len(current) >= minimum and len(results) < limit:
            results.append({"offset": current_at,
                            "text": bytes(current).decode("latin-1"),
                            "length": len(current)})
    return results


def entropy(path: str, offset: int = 0, limit: int = 1 << 20) -> Dict[str, Any]:
    """Shannon entropy of a window, in bits per byte, plus what it suggests.

    Packed and encrypted payloads sit near 8.0 bits/byte while code and text sit
    well below it, so this is the cheapest "is this thing packed?" signal there
    is.  It is a *hint*, not a verdict: compressed data, encrypted data and
    random keys are indistinguishable here, which is exactly why the result
    reports the value rather than a boolean.
    """
    from jocky.errors import JockyRuntimeError

    start = max(0, offset)
    window = max(0, limit)
    try:
        with open(path, "rb") as handle:
            if start:
                handle.seek(start)
            data = handle.read(window)
    except OSError as exc:
        raise JockyRuntimeError(f"cannot read {path}: {exc.strerror or exc}")
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    value = 0.0
    if total:
        for count in counts:
            if count:
                probability = count / total
                value -= probability * math.log2(probability)
    return {
        "path": path,
        "offset": start,
        "bytes": total,
        "entropy": round(value, 4),
        "packed_likely": value >= 7.2 and total >= 256,
        "unique_bytes": sum(1 for count in counts if count),
    }


def read_bytes(path: str, offset: int = 0, limit: int = 262144) -> str:
    """Read raw bytes and return them as a *byte string* (one char per byte).

    The bytes are decoded as latin-1, which maps 0..255 onto U+0000..U+00FF
    one-for-one: the mapping is bijective, so no byte is dropped, replaced or
    reinterpreted on the way in.  A UTF-8 decode with ``errors="replace"`` —
    what the text read ``fs.read`` does — silently destroys every invalid
    sequence, which is precisely the part of a binary worth keeping.  Since a
    character is a byte, ``len()`` is the byte count, indexing is byte
    indexing, and the result is a valid subject for the ``re.*`` engine
    (signature scanning) and for :func:`hash_bytes_raw`.

    ``offset`` seeks before reading so a large file can be paged through;
    negative offsets and limits clamp to 0, and a read that runs off the end
    returns the bytes that were there (an empty string at EOF).
    """
    from jocky.errors import JockyRuntimeError

    start = max(0, offset)
    count = max(0, limit)
    if count > MAX_READ_BYTES:
        raise JockyRuntimeError(
            f"read limit {count} exceeds the {MAX_READ_BYTES}-byte ceiling; "
            "read the file in windows with offset instead")
    try:
        with open(path, "rb") as fh:
            if start:
                fh.seek(start)
            data = fh.read(count)
    except OSError as exc:
        raise JockyRuntimeError(f"cannot read {path}: {exc.strerror or exc}")
    return data.decode("latin-1")


def hash_file(path: str, algo: str = "sha256", chunk: int = 1 << 20,
              max_bytes: Optional[int] = None) -> Optional[str]:
    """Streamed file hash; ``None`` when the file cannot be read."""
    digest = hashlib.new(algo)
    total = 0
    try:
        with open(path, "rb") as fh:
            while True:
                block = fh.read(chunk)
                if not block:
                    break
                digest.update(block)
                total += len(block)
                if max_bytes is not None and total >= max_bytes:
                    break
    except OSError:
        return None
    return digest.hexdigest()


def magic(path: str, size: int = 16) -> str:
    """Coarse file type from its leading bytes."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(size)
    except OSError:
        return "unreadable"
    for signature, name in MAGIC_SIGNATURES:
        if head.startswith(signature):
            if name == "script":
                first = head[2:40].decode("utf-8", "replace").strip()
                return f"script:{first.split()[0].split('/')[-1]}" if first else "script"
            return name
    return "data"


def stat_entry(path: str) -> Optional[Dict[str, Any]]:
    """Metadata plus the flags a triage actually looks for."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    mode = st.st_mode
    entry: Dict[str, Any] = {
        "path": path,
        "size": st.st_size,
        "mode": oct(mode & 0o7777),
        "mode_str": stat_mod.filemode(mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mtime": st.st_mtime,
        "ctime": st.st_ctime,
        "atime": st.st_atime,
        "inode": st.st_ino,
        "nlink": st.st_nlink,
        "is_dir": stat_mod.S_ISDIR(mode),
        "is_link": stat_mod.S_ISLNK(mode),
        "is_file": stat_mod.S_ISREG(mode),
        "setuid": bool(mode & stat_mod.S_ISUID),
        "setgid": bool(mode & stat_mod.S_ISGID),
        "sticky": bool(mode & stat_mod.S_ISVTX),
        "world_writable": bool(mode & stat_mod.S_IWOTH),
        "executable": bool(mode & 0o111),
        "in_temp": path.startswith(TEMP_PREFIXES),
    }
    if entry["is_link"]:
        try:
            entry["target"] = os.readlink(path)
        except OSError:
            entry["target"] = None
    return entry


def scan(root: str = "/", max_files: int = 2000, max_depth: int = 6,
         pattern: Optional[str] = None, min_size: int = 0,
         include_dirs: bool = False, with_hash: bool = False) -> List[Dict[str, Any]]:
    """Bounded recursive scan (depth and count capped, pseudo-fs skipped)."""
    results: List[Dict[str, Any]] = []
    root = os.path.abspath(root)
    stack = [(root, 0)]
    while stack and len(results) < max_files:
        current, depth = stack.pop()
        try:
            entries = os.scandir(current)
        except OSError:
            continue
        with entries:
            for item in entries:
                if len(results) >= max_files:
                    break
                path = item.path
                try:
                    is_dir = item.is_dir(follow_symlinks=False)
                except OSError:
                    continue
                if is_dir:
                    if path in SKIP_DIRS or depth >= max_depth:
                        continue
                    stack.append((path, depth + 1))
                    if include_dirs:
                        entry = stat_entry(path)
                        if entry:
                            results.append(entry)
                    continue
                if pattern and pattern not in os.path.basename(path):
                    continue
                entry = stat_entry(path)
                if entry is None or entry["size"] < min_size:
                    continue
                if with_hash:
                    entry["hash"] = hash_file(path)
                entry["magic"] = magic(path)
                results.append(entry)
    return results


def timeline(root: str = "/", limit: int = 200, max_files: int = 5000,
             max_depth: int = 6) -> List[Dict[str, Any]]:
    """Most recently modified files first — the classic quick timeline."""
    entries = scan(root, max_files=max_files, max_depth=max_depth)
    entries.sort(key=lambda e: e["mtime"], reverse=True)
    return entries[:limit]


def special_perms(root: str = "/", max_files: int = 5000,
                  max_depth: int = 6) -> Dict[str, List[Dict[str, Any]]]:
    """SUID/SGID/world-writable inventory (privilege-escalation surface)."""
    out: Dict[str, List[Dict[str, Any]]] = {"setuid": [], "setgid": [], "world_writable": []}
    for entry in scan(root, max_files=max_files, max_depth=max_depth):
        if entry["setuid"]:
            out["setuid"].append(entry)
        if entry["setgid"]:
            out["setgid"].append(entry)
        if entry["world_writable"] and not entry["is_link"]:
            out["world_writable"].append(entry)
    return out


_MOUNT_TABLE: Optional[List[tuple]] = None


def _read_mount_table() -> List[tuple]:
    rows: List[tuple] = []
    try:
        with open("/proc/mounts") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3:
                    rows.append((parts[1], parts[2]))
    except OSError:
        return rows
    rows.sort(key=lambda row: len(row[0]), reverse=True)
    return rows


def _mount_table() -> List[tuple]:
    """(mountpoint, fstype) pairs, longest mountpoint first, read once.

    Every ``fstype_for`` call used to re-read and re-sort ``/proc/mounts``; a
    PATH audit asks for the fstype of dozens of directories, so the parse cost
    was paid dozens of times for one unchanging table.
    """
    global _MOUNT_TABLE
    if _MOUNT_TABLE is None:
        _MOUNT_TABLE = _read_mount_table()
    return _MOUNT_TABLE


def reset_mount_cache() -> None:
    """Drop the cached mount table (tests that mount something mid-run)."""
    global _MOUNT_TABLE
    _MOUNT_TABLE = None


def fstype_for(path: str) -> Optional[str]:
    """Filesystem type backing ``path`` (used to interpret mode bits)."""
    for mountpoint, fstype in _mount_table():
        if path == mountpoint or path.startswith(mountpoint.rstrip("/") + "/"):
            return fstype
    return None


# Filesystems that do not implement POSIX mode bits: everything looks 0777
# there, so a "world-writable" verdict would be meaningless noise.
OPAQUE_MODE_FSTYPES = {"drvfs", "9p", "vboxsf", "cifs", "smb3", "nfs", "nfs4",
                       "fuse", "fuseblk", "ntfs", "ntfs3"}


def path_dirs(path_env: Optional[str] = None) -> List[Dict[str, Any]]:
    """Every ``$PATH`` entry with the flags that matter for hijacking.

    Symlinks are resolved before permissions are read — ``/sbin -> /usr/sbin``
    would otherwise look world-writable, because a symlink's own mode is
    always ``rwxrwxrwx`` and says nothing about the target.

    Resolution is skipped for entries already on a filesystem with no POSIX
    mode bits (:data:`OPAQUE_MODE_FSTYPES`): their ``world_writable`` flag is
    ignored wherever it points, so the verdict cannot change — and on WSL's
    drvfs bridge every unresolved path component is a separate round trip,
    which made the audit itself the slowest check in a triage run.
    """
    raw = path_env if path_env is not None else os.environ.get("PATH", "")
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for directory in raw.split(os.pathsep):
        if not directory or directory in seen:
            # Duplicate entries repeat identical work and would report the
            # same directory twice.
            continue
        seen.add(directory)
        resolved = directory if fstype_for(directory) in OPAQUE_MODE_FSTYPES \
            else os.path.realpath(directory)
        entry = stat_entry(resolved)
        if entry is None:
            out.append({"path": directory, "resolved": resolved, "exists": False})
            continue
        fstype = fstype_for(resolved)
        opaque = fstype in OPAQUE_MODE_FSTYPES
        entry.update({
            "path": directory,
            "resolved": resolved,
            "exists": True,
            "fstype": fstype,
            "opaque_permissions": opaque,
            "hijackable": (entry["world_writable"] and not opaque)
                          or entry["in_temp"],
        })
        out.append(entry)
    return out


def ld_preload() -> Dict[str, Any]:
    """``/etc/ld.so.preload`` — a favourite userland-rootkit foothold."""
    path = "/etc/ld.so.preload"
    try:
        with open(path) as fh:
            content = fh.read().strip()
    except OSError:
        return {"path": path, "exists": False, "entries": []}
    return {
        "path": path,
        "exists": True,
        "entries": [line.strip() for line in content.splitlines() if line.strip()],
        "metadata": stat_entry(path),
    }


def deleted_open_files() -> List[Dict[str, Any]]:
    """Re-exported from procfs for filesystem-shaped scripts."""
    from jocky.rt import procfs
    return procfs.deleted_open_files()


def grep_file(path: str, pattern: str, limit: int = 500,
              ignore_case: bool = False, max_bytes: Optional[int] = 32 * 1024 * 1024,
              bytes_mode: Optional[bool] = None,
              with_stats: bool = False,
              deadline: Optional[float] = None) -> Any:
    """Match ``pattern`` against the lines of ``path``.

    The file is streamed in 1 MiB chunks and lines are split *inside* the
    chunk, so neither ``limit`` nor ``max_bytes`` can be reached only after the
    unbounded work has happened: a single 500 MB record used to be materialised
    and decoded (1 GB of RAM, twice the file) before the byte cap was consulted.
    A line longer than :data:`MAX_LINE_BYTES` is matched on its first MiB and the
    remainder is skipped — reported as ``truncated``, never silently.

    ``max_bytes`` caps the walk (32 MiB by default, ``None`` for no cap) and
    ``limit`` caps the result. With ``with_stats=True`` the return value is
    ``{"matches", "lines", "scanned_bytes", "truncated"}`` so "no match" is
    distinguishable from "I stopped looking"; ``fs.grep_stats`` exposes that.

    **Byte patterns need byte semantics.** A pattern containing a ``\\xNN``
    escape above ``0x7F`` (``r"\\x90\\x90"``, ``r"[\\x80-\\xff]"``) is asking
    about the file's *bytes*, so lines are decoded latin-1 — one character per
    byte, exactly what :func:`read_bytes` returns. Every other pattern is read
    as text (UTF-8, ``errors="replace"``). This is detected from the pattern,
    because the alternative is a rule that silently matches nothing.
    """
    from jocky.errors import JockyRuntimeError
    from jocky.rt.pattern import compile_pattern

    if bytes_mode is None:
        bytes_mode = bool(_BYTE_PATTERN.search(pattern))
    encoding = "latin-1" if bytes_mode else "utf-8"
    errors = "strict" if bytes_mode else "replace"
    compiled = compile_pattern(pattern, ignore_case)
    results: List[Dict[str, Any]] = []
    consumed = 0
    lines = 0
    truncated = False
    try:
        handle = open(path, "rb")
    except OSError as exc:
        raise JockyRuntimeError(f"cannot read {path}: {exc.strerror or exc}")
    with handle:
        pending = b""
        skipping = False                 # discarding the tail of an over-long line
        try:
            while max_bytes is None or consumed < max_bytes:
                if deadline is not None and time.monotonic() > deadline:
                    # A native gets one instruction's worth of budget, which for
                    # a file walk can be seconds: checking here is what turns an
                    # overrun into a reported limit instead of an unexplained
                    # 20-second pause.
                    from jocky.lang.vm import JockyLimitError
                    raise JockyLimitError("wall-clock budget exceeded")
                want = 1 << 20 if max_bytes is None else min(1 << 20, max_bytes - consumed)
                if want <= 0:
                    truncated = True
                    break
                block = handle.read(want)
                if not block:
                    break
                consumed += len(block)
                pending += block
                while True:
                    cut = pending.find(b"\n")
                    if cut < 0:
                        break
                    raw, pending = pending[:cut], pending[cut + 1:]
                    if skipping:
                        skipping = False
                        continue
                    lines += 1
                    line = raw.decode(encoding, errors).rstrip("\r")
                    match = compiled.search(line)
                    if match is not None:
                        results.append({"line_no": lines, "line": line,
                                        "match": match.text, "start": match.start,
                                        "end": match.end,
                                        "groups": list(match.groups[1:])})
                        if len(results) >= limit:
                            truncated = True
                            break
                if len(results) >= limit:
                    break
                if len(pending) > MAX_LINE_BYTES:
                    # Match on the first MiB of the over-long line, then skip the
                    # rest of it: bounded memory, and the scan continues.
                    raw, pending = pending[:MAX_LINE_BYTES], b""
                    lines += 1
                    truncated = True
                    skipping = True
                    line = raw.decode(encoding, errors)
                    match = compiled.search(line)
                    if match is not None:
                        results.append({"line_no": lines, "line": line,
                                        "match": match.text, "start": match.start,
                                        "end": match.end,
                                        "groups": list(match.groups[1:])})
            if pending and not skipping:
                # Last line without a trailing newline.
                lines += 1
                line = pending.decode(encoding, errors).rstrip("\r")
                match = compiled.search(line)
                if match is not None and len(results) < limit:
                    results.append({"line_no": lines, "line": line,
                                    "match": match.text, "start": match.start,
                                    "end": match.end,
                                    "groups": list(match.groups[1:])})
        except OSError:
            pass            # partial results beat an exception mid-file
    if with_stats:
        return {"matches": results, "lines": lines, "scanned_bytes": consumed,
                "truncated": truncated}
    return results
