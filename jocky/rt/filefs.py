"""
Filesystem primitives for JOCKY: hashing, metadata, magic sniffing, scanning
and timeline construction.

All of it is plain read-only syscalls — no ``find``, ``sha256sum`` or ``file``
process is spawned, which keeps collection quiet and attributable.
"""
from __future__ import annotations

import hashlib
import os
import stat as stat_mod
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


def hash_bytes(data: bytes, algo: str = "sha256") -> str:
    return hashlib.new(algo, data).hexdigest()


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


def _mount_table() -> List[tuple]:
    """(mountpoint, fstype) pairs, longest mountpoint first."""
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
    """
    raw = path_env if path_env is not None else os.environ.get("PATH", "")
    out: List[Dict[str, Any]] = []
    for directory in raw.split(os.pathsep):
        if not directory:
            continue
        resolved = os.path.realpath(directory)
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
