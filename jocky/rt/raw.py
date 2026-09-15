"""Raw x86_64 Linux syscalls straight from pure Python.

Why bypass libc at all: a forensic runtime must be able to observe what the
kernel actually returned. libc wrappers funnel everything through a
thread-local, stale-prone ``errno`` and can be interposed by ``LD_PRELOAD``;
issuing the ``syscall`` instruction ourselves removes both from the evidence
chain and needs no compiler, no C source and no file on disk.

The trampoline is 15 hand-assembled bytes placed in an anonymous RWX mapping.
Everything here is guarded: if the mapping cannot be created, if
``mmap.PROT_EXEC`` is refused, or if the proof-of-life call disagrees with
:func:`os.getpid`, the raw path is abandoned and ``libc.syscall`` takes over.
A forensic tool that crashes the interpreter is worse than one that is slow.
"""
from __future__ import annotations

import ctypes
import mmap
import os
import platform
import sys
from typing import Callable, Dict, Optional, Tuple

__all__ = ["RawSyscall", "syscall", "uname", "probe"]

# Syscall numbers we depend on (x86_64, stable ABI: they never change).
SYS_GETPID = 39
SYS_UNAME = 63

# The kernel signals failure by returning -errno from the syscall instruction;
# valid errno values stay well below 4096, so anything in [-4095, -1] is a
# failure and everything else is a legitimate (possibly huge) success value.
_ERRNO_CEILING = 4095

# libc's syscall() variadic prototype: number + up to five arguments.
_MAX_ARGS = 5

# ------------------------------------------------------------------ trampoline
# The SysV x86_64 ABI hands a C function its first six integers in
# rdi, rsi, rdx, rcx, r8, r9, while the kernel expects rax, rdi, rsi, rdx,
# r10, r8. The shifts below are ordered so no source register is clobbered
# before it is consumed:
#   rax <- rdi (number)      r10 <- r8  (a4)     rdi <- rsi (a1)
#   r8  <- r9  (a5)          rsi <- rdx (a2)     rdx <- rcx (a3)
_TRAMPOLINE = bytes((
    0x48, 0x89, 0xF8,   # mov rax, rdi
    0x4D, 0x89, 0xC2,   # mov r10, r8
    0x4D, 0x89, 0xC8,   # mov r8, r9
    0x48, 0x89, 0xF7,   # mov rdi, rsi
    0x48, 0x89, 0xD6,   # mov rsi, rdx
    0x48, 0x89, 0xCA,   # mov rdx, rcx
    0x0F, 0x05,         # syscall
    0xC3,               # ret
))
_TRAMPOLINE_SIZE = 64  # one page-less allocation with slack; we only need 15

# c_long fn(c_long number, c_long a1 .. c_long a5)
_SYSCALL_PROTO = ctypes.CFUNCTYPE(
    ctypes.c_long, *([ctypes.c_long] * (_MAX_ARGS + 1))  # type: ignore[arg-type]
)


def _raw_supported() -> bool:
    """True only on x86_64 Linux, the one ABI the trampoline encodes."""
    if not sys.platform.startswith("linux"):
        return False
    return platform.machine().lower() in ("x86_64", "amd64")


class RawSyscall:
    """Direct ``syscall`` instruction access with a libc fallback.

    The trampoline is built lazily by :meth:`available`, which only reports
    success after proving itself against :func:`os.getpid` — so a caller never
    has to trust a flag that was set optimistically.
    """

    def __init__(self) -> None:
        self._mm: Optional[mmap.mmap] = None
        self._banner: Optional[ctypes.Array] = None
        self._fn: Optional[Callable[..., int]] = None
        self._libc: Optional[Callable[..., int]] = None
        self._method = "libc"
        self._probed = False
        self._ok = False

    # ------------------------------------------------------------- properties
    @property
    def method(self) -> str:
        """``"raw"`` when the trampoline works, otherwise ``"libc"``."""
        return self._method

    # ----------------------------------------------------------- trampoline
    def _build(self) -> bool:
        """Map, fill and bind the trampoline. Never raises."""
        if not _raw_supported():
            return False
        mm: Optional[mmap.mmap] = None
        try:
            mm = mmap.mmap(-1, _TRAMPOLINE_SIZE,
                           prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
            mm.write(_TRAMPOLINE)
            # from_buffer keeps the mapping exported, so the address stays
            # valid for as long as the banner object lives.
            banner = (ctypes.c_char * _TRAMPOLINE_SIZE).from_buffer(mm)
            fn = _SYSCALL_PROTO(ctypes.addressof(banner))
        except (OSError, ValueError, TypeError, AttributeError):
            banner = None  # drop any exported buffer so close() cannot fail
            if mm is not None:
                try:
                    mm.close()
                except (OSError, ValueError, BufferError):
                    pass
            return False
        self._mm = mm
        self._banner = banner
        self._fn = fn
        self._method = "raw"
        return True

    def available(self) -> bool:
        """Prove the raw path works by comparing ``getpid`` with ``os.getpid``.

        The result is memoised: the proof is a one-shot, and a trampoline that
        failed once must not be retried on every call.
        """
        if self._probed:
            return self._ok
        self._probed = True
        if not self._build():
            return False
        try:
            self._ok = int(self._fn(SYS_GETPID, 0, 0, 0, 0, 0)) == os.getpid()
        except Exception:  # a bad trampoline must degrade, not detonate
            self._ok = False
        if not self._ok:
            self.close()
        return self._ok

    # -------------------------------------------------------------- syscalls
    def syscall(self, number: int, *args: int) -> int:
        """Issue syscall ``number`` with up to five integer arguments.

        Raises :class:`OSError` carrying ``errno``/``strerror`` when the kernel
        reports failure, matching what a libc caller would see.
        """
        if len(args) > _MAX_ARGS:
            raise ValueError(
                f"syscall() takes at most {_MAX_ARGS} arguments, got {len(args)}")
        values = tuple(int(a) for a in args)
        if self.available():
            padded = values + (0,) * (_MAX_ARGS - len(values))
            raw = int(self._fn(int(number), *padded))
            if -_ERRNO_CEILING <= raw < 0:
                err = -raw
                raise OSError(err, os.strerror(err))
            return raw
        return self._libc_syscall(int(number), values)

    def _libc_syscall(self, number: int, values: Tuple[int, ...]) -> int:
        """Fallback path: ``libc.syscall`` with ``errno`` translated."""
        call = self._libc_entry()
        ctypes.set_errno(0)
        result = int(call(ctypes.c_long(number), *[ctypes.c_long(v) for v in values]))
        if result == -1:
            err = ctypes.get_errno()
            if err:
                raise OSError(err, os.strerror(err))
        return result

    def _libc_entry(self) -> Callable[..., int]:
        """Bind ``libc.syscall`` once, or explain why no path is left."""
        if self._libc is not None:
            return self._libc
        try:
            entry = ctypes.CDLL(None, use_errno=True).syscall
        except (OSError, AttributeError, TypeError) as exc:
            raise RuntimeError(
                "no syscall facility available: the x86_64 trampoline could not "
                f"be built and libc exposes no syscall(): {exc}") from exc
        entry.restype = ctypes.c_long
        self._libc = entry
        return entry

    # --------------------------------------------------------------- cleanup
    def close(self) -> None:
        """Drop the trampoline and release the RWX mapping (idempotent)."""
        self._fn = None
        self._banner = None  # release the exported buffer before closing it
        mm, self._mm = self._mm, None
        if mm is not None:
            try:
                mm.close()
            except (OSError, ValueError, BufferError):
                pass
        if self._method == "raw":
            self._method = "libc"


_SINGLETON: Optional[RawSyscall] = None


def _instance() -> RawSyscall:
    """The process-wide syscall handle, created on first use."""
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = RawSyscall()
    return _SINGLETON


def syscall(number: int, *args: int) -> int:
    """Issue ``number`` on the shared :class:`RawSyscall` handle."""
    return _instance().syscall(number, *args)


# ``struct new_utsname`` is six 65-byte C strings: sysname, nodename, release,
# version, machine, domainname. The kernel copies all six; older kernels simply
# leave domainname empty.
_UTS_FIELDS = ("sysname", "nodename", "release", "version", "machine", "domainname")
_UTS_FIELD_LEN = 65
_UTS_SIZE = _UTS_FIELD_LEN * len(_UTS_FIELDS)


def uname() -> Dict[str, str]:
    """Read ``struct utsname`` through syscall 63.

    The decode is cross-checked against :func:`os.uname`: if our layout were
    wrong the fields would be garbage, and silently reporting garbage as
    forensic evidence is unacceptable.
    """
    buf = ctypes.create_string_buffer(_UTS_SIZE)
    syscall(SYS_UNAME, ctypes.addressof(buf))
    raw = buf.raw
    result = {
        field: raw[i * _UTS_FIELD_LEN:(i + 1) * _UTS_FIELD_LEN]
        .split(b"\0", 1)[0].decode("utf-8", "replace")
        for i, field in enumerate(_UTS_FIELDS)
    }
    reference = os.uname()
    for field in ("sysname", "nodename", "release", "version", "machine"):
        expected = getattr(reference, field)
        if result[field] != expected:
            raise AssertionError(
                f"raw uname field {field}={result[field]!r} disagrees with "
                f"os.uname()={expected!r}")
    return result


def probe() -> Dict[str, object]:
    """Report which syscall path is live on this host."""
    handle = _instance()
    return {
        "available": handle.available(),
        "method": handle.method,
        "arch": platform.machine(),
        "kernel": os.uname().release,
    }
