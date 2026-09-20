"""
Landlock-based script confinement — no dependencies, no silent downgrade.

Measured facts this module relies on (see ``research/findings/res-sandboxing.md``
for the probe output):

* Landlock is reachable through three syscalls (444 ``create_ruleset``, 445
  ``add_rule``, 446 ``restrict_self``) with a raw-syscall trampoline, so the
  runtime stays standard-library only;
* a ruleset is **deny-by-default**: once applied, only the paths granted below
  are reachable, which is what makes it useful for running a script you have not
  read;
* it cannot restrict ``stat``/``chdir``/``access`` (metadata still leaks) and
  ABI 3 has no network rights — socket denial is done with a seccomp filter;
* ``PR_SET_NO_NEW_PRIVS`` is mandatory before restricting.

Levels
------
``off``     no confinement (default; use it on your own analysis host)
``vm``      full read of the system, writes only where collection outputs go
``ro``      same reads, no writes at all
``strict``  no writes, no sockets, and no *execute* outside system directories:
            a script cannot launch a payload it just dropped

The levels are enforced inside the process that runs the script. For ``jocky
run`` that is the CLI process itself, so the restriction applies for the rest of
that process's life — which is exactly one run.

Platforms: every mechanism named above is Linux-only (Landlock, seccomp, the
``syscall(2)`` instructions they are reached through). Off Linux nothing here can
be enforced, and each entry point says so through
:func:`unavailable_reason` / :func:`probe` rather than letting a host exception
escape — see :func:`apply` for what that means for a caller asking anyway.
"""
from __future__ import annotations

import ctypes
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

LEVELS = ("off", "vm", "ro", "strict")


def unavailable_reason() -> Optional[str]:
    """Why confinement cannot exist on this host, or ``None`` on Linux.

    ``None`` means "ask the kernel": Landlock may still be missing from a Linux
    kernel, which :func:`probe` reports separately. A non-``None`` answer means
    no configuration can ever make :func:`apply` enforce anything here — Landlock
    is a Linux LSM reached through Linux syscalls, and the seccomp filter that
    backs the ``strict`` level is equally Linux-only. Windows gets neither:
    ``ctypes.CDLL(None)`` there is not "the process's own libc" and raises
    ``TypeError: LoadLibrary() argument 1 must be str, not None``.
    """
    if not sys.platform.startswith("linux"):
        return (f"Landlock is a Linux-only mechanism (sys.platform={sys.platform!r}); "
                "this host has no confinement to apply")
    return None


# --- raw syscall numbers (x86_64 Linux) -------------------------------------
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
SYS_PRCTL = 157

PR_SET_NO_NEW_PRIVS = 38
LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_CREATE_RULESET_VERSION = 1

# --- filesystem access rights ----------------------------------------------
ACCESS_EXECUTE = 1 << 0
ACCESS_WRITE_FILE = 1 << 1
ACCESS_READ_FILE = 1 << 2
ACCESS_READ_DIR = 1 << 3
ACCESS_REMOVE_DIR = 1 << 4
ACCESS_REMOVE_FILE = 1 << 5
ACCESS_MAKE_CHAR = 1 << 6
ACCESS_MAKE_DIR = 1 << 7
ACCESS_MAKE_REG = 1 << 8
ACCESS_MAKE_SOCK = 1 << 9
ACCESS_MAKE_FIFO = 1 << 10
ACCESS_MAKE_BLOCK = 1 << 11
ACCESS_MAKE_SYM = 1 << 12
ACCESS_REFER = 1 << 13          # ABI 2+
ACCESS_TRUNCATE = 1 << 14       # ABI 3+

READ_ONLY = (ACCESS_READ_FILE | ACCESS_READ_DIR | ACCESS_EXECUTE)
WRITE_ACCESS = (
    ACCESS_WRITE_FILE | ACCESS_REMOVE_DIR | ACCESS_REMOVE_FILE | ACCESS_MAKE_CHAR
    | ACCESS_MAKE_DIR | ACCESS_MAKE_REG | ACCESS_MAKE_SOCK | ACCESS_MAKE_FIFO
    | ACCESS_MAKE_BLOCK | ACCESS_MAKE_SYM | ACCESS_REFER | ACCESS_TRUNCATE
)
ALL_ACCESS = READ_ONLY | WRITE_ACCESS

#: Directories a collection script legitimately needs to read. The drop zones
#: are here on purpose: dropped executables and staged payloads live in /tmp,
#: /var/tmp and /dev/shm, and confining a triage script away from them would
#: hide the artefacts it exists to find (reading them widens no privilege).
READ_ROOTS = ("/proc", "/sys", "/dev", "/usr", "/lib", "/lib64", "/etc", "/bin",
              "/sbin", "/run", "/var/log", "/snap",
              "/tmp", "/var/tmp", "/dev/shm")

#: The runtime's own package directory. A confined interpreter still has to be
#: able to import its own modules — several natives import lazily inside the
#: call (`jocky.exec.memfd`, `jocky.rt.raw`), and denying them turns a routine
#: read into an EACCES far from the cause. Granted as a read rule in every level.
PACKAGE_ROOT = os.path.dirname(os.path.abspath(__file__))

#: The same argument one level up: the *installation* the interpreter itself
#: lives in. ``READ_ROOTS`` assumes the FHS layout, which is where a distribution
#: Python sits, but a standalone or pyenv install does not live there at all — a
#: GitHub runner keeps CPython under /opt/hostedtoolcache, where the first lazy
#: stdlib import inside the ruleset (``threading``, say) is denied, as is
#: reading ``/proc/self/exe`` because that resolves to the interpreter binary.
INTERPRETER_ROOTS = tuple(dict.fromkeys(
    path for path in (sys.base_prefix, sys.prefix, sys.exec_prefix) if path))

#: Where output may be written (per level).
WRITE_ROOTS = ("/tmp", "/var/tmp", "/dev/shm")

# --- seccomp (strict level) --------------------------------------------------
SYS_SOCKET = 41
SYS_PTRACE = 101
SYS_REBOOT = 169
SYS_KEXEC_LOAD = 246
SYS_PROCESS_VM_READV = 310
SYS_PROCESS_VM_WRITEV = 311
SYS_SECCOMP = 317
SYS_KEXEC_FILE_LOAD = 320
SYS_IO_URING_SETUP = 425
SYS_IO_URING_ENTER = 426
SYS_IO_URING_REGISTER = 427

BLOCKED_SYSCALLS = (
    SYS_SOCKET,
    SYS_PTRACE,
    SYS_REBOOT,
    SYS_KEXEC_LOAD,
    SYS_PROCESS_VM_READV,
    SYS_PROCESS_VM_WRITEV,
    SYS_KEXEC_FILE_LOAD,
    SYS_IO_URING_SETUP,
    SYS_IO_URING_ENTER,
    SYS_IO_URING_REGISTER,
)

SECCOMP_SET_MODE_FILTER = 1
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
EPERM = 1
AUDIT_ARCH_X86_64 = 0xC000003E
#: Offsets inside ``struct seccomp_data`` (arch, nr, args…).
OFFSET_NR = 0
OFFSET_ARCH = 4


@dataclass
class SandboxReport:
    """What was actually enforced — never assume, report."""

    level: str = "off"
    applied: bool = False
    abi: Optional[int] = None
    reason: str = ""
    rules: List[Tuple[str, int]] = field(default_factory=list)
    #: Paths a rule was asked for but could not be installed on (missing or
    #: unreachable). Reporting them keeps "the confinement in force" honest.
    rules_skipped: List[Tuple[str, int]] = field(default_factory=list)
    seccomp: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "applied": self.applied,
            "abi": self.abi,
            "reason": self.reason,
            "rules_skipped": list(self.rules_skipped),
            "rules": [{"path": path, "access": access} for path, access in self.rules],
            "network_blocked": self.seccomp,
        }


def _raw_syscall(number: int, *args: int) -> int:
    """Prefer the direct trampoline; fall back to libc.

    Raises :class:`RuntimeError` where no syscall facility exists at all:
    ``ctypes.CDLL(None)`` only means "the libc this process is linked against"
    on a POSIX host, and calling it off Linux raises a ``TypeError`` from deep
    inside ``ctypes`` that no caller could act on.
    """
    reason = unavailable_reason()
    if reason is not None:
        raise RuntimeError(reason)
    try:
        from jocky.rt import raw

        if raw.probe().get("available"):
            return raw.syscall(number, *args)
    except Exception:
        pass
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(ctypes.c_long(number), *[ctypes.c_long(a) for a in args])
    if result < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return int(result)


def abi_version() -> Optional[int]:
    """Landlock ABI version, or ``None`` when Landlock is not there to ask.

    ``None`` covers both "this kernel has no Landlock" and "this host cannot have
    it at all" (:func:`unavailable_reason`); the return contract is unchanged by
    platform, and :func:`probe` — the one caller that has to tell the two apart —
    says which case it is.
    """
    if unavailable_reason() is not None:
        return None
    try:
        return _raw_syscall(SYS_LANDLOCK_CREATE_RULESET, 0, 0,
                            LANDLOCK_CREATE_RULESET_VERSION)
    except OSError:
        return None


def probe() -> Dict[str, Any]:
    """Report availability without changing this process.

    ``available`` is the answer to "can confinement be enforced right now";
    ``supported`` is the answer to "could it ever be, on this platform". Both are
    present on every platform so a caller never has to infer the platform from
    the reason text.
    """
    reason = unavailable_reason()
    if reason is not None:
        return {
            "available": False,
            "supported": False,
            "abi": None,
            "levels": list(LEVELS),
            "network_rights": False,
            "reason": reason,
        }
    abi = abi_version()
    return {
        "available": abi is not None and abi >= 1,
        "supported": True,
        "abi": abi,
        "levels": list(LEVELS),
        "network_rights": abi is not None and abi >= 4,
        "reason": "kernel supports Landlock" if abi else
                  "no Landlock in this kernel (needs CONFIG_SECURITY_LANDLOCK)",
    }


def _access_for(abi: int, write: bool) -> int:
    access = ALL_ACCESS if write else READ_ONLY
    if abi < 3:
        access &= ~ACCESS_TRUNCATE
    if abi < 2:
        access &= ~ACCESS_REFER
    return access


def _add_path_rule(ruleset_fd: int, path: str, access: int) -> bool:
    """Grant ``access`` beneath ``path``; report whether a rule was installed.

    The return value matters: the report is what an operator reads to decide
    whether the confinement they asked for is real, so a path that could not be
    opened (missing, or denied) must not appear as a granted rule.
    """
    try:
        parent = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        # struct landlock_path_beneath_attr { __u64 allowed_access; __s32 parent_fd; }
        # (packed: 12 bytes, which is what "<Qi" produces). The buffer must stay
        # alive until the syscall has run — passing an address of a temporary
        # sends the kernel a dangling pointer and lands on EINVAL.
        attr = struct.pack("<Qi", access, parent)
        attr_buffer = ctypes.create_string_buffer(attr, len(attr))
        result = _raw_syscall(SYS_LANDLOCK_ADD_RULE, ruleset_fd,
                              LANDLOCK_RULE_PATH_BENEATH,
                              ctypes.addressof(attr_buffer), 0)
        return result == 0
    finally:
        os.close(parent)


def _install_socket_filter() -> bool:
    """Deny dangerous attack primitives (socket, ptrace, io_uring, kexec) with EPERM.

    Constructs a linear BPF dispatch over ``BLOCKED_SYSCALLS``, falling onto
    SECCOMP_RET_ALLOW if no hazardous syscall is invoked.
    """
    program = [
        (BPF_LD | BPF_W | BPF_ABS, 0, 0, OFFSET_ARCH),
        (BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_X86_64),   # match -> nr load
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),             # other arch: allow
        (BPF_LD | BPF_W | BPF_ABS, 0, 0, OFFSET_NR),
    ]
    n_blocked = len(BLOCKED_SYSCALLS)
    for i, nr in enumerate(BLOCKED_SYSCALLS):
        jt = (n_blocked - 1 - i) + 1
        jf = 0
        program.append((BPF_JMP | BPF_JEQ | BPF_K, jt, jf, nr))

    program.append((BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW))
    program.append((BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM))
    blob = b"".join(struct.pack("<HBBI", code, jt, jf, k) for code, jt, jf, k in program)
    buffer = ctypes.create_string_buffer(blob, len(blob))
    # struct sock_fprog { unsigned short len; struct sock_filter *filter; } is
    # 16 bytes on x86_64 because the pointer is 8-byte aligned: the pointer
    # lives at offset 8, so the padding must be explicit ("<H6xQ"). Packing it
    # as "<HQ" places it at offset 2 and the kernel reads zeros -> EFAULT.
    # Both buffers are kept in locals so they outlive the syscall.
    fprog_blob = struct.pack("<H6xQ", len(program), ctypes.addressof(buffer))
    fprog = ctypes.create_string_buffer(fprog_blob, len(fprog_blob))
    try:
        _raw_syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, 0, ctypes.addressof(fprog))
        return True
    except OSError:
        return False


def run_sandboxed(level: str, function, *args: Any, **kwargs: Any) -> Any:
    """Deprecated helper kept for clarity: use :func:`apply` instead."""
    apply(level)
    return function(*args, **kwargs)


def apply(level: str, extra_write: Optional[List[str]] = None,
          extra_read: Optional[List[str]] = None) -> SandboxReport:
    """Confine the *current* process to ``level``.

    ``extra_read`` / ``extra_write`` grant paths the caller legitimately needs
    beyond the defaults — a test runner, for example, must still be able to read
    its own corpus after a ruleset is applied, and confinement cannot be relaxed
    once installed.

    Returns a report saying what was enforced; raises ``RuntimeError`` when the
    caller asked for confinement the kernel cannot provide. Silent downgrade is
    the failure mode that matters here: a script that believes it is sandboxed
    and is not would be worse than no sandbox at all.

    The two kinds of "cannot provide" are answered differently, on purpose:

    * a **Linux host whose kernel lacks Landlock** raises ``RuntimeError``. The
      host is supposed to be able to enforce, so a caller that asked anyway is
      better served by a hard stop than by a run that silently was not confined.
    * a **host with no confinement mechanism at all** (``unavailable_reason()``
      is not ``None``) returns an unenforced report — ``applied`` is ``False``
      and ``reason`` names the platform — instead of raising. There is nothing
      that could be fixed, and raising would make ``--sandbox`` unconditionally
      fatal on a platform the rest of the runtime still works on. The report is
      how the refusal reaches the caller: check ``applied``, never assume.
    """
    level = (level or "off").lower()
    if level not in LEVELS:
        raise ValueError(f"unknown sandbox level {level!r}; choose from {LEVELS}")
    report = SandboxReport(level=level)
    if level == "off":
        report.reason = "confinement disabled by request"
        return report

    reason = unavailable_reason()
    if reason is not None:
        report.reason = f"not enforced: {reason}"
        return report

    abi = abi_version()
    if abi is None or abi < 1:
        raise RuntimeError(
            "sandbox requested but this kernel has no Landlock "
            "(CONFIG_SECURITY_LANDLOCK); rerun with --sandbox=off only if that is acceptable"
        )
    report.abi = abi

    attributes = struct.pack("<Q", _access_for(abi, write=True))
    buffer = ctypes.create_string_buffer(attributes, len(attributes))
    ruleset_fd = _raw_syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.addressof(buffer),
                              len(attributes), 0)

    read_access = _access_for(abi, write=False)
    write_access = _access_for(abi, write=True)
    def grant(path: str, access: int) -> None:
        if _add_path_rule(ruleset_fd, path, access):
            report.rules.append((path, access))
        else:
            report.rules_skipped.append((path, access))

    for root in READ_ROOTS + (PACKAGE_ROOT,) + INTERPRETER_ROOTS:
        grant(root, read_access)
    for root in extra_read or ():
        grant(root, read_access)
    for root in tuple(WRITE_ROOTS) + tuple(extra_write or ()):
        if level in ("vm",):
            grant(root, write_access)
    # the working directory is where collection output goes
    if level == "vm":
        grant(os.getcwd(), write_access)

    # PR_SET_DUMPABLE=0 forbids /proc/self/mem modifications and unprivileged ptrace
    PR_SET_DUMPABLE = 4
    _raw_syscall(SYS_PRCTL, PR_SET_DUMPABLE, 0, 0, 0, 0)
    # PR_SET_NO_NEW_PRIVS is a hard prerequisite for landlock_restrict_self
    _raw_syscall(SYS_PRCTL, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    _raw_syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
    os.close(ruleset_fd)
    report.applied = True
    report.reason = f"Landlock ABI {abi} ruleset applied"

    if level == "strict":
        report.seccomp = _install_socket_filter()
        report.reason += "; socket(2) denied" if report.seccomp else \
            "; socket(2) NOT denied (seccomp unavailable)"
    return report
