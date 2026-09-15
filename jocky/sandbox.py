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
"""
from __future__ import annotations

import ctypes
import os
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

LEVELS = ("off", "vm", "ro", "strict")

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

#: Directories a collection script legitimately needs to read.
READ_ROOTS = ("/proc", "/sys", "/dev", "/usr", "/lib", "/lib64", "/etc", "/bin",
              "/sbin", "/run", "/var/log", "/snap")

#: The runtime's own package directory. A confined interpreter still has to be
#: able to import its own modules — several natives import lazily inside the
#: call (`jocky.exec.memfd`, `jocky.rt.raw`), and denying them turns a routine
#: read into an EACCES far from the cause. Granted as a read rule in every level.
PACKAGE_ROOT = os.path.dirname(os.path.abspath(__file__))
#: Where output may be written (per level).
WRITE_ROOTS = ("/tmp", "/var/tmp", "/dev/shm")

# --- seccomp (strict level) --------------------------------------------------
SYS_SOCKET = 41
SYS_SECCOMP = 317
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
    seccomp: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "applied": self.applied,
            "abi": self.abi,
            "reason": self.reason,
            "rules": [{"path": path, "access": access} for path, access in self.rules],
            "network_blocked": self.seccomp,
        }


def _raw_syscall(number: int, *args: int) -> int:
    """Prefer the direct trampoline; fall back to libc."""
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
    """Landlock ABI version, or ``None`` when the kernel lacks Landlock."""
    try:
        return _raw_syscall(SYS_LANDLOCK_CREATE_RULESET, 0, 0,
                            LANDLOCK_CREATE_RULESET_VERSION)
    except OSError:
        return None


def probe() -> Dict[str, Any]:
    """Report availability without changing this process."""
    abi = abi_version()
    return {
        "available": abi is not None and abi >= 1,
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


def _add_path_rule(ruleset_fd: int, path: str, access: int) -> None:
    """Grant ``access`` beneath ``path`` (silently skips absent paths)."""
    try:
        parent = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        return
    try:
        # struct landlock_path_beneath_attr { __u64 allowed_access; __s32 parent_fd; }
        # (packed: 12 bytes, which is what "<Qi" produces). The buffer must stay
        # alive until the syscall has run — passing an address of a temporary
        # sends the kernel a dangling pointer and lands on EINVAL.
        attr = struct.pack("<Qi", access, parent)
        attr_buffer = ctypes.create_string_buffer(attr, len(attr))
        _raw_syscall(SYS_LANDLOCK_ADD_RULE, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                     ctypes.addressof(attr_buffer), 0)
    finally:
        os.close(parent)


def _install_socket_filter() -> bool:
    """Deny ``socket(2)`` with EPERM using a hand-built classic BPF program.

    Jump semantics: the next instruction is ``index + 1 + jt`` on match and
    ``index + 1 + jf`` otherwise, so the two conditional jumps below either skip
    the allow-branch or fall onto it.
    """
    program = [
        (BPF_LD | BPF_W | BPF_ABS, 0, 0, OFFSET_ARCH),
        (BPF_JMP | BPF_JEQ | BPF_K, 1, 0, AUDIT_ARCH_X86_64),   # match -> nr load
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),             # other arch: allow
        (BPF_LD | BPF_W | BPF_ABS, 0, 0, OFFSET_NR),
        (BPF_JMP | BPF_JEQ | BPF_K, 1, 0, SYS_SOCKET),          # match -> EPERM
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
        (BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | EPERM),
    ]
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
    """
    level = (level or "off").lower()
    if level not in LEVELS:
        raise ValueError(f"unknown sandbox level {level!r} (expected one of {', '.join(LEVELS)})")
    report = SandboxReport(level=level)
    if level == "off":
        report.reason = "confinement disabled by request"
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
    for root in READ_ROOTS + (PACKAGE_ROOT,):
        _add_path_rule(ruleset_fd, root, read_access)
        report.rules.append((root, read_access))
    for root in extra_read or ():
        _add_path_rule(ruleset_fd, root, read_access)
        report.rules.append((root, read_access))
    for root in tuple(WRITE_ROOTS) + tuple(extra_write or ()):
        if level in ("vm",):
            _add_path_rule(ruleset_fd, root, write_access)
            report.rules.append((root, write_access))
    # the working directory is where collection output goes
    if level == "vm":
        _add_path_rule(ruleset_fd, os.getcwd(), write_access)
        report.rules.append((os.getcwd(), write_access))

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
