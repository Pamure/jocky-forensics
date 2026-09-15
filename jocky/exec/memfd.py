"""Fileless execution for the JOCKY runtime.

Programs and payloads are never written to disk: they live in an anonymous
``memfd`` (``memfd_create``), are made executable, and are handed to the kernel
through the ``/proc/self/fd/N`` magic link. That is the same technique real
fileless malware uses, so the runtime can both *perform* and *observe* it:

* :func:`run_in_memfd` runs a Python program from memory and captures the
  result, leaving no artefact on the filesystem to clean up or to leak.
* :func:`is_memfd_process` and :func:`memfd_backed_maps` are the detection
  side, reading only ``/proc``.

The memfd is deliberately created *without* ``MFD_CLOEXEC``: the descriptor has
to survive the ``execve`` so the executable (and, for scripts, the interpreter)
can still reach it after the process image is replaced.
"""
from __future__ import annotations

import os
import selectors
import signal
import time
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "create_memfd",
    "run_in_memfd",
    "is_memfd_process",
    "memfd_backed_maps",
    "DEFAULT_SHEBANG",
]

#: Interpreter line injected when the caller hands us bare source.
DEFAULT_SHEBANG = "#!/usr/bin/env python3"

_READ_CHUNK = 65536
_POLL_INTERVAL = 0.05
#: Grace period after SIGKILL: a process stuck in uninterruptible sleep may
#: outlive the signal, and we would rather report that than block forever.
_KILL_GRACE = 5.0


def create_memfd(name: str, data: bytes, mode: int = 0o700) -> int:
    """Create an executable anonymous file named ``name`` holding ``data``.

    ``flags=0`` is load bearing — ``MFD_CLOEXEC`` would close the descriptor on
    ``execve``, which is exactly the descriptor the new process needs to read
    itself. Returns an open, rewound descriptor; the caller owns it.
    """
    if not hasattr(os, "memfd_create"):
        raise RuntimeError("memfd_create is unavailable on this platform")
    try:
        fd = os.memfd_create(name, flags=0)
    except OSError as exc:
        raise RuntimeError(f"memfd_create({name!r}) failed: {exc}") from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:  # pragma: no cover - the kernel does not do this
                raise OSError(f"short write to memfd {name!r}")
            view = view[written:]
        os.fchmod(fd, mode)
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError as exc:
        os.close(fd)
        raise RuntimeError(f"populating memfd {name!r} failed: {exc}") from exc
    return fd


def _with_shebang(source: str) -> str:
    """Ensure the program starts with exactly one interpreter line."""
    body = source[1:] if source.startswith("\ufeff") else source
    if body.startswith("#!"):
        return body
    return f"{DEFAULT_SHEBANG}\n{body}"


def _close_extra_fds(keep: set) -> None:
    """Close everything above stderr except ``keep``.

    A process launched from memory must not silently inherit the launcher's
    session logs, sockets or caches; and an inherited pipe would keep the
    parent's capture fds open after the child is gone.
    """
    try:
        entries = os.listdir("/proc/self/fd")
    except OSError:
        return
    for entry in entries:
        try:
            fd = int(entry)
        except ValueError:
            continue
        if fd <= 2 or fd in keep:
            continue
        try:
            os.close(fd)
        except OSError:
            pass


def _child_exec(out_r: int, out_w: int, err_r: int, err_w: int, st_w: int,
                name: str, data: bytes, argv: List[str], env: Dict[str, str]) -> None:
    """Child half of :func:`run_in_memfd`; never returns."""
    try:
        devnull = os.open(os.devnull, os.O_RDONLY)
        os.close(out_r)
        os.close(err_r)
        os.dup2(devnull, 0)
        os.dup2(out_w, 1)
        os.dup2(err_w, 2)
        for fd in (devnull, out_w, err_w):
            if fd > 2:
                os.close(fd)
        # The status pipe is CLOEXEC, so it disappears on a successful exec and
        # the parent sees EOF; the memfd is not, and must not be.
        _close_extra_fds({st_w})
        fd = create_memfd(name, data)
        os.write(st_w, b"OK %d\n" % fd)
        os.execve(f"/proc/self/fd/{fd}", argv, env)
    except BaseException as exc:  # noqa: BLE001 - the child must only report
        try:
            os.write(st_w, f"ERR {type(exc).__name__}: {exc}\n".encode("utf-8", "replace"))
        except OSError:
            pass
    os._exit(127)


def _read_status(data: bytes) -> Tuple[Optional[int], Optional[str]]:
    """Decode the child's status line into ``(memfd_fd, error_message)``."""
    lines = [line for line in data.decode("utf-8", "replace").splitlines() if line]
    if not lines:
        return None, None
    line = lines[-1]  # an execve failure lands after the OK line
    if line.startswith("OK "):
        try:
            return int(line[3:]), None
        except ValueError:
            return None, line
    return None, line


def _drain(fds: List[int], deadline: Optional[float]) -> Tuple[Dict[int, bytes], bool]:
    """Read every pipe to EOF, or until ``deadline``; report the timeout."""
    buffers: Dict[int, bytearray] = {fd: bytearray() for fd in fds}
    timed_out = False
    selector = selectors.DefaultSelector()
    for fd in fds:
        selector.register(fd, selectors.EVENT_READ)
    pending = set(fds)
    try:
        while pending:
            wait = None
            if deadline is not None:
                wait = deadline - time.monotonic()
                if wait <= 0:
                    timed_out = True
                    break
            for key, _ in selector.select(timeout=wait):
                try:
                    chunk = os.read(key.fd, _READ_CHUNK)
                except OSError:
                    chunk = b""
                if chunk:
                    buffers[key.fd] += chunk
                else:
                    selector.unregister(key.fd)
                    pending.discard(key.fd)
                    os.close(key.fd)
    finally:
        selector.close()
        for fd in pending:
            try:
                os.close(fd)
            except OSError:
                pass
    return {fd: bytes(buf) for fd, buf in buffers.items()}, timed_out


def _reap(pid: int, deadline: Optional[float]) -> Optional[int]:
    """Wait for ``pid``, or return ``None`` once ``deadline`` passes."""
    while True:
        try:
            done, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return None
        if done == pid:
            return status
        if deadline is not None and time.monotonic() >= deadline:
            return None
        time.sleep(_POLL_INTERVAL / 10)


def _exit_code(status: Optional[int]) -> Optional[int]:
    """Normalise a wait status to a process exit code (negative = signal)."""
    if status is None:
        return None
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    return None


def run_in_memfd(source: str, argv: Optional[List[str]] = None,
                 env: Optional[Dict[str, str]] = None, timeout: Optional[float] = None,
                 name: str = "jky") -> Dict[str, Any]:
    """Run ``source`` as a program that exists only in memory.

    The source is stored in an anonymous ``memfd`` and executed through
    ``/proc/self/fd/<fd>``, so no temporary file is created anywhere. stdout and
    stderr are captured through pipes and ``timeout`` (seconds) eventually
    SIGKILLs the child.

    Returns ``exit_code`` (``None`` if it never reaped, negative when killed by
    a signal), ``stdout``/``stderr`` text, ``duration_ms``, the child ``pid``,
    ``memfd_created`` (the child's memfd descriptor, ``None`` when the child
    failed before exec) and ``timed_out``.
    """
    program = _with_shebang(source)
    data = program.encode("utf-8")
    child_argv = ["/memfd:" + name, *(argv or [])]
    child_env = dict(env) if env else dict(os.environ)

    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    # CLOEXEC: the child writes its status before execve, and the descriptor
    # must not leak into the program (that would keep our reader open forever).
    st_r, st_w = os.pipe2(os.O_CLOEXEC)

    started = time.monotonic()
    deadline = None if timeout is None else started + float(timeout)
    pid = os.fork()
    if pid == 0:
        _child_exec(out_r, out_w, err_r, err_w, st_w, name, data, child_argv, child_env)
        os._exit(127)  # _child_exec never returns; keep the parent half unreachable

    os.close(out_w)
    os.close(err_w)
    os.close(st_w)
    captured, timed_out = _drain([out_r, err_r, st_r], deadline)

    if timed_out:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        status = _reap(pid, time.monotonic() + _KILL_GRACE)
    else:
        status = _reap(pid, deadline)
    duration_ms = int(round((time.monotonic() - started) * 1000))

    memfd_fd, child_error = _read_status(captured.get(st_r, b""))
    stderr = captured.get(err_r, b"").decode("utf-8", "replace")
    if child_error:
        # Surface a pre-exec failure (no memfd, execve refused) instead of a
        # bare exit code 127.
        stderr = f"{stderr}{'' if not stderr or stderr.endswith(chr(10)) else chr(10)}memfd child: {child_error}\n"
    return {
        "exit_code": _exit_code(status),
        "stdout": captured.get(out_r, b"").decode("utf-8", "replace"),
        "stderr": stderr,
        "duration_ms": duration_ms,
        "pid": pid,
        "memfd_created": memfd_fd,
        "timed_out": timed_out,
    }


def is_memfd_process(pid: int) -> bool:
    """True when ``pid`` runs code that came from an anonymous memory file.

    A native (ELF) memfd program *is* the process image, so ``/proc/<pid>/exe``
    names ``/memfd:<name> (deleted)``. A shebang script is different: the kernel
    replaces the image with the interpreter, so ``exe`` is plain ``python3``
    while the memfd survives as the non-CLOEXEC descriptor it was exec'd from.
    Both shapes are reported, with the descriptor scan as the second opinion.
    """
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return False
    if "memfd:" in exe:
        return True
    try:
        descriptors = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return False
    for entry in descriptors:
        try:
            if "memfd:" in os.readlink(f"/proc/{pid}/fd/{entry}"):
                return True
        except OSError:
            continue
    return False


def memfd_backed_maps(pid: int) -> List[Dict[str, Any]]:
    """Report mapped regions of ``pid`` whose backing file is a memfd.

    Only ``/proc/<pid>/maps`` is consulted, so this sees actual memory
    mappings — the strongest evidence of in-memory code execution.
    """
    entries: List[Dict[str, Any]] = []
    try:
        with open(f"/proc/{pid}/maps", "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return entries
    for line in lines:
        fields = line.split()
        if len(fields) < 6:
            continue
        path = " ".join(fields[5:])
        if "memfd:" not in path:
            continue
        try:
            start, end = (int(part, 16) for part in fields[0].split("-", 1))
        except ValueError:
            continue
        entries.append({
            "start": start,
            "end": end,
            "perms": fields[1],
            "path": path,
        })
    return entries
