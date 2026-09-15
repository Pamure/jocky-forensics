"""
True fileless execution: interpreter, runtime and payload live only in memory.

Measured facts this module is built on (probe output is reproduced in
``evidence/report.md``):

* a Python interpreter ELF written into ``memfd_create()`` and executed via
  ``/proc/self/fd/<fd>`` runs normally — ``/proc/<pid>/exe`` then reads
  ``/memfd:python3 (deleted)`` and the kernel reports memfd-backed mappings;
* ``zipimport`` accepts ``/proc/self/fd/<fd>`` as a ``sys.path`` entry, so the
  whole ``jocky`` package is imported out of an anonymous memory file;
* the payload (script text or compiled artifact) is a third memfd.

Consequence: no program text, no runtime module and no interpreter path is
written to the target's filesystem.  What *is* still observable — and the
runtime does not pretend otherwise — is process creation, the
``memfd_create``/``execve`` syscalls themselves, and the live process image
(which is exactly why :mod:`jocky.rt.detect` can find this technique).
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
import zipfile
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Bootstrap passed with -c: pure argv text, never a file on disk.  It hardens
# the child before importing anything (process name, no core dumps, not
# dumpable so other same-uid processes cannot read the payload fd), applies the
# capability policy handed over in JKY_ALLOW, and closes the payload descriptor
# once it has been read.  The package fd stays open because zipimport reads it
# lazily for the lifetime of the process.
BOOTSTRAP = """\
import ctypes, json, os, resource, sys
def _harden():
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(15, b"jky", 0, 0, 0)        # PR_SET_NAME
        if os.environ.get("JKY_DUMPABLE", "1") == "0":
            # Opt-in: PR_SET_DUMPABLE=0 makes /proc/<pid>/* root-only, hiding the
            # payload and maps from same-uid processes. It also hides this process
            # from JOCKY's own triage, so it is off by default (see --private).
            libc.prctl(4, 0, 0, 0, 0)
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
_harden()
sys.path.insert(0, "/proc/self/fd/" + os.environ["JKY_PKG"])
from jocky.runner import policy_ctx, run_bytes
with open("/proc/self/fd/" + os.environ["JKY_PAYLOAD"], "rb") as handle:
    data = handle.read()
try:
    os.close(int(os.environ["JKY_PAYLOAD"]))
except OSError:
    pass
result = run_bytes(data, wall_clock_ms=float(os.environ.get("JKY_WALL", "60000")),
                   ctx=policy_ctx(os.environ.get("JKY_ALLOW")))
sys.stdout.write("JKY_RESULT " + json.dumps(result.to_dict()))
"""

_PYTHON_ELF: Optional[bytes] = None
_PACKAGE_ZIP: Optional[bytes] = None


def python_elf() -> bytes:
    """Interpreter image used as the memfd-executed process (cached)."""
    global _PYTHON_ELF
    if _PYTHON_ELF is None:
        with open(os.path.realpath(sys.executable), "rb") as fh:
            _PYTHON_ELF = fh.read()
    return _PYTHON_ELF


def package_zip() -> bytes:
    """The ``jocky`` package packed in memory, so imports need no disk file."""
    global _PACKAGE_ZIP
    if _PACKAGE_ZIP is None:
        buffer = BytesIO()
        package_dir = os.path.join(_REPO_ROOT, "jocky")
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for root, _dirs, files in os.walk(package_dir):
                if "__pycache__" in root:
                    continue
                for name in files:
                    if not name.endswith(".py"):
                        continue
                    full = os.path.join(root, name)
                    archive.write(full, os.path.relpath(full, _REPO_ROOT))
        _PACKAGE_ZIP = buffer.getvalue()
    return _PACKAGE_ZIP


MFD_EXEC = 0x0000_1000          # Linux 6.3+; older kernels return EINVAL


def create_memfd(name: str, data: bytes, mode: int = 0o700) -> int:
    """Anonymous executable/readable memory file (no CLOEXEC, survives exec).

    ``MFD_EXEC`` is requested explicitly where the kernel understands it: with
    ``vm.memfd_noexec >= 1`` a plain ``memfd_create(name, 0)`` is created
    non-executable and a later ``fchmod(+x)`` fails with EPERM, which would
    break fileless mode on hardened hosts.
    """
    try:
        fd = os.memfd_create(name, MFD_EXEC)
    except (OSError, ValueError):
        fd = os.memfd_create(name, 0)
    os.write(fd, data)
    os.fchmod(fd, mode)
    os.lseek(fd, 0, 0)
    return fd


def _drain(fd: int, sink: List[bytes]) -> None:
    while True:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        sink.append(chunk)


def _watch_proc(pid: int, out: Dict[str, Any], stop: threading.Event) -> None:
    """Record the child's exe link and memfd mappings while it is alive.

    The child's first instants are still the *pre-exec* image (a fork of this
    runner), so a single early read reports ``/usr/bin/python3`` and no memfd
    mappings — sampling until the exec has landed is what captures the state an
    analyst would actually see.
    """
    deadline = time.time() + 3.0
    best_score = -1
    while time.time() < deadline and not stop.is_set():
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            with open(f"/proc/{pid}/maps") as fh:
                maps = [line.split()[-1] for line in fh if "memfd:" in line]
        except OSError:
            return                                    # process already gone
        score = (1 if "memfd:" in exe else 0) + len(maps)
        if score > best_score:
            best_score = score
            out.update({"exe": exe, "memfd_maps": maps[:4],
                        "memfd_map_count": len(maps), "observed": True})
        if "memfd:" in exe and maps:
            return                                    # exec landed: done
        if stop.wait(0.02):
            return


def run_fileless(payload: bytes, wall_clock_ms: float = 60_000.0,
                 timeout: float = 120.0, name: str = "jky",
                 inspect: bool = True,
                 allow: Optional[str] = None,
                 private: bool = False) -> Dict[str, Any]:
    """Execute ``payload`` (script bytes or artifact) with nothing on disk.

    ``allow`` is the capability list granted to the child VM (``syscall``,
    ``exec``); it is deny-by-default in :func:`jocky.runner.policy_ctx`.

    ``private=True`` suppresses core dumps *and* marks the process
    non-dumpable, which makes ``/proc/<pid>`` root-only: the payload stops being
    readable by other same-uid processes, and JOCKY's own triage can no longer
    see the process either. The default keeps the process inspectable so the
    detection claim in the evidence bundle remains verifiable.
    """
    elf_fd = create_memfd("python3", python_elf(), 0o755)
    pkg_fd = create_memfd(f"{name}-pkg", package_zip(), 0o600)
    pay_fd = create_memfd(f"{name}-payload", payload, 0o600)

    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    started = time.perf_counter()
    pid = os.fork()
    if pid == 0:                                    # ---- child
        try:
            os.dup2(out_w, 1)
            os.dup2(err_w, 2)
            for fd in (out_r, err_r, out_w, err_w):
                os.close(fd)
            env = {
                "PATH": "/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "JKY_PKG": str(pkg_fd),
                "JKY_PAYLOAD": str(pay_fd),
                "JKY_WALL": str(float(wall_clock_ms)),
                "JKY_ALLOW": str(allow or ""),
                "JKY_DUMPABLE": "0" if private else "1",
            }
            os.execve(f"/proc/self/fd/{elf_fd}", ["python3", "-c", BOOTSTRAP], env)
        except BaseException:
            os._exit(127)

    os.close(out_w)
    os.close(err_w)
    stdout_chunks: List[bytes] = []
    stderr_chunks: List[bytes] = []
    watcher_state: Dict[str, Any] = {}
    stop = threading.Event()
    threads = [
        threading.Thread(target=_drain, args=(out_r, stdout_chunks), daemon=True),
        threading.Thread(target=_drain, args=(err_r, stderr_chunks), daemon=True),
        threading.Thread(target=_watch_proc, args=(pid, watcher_state, stop), daemon=True),
    ]
    for thread in threads:
        thread.start()

    timed_out = False
    exit_code: Optional[int] = None
    deadline = started + timeout
    while True:
        try:
            done_pid, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            done_pid, status = pid, 0
        if done_pid == pid:
            exit_code = os.waitstatus_to_exitcode(status)
            break
        if time.perf_counter() > deadline:
            timed_out = True
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except OSError:
                pass
            exit_code = -9
            break
        time.sleep(0.01)

    stop.set()
    for thread in threads[1:]:
        thread.join(timeout=0.5)
    for fd in (out_r, err_r):
        try:
            os.close(fd)
        except OSError:
            pass
    duration_ms = (time.perf_counter() - started) * 1000.0

    stdout = b"".join(stdout_chunks).decode("utf-8", "replace")
    stderr = b"".join(stderr_chunks).decode("utf-8", "replace")
    result: Optional[Dict[str, Any]] = None
    for line in stdout.splitlines():
        if line.startswith("JKY_RESULT "):
            try:
                result = json.loads(line[len("JKY_RESULT "):])
            except json.JSONDecodeError:
                result = None

    for fd in (elf_fd, pkg_fd, pay_fd):
        try:
            os.close(fd)
        except OSError:
            pass

    return {
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": round(duration_ms, 3),
        "pid": pid,
        "timed_out": timed_out,
        "result": result,
        "ok": bool(result is not None and not result.get("errors")
                   and exit_code == 0),
        "evidence": {
            "exe": watcher_state.get("exe"),
            "memfd_maps": watcher_state.get("memfd_maps", [])[:4],
            "memfd_map_count": len(watcher_state.get("memfd_maps", [])),
            "observed": watcher_state.get("observed", False),
            "in_memory": {
                "interpreter_bytes": len(python_elf()),
                "package_zip_bytes": len(package_zip()),
                "payload_bytes": len(payload),
            },
        },
    }


def run_fileless_file(path: str, **kwargs: Any) -> Dict[str, Any]:
    with open(path, "rb") as fh:
        return run_fileless(fh.read(), name=os.path.basename(path)[:24], **kwargs)
