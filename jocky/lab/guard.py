"""Capability guard for the execution lab.

Why this module exists
----------------------
SIH26148 pillar 3 asks for hollowing / injection / hijack / BYOVD-style
execution.  The project's standing decision (docs/DESIGN.md §10,
docs/EVIDENCE.md) is that those mechanisms may only ever run inside a
capability harness against targets the harness itself spawned — never against
a pid supplied from outside.  :class:`HarnessGuard` is the enforcement point:
it owns process creation, decides whether a pid is a legitimate target, and
tears down exactly what it started and nothing else.

Decisions that matter
---------------------
* Identity is established two ways and both must agree.  A target pid must be
  recorded as spawned by *this* guard instance AND a ``/proc/<pid>/stat``
  ppid walk (bounded at 32 hops) must still reach ``os.getpid()``.  The record
  alone can be stale (child exited, pid reused); the walk alone would accept
  any child of this process, including ones the guard never started.  Both
  together are what "mine" means here.
* ``assert_owned(os.getpid())`` passes: the harness is always a legitimate
  authority over itself.  Ancestors of the harness (walked from ``os.getpid()``)
  are also allowed — an ancestor refusing itself would deadlock the lab — but
  any other live pid found in ``/proc`` is refused with a reason.
* Signals are sent only to pids this guard spawned, and only from
  :meth:`cleanup`.  Nothing in this module ever signals a foreign pid, reads a
  foreign process's memory, or touches ``/dev/kmem``, ``/proc/<pid>/mem`` of a
  process it did not start, or the module-loading syscalls.
* Standard library only; the only state read is ``/proc`` stat files, the only
  state written is a ``tempfile.mkdtemp`` working directory the guard created.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from typing import List, Optional

from jocky.lab.errors import LabRefusal

__all__ = ["HarnessGuard"]

#: Upper bound on the ppid walk.  Real chains are a handful of entries; 32 is
#: generous headroom and guarantees the walk terminates even on a corrupt read.
_MAX_PPID_HOPS = 32

#: How long cleanup waits for a terminated child before escalating to SIGKILL.
_TERMINATE_GRACE_S = 2.0


def _read_ppid(pid: int) -> Optional[int]:
    """Parent pid from ``/proc/<pid>/stat``; ``None`` when the pid is gone.

    The comm field is parenthesised and may itself contain spaces or ``)``,
    so the fields after it are located by the *last* closing parenthesis.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            stat = fh.read().decode("utf-8", "replace")
    except OSError:
        return None
    try:
        fields = stat[stat.rindex(")") + 2:].split()
        return int(fields[1])  # fields[0] is state, fields[1] is ppid
    except (ValueError, IndexError):
        return None


def _ancestors(pid: int, max_hops: int = _MAX_PPID_HOPS) -> Optional[List[int]]:
    """Ppid chain above ``pid`` (excluding ``pid`` itself).

    ``None`` when the walk breaks: the start pid, or a pid midway through the
    chain, no longer has a readable ``/proc`` entry.  A truncated-at-max-hops
    chain is returned as-is — it is still honest ancestry data.
    """
    chain: List[int] = []
    seen = {pid}
    current = pid
    for _ in range(max_hops):
        ppid = _read_ppid(current)
        if ppid is None:
            return None
        if ppid <= 0:
            return chain                     # kernel root: no further parents
        chain.append(ppid)
        if ppid == 1 or ppid in seen:
            return chain
        seen.add(ppid)
        current = ppid
    return chain


class HarnessGuard:
    """Owns the lab's processes and decides what a technique may target."""

    def __init__(self) -> None:
        self._workdir = tempfile.mkdtemp(prefix="jocky-lab-")
        self._procs: List[subprocess.Popen] = []
        # Pids created through the fork-based fileless path (jocky.exec.fileless)
        # rather than through Popen: recorded so ownership claims and cleanup
        # see the complete set of children the harness caused to exist.
        self._adopted: List[int] = []
        self._cleaned = False

    @property
    def workdir(self) -> str:
        """Temporary directory the guard created; children run with it as cwd."""
        return self._workdir

    def spawn_argv(self, argv: List[str]) -> int:
        """Spawn ``argv`` as a child of this harness; return its pid.

        The child's cwd is the guard's own temporary directory and its
        stdout/stderr are pipes held by the guard, so a lab child cannot
        silently inherit a caller's terminal or working state.
        """
        if self._cleaned:
            raise LabRefusal("this guard has been cleaned up; refusing to spawn")
        if (not isinstance(argv, (list, tuple)) or not argv
                or not all(isinstance(part, str) and part for part in argv)):
            raise ValueError("argv must be a non-empty list of non-empty strings")
        proc = subprocess.Popen(
            list(argv), cwd=self._workdir,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self._procs.append(proc)
        return proc.pid

    def adopt(self, pid: int) -> None:
        """Record a child this process created outside :meth:`spawn_argv`.

        Used by the fileless wrapper: :func:`jocky.exec.fileless.run_fileless`
        forks the executing child directly, so no ``Popen`` handle exists, but
        the child is still a descendant of the harness and belongs in
        :meth:`own_children`.  Signals are never derived from this list.
        """
        self._adopted.append(int(pid))

    def own_children(self) -> List[int]:
        """Every pid this guard caused to be spawned, in spawn order."""
        return [proc.pid for proc in self._procs] + list(self._adopted)

    def assert_owned(self, pid: int) -> None:
        """Allow ``pid`` as a technique target, or raise :class:`LabRefusal`.

        Allowed: the harness itself (``os.getpid()``), an ancestor of the
        harness, or a pid this guard spawned whose ``/proc`` ppid chain still
        reaches the harness.  Everything else — dead pids, foreign pids,
        non-integer pids — is refused with the reason in the message.
        """
        if isinstance(pid, bool) or not isinstance(pid, int):
            raise LabRefusal(f"refusing non-integer target pid {pid!r}")
        me = os.getpid()
        if pid == me:
            return                                   # the harness itself
        if pid <= 0:
            raise LabRefusal(f"refusing implausible target pid {pid}")

        chain = _ancestors(pid)
        if pid in self.own_children():
            if chain is None:
                raise LabRefusal(
                    f"pid {pid} was spawned by this harness but no longer has a "
                    f"/proc entry — it is gone, and a reused pid is not the "
                    f"process this harness started")
            if me in chain:
                return
            raise LabRefusal(
                f"pid {pid} was spawned by this harness but its ppid chain no "
                f"longer reaches harness pid {me} (reparented away)")

        # Not spawned here: only the harness's own ancestry is legitimate.
        my_chain = _ancestors(me) or []
        if pid in my_chain:
            return
        if chain is None:
            raise LabRefusal(
                f"pid {pid} is not present in /proc and was never spawned by "
                f"this harness")
        raise LabRefusal(
            f"pid {pid} exists in /proc but was not spawned by this harness "
            f"and is not an ancestor of harness pid {me}")

    def cleanup(self) -> None:
        """Terminate and reap everything this guard spawned; remove its workdir.

        Idempotent: a second call is a no-op.  SIGTERM/SIGKILL go exclusively
        to pids from :meth:`spawn_argv`; adopted pids are only ever reaped
        (``waitpid``), never signalled — the fileless path already waits on
        them itself.
        """
        if self._cleaned:
            return
        self._cleaned = True

        for proc in self._procs:
            if proc.poll() is None:
                try:
                    proc.terminate()
                except OSError:
                    pass                    # already gone between poll and signal
        deadline = time.monotonic() + _TERMINATE_GRACE_S
        for proc in self._procs:
            try:
                proc.wait(timeout=max(deadline - time.monotonic(), 0.0))
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError:
                    pass
                try:
                    proc.wait(timeout=_TERMINATE_GRACE_S)
                except (subprocess.TimeoutExpired, OSError):
                    pass
            except OSError:
                pass
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except OSError:
                    pass

        for pid in self._adopted:
            try:
                os.waitpid(pid, os.WNOHANG)  # reap only; never signal
            except (ChildProcessError, OSError):
                pass

        shutil.rmtree(self._workdir, ignore_errors=True)
