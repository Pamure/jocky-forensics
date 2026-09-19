"""Guard-gated fileless execution: the lab's one sanctioned execution path.

This module deliberately contains no execution machinery of its own.  All the
real work — the memfd interpreter/package/payload trio, the fork, the
bootstrap — lives in :mod:`jocky.exec.fileless`.  What the lab adds is the
*gate*: before any byte is executed in memory, :class:`HarnessGuard
<jocky.lab.guard.HarnessGuard>` must accept the caller's anchor pid, and the
child that ends up running the artifact is recorded back into the guard so the
harness's view of what it caused to exist stays complete.

Ownership argument: :func:`jocky.exec.fileless.run_fileless` forks its child
directly from the calling process, so when the harness calls it, the executing
child is by construction a descendant of the harness — the property
:meth:`~jocky.lab.guard.HarnessGuard.assert_owned` enforces for every other
technique.  The wrapper also requires an explicit ``target_pid`` anchor (a pid
the guard validates) so "whose authority is this run under?" is an argument,
not an assumption.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from jocky.exec.fileless import run_fileless
from jocky.lab.errors import LabRefusal
from jocky.lab.guard import HarnessGuard

__all__ = ["run_prefab_fileless_files"]


def run_prefab_fileless_files(guard: HarnessGuard, payload: bytes, *,
                              target_pid: int,
                              wall_clock_ms: float = 30_000.0,
                              timeout: float = 60.0,
                              name: str = "jky-lab",
                              allow: Optional[str] = None) -> Dict[str, Any]:
    """Execute ``payload`` (script text or polymorphic artifact) in memory.

    The run proceeds only after ``guard.assert_owned(target_pid)`` accepts the
    anchor pid; a :class:`~jocky.lab.errors.LabRefusal` therefore always means
    "nothing was executed".  The executing child is forked from this process by
    :func:`jocky.exec.fileless.run_fileless` — i.e. it is a child of the
    harness — and its pid is recorded with ``guard.adopt`` so
    ``guard.own_children()`` covers it.  Returns the underlying run's result
    dict plus a ``harness`` key naming the anchor and child pids.
    """
    if not isinstance(guard, HarnessGuard):
        raise LabRefusal(
            "run_prefab_fileless_files requires the lab HarnessGuard; "
            "fileless execution outside the harness is refused")
    guard.assert_owned(target_pid)

    result = run_fileless(payload, wall_clock_ms=wall_clock_ms,
                          timeout=timeout, name=name, allow=allow)
    guard.adopt(result["pid"])
    result["harness"] = {"target_pid": target_pid,
                         "child_pid": result["pid"],
                         "owned_child": True}
    return result
