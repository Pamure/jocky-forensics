"""Windows execution techniques, present on this build only as loud refusals.

Process hollowing, reflective injection, thread hijacking and a BYOVD probe
are Windows techniques: their entire API surface (``CreateProcess`` with
``CREATE_SUSPENDED``, ``NtUnmapViewOfSection``, ``NtQueueApcThread``,
``NtSetContextThread``, ``NtLoadDriver`` …) does not exist on Linux, and
emulating any of it here would produce a stub that lies about having done
something.  So every entry point in this module raises
:class:`~jocky.lab.errors.LabRefusal`, and *where* it raises encodes the
safety contract:

* off Windows the refusal fires first, before the enable-flag or any target
  validation is even consulted — environment variables must never unlock a
  technique on the wrong OS;
* on Windows the technique is still gated on ``JOCKY_LAB_ENABLE=1`` and on a
  :class:`~jocky.lab.guard.HarnessGuard` accepting the target pid;
* and even with all three satisfied the call *still* raises, because the real
  implementation is Phase-0 scope (a dedicated Hyper-V VM with test signing
  enabled) and does not exist in this build.

None of these functions can return success.  There is no return path.
"""
from __future__ import annotations

import os
import sys
from typing import Any, NoReturn, Optional

from jocky.lab.errors import LabRefusal
from jocky.lab.guard import HarnessGuard

__all__ = ["hollow_process", "reflective_load", "hijack_thread", "byovd_probe"]


def _gate(technique: str, guard: Optional[HarnessGuard],
          target_pid: Optional[int]) -> NoReturn:
    """Raise the refusal that applies to ``technique`` right here, right now."""
    if sys.platform != "win32":
        raise LabRefusal(
            f"{technique}: windows-only technique; this linux build provides no "
            f"Windows API surface and refuses outright — performs only inside "
            f"the Hyper-V Phase-0 VM with testsigning on")
    if os.environ.get("JOCKY_LAB_ENABLE") != "1":
        raise LabRefusal(
            f"{technique}: JOCKY_LAB_ENABLE=1 is not set; lab techniques stay "
            f"disabled until the operator opts in explicitly")
    if guard is None or target_pid is None:
        raise LabRefusal(
            f"{technique}: requires the lab HarnessGuard and a target pid it "
            f"spawned; running without ownership validation is refused")
    guard.assert_owned(target_pid)
    raise LabRefusal(
        f"{technique}: windows vm not attached — technique acknowledged and "
        f"authorised, but not implemented in this build (Phase-0 scope)")


def hollow_process(guard: Optional[HarnessGuard] = None,
                   target_pid: Optional[int] = None, **_ignored: Any) -> NoReturn:
    """Process hollowing — **not implemented here; always raises LabRefusal.**

    The technique performs only inside the Hyper-V Phase-0 VM with testsigning on: a decoy process created with ``CreateProcess(CREATE_SUSPENDED)``, its
    original image removed via ``NtUnmapViewOfSection``, the replacement image
    written with ``VirtualAllocEx``/``WriteProcessMemory``, the entry point
    repointed with ``NtSetContextThread``, and execution released with
    ``ResumeThread``.  None of that API surface exists on Linux, and shipping
    a Linux "version" would require writing into a foreign process's address
    space — which this harness refused to do by design — so this function only
    ever documents the shape and raises.  Phase 0 (Windows VM) is where a real
    implementation is expected to land.
    """
    _gate("hollow_process", guard, target_pid)


def reflective_load(guard: Optional[HarnessGuard] = None,
                    target_pid: Optional[int] = None, **_ignored: Any) -> NoReturn:
    """Reflective DLL injection — **not implemented here; always raises LabRefusal.**

    The technique performs only inside the Hyper-V Phase-0 VM with testsigning on: a DLL buffer is copied into the target with
    ``VirtualAllocEx``/``WriteProcessMemory`` and its self-locating
    ``ReflectiveLoader`` export is invoked in the target — typically by
    queueing execution onto one of its threads with ``NtQueueApcThread`` or a
    hijacked thread — so the image never passes through ``LoadLibrary`` and
    never touches disk.  None of this is implementable against a Linux
    process without ``process_vm_writev``/``ptrace`` writes into a foreign
    address space, both of which this harness refuses to use, so the function
    only ever raises.  Phase 0 (Windows VM) is where a real implementation is
    expected to land.
    """
    _gate("reflective_load", guard, target_pid)


def hijack_thread(guard: Optional[HarnessGuard] = None,
                  target_pid: Optional[int] = None, **_ignored: Any) -> NoReturn:
    """Thread hijacking — **not implemented here; always raises LabRefusal.**

    The technique performs only inside the Hyper-V Phase-0 VM with testsigning on: an existing thread of the target is opened with ``OpenThread`` /
    ``NtOpenThread``, suspended with ``SuspendThread``, its register context is
    captured with ``GetThreadContext`` and rewritten with
    ``NtSetContextThread``/``SetThreadContext`` so the instruction pointer
    lands on attacker-chosen code, then resumed.  Linux has no thread-context
    redirection API reachable without ``ptrace(PTRACE_SETREGS)`` on a foreign
    process, which this harness refuses to do, so the function only ever
    raises.  Phase 0 (Windows VM) is where a real implementation is expected
    to land.
    """
    _gate("hijack_thread", guard, target_pid)


def byovd_probe(guard: Optional[HarnessGuard] = None,
                target_pid: Optional[int] = None, **_ignored: Any) -> NoReturn:
    """BYOVD probing stub — **not implemented here; always raises LabRefusal.**

    The technique performs only inside the Hyper-V Phase-0 VM with testsigning on: a legitimately signed but exploitable driver is registered and started
    (``NtLoadDriver`` / the service control manager), and its IOCTL surface is
    reached with ``DeviceIoControl``/``NtDeviceIoControlFile`` to exercise a
    kernel-memory read/write primitive.  On Linux the honest counterpart is
    the read-only detector in :mod:`jocky.rt.byovd`, and the lab's own future
    test driver is described — as a spec, not code — by
    :func:`jocky.lab.byovd.test_driver_spec`.  This function loads nothing,
    probes nothing, and only ever raises.  Phase 0 (Windows VM) is where a
    real implementation is expected to land.
    """
    _gate("byovd_probe", guard, target_pid)
