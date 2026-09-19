"""The SIH26148 execution lab: a capability harness for pillar-3 techniques.

Every execution technique this project experiments with routes through
:class:`~jocky.lab.guard.HarnessGuard`, which spawns and owns its targets and
refuses everything else (:class:`~jocky.lab.errors.LabRefusal`).  Linux-side
execution exists today as guard-gated fileless execution
(:mod:`jocky.lab.fileless`, built on :mod:`jocky.exec.fileless`); the four
Windows techniques exist as loudly-raising placeholders
(:mod:`jocky.lab.windows`); the BYOVD test driver exists as a written spec
(:mod:`jocky.lab.byovd`).
"""
from __future__ import annotations

from jocky.lab import byovd, errors, fileless, guard, windows
from jocky.lab.byovd import test_driver_spec
from jocky.lab.errors import LabRefusal
from jocky.lab.fileless import run_prefab_fileless_files
from jocky.lab.guard import HarnessGuard
from jocky.lab.windows import byovd_probe, hijack_thread, hollow_process, reflective_load

__all__ = [
    "HarnessGuard",
    "LabRefusal",
    "run_prefab_fileless_files",
    "test_driver_spec",
    "hollow_process",
    "reflective_load",
    "hijack_thread",
    "byovd_probe",
    "byovd",
    "errors",
    "fileless",
    "guard",
    "windows",
]
