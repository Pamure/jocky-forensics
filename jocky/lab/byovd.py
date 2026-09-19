"""BYOVD in the lab: today a spec for the test driver, not a driver.

The detection half of BYOVD already exists and lives in
:mod:`jocky.rt.byovd` — read-only triage over ``/proc/modules``,
``/proc/sys/kernel/tainted`` and ``/sys/module`` (driver versions, taint
flags, late loads, deleted backing files).  This module holds the *execution*
half's only deliverable for this build: a precise contract for the signed test
driver the Phase-0 Hyper-V VM will eventually load, so the harness, the
evidence bundle and the VM runner scripts are all designed against one
document instead of tribal knowledge.

Honesty rules: :func:`test_driver_spec` returns a plain dict describing intent.
It does not build, sign, install, load, unload or probe anything, and it
leaves no files behind.  When the VM exists (Phase 0, testsigning on), the
driver named here will be written against this spec — never the other way
around.
"""
from __future__ import annotations

from typing import Any, Dict

__all__ = ["test_driver_spec"]


def test_driver_spec() -> Dict[str, Any]:
    """Describe the WILL-BE-AUTHORED lab test driver ``jockyprobe.sys``.

    Pure data: no driver exists yet and this function creates no state.  The
    contract below is deliberately minimal — one IOCTL that only ever touches
    the caller's own buffer — so the driver can demonstrate "the harness can
    load and talk to a signed driver it brought" without shipping an actual
    kernel read/write primitive.
    """
    return {
        "driver_name": "jockyprobe.sys",
        "implemented": False,
        "summary": (
            "Spec for the lab's own signed test driver. Will be authored for "
            "the Phase-0 Hyper-V VM; this build ships only this description."),
        "device": {
            "name": "\\\\Device\\\\JockyProbe",
            "symbolic_link": "\\\\DosDevices\\\\JockyProbe",
            "access": "opened by the VM-side probe client over CreateFile",
        },
        "ioctls": [
            {
                "name": "IOCTL_JOCKYPROBE_ECHO",
                "code": ("CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, "
                         "METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)"),
                "semantics": (
                    "Copies the caller's input buffer verbatim into the "
                    "caller's output buffer and returns its length. Reads and "
                    "writes ONLY the caller-supplied buffers: METHOD_BUFFERED "
                    "means the I/O manager probes and copies both, and the "
                    "driver touches no kernel address it was not handed. There "
                    "is deliberately no arbitrary read/write IOCTL."),
            },
        ],
        "test_signing": {
            "required": True,
            "setup": ("Inside the Phase-0 VM only: `bcdedit /set testsigning on`, "
                      "reboot, sign with a self-issued test certificate installed "
                      "in the VM's Trusted Root store — never on the host."),
        },
        "runner_scripts": [
            {
                "path": "tools/vm/install_jockyprobe.ps1",
                "purpose": ("VM-side: copy the signed jockyprobe.sys next to the "
                            "script, `sc.exe create`/`start` the service, verify "
                            "with `sc.exe query`."),
            },
            {
                "path": "tools/vm/probe_jockyprobe.ps1",
                "purpose": ("VM-side: open \\\\.\\JockyProbe, DeviceIoControl the "
                            "echo IOCTL with a canary buffer, print the round-trip "
                            "result, then `sc.exe stop`/`delete` the service."),
            },
        ],
        "side_effects": (
            "None. This function is a pure factory for a description dict: "
            "nothing is loaded, unloaded, installed, probed, or written."),
    }
