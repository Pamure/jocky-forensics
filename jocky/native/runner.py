"""Run a native JOCKY image: extract the embedded artifact and execute it.

The native emitter (:mod:`jocky.native.emit_elf`) wraps a polymorphic
``JKY1`` artifact in a real x86-64 ELF64 executable.  The shipped stub only
proves the container (it prints a marker and exits); execution of the script
itself still happens in the existing bytecode VM, by extracting the embedded
artifact back out of the image.  This module is that bridge, and it is the
only endorsed way to go from ``*.jky.native`` bytes to behaviour until the
AOT backend (opcode-level native codegen) lands — the emitter's module
docstring keeps that limitation on record.

Detection rule: a blob is a native image when it is ELF64/EXEC/x86-64 with a
seed-named ``.jk*`` section that :func:`jocky.native.emit_elf.read_artifact`
can reverse.  Anything else is (per the caller) bytecode or source.
"""
from __future__ import annotations

from typing import Any

from jocky.native.emit_elf import inspect_elf, read_artifact

__all__ = ["accepts", "extract", "run_native"]

_ELF_MAGIC = b"\x7fELF"


def accepts(blob: bytes) -> bool:
    """True when ``blob`` parses as a JOCKY native image.

    Cheap on purpose: the ELF64 header check plus one section scan.  Returns
    ``False`` for ordinary ELF binaries — they have no ``.jk*`` section.
    """
    if len(blob) < 64 or blob[:4] != _ELF_MAGIC:
        return False
    try:
        read_artifact(blob)
    except ValueError:
        return False
    return True


def extract(blob: bytes) -> bytes:
    """The embedded ``JKY1`` artifact, or ``ValueError`` if ``blob`` is none."""
    if len(blob) < 64 or blob[:4] != _ELF_MAGIC:
        raise ValueError("not a JOCKY native image")
    return read_artifact(blob)


def run_native(blob: bytes, **kwargs: Any) -> "Any":
    """Extract the artifact from a native image and run it in the VM.

    Returns what :func:`jocky.runner.run_artifact` returns; the caller's
    sandbox/ctx/budget kwargs pass through unchanged.
    """
    artifact = extract(blob)
    from jocky.runner import run_artifact  # late import: no cycle
    return run_artifact(artifact, **kwargs)


def inspect_blob(blob: bytes) -> dict:
    """Inspect information for a native image, for the CLI's ``--inspect``."""
    from jocky.poly.encoder import PolyEncoder

    artifact = extract(blob)
    info = inspect_elf(blob)
    try:
        art = dict(PolyEncoder.inspect(artifact))
    except Exception:
        art = {}
    return {"container": "elf64", "elf": info, "artifact": art}
