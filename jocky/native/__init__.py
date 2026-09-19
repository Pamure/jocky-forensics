"""
jocky.native — native-binary backends for JOCKY artifacts.

Phase A is the ELF64 emitter: it wraps a ``JKY1`` bytecode artifact in a
static, dependency-free x86-64 Linux executable (see
:mod:`jocky.native.emit_elf` for what this phase does and explicitly does
not do).  :mod:`jocky.native.runner` goes the other way — native image back
to embedded artifact back to the bytecode VM for execution.  What is still
not present: AOT translation of JOCKY opcodes into native instructions; the
embedded artifact is always executed by the existing bytecode VM.
"""
from __future__ import annotations

from jocky.native.emit_elf import emit_elf, inspect_elf, read_artifact
from jocky.native.runner import accepts, extract, run_native

__all__ = ["emit_elf", "inspect_elf", "read_artifact",
           "accepts", "extract", "run_native"]
