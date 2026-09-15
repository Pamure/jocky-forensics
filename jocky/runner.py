"""
Single execution entry point for JOCKY — used by the CLI, the agent, the
evidence harness and the tests.

Three execution modes, in increasing order of stealth:

* **source**   — compile and run a ``.jky`` script in-process;
* **artifact** — decode a polymorphic build and run it;
* **fileless** — interpreter, runtime and payload all live in anonymous
  memfds, so ``/proc/<pid>/exe`` reads ``/memfd:python3 (deleted)`` and no
  program text ever reaches the target's filesystem (see
  :mod:`jocky.exec.fileless`).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, Optional, Tuple

from jocky.lang.compiler import Program, compile_program
from jocky.lang.parser import parse
from jocky.lang.vm import RunResult, VM
from jocky.rt.builtins import default_natives

DEFAULT_WALL_MS = 60_000.0
DEFAULT_MAX_STEPS = 50_000_000

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------- compilation
def policy_ctx(allow: Any = None) -> Dict[str, Any]:
    """Build the VM context that grants explicit script capabilities.

    Scripts are deny-by-default for the two privileged natives
    (``mem.syscall`` and ``mem.memfd_run``); ``--allow syscall,exec`` is the
    operator's explicit acknowledgement.
    """
    from jocky.rt.builtins import GUARDED_CAPABILITIES

    if allow is None:
        granted: set = set()
    elif isinstance(allow, str):
        granted = {item.strip() for item in allow.split(",") if item.strip()}
    else:
        granted = {str(item).strip() for item in allow if str(item).strip()}
    unknown = granted - set(GUARDED_CAPABILITIES)
    if unknown:
        raise ValueError(
            f"unknown capability: {', '.join(sorted(unknown))} "
            f"(known: {', '.join(sorted(GUARDED_CAPABILITIES))})"
        )
    return {"policy": {"allow": granted}}


def compile_source(source: str) -> Program:
    """Parse + compile a script."""
    return compile_program(parse(source))


def disassemble(source: str) -> str:
    """Human-readable listing of the compiled program."""
    return compile_source(source).disassemble()


def build_artifact(source: str, seed: Optional[bytes] = None,
                   deterministic: bool = False) -> Tuple[bytes, Dict[str, Any]]:
    """Compile a script and encode it into a polymorphic artifact.

    ``deterministic=True`` (with an explicit ``seed``) reproduces identical
    bytes, which is what rebuild-and-compare provenance needs.
    """
    from jocky.poly.encoder import PolyEncoder
    program = compile_source(source)
    encoder = PolyEncoder(seed=seed, deterministic=deterministic)
    artifact = encoder.encode(program)
    meta = PolyEncoder.inspect(artifact)
    meta["source_sha256"] = hashlib.sha256(source.encode("utf-8")).hexdigest()
    return artifact, meta


def inspect_artifact(artifact: bytes) -> Dict[str, Any]:
    from jocky.poly.encoder import PolyEncoder
    return PolyEncoder.inspect(artifact)


# ----------------------------------------------------------------- execution
def run_program(program: Program, natives: Optional[Dict[str, Any]] = None,
                wall_clock_ms: Optional[float] = DEFAULT_WALL_MS,
                max_steps: int = DEFAULT_MAX_STEPS,
                ctx: Optional[Dict[str, Any]] = None,
                sandbox: str = "off",
                sandbox_extra_read: Optional[List[str]] = None,
                sandbox_extra_write: Optional[List[str]] = None,
                emit_sink: Optional[Any] = None) -> RunResult:
    """Execute a compiled program with the full forensic runtime.

    ``sandbox`` selects a Landlock confinement level (``off``/``vm``/``ro``/
    ``strict``); it is applied to the *current* process before the VM starts and
    cannot be relaxed afterwards, so ``sandbox_extra_read``/``_write`` exist for
    paths the caller must keep (a test runner's own corpus, for example). The
    report is attached to the result.
    """
    vm = VM(natives=natives if natives is not None else default_natives(),
            max_steps=max_steps, emit_sink=emit_sink)
    if ctx:
        vm.ctx.update(ctx)
    if sandbox and sandbox != "off":
        from jocky.sandbox import apply as apply_sandbox
        vm.ctx["sandbox"] = apply_sandbox(
            sandbox, extra_read=sandbox_extra_read,
            extra_write=sandbox_extra_write).to_dict()
    return vm.run(program, wall_clock_ms=wall_clock_ms)


def run_source(source: str, **kwargs: Any) -> RunResult:
    """Compile and run a script in-process."""
    return run_program(compile_source(source), **kwargs)


def run_artifact(artifact: bytes, **kwargs: Any) -> RunResult:
    """Decode a polymorphic artifact and execute it in-process."""
    from jocky.poly.encoder import PolyEncoder
    return run_program(PolyEncoder.decode(artifact), **kwargs)


def run_bytes(payload: bytes, **kwargs: Any) -> RunResult:
    """Run an artifact if it looks like one, otherwise treat it as source."""
    if payload[:4] in (b"JKY1", b"JKY0"):
        return run_artifact(payload, **kwargs)
    return run_source(payload.decode("utf-8"), **kwargs)


# ------------------------------------------------------------------ fileless
def fileless_run_bytes(payload: bytes, wall_clock_ms: float = DEFAULT_WALL_MS,
                       timeout: float = 120.0, name: str = "jky",
                       allow: Optional[str] = None,
                       private: bool = False) -> Dict[str, Any]:
    """Execute raw script/artifact bytes with nothing written to disk."""
    from jocky.exec import fileless
    return fileless.run_fileless(payload, wall_clock_ms=wall_clock_ms,
                                 timeout=timeout, name=name, allow=allow,
                                 private=private)


def fileless_run_source(source: str, **kwargs: Any) -> Dict[str, Any]:
    return fileless_run_bytes(source.encode("utf-8"), name="jky-src", **kwargs)


def fileless_run_artifact(artifact: bytes, **kwargs: Any) -> Dict[str, Any]:
    return fileless_run_bytes(artifact, name="jky-art", **kwargs)


def fileless_run_file(path: str, **kwargs: Any) -> Dict[str, Any]:
    with open(path, "rb") as fh:
        return fileless_run_bytes(fh.read(), name=os.path.basename(path)[:24], **kwargs)


# -------------------------------------------------------------------- helpers
def stamp_findings(findings: Any, now: Optional[float] = None,
                   field: str = "ts") -> int:
    """Anchor finding maps to a wall-clock time; returns how many were stamped.

    A finding carries no time of its own, so a run cannot be aligned with
    journald/auditd output without one.  Three rules keep that safe: only
    mappings are stamped (a script may emit bare strings), only when the field
    is absent — a script that recorded when the *event* happened knows better
    than the runner does — and every finding of a run shares one value, the
    moment the run was collected.
    """
    stamp = round(time.time() if now is None else now, 3)
    stamped = 0
    for finding in findings or []:
        if isinstance(finding, dict) and field not in finding:
            finding[field] = stamp
            stamped += 1
    return stamped


def result_summary(result: RunResult) -> str:
    """One-line human summary used by the CLI.

    Counts findings with ``finding_count``: a streamed run
    (``emit_sink``) hands every finding to the caller as it is produced and
    keeps none, so ``len(result.findings)`` would report zero.
    """
    return (f"{result.finding_count or len(result.findings)} finding(s), "
            f"{len(result.errors)} error(s), "
            f"{result.steps} steps, {result.duration_ms:.1f} ms")


def parse_result_line(stdout: str) -> Optional[Dict[str, Any]]:
    """Extract the ``JKY_RESULT`` JSON line emitted by the memfd bootstrap."""
    for line in stdout.splitlines():
        if line.startswith("JKY_RESULT "):
            try:
                return json.loads(line[len("JKY_RESULT "):])
            except json.JSONDecodeError:
                return None
    return None
