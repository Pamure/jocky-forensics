"""
Polymorphic encoder contract tests.

The encoder is the piece that makes a build's bytes unique while keeping its
meaning identical, so the contract is:

1. **unique**  — N builds of one script produce N distinct SHA-256 digests and
   non-constant lengths;
2. **equivalent** — decoding any build reproduces the *same findings* as the
   source run (checked through the real VM, not by comparing bytecode);
3. **integrity** — truncation and single-byte tampering raise
   ``JockyArtifactError`` instead of executing something half-decoded;
4. **reshaped** — the *control-flow* shape of a build, not just its bytes,
   differs from other builds of the same source, which
   :func:`control_flow_signature` measures and the try/catch-path test keeps
   honest.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.errors import JockyArtifactError  # noqa: E402
from jocky.poly.encoder import PolyEncoder, control_flow_signature  # noqa: E402
from jocky.runner import build_artifact, compile_source, run_artifact, run_source  # noqa: E402

PROGRAMS = {
    "arith": """
        let total = 0
        for i in range(1, 10) { set total = total + i * 2 }
        emit {"kind": "arith", "total": total, "neg": -7, "ratio": 3 / 2}
    """,
    "strings": """
        let parts = ["alpha", "beta", "gamma"]
        for p in parts { emit "long-string-constant::{p.upper()}::{p.len()}" }
    """,
    "closure": """
        fn counter() {
          let c = 0
          return fn() { set c = c + 1
            return c }
        }
        let c1 = counter()
        emit [c1(), c1(), c1()]
    """,
    "errors": """
        let caught = 0
        for n in [1, 0, 2] {
          try { let v = 10 / n } catch e { set caught = caught + 1 }
        }
        emit {"kind": "errors", "caught": caught}
    """,
    "host": """
        emit {"kind": "host", "uptime": sys.uptime().seconds > 0,
              "listeners": len(net.listeners())}
    """,
    # Errors raised in one frame and caught in another: the handler the VM
    # jumps to is reached by an unwind, never by a branch, so a transform that
    # remaps the code without remapping ``handlers``/``TRY_ENTER`` corrupts it.
    "unwind": """
        fn thrower(n) {
          let x = 10 / n
          return x
        }
        let crossed = 0
        try {
          let direct = 3 / 0
        } catch e {
          set crossed = crossed + 1
        }
        try {
          let t = thrower(0)
        } catch e {
          set crossed = crossed + 10
        }
        emit {"kind": "unwind", "crossed": crossed, "ok": thrower(4)}
    """,
}


def _findings_hash(result) -> str:
    blob = json.dumps(result.findings, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


@pytest.mark.parametrize("name", sorted(PROGRAMS))
def test_decoded_build_behaves_like_the_source(name):
    source = PROGRAMS[name]
    reference = run_source(source)
    assert not reference.errors, reference.errors
    artifact, _meta = build_artifact(source)
    decoded = run_artifact(artifact)
    assert not decoded.errors, decoded.errors
    assert _findings_hash(decoded) == _findings_hash(reference)


@pytest.mark.parametrize("name", ["arith", "closure"])
def test_builds_are_unique_across_repetitions(name):
    source = PROGRAMS[name]
    hashes, sizes = set(), set()
    for _ in range(120):
        artifact, _meta = build_artifact(source)
        hashes.add(hashlib.sha256(artifact).hexdigest())
        sizes.add(len(artifact))
    assert len(hashes) == 120, "artifact bytes repeat across builds"
    assert len(sizes) > 1, "artifact length is constant, padding is not random"


def test_obfuscated_builds_keep_the_try_catch_path():
    """One draw proves little: builds vary per call, so check many.

    The handler a ``catch`` runs from is reached by an unwind rather than by a
    branch, so an instruction-count-changing transform that forgets to remap
    ``handlers``/``TRY_ENTER`` still produces a well-formed artifact and only
    misbehaves at the moment an error is raised.
    """
    source = PROGRAMS["unwind"]
    reference = run_source(source)
    assert not reference.errors, reference.errors
    expected = _findings_hash(reference)
    for _ in range(16):
        artifact, _meta = build_artifact(source)
        decoded = run_artifact(artifact)
        assert not decoded.errors, decoded.errors
        assert _findings_hash(decoded) == expected


def test_control_flow_signature_moves_with_the_shape_only():
    """The metric the byte-level transforms cannot move.

    ``control_flow_signature`` has to fingerprint branching shape and nothing
    else: a rebuilt artifact (same seed, same bytes) must score the same, while
    fresh builds of one program must not share a score — before control-flow
    obfuscation every build of a program had exactly one branching skeleton.
    """
    program = compile_source(PROGRAMS["unwind"])
    seed = b"\x11" * 32
    rebuilt = PolyEncoder(seed=seed, deterministic=True).encode(program)
    again = PolyEncoder(seed=seed, deterministic=True).encode(program)
    assert (control_flow_signature(PolyEncoder.decode(rebuilt))
            == control_flow_signature(PolyEncoder.decode(again)))

    source_branches = sum(
        1 for op, _arg in program.main.code if op in ("JMP", "JMPF", "JMPT", "ITER_NEXT"))
    artifacts = [PolyEncoder().encode(program) for _ in range(32)]
    decoded = [PolyEncoder.decode(artifact) for artifact in artifacts]
    full = {control_flow_signature(item) for item in decoded}
    skeletons = {control_flow_signature(item, skeleton=True) for item in decoded}
    # A wide margin under the measured 32/32: the assertion is that the shape
    # moves per build, not that the draw is lucky.
    assert len(full) >= 8, f"only {len(full)} distinct signatures in 32 builds"
    assert len(skeletons) >= 8, f"only {len(skeletons)} distinct skeletons in 32 builds"
    assert max(
        sum(1 for op, _arg in item.main.code
            if op in ("JMP", "JMPF", "JMPT", "ITER_NEXT"))
        for item in decoded) > source_branches, "no build gained any control flow"


def test_indirect_jumps_compute_their_target():
    """The destination of an indirect jump is named nowhere in the artifact.

    Jump indirection is only worth the name if a disassembler cannot read the
    destination off the instruction stream, so the assertion is negative: a
    ``JMPI`` carries no operand and the site in front of it holds no literal
    target.  The destination exists only as two pool values, each encrypted
    under its own key, that ``ADD`` back into a real instruction index -- which
    the positive assertions check, so the negative ones cannot pass on a site
    that has quietly stopped jumping anywhere at all.
    """
    sites = 0
    for name in sorted(PROGRAMS):
        program = compile_source(PROGRAMS[name])
        for _ in range(4):
            decoded = PolyEncoder.decode(PolyEncoder().encode(program))
            for proto in decoded.all_protos():
                for ip, (op, arg) in enumerate(proto.code):
                    if op != "JMPI":
                        continue
                    assert arg is None, (
                        f"JMPI at {ip} in {name} carries an operand ({arg!r})")
                    head = proto.code[ip - 3:ip]
                    assert [head_op for head_op, _ in head] == ["CONST", "CONST", "ADD"], (
                        f"JMPI at {ip} in {name} is not fed by an arithmetic site: {head}")
                    assert head[2][1] is None, f"ADD at {ip - 1} in {name} has an operand"
                    left, right = decoded.consts[head[0][1]], decoded.consts[head[1][1]]
                    target = left + right
                    assert 0 <= target < len(proto.code), (
                        f"JMPI at {ip} in {name} computes {target}, outside its "
                        f"{len(proto.code)} instructions")
                    # Neither half is the destination: reading the pool does not
                    # hand the target over, only adding the halves does.
                    assert left != target and right != target, (
                        f"JMPI at {ip} in {name} is preceded by its own target ({target})")
                    sites += 1
    assert sites >= 8, f"only {sites} indirect jumps across {len(PROGRAMS)} programs"


def test_seed_controls_the_build_shape():
    source = PROGRAMS["arith"]
    first, _info_first = build_artifact(source, seed=b"\x01" * 32)
    second, _info_second = build_artifact(source, seed=b"\x01" * 32)
    third, _info_third = build_artifact(source, seed=b"\x02" * 32)

    info_first = PolyEncoder.inspect(first)
    info_second = PolyEncoder.inspect(second)
    info_third = PolyEncoder.inspect(third)
    # artifact_hash identifies the bytes; build_hash identifies the seed profile
    assert info_first["artifact_hash"] == hashlib.sha256(first).hexdigest()
    assert info_second["artifact_hash"] == hashlib.sha256(second).hexdigest()
    assert info_first["build_hash"] == info_second["build_hash"]
    assert info_first["artifact_hash"] != info_second["artifact_hash"]
    assert info_first["build_hash"] != info_third["build_hash"]
    assert third != first
    assert first != second, "same seed must still produce fresh artifact bytes"


def test_inspect_reports_artifact_metadata():
    artifact, _meta = build_artifact(PROGRAMS["host"])
    info = PolyEncoder.inspect(artifact)
    for key in ("build_hash", "artifact_hash", "size", "opmap_size", "nops",
                "const_count", "proto_count", "seed_hex"):
        assert key in info, f"inspect() is missing {key}"
    assert info["size"] == len(artifact)
    assert info["opmap_size"] >= 35
    assert info["const_count"] >= 1


def test_truncated_artifact_is_rejected():
    artifact, _meta = build_artifact(PROGRAMS["arith"])
    for cut in (4, len(artifact) // 2, len(artifact) - 8):
        with pytest.raises(JockyArtifactError):
            PolyEncoder.decode(artifact[:cut])


def test_tampered_artifact_is_rejected():
    artifact, _meta = build_artifact(PROGRAMS["arith"])
    body = bytearray(artifact)
    index = len(body) // 2
    body[index] ^= 0x40
    with pytest.raises(JockyArtifactError):
        PolyEncoder.decode(bytes(body))


def test_garbage_input_is_rejected_cleanly():
    with pytest.raises(JockyArtifactError):
        PolyEncoder.decode(b"not a jocky artifact at all")


def test_empty_script_round_trips():
    artifact, _meta = build_artifact("")
    result = run_artifact(artifact)
    assert not result.errors
    assert result.findings == []


def test_compiled_program_survives_encode_decode_structurally():
    program = compile_source(PROGRAMS["strings"])
    encoder = PolyEncoder()
    artifact = encoder.encode(program)
    decoded = PolyEncoder.decode(artifact)
    assert decoded.main.nlocals == program.main.nlocals
    assert len(decoded.protos) == len(program.protos)
    assert decoded.names == program.names
    # constant splitting appends chunk constants, so only the prefix is stable —
    # and the pool must never *lose* an original constant or change its type
    assert decoded.consts[:len(program.consts)] == program.consts
    assert len(decoded.consts) >= len(program.consts)
    # no constant survives in cleartext inside the artifact bytes
    assert b"long-string-constant" not in artifact
    assert b"alpha" not in artifact
