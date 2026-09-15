"""
Security-property tests.

These pin the guarantees that must not silently regress:

* privileged natives are deny-by-default and only run with an explicit grant;
* a case directory can be attested, tampered with, and re-verified;
* a build can be reproduced byte-for-byte when that is asked for.

Everything here fails if the corresponding protection is removed — that is the
point, because each of these was added in response to a demonstrated weakness
(see research/findings/lim-security.md and res-evidence-integrity.md).
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky import case, runner  # noqa: E402


# ------------------------------------------------------------- capabilities
def test_privileged_natives_are_denied_by_default():
    result = runner.run_source("emit mem.syscall(39)")
    assert result.errors, "mem.syscall ran without a grant"
    assert "capability is disabled" in result.errors[0]
    assert "--allow syscall" in result.errors[0]


def test_capability_grant_enables_the_native():
    result = runner.run_source("emit mem.syscall(39)",
                              ctx=runner.policy_ctx("syscall"))
    assert not result.errors, result.errors
    assert result.findings == [os.getpid()]


def test_memfd_execution_requires_its_own_grant():
    result = runner.run_source('emit mem.memfd_run("print(1)")')
    assert result.errors and "capability is disabled" in result.errors[0]
    assert "--allow exec" in result.errors[0]


def test_unknown_capability_is_rejected():
    with pytest.raises(ValueError) as excinfo:
        runner.policy_ctx("syscall,root")
    assert "unknown capability" in str(excinfo.value)
    assert "syscall" in str(excinfo.value)


def test_policy_ctx_accepts_lists_and_empty_values():
    assert runner.policy_ctx(None)["policy"]["allow"] == set()
    assert runner.policy_ctx("")["policy"]["allow"] == set()
    assert runner.policy_ctx(["syscall", " exec "])["policy"]["allow"] == {"syscall", "exec"}


def test_a_caught_denial_is_still_recorded():
    """A script may fall back after a refusal, but it cannot hide the attempt.

    The refusal stays catchable (a triage script may legitimately try and fall
    back), yet the run reports what it reached for and what it was granted, so
    an operator reading the result sees the attempt either way.
    """
    source = """
    let outcome = "unknown"
    try { mem.syscall(39)
      set outcome = "allowed" } catch e { set outcome = "refused" }
    emit outcome
    """
    result = runner.run_source(source)
    assert not result.errors, result.errors
    assert result.findings == ["refused"], "the refusal is catchable"
    assert [d["capability"] for d in result.denials] == ["syscall"], result.denials
    assert result.permissions["granted"] == []


def test_permissions_are_reported_for_a_granted_run():
    result = runner.run_source("emit mem.syscall(39)", ctx=runner.policy_ctx("syscall"))
    assert not result.errors, result.errors
    assert result.permissions["granted"] == ["syscall"]
    assert result.denials == []


# ------------------------------------------------------------ case integrity
@pytest.fixture()
def case_dir(tmp_path):
    root = tmp_path / "case"
    (root / "sub").mkdir(parents=True)
    (root / "findings.json").write_text('{"kind": "finding"}', encoding="utf-8")
    (root / "sub" / "proc.txt").write_text("pid name\n1 init\n", encoding="utf-8")
    return root


def test_attest_then_verify_is_clean(case_dir):
    summary = case.attest(str(case_dir), note="unit test")
    assert summary["file_count"] == 2
    assert (case_dir / "manifest.json").exists()
    assert (case_dir / "manifest.head").exists()

    result = case.verify(str(case_dir))
    assert result["ok"], result["errors"]
    assert result["checked"] == 2
    assert result["head_matches"] is True


def test_modified_file_is_detected(case_dir):
    case.attest(str(case_dir))
    (case_dir / "findings.json").write_text('{"kind": "tampered"}', encoding="utf-8")
    result = case.verify(str(case_dir))
    assert not result["ok"]
    assert result["modified"] == ["findings.json"]
    assert any("modified file" in error for error in result["errors"])


def test_deleted_and_added_files_are_detected(case_dir):
    case.attest(str(case_dir))
    os.unlink(case_dir / "sub" / "proc.txt")
    (case_dir / "extra.txt").write_text("smuggled", encoding="utf-8")
    result = case.verify(str(case_dir))
    assert result["missing"] == ["sub/proc.txt"]
    assert result["added"] == ["extra.txt"]
    assert not result["ok"]


def test_truncated_manifest_head_is_detected(case_dir):
    case.attest(str(case_dir))
    (case_dir / "manifest.head").write_text("0" * 64 + " 2 now\n", encoding="utf-8")
    result = case.verify(str(case_dir))
    assert not result["ok"]
    assert result["head_matches"] is False


def test_hand_edited_manifest_is_rejected(case_dir):
    """Editing the manifest must not be a way to legitimise changed files."""
    case.attest(str(case_dir))
    manifest_path = case_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["entries"][0]["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    result = case.verify(str(case_dir))
    assert not result["ok"]
    assert any("canonical form" in error for error in result["errors"])


def test_signature_round_trip_and_wrong_key(case_dir):
    case.attest(str(case_dir))
    key = b"analyst-key-material"
    record = case.sign_head(str(case_dir), key=key)
    assert record["algorithm"] == "HMAC-SHA256"

    good = case.verify(str(case_dir), key=key)
    assert good["ok"], good["errors"]
    assert good["signature_valid"] is True

    bad = case.verify(str(case_dir), key=b"different-key")
    assert bad["signature_valid"] is False
    assert not bad["ok"]


def test_missing_signature_is_reported_when_a_key_is_supplied(case_dir):
    case.attest(str(case_dir))
    result = case.verify(str(case_dir), key=b"analyst-key-material")
    assert result["signature_valid"] is False
    assert any("unauthenticated" in error for error in result["errors"])


def test_signing_without_a_key_is_an_error(case_dir):
    case.attest(str(case_dir))
    with pytest.raises(ValueError):
        case.sign_head(str(case_dir), key=None, key_source=None)


def test_anchor_written_outside_the_directory(case_dir, tmp_path):
    anchor = tmp_path / "off-host-head.txt"
    case.attest(str(case_dir), anchor=str(anchor))
    assert anchor.exists()
    # verifying against the off-host anchor still works
    assert case.verify(str(case_dir), anchor=str(anchor))["head_matches"] is True


# --------------------------------------------------------- reproducible build
def test_deterministic_builds_reproduce_byte_for_byte():
    source = 'emit {"kind": "repro", "value": 40 + 2}'
    seed = b"\x11" * 32
    first, _meta_first = runner.build_artifact(source, seed=seed, deterministic=True)
    second, _meta_second = runner.build_artifact(source, seed=seed, deterministic=True)
    assert first == second
    assert hashlib.sha256(first).hexdigest() == hashlib.sha256(second).hexdigest()


def test_non_deterministic_builds_stay_unique():
    source = 'emit {"kind": "unique"}'
    seed = b"\x22" * 32
    first, _a = runner.build_artifact(source, seed=seed)
    second, _b = runner.build_artifact(source, seed=seed)
    assert first != second, "entropy must keep builds unique by default"


def test_deterministic_artifacts_still_run():
    source = 'emit {"kind": "runs", "n": 3}'
    artifact, _meta = runner.build_artifact(source, seed=b"\x33" * 32, deterministic=True)
    result = runner.run_artifact(artifact)
    assert not result.errors, result.errors
    assert result.findings == [{"kind": "runs", "n": 3}]


def test_artifact_operands_are_range_checked_at_decode():
    """The artifact HMAC detects corruption, not an adversary — anyone can forge
    the key material it carries. So every operand a hostile artifact claims is
    range-checked at decode: an out-of-range jump or pool index must be reported
    as a malformed *artifact*, never surface as a host IndexError from inside the
    VM (and a negative jump target must not wrap to the last instruction and burn
    the whole step budget).
    """
    from types import SimpleNamespace

    from jocky.errors import JockyArtifactError
    from jocky.poly.encoder import _validate_operands

    proto = SimpleNamespace(code=[("JMP", -1)])
    program = SimpleNamespace(main=proto, protos=[], consts=["a"])
    with pytest.raises(JockyArtifactError, match="outside its"):
        _validate_operands(program)

    proto = SimpleNamespace(code=[("JMP", 5)])
    program = SimpleNamespace(main=proto, protos=[], consts=["a"])
    with pytest.raises(JockyArtifactError, match="outside its"):
        _validate_operands(program)

    proto = SimpleNamespace(code=[("CONST", 99)])
    program = SimpleNamespace(main=proto, protos=[], consts=["a"])
    with pytest.raises(JockyArtifactError, match="CONST"):
        _validate_operands(program)

    proto = SimpleNamespace(code=[("MK_FN", 99)])
    program = SimpleNamespace(main=proto, protos=[], consts=["a"])
    with pytest.raises(JockyArtifactError, match="MK_FN"):
        _validate_operands(program)

    # A sane program passes untouched.
    proto = SimpleNamespace(code=[("CONST", 0), ("EMIT", None), ("HALT", None)])
    program = SimpleNamespace(main=proto, protos=[], consts=["a"])
    _validate_operands(program)


def test_tampered_attestation_timestamp_is_detected(case_dir):
    case.attest(str(case_dir))
    head_path = case_dir / "manifest.head"
    fields = head_path.read_text(encoding="utf-8").strip().split()
    # Tamper the timestamp
    tampered = f"{fields[0]} {fields[1]} 1980-01-01T00:00:00+0000\n"
    head_path.write_text(tampered, encoding="utf-8")
    result = case.verify(str(case_dir))
    assert not result["ok"]
    assert result["head_matches"] is False
    assert any("timestamp" in err for err in result["errors"])


def test_malformed_signature_file_handled_gracefully(case_dir):
    case.attest(str(case_dir))
    sig_path = case_dir / "manifest.sig"
    sig_path.write_text("NOT_JSON_DATA_CORRUPT", encoding="utf-8")
    result = case.verify(str(case_dir), key=b"key")
    assert not result["ok"]
    assert result["signature_valid"] is False
    assert any("malformed manifest.sig" in err for err in result["errors"])


def test_attest_and_verify_with_exclusions(case_dir):
    (case_dir / "temp.log").write_text("ephemeral log data", encoding="utf-8")
    res_attest = case.attest(str(case_dir), exclude=["*.log"])
    assert res_attest["file_count"] >= 1
    res_verify = case.verify(str(case_dir))
    assert res_verify["ok"], res_verify["errors"]
    assert res_verify["checked"] == res_attest["file_count"]
