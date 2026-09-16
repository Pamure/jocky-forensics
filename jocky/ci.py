"""
Automated polymorphism gate for CI/CD.

``jocky.evidence`` measures what the tool does and writes a report a human
reads afterwards.  A pipeline needs the other half: a *verdict* a machine acts
on, produced without a human in the loop and without ever crashing for a reason
that is not a real regression.

Three properties are checked, in the order they can fail:

1. mutation — N builds of one script must all differ (unique SHA-256 per build),
2. faithfulness — a sample of those exact bytes must still *mean* the same
   thing as the source, compared on canonicalised findings, not on stdout,
3. survivability — a build or run that raises becomes a failure reason in the
   report, never a traceback escaping the gate.  A gate that dies blocks every
   pull request for the wrong reason.

The measurement definitions (SHA-256 over the artifact bytes, ``_hash_json``
over findings, builds per wall second) are deliberately the ones
``jocky.evidence.stage_polymorphism`` already uses, so a CI number and an
evidence number can be quoted side by side without a footnote.

Why volatile fields are *measured* rather than assumed: a script that reports
``sys.uptime()`` or a live socket count cannot produce identical findings even
when run twice as source, so comparing artifacts against a single reference run
would fail on timing noise.  The gate therefore runs the source twice more,
diffs those runs, and excludes exactly the paths source mode itself cannot
reproduce — no more (an unwarranted exclusion hides real corruption) and no
less (a missing one fails honest builds).  The excluded paths are published in
the report so a reviewer can see what the comparison did *not* cover, and an
irreproducible *shape* is reported instead of silently passing everything.
"""
from __future__ import annotations

import base64
import hashlib
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from jocky import evidence, runner

#: Replacement for a value whose source-mode runs disagree with each other.
#: A sentinel rather than a deletion: dropping a key or an index would shift
#: sequence positions, and a shift is indistinguishable from a real difference.
VOLATILE = "<volatile>"

#: Path into a findings tree: string keys for mappings, ints for sequences.
Path = Tuple[Any, ...]


# --------------------------------------------------------------------- helpers
def _walk(node: Any, path: Path, values: Dict[Path, Any],
          shape: Dict[Path, Any]) -> None:
    """Flatten a findings tree into leaf values and container shapes.

    Args:
        node: Value to walk, usually ``RunResult.findings``.
        path: Path of ``node`` from the root: strings for mapping keys, ints
            for sequence indices.
        values: Filled with ``path -> scalar`` for every leaf.
        shape: Filled with ``path -> key tuple or length`` for every container.
            Two runs whose container shapes differ cannot be compared element
            by element, so that container has to be dropped as a unit.
    """
    if isinstance(node, dict):
        shape[path] = tuple(sorted(str(key) for key in node))
        for key, value in node.items():
            _walk(value, path + (str(key),), values, shape)
    elif isinstance(node, list):
        shape[path] = len(node)
        for index, value in enumerate(node):
            _walk(value, path + (index,), values, shape)
    else:
        values[path] = node


def _volatile_paths(left: Any, right: Any) -> Set[Path]:
    """Find the paths two runs of the *same* source already disagree on.

    Args:
        left: Findings from one source run.
        right: Findings from another source run of the same source.

    Returns:
        Paths to exclude from comparison: a differing container by its own
        path, a differing leaf by its own path.  Empty for a reproducible
        source, which is what keeps the gate strict for deterministic
        collections.
    """
    left_values: Dict[Path, Any] = {}
    left_shape: Dict[Path, Any] = {}
    right_values: Dict[Path, Any] = {}
    right_shape: Dict[Path, Any] = {}
    _walk(left, (), left_values, left_shape)
    _walk(right, (), right_values, right_shape)

    drop: Set[Path] = {path for path in set(left_shape) | set(right_shape)
                       if left_shape.get(path) != right_shape.get(path)}
    drop |= {path for path in set(left_values) | set(right_values)
             if left_values.get(path) != right_values.get(path)}
    # Keep only the outermost path of each volatile subtree: pruning stops at
    # the first dropped ancestor, so listing its descendants would pad the
    # report with paths that were never compared separately.
    return {path for path in drop
            if not any(other != path and path[:len(other)] == other
                       for other in drop)}


def _prune(node: Any, path: Path, drop: Set[Path]) -> Any:
    """Copy ``node`` with every dropped path replaced by :data:`VOLATILE`.

    Args:
        node: Findings value to copy.
        path: Path of ``node`` as built by :func:`_walk`.
        drop: Paths to blank out.

    Returns:
        A new tree.  Leaf objects are shared, never mutated, because the
        caller may still need the unpruned findings for diagnostics.
    """
    if path in drop:
        return VOLATILE
    if isinstance(node, dict):
        return {key: _prune(value, path + (str(key),), drop)
                for key, value in node.items()}
    if isinstance(node, list):
        return [_prune(value, path + (index,), drop)
                for index, value in enumerate(node)]
    return node


def _canonical_hash(findings: Any, drop: Set[Path]) -> str:
    """Hash findings the way the evidence harness does, minus volatile paths.

    Reusing ``evidence._hash_json`` instead of a local copy is what keeps this
    hash comparable with the one in ``evidence/report.md``.

    Args:
        findings: Findings list from a run.
        drop: Volatile paths to blank out before hashing.

    Returns:
        Hex SHA-256 of the canonical JSON of the pruned findings.
    """
    return evidence._hash_json(_prune(findings, (), drop))


def _format_path(path: Path) -> str:
    """Render a findings path as ``findings[0].uptime_s`` for the report."""
    out = "findings"
    for part in path:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}"
    return out


def _error_text(exc: BaseException) -> str:
    """One-line ``Type: message`` for an exception captured into the report.

    Whitespace is collapsed because this text lands in markdown table cells:
    a multi-line parser error would otherwise break the step summary's table.
    """
    return " ".join(f"{type(exc).__name__}: {exc}".split())


def _sample_indices(total: int, sample: int) -> List[int]:
    """Choose which artifacts to execute, spread across the whole matrix.

    Evidence samples the first N builds; a 256-build pipeline gate should not
    ignore the last 248, so the sample is evenly spaced and always includes
    both ends.

    Args:
        total: Number of artifacts available.
        sample: How many to verify.

    Returns:
        Ascending distinct indices, at most ``total`` of them.
    """
    take = min(sample, total)
    if take <= 0:
        return []
    if take == 1:
        return [0]
    stride = (total - 1) / (take - 1)
    return sorted({int(round(index * stride)) for index in range(take)})


# -------------------------------------------------------------------- building
def _build_artifacts(script: str, count: int, seed: Optional[bytes]
                     ) -> Tuple[List[bytes], List[str], List[int], float,
                                List[Dict[str, Any]]]:
    """Build ``count`` artifacts from one script, surviving build failures.

    Args:
        script: JOCKY source to encode.
        count: How many artifacts to build.
        seed: Optional build seed.  The encoder still mixes fresh entropy into
            every call — that is what makes the bytes unique — so a seed
            identifies the build profile without collapsing the matrix.

    Returns:
        ``(artifacts, hashes, sizes, seconds, failures)``: parallel lists for
        the builds that succeeded, the wall time of the whole loop, and one
        entry per build that raised.
    """
    artifacts: List[bytes] = []
    hashes: List[str] = []
    sizes: List[int] = []
    failures: List[Dict[str, Any]] = []
    started = time.perf_counter()
    for index in range(count):
        try:
            artifact, _meta = runner.build_artifact(script, seed=seed)
        except Exception as exc:  # a broken build is a verdict, not a traceback
            failures.append({"index": index, "error": _error_text(exc)})
            continue
        artifacts.append(artifact)
        hashes.append(hashlib.sha256(artifact).hexdigest())
        sizes.append(len(artifact))
    return artifacts, hashes, sizes, time.perf_counter() - started, failures


def _source_sha256(script: str) -> str:
    """Digest the source bytes, the same value the encoder records in meta."""
    return hashlib.sha256(script.encode("utf-8")).hexdigest()


def _matrix_report(count: int, artifacts: Sequence[bytes], hashes: List[str],
                   sizes: List[int], seconds: float,
                   failures: List[Dict[str, Any]], source_sha256: str
                   ) -> Dict[str, Any]:
    """Shape one build pass into the dict :func:`build_matrix` returns."""
    unique = len(set(hashes))
    return {
        "count": count,
        "built": len(artifacts),
        "unique_hashes": unique,
        "unique_sizes": len(set(sizes)),
        "sizes": {
            "min": min(sizes) if sizes else 0,
            "max": max(sizes) if sizes else 0,
            "mean": round(sum(sizes) / len(sizes), 1) if sizes else 0.0,
        },
        "hashes": hashes,
        "all_unique": bool(hashes) and unique == count,
        "build_rate_per_s": round(len(artifacts) / seconds, 1) if seconds else 0.0,
        "build_failures": failures,
        "source_sha256": source_sha256,
        "artifacts_b64": [base64.b64encode(item).decode("ascii")
                          for item in artifacts],
    }


def build_matrix(script: str, count: int, seed: Optional[bytes] = None
                 ) -> Dict[str, Any]:
    """Build ``count`` polymorphic artifacts from one script and measure them.

    Hash and size definitions match ``jocky.evidence.stage_polymorphism``:
    SHA-256 over the artifact bytes, size in bytes, rate as builds per wall
    second.

    Args:
        script: JOCKY source to encode.
        count: Number of builds; each draws fresh entropy unless a
            reproducible profile is requested through ``seed``.
        seed: Optional build seed; ``None`` (the CI default) lets the encoder
            pick one from ``os.urandom``.

    Returns:
        Dict with ``count``, ``built``, ``unique_hashes``, ``unique_sizes``,
        ``sizes`` (``min``/``max``/``mean``), ``hashes``, ``all_unique``,
        ``build_rate_per_s``, ``build_failures``, ``source_sha256`` and
        ``artifacts_b64`` — the encoded artifacts themselves, so a caller can
        verify the very bytes it measured.  A build that raises is recorded in
        ``build_failures`` and the loop continues, because one broken build
        should still produce a diagnosable report.
    """
    artifacts, hashes, sizes, seconds, failures = _build_artifacts(
        script, count, seed)
    return _matrix_report(count, artifacts, hashes, sizes, seconds, failures,
                          _source_sha256(script))


# ---------------------------------------------------------------- verification
def verify_equivalence(script: str, artifacts: List[bytes], sample: int = 25
                       ) -> Dict[str, Any]:
    """Prove that a sample of built artifacts still behaves like the source.

    Findings are compared, not stdout: stdout carries formatting and ordering
    an encoder is free to change, findings carry meaning.  Volatile paths are
    measured first (two extra source runs), then both sides are blanked at
    those paths before hashing, so the comparison tests semantics rather than
    timing.

    Args:
        script: The source the artifacts were built from.
        artifacts: Artifact bytes in build order; the sampled indices are
            spread across the whole list.
        sample: How many artifacts to execute.  ``0`` or an empty list yields
            ``ok=False``: a sample that proves nothing must not read as a pass.

    Returns:
        Dict with ``reference_findings_sha256`` (canonical hash of the
        volatility-pruned reference findings), ``sampled``, ``mismatches``,
        ``ok``, plus evidence for the verdict: ``volatile_fields`` (paths
        source mode itself cannot reproduce), ``irreproducible_shape`` (true
        when the findings' own shape varies between source runs, which makes
        any equivalence claim vacuous), ``reference_findings`` (count),
        ``reference_errors``, ``sampled_indices`` and ``probe_error``.

        A mismatched sample appears in ``mismatches`` as
        ``{"index", "sha256", "findings_sha256", "errors"}``; a sample that
        would not decode or run appears as ``{"index", "error"}``.  Nothing
        raised here escapes: every failure is data.
    """
    sampled_indices = _sample_indices(len(artifacts), sample)
    reference_error: List[str] = []
    mismatches: List[Dict[str, Any]] = []

    try:
        reference = runner.run_source(script)
    except Exception as exc:
        # The report must stay shaped like a report even when the source it
        # describes cannot run; the gate reads these keys unconditionally.
        reference_error.append(_error_text(exc))
        return {
            "reference_findings_sha256": "",
            "sampled": 0,
            "mismatches": [{"index": None, "error": reference_error[0]}],
            "ok": False,
            "volatile_fields": [],
            "irreproducible_shape": False,
            "reference_findings": 0,
            "reference_errors": reference_error,
            "sampled_indices": sampled_indices,
            "probe_error": "",
        }

    # Execute the sample first, then probe for volatility: probing around the
    # sample (not just before it) catches fields that drift slowly, such as an
    # integer uptime that only ticks while the artifacts are running.
    executed: List[Tuple[int, Optional[Any], List[str]]] = []
    for index in sampled_indices:
        try:
            result = runner.run_artifact(artifacts[index])
            executed.append((index, result.findings, list(result.errors)))
        except Exception as exc:
            executed.append((index, None, []))
            mismatches.append({"index": index, "error": _error_text(exc)})

    volatile: Set[Path] = set()
    probe_error = ""
    for _ in range(2):
        try:
            volatile |= _volatile_paths(reference.findings,
                                        runner.run_source(script).findings)
        except Exception as exc:
            probe_error = _error_text(exc)

    reference_hash = _canonical_hash(reference.findings, volatile)
    for index, findings, errors in executed:
        if findings is None:
            continue
        findings_hash = _canonical_hash(findings, volatile)
        if findings_hash != reference_hash or errors:
            mismatches.append({
                "index": index,
                "sha256": hashlib.sha256(artifacts[index]).hexdigest(),
                "findings_sha256": findings_hash,
                "errors": errors,
            })

    # A volatile root means the runs produced differently *shaped* findings:
    # every path is blanked, the comparison proves nothing, and reporting that
    # as a pass would turn the gate into decoration.
    irreproducible = () in volatile
    ok = not (mismatches or reference.errors or irreproducible) and bool(sampled_indices)
    return {
        "reference_findings_sha256": reference_hash,
        "sampled": len(sampled_indices),
        "mismatches": mismatches,
        "ok": ok,
        "volatile_fields": sorted(_format_path(path) for path in volatile),
        "irreproducible_shape": irreproducible,
        "reference_findings": len(reference.findings),
        "reference_errors": reference_error + list(reference.errors),
        "sampled_indices": sampled_indices,
        "probe_error": probe_error,
    }


# ------------------------------------------------------------------- the gate
def gate(script: str, count: int = 64, sample: int = 8) -> Dict[str, Any]:
    """Run the CI gate: build the matrix, verify a sample, return a verdict.

    The two sub-reports are nested rather than merged because both carry their
    own idea of success and only one ``ok`` may exist in a report a pipeline
    reads.

    Args:
        script: JOCKY source to build and verify.
        count: Number of artifacts to build (one build pass, reused for the
            equivalence sample — the verified bytes are the measured bytes).
        sample: How many of those artifacts to execute.

    Returns:
        Dict with ``ok``, ``reason``, ``builds`` (:func:`build_matrix`
        result), ``equivalence`` (:func:`verify_equivalence` result) and
        ``generated_at`` (UTC ISO-8601).  ``ok`` is false when two artifacts
        collide, when a sampled artifact's findings differ from the reference
        or errored, when a build or run raised, and when the script's own
        findings are too unstable for equivalence to mean anything.
    """
    artifacts, hashes, sizes, seconds, failures = _build_artifacts(
        script, count, None)
    builds = _matrix_report(count, artifacts, hashes, sizes, seconds, failures,
                            _source_sha256(script))
    # The verified bytes are the measured bytes: verifying the same list here
    # avoids decoding the base64 in ``builds`` just to get them back.
    equivalence = verify_equivalence(script, artifacts, sample=sample)

    reasons: List[str] = []
    if builds["build_failures"]:
        first = builds["build_failures"][0]
        reasons.append(f"{len(builds['build_failures'])} build(s) failed, "
                       f"first at index {first['index']}: {first['error']}")
    if not builds["all_unique"]:
        reasons.append(f"hash collision: {builds['unique_hashes']} unique of "
                       f"{builds['count']} builds")
    if not artifacts:
        reasons.append("no artifacts were built, so nothing could be verified")
    elif equivalence["irreproducible_shape"]:
        reasons.append("script findings are not reproducible in source mode "
                       "(the root shape varies between source runs), so "
                       "artifact equivalence cannot be established")
    elif not equivalence["ok"]:
        errors = [item for item in equivalence["mismatches"] if item.get("error")]
        if errors:
            reasons.append(f"{len(errors)} artifact(s) failed to run, first: "
                           f"{errors[0]['error']}")
        differing = len(equivalence["mismatches"]) - len(errors)
        if differing:
            reasons.append(f"{differing} sampled artifact(s) produced findings "
                           f"that differ from the source reference")
    if equivalence["probe_error"]:
        reasons.append("the volatility probe run failed, so per-run fields "
                       "could not be excluded: "
                       f"{equivalence['probe_error']}")

    reason = ("all builds unique and the sampled artifacts are equivalent to "
              "the source" if not reasons else "; ".join(reasons))
    return {
        "ok": not reasons,
        "reason": reason,
        "builds": builds,
        "equivalence": equivalence,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


# ------------------------------------------------------------------ rendering
def _verdict_table(report: Dict[str, Any]) -> List[str]:
    """Build the markdown rows for a gate report."""
    builds = report.get("builds") or {}
    equivalence = report.get("equivalence") or {}
    sizes = builds.get("sizes") or {}
    failures = builds.get("build_failures") or []
    sampled = equivalence.get("sampled", 0)
    mismatches = equivalence.get("mismatches") or []
    volatile = equivalence.get("volatile_fields") or []

    rows = [
        ("Script SHA-256", f"`{builds.get('source_sha256', '')}`"),
        ("Artifacts built", f"{builds.get('built', 0)} of {builds.get('count', 0)}"
                            + (f" ({len(failures)} failed)" if failures else "")),
        ("Unique hashes", f"{builds.get('unique_hashes', 0)} of "
                          f"{builds.get('count', 0)}"),
        ("Unique sizes", builds.get("unique_sizes", 0)),
        ("Size min / max / mean", f"{sizes.get('min', 0)} / {sizes.get('max', 0)} / "
                                  f"{sizes.get('mean', 0)} bytes"),
        ("Build rate", f"{builds.get('build_rate_per_s', 0)} builds/s"),
        ("Reference findings SHA-256",
         f"`{equivalence.get('reference_findings_sha256', '')}`"),
        ("Equivalence sampled", f"{sampled} artifact(s)"),
        ("Equivalence mismatches", len(mismatches)),
        ("Volatile fields excluded",
         f"{len(volatile)}" + (f" ({', '.join(volatile[:3])})" if volatile else "")),
    ]
    return [f"| {name} | {value} |" for name, value in rows]


def render_markdown(report: Dict[str, Any]) -> str:
    """Render a gate report as the GitHub step-summary markdown.

    Args:
        report: A :func:`gate` result (or anything shaped like one).

    Returns:
        Markdown: a heading with the verdict, the reason, a Measure/Result
        table, and — only when the gate failed — the bounded detail that says
        *which* artifact broke.
    """
    ok = bool(report.get("ok"))
    builds = report.get("builds") or {}
    equivalence = report.get("equivalence") or {}
    failures = builds.get("build_failures") or []
    mismatches = equivalence.get("mismatches") or []

    lines = [
        "## Polymorphic CI gate",
        "",
        f"**Verdict: {'PASS' if ok else 'FAIL'}** — {report.get('reason', '')}",
        "",
        f"Generated {report.get('generated_at', 'n/a')}.",
        "",
        "| Measure | Result |",
        "| --- | --- |",
    ]
    lines.extend(_verdict_table(report))

    if failures or mismatches:
        lines.extend(["", "### Failure detail", "", "| Where | What |",
                      "| --- | --- |"])
        for item in failures[:5]:
            lines.append(f"| build {item.get('index')} | {item.get('error')} |")
        for item in mismatches[:5]:
            detail = (item.get("error") or
                      f"errors={item.get('errors')} findings={item.get('findings_sha256')}")
            lines.append(f"| artifact {item.get('index')} | {detail} |")
        extra = max(0, len(failures) - 5) + max(0, len(mismatches) - 5)
        if extra:
            lines.append(f"| … | {extra} further failure(s) omitted |")

    return "\n".join(lines) + "\n"
