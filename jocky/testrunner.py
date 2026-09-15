"""
In-language test runner: `jocky test <dir>`.

The language ships assertions (`assert`, `expect`, `expect_throws`, `fail`,
`skip`) that record their results into the run, so a `.jky` file can test its
own behaviour without any host-side scaffolding. This module discovers those
files, runs them with the same runtime the CLI uses, and aggregates the checks.

Why a second test facility next to pytest: the Python suite tests the
*implementation* (parser tables, collector fields, security properties); this
corpus tests the *language as a user experiences it* — arithmetic, closures,
error messages, capability refusals — and it is the artefact a reviewer can read
to learn what the language promises.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

DEFAULT_PATTERN = "*.jky"


@dataclass
class FileResult:
    path: str
    checks: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    findings: int = 0
    duration_ms: float = 0.0
    truncated: bool = False
    load_error: str = ""

    @property
    def failed_checks(self) -> List[Dict[str, Any]]:
        return [check for check in self.checks if not check.get("ok")]

    @property
    def skipped(self) -> int:
        return sum(1 for check in self.checks if check.get("skipped"))

    @property
    def ok(self) -> bool:
        return not self.load_error and not self.errors and not self.failed_checks

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "ok": self.ok,
            "checks": len(self.checks),
            "failed": [f"{c['label']}: {c.get('detail', '')}" for c in self.failed_checks],
            "skipped": self.skipped,
            "errors": self.errors,
            "findings": self.findings,
            "duration_ms": round(self.duration_ms, 3),
            "truncated": self.truncated,
            "load_error": self.load_error,
        }


def discover(path: str, pattern: str = DEFAULT_PATTERN) -> List[str]:
    """Test files under ``path`` (a file is used as-is, a directory is walked)."""
    import glob

    if os.path.isfile(path):
        return [path]
    if not os.path.isdir(path):
        raise FileNotFoundError(f"no such file or directory: {path}")
    found = glob.glob(os.path.join(path, "**", pattern), recursive=True)
    return sorted(found)


def run_file(path: str, wall_ms: float = 30_000.0, sandbox: str = "off",
             allow: Optional[str] = None) -> FileResult:
    """Execute one test file and collect its checks.

    Confinement is applied in-process and cannot be relaxed, so the corpus
    directory is granted read access: without that, the first `--sandbox=ro`
    file would blind the runner to every file after it.
    """
    from jocky import runner

    result = FileResult(path=path)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
    except OSError as exc:
        result.load_error = f"{type(exc).__name__}: {exc}"
        return result

    corpus_dir = os.path.dirname(os.path.abspath(path))
    try:
        ctx = runner.policy_ctx(allow)
        run = runner.run_source(source, wall_clock_ms=wall_ms, ctx=ctx, sandbox=sandbox,
                                sandbox_extra_read=[corpus_dir],
                                sandbox_extra_write=[corpus_dir] if sandbox == "vm" else None)
    except Exception as exc:  # a syntax error must fail the file, not the runner
        result.load_error = f"{type(exc).__name__}: {exc}"
        return result

    result.checks = list(run.checks)
    result.errors = list(run.errors)
    result.findings = len(run.findings)
    result.duration_ms = run.duration_ms
    result.truncated = run.truncated
    return result


def run(path: str, pattern: str = DEFAULT_PATTERN, wall_ms: float = 30_000.0,
        sandbox: str = "off", allow: Optional[str] = None) -> Dict[str, Any]:
    """Run every discovered file; returns a JSON-serialisable summary."""
    started = time.perf_counter()
    files = discover(path, pattern)
    results: List[FileResult] = [
        run_file(item, wall_ms=wall_ms, sandbox=sandbox, allow=allow) for item in files
    ]
    checks = sum(len(item.checks) for item in results)
    failed = sum(len(item.failed_checks) for item in results)
    skipped = sum(item.skipped for item in results)
    errors = sum(len(item.errors) for item in results) + sum(1 for item in results if item.load_error)
    return {
        "ok": all(item.ok for item in results),
        "path": os.path.abspath(path),
        "pattern": pattern,
        "sandbox": sandbox,
        "files": len(results),
        "checks": checks,
        "failed": failed,
        "skipped": skipped,
        "errors": errors,
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "results": [item.to_dict() for item in results],
    }


def format_report(summary: Dict[str, Any], verbose: bool = False) -> str:
    """Human-readable report: one line per file, details for anything failing."""
    lines: List[str] = []
    for item in summary["results"]:
        name = os.path.relpath(item["path"], summary["path"]) if os.path.isdir(
            summary["path"]) else item["path"]
        if item["load_error"]:
            lines.append(f"ERROR {name}: {item['load_error']}")
            continue
        status = "PASS " if item["ok"] else "FAIL "
        detail = f"{item['checks']} check(s)"
        if item["skipped"]:
            detail += f", {item['skipped']} skipped"
        if item["findings"]:
            detail += f", {item['findings']} finding(s)"
        lines.append(f"{status} {name:<34} {detail}  ({item['duration_ms']:.0f} ms)")
        for failure in item["failed"]:
            lines.append(f"       ✗ {failure}")
        for error in item["errors"]:
            lines.append(f"       ! {error}")
        if item["truncated"]:
            lines.append("       ! hit a step or wall-clock budget")
        if verbose:
            for check in item.get("checks", []):
                pass
    verdict = "all green" if summary["ok"] else "FAILURES"
    lines.append(
        f"\n{verdict}: {summary['files']} file(s), {summary['checks']} check(s), "
        f"{summary['failed']} failed, {summary['errors']} error(s), "
        f"{summary['skipped']} skipped in {summary['duration_ms']:.0f} ms"
    )
    if summary["sandbox"] != "off":
        lines.append(f"confinement: --sandbox={summary['sandbox']}")
    return "\n".join(lines)
