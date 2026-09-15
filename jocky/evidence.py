"""
Evidence harness — every claim the project makes, measured and written down.

The harness is deliberately hostile to its own claims: it records raw logs and
numbers (hashes, durations, file deltas, audited syscall-adjacent events) so a
reviewer can re-run it and check the report rather than trust it.

Stages
------
1. ``polymorphism``  — build N artifacts from one script; record every SHA-256,
   count unique hashes and size spread, then re-execute a sample of the builds
   and prove their findings are byte-identical to the reference run.
2. ``runs``          — execute the same build N times, record durations and the
   hash of each run's findings; proves stability, not just a single happy path.
3. ``artifacts``     — snapshot the filesystem, run in source mode and in
   fileless mode, snapshot again and diff; fileless runs must create nothing.
4. ``audit``         — run the collection in-process under a Python audit hook
   that counts child-process creation, write-mode ``open`` calls, execs and
   socket activity.  This is how "no processes spawned" is measured rather than
   asserted.
5. ``detection``     — start a real fileless process and require JOCKY's own
   detector to find it (evasion and detection proven against each other).

Outputs under ``evidence/``: ``polymorphism.csv``, ``runs.json``,
``artifacts.json``, ``audit.json``, ``detection.json`` and ``report.md``.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SCRIPTS = os.path.join(REPO_ROOT, "scripts")

SKIP_DIRS = {".git", "venv", "__pycache__", ".jocky-server", ".jocky-agent",
             "evidence", "node_modules"}

# Python audit hook used by the ``audit`` stage: counts the events that matter
# for "does this tool spawn processes or write files on the target".
_AUDIT_PROBE = r'''
import json, os, sys
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
counters = {
    "child_process": 0, "exec": 0, "write_open": 0, "read_open": 0,
    "socket": 0, "import": 0, "write_paths": [], "exec_paths": [],
}

def hook(event, args):
    try:
        if event in ("subprocess.Popen", "os.system", "os.posix_spawn",
                     "os.fork", "os.forkpty", "os.spawn"):
            counters["child_process"] += 1
        elif event == "os.exec":
            counters["exec"] += 1
            counters["exec_paths"].append(str(args[0])[:120])
        elif event == "open":
            path, mode, flags = (list(args) + [None, None, None])[:3]
            if isinstance(flags, int) and flags & WRITE_FLAGS:
                counters["write_open"] += 1
                counters["write_paths"].append(str(path)[:160])
            else:
                counters["read_open"] += 1
        elif event in ("socket.connect", "socket.getaddrinfo", "socket.bind"):
            counters["socket"] += 1
        elif event == "import":
            counters["import"] += 1
    except Exception:
        pass

sys.addaudithook(hook)
source = sys.stdin.read()
from jocky.runner import run_source
result = run_source(source, wall_clock_ms=120000.0)
counters["findings"] = len(result.findings)
counters["errors"] = result.errors
counters["steps"] = result.steps
counters["duration_ms"] = result.duration_ms
sys.stderr.write("AUDIT_JSON " + json.dumps(counters))
'''


# --------------------------------------------------------------------- helpers
def _hash_json(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _snapshot(roots: List[str], max_entries: int = 4000) -> Dict[str, float]:
    """path -> mtime for files under ``roots`` (bounded, skips heavy dirs)."""
    snapshot: Dict[str, float] = {}
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if len(snapshot) >= max_entries:
                    return snapshot
                path = os.path.join(dirpath, name)
                try:
                    snapshot[path] = os.stat(path).st_mtime
                except OSError:
                    continue
            if dirpath.count(os.sep) - root.count(os.sep) > 3:
                dirnames[:] = []
    return snapshot


def _diff_snapshots(before: Dict[str, float], after: Dict[str, float]) -> Dict[str, List[str]]:
    created = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    modified = sorted(p for p in set(before) & set(after) if before[p] != after[p])
    return {"created": created[:200], "deleted": deleted[:200],
            "modified": modified[:200],
            "created_count": len(created), "deleted_count": len(deleted),
            "modified_count": len(modified)}


def _percentile(values: List[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * fraction))
    return ordered[index]


def _ms(value: Any) -> str:
    """Format a duration that may be missing or non-numeric."""
    return f"{float(value):,.1f} ms" if isinstance(value, (int, float)) else "n/a"


# ---------------------------------------------------------------------- stages
def stage_polymorphism(source: str, iterations: int, out_dir: str,
                       sample: int = 25) -> Dict[str, Any]:
    """Build the artifact many times and prove unique bytes, identical meaning."""
    from jocky import runner

    reference = runner.run_source(source)
    reference_hash = _hash_json(reference.findings)
    rows: List[Tuple[int, str, int]] = []
    started = time.perf_counter()
    for index in range(iterations):
        artifact, _meta = runner.build_artifact(source)
        rows.append((index, hashlib.sha256(artifact).hexdigest(), len(artifact)))
    build_seconds = time.perf_counter() - started

    with open(os.path.join(out_dir, "polymorphism.csv"), "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["index", "sha256", "size_bytes"])
        writer.writerows(rows)

    unique = len({row[1] for row in rows})
    sizes = [row[2] for row in rows]
    equivalence_failures: List[Dict[str, Any]] = []
    checked = 0
    for index in range(0, min(sample, iterations)):
        artifact, _meta = runner.build_artifact(source)
        result = runner.run_artifact(artifact)
        checked += 1
        if _hash_json(result.findings) != reference_hash or result.errors:
            equivalence_failures.append({"iteration": index, "errors": result.errors})

    return {
        "iterations": iterations,
        "unique_hashes": unique,
        "all_unique": unique == iterations,
        "size_min": min(sizes) if sizes else 0,
        "size_max": max(sizes) if sizes else 0,
        "size_distinct": len(set(sizes)),
        "build_seconds": round(build_seconds, 3),
        "builds_per_second": round(iterations / build_seconds, 1) if build_seconds else 0,
        "equivalence_checked": checked,
        "equivalence_failures": equivalence_failures,
        "reference_findings_hash": reference_hash,
        "reference_findings": len(reference.findings),
    }


def stage_runs(payload: bytes, iterations: int, out_dir: str,
               artifact: bool = True) -> Dict[str, Any]:
    """Execute one build many times; stability and latency distribution."""
    from jocky import runner

    durations: List[float] = []
    hashes = set()
    errors = 0
    started = time.perf_counter()
    for _ in range(iterations):
        result = runner.run_bytes(payload) if artifact else runner.run_source(
            payload.decode("utf-8"))
        durations.append(result.duration_ms)
        hashes.add(_hash_json(result.findings))
        errors += len(result.errors)
    total_seconds = time.perf_counter() - started
    summary = {
        "iterations": iterations,
        "distinct_finding_hashes": len(hashes),
        "errors": errors,
        "total_seconds": round(total_seconds, 3),
        "runs_per_second": round(iterations / total_seconds, 1) if total_seconds else 0,
        "duration_ms": {
            "min": round(min(durations), 3),
            "median": round(statistics.median(durations), 3),
            "p95": round(_percentile(durations, 0.95), 3),
            "max": round(max(durations), 3),
        },
    }
    with open(os.path.join(out_dir, "runs.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    return summary


def _cold_source_mode(script_path: str, out_dir: str) -> Dict[str, Any]:
    """What a *cold* interpreter leaves behind when running source mode.

    A fresh Python process writes bytecode caches for the modules it imports.
    ``PYTHONPYCACHEPREFIX`` redirects them into a probe directory, so the count
    is measured without touching the working tree.
    """
    cache_dir = os.path.join(out_dir, "_pycache_probe")
    shutil.rmtree(cache_dir, ignore_errors=True)
    os.makedirs(cache_dir, exist_ok=True)
    env = dict(os.environ, PYTHONPYCACHEPREFIX=cache_dir)
    try:
        finished = subprocess.run(
            [sys.executable, "-m", "jocky", "run", script_path],
            cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=300)
        returncode = finished.returncode
    except subprocess.TimeoutExpired:
        returncode = -1
    cache_files = sum(len(files) for _root, _dirs, files in os.walk(cache_dir))
    shutil.rmtree(cache_dir, ignore_errors=True)
    return {"returncode": returncode, "bytecode_cache_files": cache_files}


def stage_artifacts(source: str, out_dir: str) -> Dict[str, Any]:
    """Compare on-disk footprints: source mode vs fileless mode."""
    from jocky import runner
    from jocky.exec import fileless

    roots = [REPO_ROOT, "/tmp", "/dev/shm", "/var/tmp"]
    report: Dict[str, Any] = {}

    before = _snapshot(roots)
    runner.run_source(source)
    report["source_mode"] = _diff_snapshots(before, _snapshot(roots))
    report["source_mode_cold"] = _cold_source_mode(
        os.path.join(REPO_ROOT, "scripts", "evidence.jky"), out_dir)

    before = _snapshot(roots)
    outcome = runner.fileless_run_bytes(source.encode("utf-8"), timeout=180.0)
    report["fileless_mode"] = _diff_snapshots(before, _snapshot(roots))
    report["fileless_mode"]["exit_code"] = outcome.get("exit_code")
    report["fileless_mode"]["ok"] = outcome.get("ok")
    report["fileless_mode"]["exe"] = outcome.get("evidence", {}).get("exe")
    report["fileless_mode"]["memfd_map_count"] = outcome.get("evidence", {}).get(
        "memfd_map_count")
    report["fileless_code_created_nothing"] = report["fileless_mode"]["created_count"] == 0
    report["interpreter_bytes"] = len(fileless.python_elf())
    report["runtime_zip_bytes"] = len(fileless.package_zip())

    with open(os.path.join(out_dir, "artifacts.json"), "w") as fh:
        json.dump(report, fh, indent=2)
    return report


def stage_audit(source: str, out_dir: str) -> Dict[str, Any]:
    """Measure spawn/write behaviour with a Python audit hook."""
    finished = subprocess.run(
        [sys.executable, "-c", _AUDIT_PROBE], input=source, text=True,
        capture_output=True, cwd=REPO_ROOT, timeout=300,
    )
    data: Dict[str, Any] = {"returncode": finished.returncode}
    for line in finished.stderr.splitlines():
        if line.startswith("AUDIT_JSON "):
            data.update(json.loads(line[len("AUDIT_JSON "):]))
    if "child_process" not in data:
        data["stderr_tail"] = finished.stderr[-800:]
    data["no_child_processes"] = data.get("child_process", -1) == 0
    with open(os.path.join(out_dir, "audit.json"), "w") as fh:
        json.dump(data, fh, indent=2)
    return data


def stage_detection(out_dir: str, script_path: str, dwell_seconds: float = 12.0) -> Dict[str, Any]:
    """Start a real fileless process and require our own detector to find it.

    The dwell window is deliberately longer than the script's own runtime so the
    run also completes and reports; a shorter window would prove detection but
    lose the child's self-report.
    """
    from jocky.rt import detect, procfs

    process = subprocess.Popen(
        [sys.executable, "-m", "jocky", "fileless", script_path, "--json"],
        cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    report: Dict[str, Any] = {"pid": process.pid}
    try:
        seen: List[Dict[str, Any]] = []
        deadline = time.time() + dwell_seconds
        while time.time() < deadline and not seen:
            seen = [p for p in procfs.list_processes() if "/memfd:" in (p.get("exe") or "")]
            if not seen:
                time.sleep(0.1)
        report["memfd_processes_seen"] = [
            {"pid": p["pid"], "name": p["name"], "exe": p["exe"]} for p in seen
        ]
        findings = detect.fileless_processes()
        report["detector_findings"] = len(findings)
        report["detector_titles"] = [f["title"] for f in findings[:3]]
        report["memfd_mappings"] = len(detect.memfd_mappings())
        report["detected"] = bool(seen and findings)
    finally:
        # let the job finish on its own so the child's self-report is captured;
        # only kill what overstays the dwell window
        try:
            stdout, _stderr = process.communicate(timeout=dwell_seconds)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                stdout, _stderr = process.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout = ""
        try:
            report["run_report"] = json.loads(stdout)
        except Exception:
            report["run_report"] = None
    with open(os.path.join(out_dir, "detection.json"), "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    return report


# ------------------------------------------------------------------- reporting
def _write_report(out_dir: str, stages: Dict[str, Any], quick: bool) -> str:
    poly = stages["polymorphism"]
    runs = stages["runs"]
    artifacts = stages["artifacts"]
    audit = stages["audit"]
    detection = stages["detection"]
    _child = detection.get("run_report") or {}
    lines = [
        "# JOCKY evidence report (SIH26148)",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Host: {os.uname().nodename} · kernel {os.uname().release} · "
        f"python {sys.version.split()[0]}",
        f"Mode: {'quick' if quick else 'full'}",
        "",
        "Every number below was produced by `python -m jocky evidence`; raw logs sit "
        "next to this file (`polymorphism.csv`, `runs.json`, `artifacts.json`, "
        "`audit.json`, `detection.json`).",
        "",
        "## 1. Polymorphic builds",
        "",
        f"- builds: **{poly['iterations']}**, unique SHA-256: **{poly['unique_hashes']}** "
        f"({'all unique' if poly['all_unique'] else 'COLLISION — investigate'})",
        f"- artifact sizes: {poly['size_min']}–{poly['size_max']} bytes, "
        f"{poly['size_distinct']} distinct sizes (per-build padding/structure differs)",
        f"- build throughput: {poly['builds_per_second']}/s",
        f"- semantic equivalence: {poly['equivalence_checked']} freshly built artifacts "
        f"re-executed, findings hash identical to the reference run "
        f"({poly['reference_findings']} finding(s), "
        f"{len(poly['equivalence_failures'])} failures)",
        "",
        "## 2. Repeatability of a single build",
        "",
        f"- runs: **{runs['iterations']}**, distinct finding-hashes: "
        f"**{runs['distinct_finding_hashes']}**, errors: {runs['errors']}",
        f"- latency ms — min {runs['duration_ms']['min']}, median "
        f"{runs['duration_ms']['median']}, p95 {runs['duration_ms']['p95']}, "
        f"max {runs['duration_ms']['max']}",
        f"- throughput: {runs['runs_per_second']} runs/s",
        "",
        "## 3. On-disk footprint",
        "",
        f"- source mode (warm interpreter): created "
        f"{artifacts['source_mode']['created_count']}, modified "
        f"{artifacts['source_mode']['modified_count']} file(s)",
        f"- source mode (cold interpreter): "
        f"{artifacts.get('source_mode_cold', {}).get('bytecode_cache_files', 'n/a')} "
        f"bytecode-cache file(s) written — the interpreter caches imported modules, "
        f"which fileless mode never does",
        f"- fileless mode: created {artifacts['fileless_mode']['created_count']}, "
        f"modified {artifacts['fileless_mode']['modified_count']} file(s); "
        f"exit={artifacts['fileless_mode'].get('exit_code')} "
        f"ok={artifacts['fileless_mode'].get('ok')}",
        f"- fileless process image: `{artifacts['fileless_mode'].get('exe')}` "
        f"with {artifacts['fileless_mode'].get('memfd_map_count')} memfd-backed mappings",
        f"- in-memory payload: interpreter {artifacts['interpreter_bytes']} bytes, "
        f"runtime zip {artifacts['runtime_zip_bytes']} bytes",
        "",
        "## 4. Process and write telemetry (audit hook)",
        "",
        f"- child processes spawned during collection: **{audit.get('child_process')}**",
        f"- execve calls: {audit.get('exec')} · write-mode opens: "
        f"{audit.get('write_open')} · socket calls: {audit.get('socket')}",
        f"- read-mode opens: {audit.get('read_open')} · imports: {audit.get('import')}",
        f"- VM steps: {audit.get('steps')} · findings: {audit.get('findings')} · "
        f"duration {_ms(audit.get('duration_ms'))}",
        "",
        "## 5. Detection proves the technique",
        "",
        f"- memfd-backed processes observed while the fileless job ran: "
        f"**{len(detection.get('memfd_processes_seen', []))}**",
        f"- detector findings: **{detection.get('detector_findings')}** "
        f"(executable memfd mappings: {detection.get('memfd_mappings')})",
        f"- example: {detection.get('detector_titles')[:1]}",
        f"- the fileless job's own report: ok={_child.get('ok')}, "
        f"exe={(_child.get('evidence') or {}).get('exe')}, memfd mappings="
        f"{(_child.get('evidence') or {}).get('memfd_map_count')}",
        "",
    ]
    if audit.get("write_paths"):
        lines += ["Write-mode opens recorded (first 10):", ""]
        lines += [f"- `{path}`" for path in audit["write_paths"][:10]]
        lines.append("")
    if artifacts["source_mode"]["created"]:
        lines += ["Files created by a source-mode run (expected: bytecode caches):", ""]
        lines += [f"- `{path}`" for path in artifacts["source_mode"]["created"][:10]]
        lines.append("")
    text = "\n".join(lines)
    path = os.path.join(out_dir, "report.md")
    with open(path, "w") as fh:
        fh.write(text)
    return path


def run_all(iterations: int = 1000, out_dir: str = "evidence",
            quick: bool = False) -> Dict[str, Any]:
    """Run every stage and write the report. ``quick`` shrinks the counts."""
    from jocky import runner

    out_path = out_dir if os.path.isabs(out_dir) else os.path.join(REPO_ROOT, out_dir)
    os.makedirs(out_path, exist_ok=True)
    # stage 5 needs a script that stays alive; stages 1-4 need deterministic
    # output, otherwise "identical findings" comparisons would be noise
    dwell_script = os.path.join(REPO_ROOT, "scripts", "watch.jky")
    workload_path = os.path.join(REPO_ROOT, "scripts", "evidence.jky")
    if not os.path.exists(workload_path):
        workload_path = os.path.join(REPO_ROOT, "scripts", "smoke.jky")

    with open(workload_path, "r", encoding="utf-8") as fh:
        workload_source = fh.read()
    artifact, _meta = runner.build_artifact(workload_source)

    build_iterations = max(10, iterations // (5 if quick else 1))
    run_iterations = max(10, iterations // (10 if quick else 1))

    stages = {
        "polymorphism": stage_polymorphism(workload_source, build_iterations, out_path),
        "runs": stage_runs(artifact, run_iterations, out_path),
        "artifacts": stage_artifacts(workload_source, out_path),
        "audit": stage_audit(workload_source, out_path),
        "detection": stage_detection(out_path, dwell_script),
    }
    report_path = _write_report(out_path, stages, quick)
    stages["report"] = report_path
    stages["out_dir"] = out_path
    return stages
