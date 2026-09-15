# The evidence harness

Every performance and telemetry claim in this documentation comes from one
command: `jocky evidence`. It is not a test suite and it asserts almost
nothing — it runs the real builds, the real executions and the real collection
code, records raw logs for each stage, and writes a report from those numbers.
A reviewer can re-run it and compare files instead of trusting prose.

```bash
./venv/bin/jocky evidence --iterations 1000 --out evidence
```

| Flag | Default | Effect |
|---|---|---|
| `--iterations N` | `1000` | Build and run count for the polymorphism and repeatability stages |
| `--out DIR` | `evidence` | Output directory. A relative path is resolved against the repository root, not the current directory |
| `--quick` | off | Shrinks the run: builds `max(10, N // 5)`, executions `max(10, N // 10)` |

The command prints its full result as JSON on stdout (top-level keys
`polymorphism`, `runs`, `artifacts`, `audit`, `detection`, `report`, `out_dir`)
and exits `0`. A full run on the development host takes about 47 s, dominated
by the thousand executions and the detector stage's dwell window; a quick run
(`--iterations 40 --quick`) takes about 11 s.

## What each stage measures

| Stage | Question it answers | Raw log |
|---|---|---|
| 1 `polymorphism` | Are builds of one script byte-unique, and do they still behave identically? | `polymorphism.csv` |
| 2 `runs` | Is one build's output stable, and how long does it take? | `runs.json` |
| 3 `artifacts` | What does each execution mode leave on disk? | `artifacts.json` |
| 4 `audit` | Does the collection spawn processes, exec, write files or open sockets? | `audit.json` |
| 5 `detection` | Can JOCKY's own triage see the fileless technique while it runs? | `detection.json` |

`report.md` in the same directory is generated from those logs — it is an
output, not an input. Editing it is pointless: the next run rewrites it.

The workload for stages 1–4 is `scripts/evidence.jky`, which touches the
language core, the procfs collector and the network table, so the timings cover
real collection work rather than an empty program. Stage 5 uses
`scripts/watch.jky`, which stays alive long enough to be observed.

## 1. Polymorphic builds — `polymorphism.csv`

The stage runs the workload once in source mode and hashes its findings; then it
builds the script `--iterations` times, recording each artifact's SHA-256 and
size; then it builds and re-executes a sample of 25 fresh artifacts and compares
their findings hash to the reference.

The CSV is three columns, one row per build:

```text
index,sha256,size_bytes
0,2260f6485196f2d1fdefe28c849e7f7f078fe6b8eb8e059d7fbef7c2736562ea,3856
1,cfd90f6259da218a0237653631b4700d483f5c96884142eefe80b0b10a1c3eec,3987
2,6fe32c71868ab3f35bf1d04c1e79a3702e28e4869a6089dabe8e9b46dcf031a5,4018
```

Reading it with the usual tools:

```bash
wc -l < evidence/polymorphism.csv                                            # 1001
cut -d, -f2 evidence/polymorphism.csv | tail -n +2 | sort -u | wc -l         # 1000
cut -d, -f3 evidence/polymorphism.csv | tail -n +2 | sort -n | sed -n '1p;$p'  # 3625 4175
cut -d, -f3 evidence/polymorphism.csv | tail -n +2 | sort -u | wc -l         # 367
```

The first three lines are the load-bearing ones: 1000 rows including the header,
1000 distinct hashes, and 367 distinct sizes for those 1000 builds. The size
column is *not* unique — sizes collide, and in the committed log the most
common size is shared by 9 builds — so size is a weak discriminator while the
digest is not. That distinction matters when you are deciding what an EDR could
key on; the harness records both so you can see it rather than assume it.

Semantic equivalence is checked separately from byte uniqueness: 25 freshly
built artifacts are executed and their findings hash is compared with the
reference run. A change that produced unique bytes *and* different behaviour
would show up as `equivalence_failures`, not as a passing run.

## 2. Repeatability — `runs.json`

One build, executed `--iterations` times in-process, recording each run's
duration and hashing each run's findings:

```json
{
  "iterations": 1000,
  "distinct_finding_hashes": 1,
  "errors": 0,
  "total_seconds": 18.119,
  "runs_per_second": 55.2,
  "duration_ms": {
    "min": 12.298,
    "median": 16.121,
    "p95": 21.358,
    "max": 28.348
  }
}
```

`distinct_finding_hashes: 1` across 1000 runs is the stability claim: the
artifact's output does not drift between executions. `errors` counts VM errors
reported by the runs themselves, not harness failures. The duration block is a
distribution rather than an average, because collection latency on a busy host
is not symmetric:

```bash
jq -r '.duration_ms | "min=\(.min) median=\(.median) p95=\(.p95) max=\(.max)"' evidence/runs.json
```

## 3. On-disk footprint — `artifacts.json`

The stage snapshots the repository, `/tmp`, `/dev/shm` and `/var/tmp`, runs the
workload in source mode, snapshots again and diffs; then it repeats the
snapshot/diff cycle around a fileless run. Separately, a *cold* interpreter probe
re-runs source mode with `PYTHONPYCACHEPREFIX` pointed at a scratch directory,
so the bytecode caches a fresh Python process writes are counted without
polluting the working tree.

```json
{
  "source_mode": {"created_count": 0, "modified_count": 0},
  "source_mode_cold": {"returncode": 0, "bytecode_cache_files": 74},
  "fileless_mode": {"created_count": 0, "modified_count": 0, "exit_code": 0,
                    "ok": true, "exe": "/memfd:python3 (deleted)",
                    "memfd_map_count": 4},
  "fileless_code_created_nothing": true,
  "interpreter_bytes": 8020928,
  "runtime_zip_bytes": 94110
}
```

Two honest readings of this file. First, "created 0" for source mode is measured
on a *warm* interpreter: the same run on a cold interpreter writes 74 bytecode
cache files, which is exactly why fileless mode exists. Second,
`interpreter_bytes` and `runtime_zip_bytes` are the size of the two memfds the
fileless bootstrap needs; `runtime_zip_bytes` tracks the size of the `jocky`
package, so it changes whenever the code does. The snapshot diff is bounded
(4000 entries, three directory levels, heavy directories skipped) — it is a
practical detector of writes in the probed roots, not a filesystem audit.

## 4. Audit-hook methodology — `audit.json`

This is the stage that justifies the phrase "no child processes". A Python
[audit hook](https://docs.python.org/3/library/audit_events.html) (PEP 578) is
installed inside the process that hosts the collection run; the real workload
runs under it; the hook increments counters and the probe prints them as one
JSON line.

What the hook counts:

| Counter | Audit events |
|---|---|
| `child_process` | `subprocess.Popen`, `os.system`, `os.posix_spawn`, `os.fork`, `os.forkpty`, `os.spawn` |
| `exec` | `os.exec` (with the first 120 characters of each path) |
| `write_open` / `read_open` | `open`, split by whether the flag word intersects `O_WRONLY\|O_RDWR\|O_CREAT\|O_APPEND\|O_TRUNC`; write paths are recorded |
| `socket` | `socket.connect`, `socket.getaddrinfo`, `socket.bind` |
| `import` | `import` |

The run result also contributes `steps`, `findings`, `errors` and
`duration_ms`, and the file ends with the derived verdict:

```json
{
  "returncode": 0,
  "child_process": 0,
  "exec": 0,
  "write_open": 0,
  "read_open": 405,
  "socket": 0,
  "import": 62,
  "write_paths": [],
  "exec_paths": [],
  "findings": 1,
  "errors": [],
  "steps": 885,
  "duration_ms": 20.29079299973091,
  "no_child_processes": true
}
```

Why this is the honest way to claim it, and not just a convenient number:

* The hook is installed **in the process that performs the collection**, not in
  a wrapper around it. `subprocess.run([...,"-c", probe])` in the harness is the
  harness's own spawn of that process; it is not counted, and nothing inside the
  measured process can spawn a child without firing one of the events above.
* The zero is supported by non-zero neighbours in the same file: 405 read-mode
  opens and 62 imports prove the hook was live and the workload was real. A
  broken hook would have shown zeros everywhere.
* Read, write and exec are recorded separately, so "no writes" can never be
  confused with "no filesystem activity at all".
* What it cannot see is stated plainly: audit hooks instrument CPython, so
  direct syscalls made through the `mem` namespace are outside their view, and
  kernel-level telemetry (eBPF, LSM, auditd) sees `memfd_create`, `execveat` and
  the file reads regardless of what this file says. Stage 4 measures the
  *collection* path; stage 3 and stage 5 cover the fileless child.

## 5. Self-detection — `detection.json`

The stage starts a real fileless child (`jocky fileless scripts/watch.jky
--json`), polls `/proc` for up to 12 s for a process whose `exe` contains
`/memfd:`, and then requires `detect.fileless_processes()` to find something:

```json
{
  "pid": 30384,
  "memfd_processes_seen": [
    {"pid": 30385, "name": "4", "exe": "/memfd:python3 (deleted)"}
  ],
  "detector_findings": 1,
  "detector_titles": ["process 30385 (4) runs from memory"],
  "memfd_mappings": 1,
  "detected": true,
  "run_report": {
    "exit_code": 0,
    "ok": true,
    "evidence": {"exe": "/memfd:python3 (deleted)", "memfd_map_count": 4}
  }
}
```

This stage is the only one with a race in it, and it says so in its own output.
On a loaded host the 12 s observation window can close before the parent's
`/proc` scan catches the child: a re-run during this documentation pass recorded
`"detected": false` while `run_report.evidence.exe` still read
`/memfd:python3 (deleted)`. The child's self-report is therefore the
independent half of the stage — the process image claim and the detector claim
are recorded separately, so a missed scan is visible as a missed scan rather
than as a silent pass.

## Measured results

From `evidence/report.md` — the committed bundle is a 1.2.0-era run, generated
`2026-09-15 19:14:23` (full mode, `stormbreaker`, kernel
`6.6.87.2-microsoft-standard-WSL2`, Python 3.12.3):

| Measurement | Result | Backing log |
|---|---|---|
| Polymorphic builds | 1000 builds → **1000 unique SHA-256**, 3625–4175 bytes, 367 distinct sizes, 296.0 builds/s | `polymorphism.csv` |
| Semantic equivalence | 25 freshly built artifacts re-executed, findings hash identical to the reference run, **0 failures** | `polymorphism.csv` + report |
| Repeatability | 1000 executions → **1 distinct findings hash**, 0 errors | `runs.json` |
| Latency | min 12.298 ms, median 16.121 ms, p95 21.358 ms, max 28.348 ms; 55.2 runs/s | `runs.json` |
| Source mode (warm) | 0 files created, 0 modified | `artifacts.json` |
| Source mode (cold) | 74 bytecode-cache files written | `artifacts.json` |
| Fileless mode | 0 files created, 0 modified, exit 0 | `artifacts.json` |
| Fileless process image | `/memfd:python3 (deleted)`, 4 memfd-backed mappings | `artifacts.json`, `detection.json` |
| In-memory payload | interpreter 8 020 928 bytes, runtime zip 94 110 bytes | `artifacts.json` |
| Process telemetry | **0 child processes**, 0 execve, 0 write-mode opens, 0 socket calls; 405 read opens, 62 imports | `audit.json` |
| Self-detection | 1 memfd-backed process observed, 1 detector finding | `detection.json` |

These numbers are a snapshot of one host at one moment, which is the point of
publishing the raw logs next to them. Re-running the same command during this
documentation pass produced the same shape — 1000 builds / 1000 unique hashes,
1000 runs / 1 findings hash, 0 child processes, 0 files created in fileless
mode — with a slower host behind it: 232.7 builds/s, 34.6 runs/s, median latency
25.919 ms, and (that time) a missed detection window. Read the columns, not the
digits. The report records its host, kernel and Python version for exactly this
reason.

To reproduce and then inspect rather than trust:

```bash
./venv/bin/jocky evidence --iterations 1000 --out evidence
sed -n '1,60p' evidence/report.md
jq '{child_process, write_open, read_open}' evidence/audit.json
```

The run overwrites the logs in the output directory, so if you are citing a
published bundle, copy it first and run the harness somewhere else — `--out`
accepts an absolute path.
