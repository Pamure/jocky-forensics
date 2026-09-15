# JOCKY — a forensic scripting runtime (SIH26148)

> **Problem statement SIH26148** — *Creation of scripts/functions with a new
> programming language to commence computer & network forensic analysis without
> triggering security solutions.* Organisation: **NTRO** · Theme: **Blockchain &
> Cybersecurity** · Category: Software.

JOCKY is a small, self-contained forensic toolkit built around a **purpose-made
language**:

| Pillar in the problem statement | What this repository implements |
|---|---|
| New programming language + compiler | `jocky/lang/` — hand-written lexer → recursive-descent parser → bytecode compiler → stack VM (closures, `try/catch`, step/clock budgets) |
| Polymorphic scripts (unique hashes, altered entry points/imports) | `jocky/poly/` — per-build opcode permutation, slot remapping, constant encryption + splitting, junk insertion, keystream-encrypted payload, integrity footer |
| Living-off-the-land execution (no noisy API calls / file-less) | `jocky/rt/` + `jocky/exec/` — pure `/proc`, `/proc/net`, `/sys` collection (**zero external binaries**), direct syscalls via a generated trampoline, and **true fileless execution** (interpreter + runtime + payload in memfds → `/proc/<pid>/exe = /memfd:python3 (deleted)`) |
| Central management interface | `jocky/agent/` — TLS server with token auth, sqlite job/finding store, polling agents, frontable client mode (separate SNI/Host) |
| Detection counterpart | `jocky/rt/detect.py` — finds the very techniques above (fileless processes, executable memfd mappings, deleted executables, hidden kernel modules, injected `LD_*`, suspicious command lines, IOC correlation) |

Everything claimed here is **measured** by `python -m jocky evidence`, which
writes raw logs plus `evidence/report.md`.

## Quickstart

```bash
# 1. run a script with the built-in triage library
./venv/bin/python -m jocky run scripts/triage.jky

# 2. object inventory / hunting / timeline
./venv/bin/python -m jocky run scripts/inventory.jky
./venv/bin/python -m jocky run scripts/hunt.jky
./venv/bin/python -m jocky run scripts/timeline.jky

# 3. compile to a polymorphic artifact and run the artifact
./venv/bin/python -m jocky build scripts/hunt.jky -o /tmp/hunt.jky.build
./venv/bin/python -m jocky exec /tmp/hunt.jky.build --json

# 4. fileless execution: nothing written to disk, memfd-backed process image
./venv/bin/python -m jocky fileless scripts/triage.jky

# 5. built-in host triage (no script needed)
./venv/bin/python -m jocky triage --json

# 6. central management
./venv/bin/python -m jocky serve --port 8443 --token SECRET --state /tmp/jky-server
./venv/bin/python -m jocky agent --server https://127.0.0.1:8443 --token SECRET --once

# 7. reproduce all evidence (1000+ builds, 1000+ executions, file/audit deltas)
./venv/bin/python -m jocky evidence --iterations 1000 --out evidence
```

No third-party packages are required — Python 3.12 standard library only, Linux.

## The language in 20 lines

```jocky
# hunt.jky — in-memory execution, correlated with live sockets
let flagged = []

for f in det.fileless()  { flagged.push(f) }
for f in det.temp_exes() { flagged.push(f) }
for f in det.suspicious_cmdline() {
  if f.severity == "high" or f.severity == "critical" { flagged.push(f) }
}

let pids = transform(flagged, fn(f) { return f.evidence.pid })

for connection in net.established() {
  if contains(connection.pid, pids) {
    emit {"kind": "flagged_socket", "pid": connection.pid,
          "remote": connection.remote_addr, "port": connection.remote_port}
  }
}
```

Language features: `let`/`set`, `if`/`elif`/`else`, `while`, `for … in`,
`fn` declarations and lambdas, closures with **shared mutable capture**,
`try`/`catch`, string interpolation (`"{pid}={value}"`), lists and maps,
member/method dispatch (`p.pid`, `s.upper()`), and `emit` for structured
findings. The VM enforces step, wall-clock and call-depth budgets so a bad
script cannot wedge an investigation.

## Runtime namespaces (what a script can call)

| Namespace | Purpose |
|---|---|
| `proc` | process inventory, cmdline/exe/cwd, fds, maps, threads, io, deleted-open files, socket→pid map |
| `net` | socket tables (`tcp/tcp6/udp/udp6/raw/unix`), listeners, established connections, per-process attribution, interfaces, routes |
| `fs` | hashing, metadata + POSIX flags, magic sniffing, bounded scans, timeline, SUID/SGID inventory, `PATH` audit, `ld.so.preload` |
| `sys` | kernel/distro/uptime/memory/cpu, mounts, module views (+hidden-module diff), kallsyms visibility, containers |
| `det` | triage: fileless processes, memfd mappings, deleted executables, temp executables, rwx regions, unusual listeners, deleted-open files, `LD_*` injection, suspicious command lines, persistence, hijackable PATH entries |
| `ioc` | correlate indicator sets (IPs, names, paths, domains, hashes) against processes, sockets and files |
| `mem` | direct-syscall probe/execute, memfd self-test, `is_memfd`/`memfd_maps` |
| `re` | linear-time pattern matching (`test`/`full`/`find`/`captures`/`replace`/`split`/`escape`) and `fs.grep` for log lines — never the host's backtracking regex engine |
| `time` | UTC timestamps: `now`, `iso`, `parse`, `format`, `filetime`, `delta` |
| `tl` | timeline shaping: `merge`, `window`, `bucket` over collected events |

## Why it does not trip noisy telemetry

Measured by the evidence harness, not asserted:

* **No external processes.** Collection reads `/proc` and `/sys` directly, so
  there is no `ps`, `ss`, `lsof`, `lsmod`, `find`, `sha256sum` or shell in the
  process tree (audit-hook count of child-process events: see `evidence/audit.json`).
* **No program text on disk.** `jocky fileless` executes everything from
  anonymous memory files; the interpreter's own image is a memfd, so
  `/proc/<pid>/exe` reads `/memfd:python3 (deleted)` and the kernel reports
  memfd-backed mappings (`evidence/artifacts.json`).
* **No stable byte signature.** Each build permutes opcodes, re-maps slots,
  encrypts and splits constants, inserts junk, pads and re-keys the payload: a
  thousand builds of one script produce a thousand distinct SHA-256 digests
  with identical behaviour (`evidence/polymorphism.csv`).

## Honest limits (what this does *not* claim)

* Kernel-level telemetry (eBPF/kprobes, LSM/auditd rules) still sees
  `memfd_create`, the `execve` of `/proc/self/fd/N` and the file reads. Nothing
  user-space can hide those from a privileged observer; what JOCKY removes is the
  *noisy, noisy-by-convention* part (spawning tools, writing files, mangling argv).
* In-memory payloads remain visible in `/proc/<pid>/maps` while they run —
  which is exactly why the same runtime ships the detector that finds them.
* Domain fronting needs a real CDN; the client implements the *frontable*
  mechanics (separate SNI and Host, TLS over 443) and says so in `--help`
  rather than pretending a front exists.
* Windows collection is not implemented: the runtime targets Linux procfs. The
  language/compiler/encoder and the agent protocol are platform-neutral.

## Measured results

Produced by `python -m jocky evidence --iterations 1000` on the development host
(`evidence/report.md` plus the raw logs in `evidence/`):

| Measurement | Result |
|---|---|
| Polymorphic builds of one script | **1000 builds → 1000 unique SHA-256**, 3604–4193 bytes, ~270 builds/s |
| Semantic equivalence of fresh builds | 25 freshly rebuilt artifacts re-executed: findings hash identical to the reference run, **0 failures** |
| Repeatability | **1000 executions → 1 distinct findings hash**, 0 errors, median 17.7 ms, ~51 runs/s |
| Process telemetry during collection | **0 child processes, 0 execve, 0 write-mode opens** (Python audit hook over a real triage run) |
| On-disk footprint | cold source-mode run writes 74 bytecode-cache files; **fileless run creates 0 files** |
| Fileless process image | `/proc/<pid>/exe = /memfd:python3 (deleted)`, 4 memfd-backed mappings, interpreter + runtime zip + payload all in memory |
| Self-detection | JOCKY's own triage reported the fileless job while it ran (`detected: true`, finding `process … runs from memory`) |

Raw logs: `polymorphism.csv`, `runs.json`, `artifacts.json`, `audit.json`,
`detection.json`; narrative: `report.md` — all under `evidence/`.

## Repository layout

```
jocky/lang/     lexer, parser (AST), bytecode compiler, VM + native dispatch
jocky/poly/     polymorphic encoder: wire format + per-build mutation
jocky/rt/       collectors (procfs, netfs, filefs, sysinfo, detect, raw syscalls)
jocky/exec/     memfd primitives and true fileless execution
jocky/agent/    TLS management server (sqlite store) and polling agent
jocky/runner.py single execution entry point (source / artifact / fileless)
jocky/evidence.py proof harness (builds, runs, file deltas, audit hook, detection)
jocky/cli.py    `jocky run|exec|build|fileless|disasm|info|triage|evidence|serve|agent`
scripts/*.jky   triage, hunt, inventory, timeline, watch, smoke, evidence
tests/          language semantics, runtime collectors, live detection, encoder, agent
evidence/       generated proof: raw logs + report.md
docs/DESIGN.md  deeper design notes: language spec, artifact format, telemetry matrix
research/       background research behind the design (EDR evasion, in-memory
                execution, BYOVD, CDN fronting, DSL security, network forensics)
knowledge.md    consolidated problem-statement analysis and citation index
```

## Reproducing the claims

```bash
./venv/bin/python -m pytest tests/ -q          # behavioural test suite
./venv/bin/python -m jocky evidence --iterations 1000 --out evidence
sed -n '1,80p' evidence/report.md             # numbers + raw-log pointers
```

`evidence/report.md` is generated from the run: it lists build counts and
unique hashes, execution latencies, files created per mode, audited process and
write events, and the live detection result — each row traceable to
`polymorphism.csv`, `runs.json`, `artifacts.json`, `audit.json` or
`detection.json` in the same directory.
