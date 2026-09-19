# JOCKY — a forensic scripting runtime (SIH26148)

> **Problem statement SIH26148** — *Creation of scripts/functions with a new
> programming language to commence computer & network forensic analysis without
> triggering security solutions.* Organisation: **NTRO** · Theme: **Blockchain &
> Cybersecurity** · Category: Software.

JOCKY is a small, self-contained forensic toolkit built around a **purpose-made
language**:

| Pillar in the problem statement | What this repository implements |
|---|---|
| New programming language + compiler, altered token generation | `jocky/lang/` — hand-written lexer → recursive-descent parser → bytecode compiler → stack VM (closures, `try/catch`, step/clock budgets). `jocky/poly/sourcemut.py` re-spells every keyword from a per-build seed (`jocky build --alias-tokens`): the delivered source text differs per build while the compiled program is provably identical (114 mutated runs over the full script library) |
| Polymorphic scripts (unique hashes, altered entry points/imports) | `jocky/poly/` — per-build opcode permutation, slot remapping, constant encryption + splitting, junk insertion, keystream-encrypted payload, integrity footer. `jocky/native/` embeds the artifact in a real x86-64 ELF64 executable (`jocky build --target native`): `.text` lands on a per-build page (64 distinct entry addresses measured), the image has **zero imports** — nothing to pattern-match — and every emitted binary runs on the host (tested) |
| Automated CI/CD polymorphic pipeline | `jocky/ci.py` + `.github/workflows/polymorphism.yml` — `jocky ci` builds N artifacts per commit, fails the build on any hash collision, and compares re-executed findings against a source run so uniqueness cannot drift from semantics |
| Living-off-the-land execution (no noisy API calls / file-less) | `jocky/rt/` + `jocky/exec/` — pure `/proc`, `/proc/net`, `/sys` collection (**zero external binaries**), direct syscalls via a generated trampoline, and **true fileless execution** (interpreter + runtime + payload in memfds → `/proc/<pid>/exe = /memfd:python3 (deleted)`) |
| BYOVD / kernel-integrity forensics | `jocky/rt/byovd.py` — loaded-module integrity: known-vulnerable driver matches (20 curated entries, CVE-checked), out-of-tree/unsigned/force-loaded taint classes, modules loaded long after boot, modules whose backing `.ko` was deleted, and the global taint bits. Read-only: nothing here loads or modifies a module |
| Central management interface | `jocky/agent/` — TLS server with token auth, sqlite job/finding store, polling agents, and a **self-contained web console** at `GET /` (no CDN, no build step, CSP-restricted, DOM built with `textContent` so hostile agent names cannot become XSS). The agent can dial an address while presenting a different TLS name (`--sni`) and `Host` (`--host-header`) — vhost selection at an ingress you control, **not** domain fronting; see the limits below |
| Cross-platform collection | `jocky/rt/winapi.py` — Windows equivalents of the process/socket/module collectors through pure `ctypes` (**no `tasklist`, `netstat`, `wmic` or PowerShell**), emitting the same key names as the Linux side so a script runs unchanged on either |
| Detection counterpart | `jocky/rt/detect.py` — finds the very techniques above (fileless processes, executable memfd mappings, deleted executables, hidden kernel modules, injected `LD_*`, suspicious command lines, vulnerable drivers, IOC correlation) |

Everything claimed here is **measured** by `python -m jocky evidence`, which
writes raw logs plus `evidence/report.md`.

## Quickstart

**New here? Read [docs/INSTALL.md](docs/INSTALL.md)** — requirements, install on
Linux and Windows, Docker, the platform capability matrix, and troubleshooting.
The short version:

```bash
git clone https://github.com/Pamure/jocky-forensics.git && cd jocky-forensics
python3 -m venv venv && ./venv/bin/pip install -e .
./venv/bin/jocky doctor          # verify the host can run every mode
```

Then:

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

# 6. central management, with a web console at the printed URL
./venv/bin/python -m jocky serve --port 8443 --token SECRET --state /tmp/jky-server
./venv/bin/python -m jocky agent --server https://127.0.0.1:8443 --token SECRET --once

# 7. the polymorphic CI gate
./venv/bin/python -m jocky ci --script scripts/hunt.jky --count 256

# 8. reproduce all evidence (1000+ builds, 1000+ executions, file/audit deltas)
./venv/bin/python -m jocky evidence --iterations 1000 --out evidence
```

No third-party packages are required — Python 3.12 standard library only.

**Platform support:** Linux is the full-capability platform. Windows collects
through `ctypes` and runs the language, encoder, CI gate and console; the two
Linux-only mechanisms (memfd fileless execution, Landlock/seccomp confinement)
are reported as unavailable rather than silently failing. The capability matrix
is in [docs/INSTALL.md](docs/INSTALL.md#6-platform-capability-matrix).

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
| `det` | triage: fileless processes, memfd mappings, deleted executables, temp executables, rwx regions, unusual listeners, deleted-open files, `LD_*` injection, suspicious command lines, persistence, hijackable PATH entries, BYOVD/kernel integrity, Windows process-injection detection |
| `ioc` | correlate indicator sets (IPs, names, paths, domains, hashes) against processes, sockets and files |
| `mem` | direct-syscall probe/execute, memfd self-test, `is_memfd`/`memfd_maps` |
| `re` | linear-time pattern matching (`test`/`full`/`find`/`captures`/`replace`/`split`/`escape`) and `fs.grep` for log lines — never the host's backtracking regex engine |
| `pcap` | **offline network forensics**: read libpcap and pcapng captures, decode packets, reconstruct bidirectional flows, extract DNS queries, TLS ClientHello SNI + JA3, and cleartext HTTP requests |
| `sigma` | evaluate Sigma rules (documented YAML subset) on the linear-time engine |
| `yara` | evaluate YARA-subset byte signatures on the same engine |
| `time` | UTC timestamps: `now`, `iso`, `parse`, `format`, `filetime`, `delta` |
| `tl` | timeline shaping: `merge`, `window`, `bucket` over collected events |

## Why it does not trip noisy telemetry

Two kinds of evidence, and they are different questions:

**Measured by the evidence harness** (`jocky evidence`), which reports what the
runtime *does*:

* **No external processes.** Collection reads `/proc` and `/sys` directly, so
  there is no `ps`, `ss`, `lsof`, `lsmod`, `find`, `sha256sum` or shell in the
  process tree (audit-hook count of child-process events: see `evidence/audit.json`).
* **No program text on disk.** `jocky fileless` executes everything from
  anonymous memory files; the interpreter's own image is a memfd, so
  `/proc/<pid>/exe` reads `/memfd:python3 (deleted)` and the kernel reports
  memfd-backed mappings (`evidence/artifacts.json`).
* **No stable byte signature.** Each build permutes opcodes, re-maps slots,
  encrypts and splits constants, inserts opaque guards and dead code, and
  **reshapes the control flow** — a thousand builds of one script produce a
  thousand distinct SHA-256 digests *and* a thousand distinct control-flow
  signatures, with identical behaviour (`evidence/polymorphism.csv`).

**Measured against a real endpoint protection** (`docs/EVASION.md`), which
answers "does anything flag it" — the question the problem statement actually
asks. Microsoft Defender, signature `1.459.226.0`, real-time protection on: 29
polymorphic artifacts scanned clean, execution produced zero detections, and the
harnesses carry a positive control (EICAR) that *was* detected, so "clean" is a
result rather than a broken test. That report also states plainly what was not
tested — other vendors, kernel telemetry, network inspection — and one
measurement that turned out to be unreliable and was discarded.

## Honest limits (what this does *not* claim)

**Most clauses of the problem statement are implemented and measured. What remains
unmet is listed here first — read it before the table above.**

* **Native output is ELF-only, and scripts don't run natively yet.** `jocky build
  --target native` produces a real, executable ELF64 image — its per-build entry
  address and empty import list satisfy pillar 2's entry-point and import-table
  clauses — but the embedded artifact is still executed by the bytecode VM, not
  by AOT-compiled native code. Emitting PE32+ (Windows) and compiling opcodes to
  machine code are the remaining work.
* **The offensive half of pillar 3 is deliberately not free-standing.** Process
  hollowing, reflective DLL injection, API unhooking, thread execution hijacking
  and BYOVD *exploitation* exist only as harness-scoped mechanisms in
  `jocky/lab/` — every entry point routes through `HarnessGuard`, which refuses
  any target the harness did not itself spawn, and the Windows techniques raise
  `LabRefusal` until the Phase-0 Windows test VM (with test signing) is attached.
  This is a scope decision, not an omission: a forensic toolkit that weaponises
  the techniques it finds against arbitrary processes is not a forensic toolkit.
  The non-offensive half is performed today: in-memory/fileless execution via
  `memfd_create`, direct Linux x86_64 syscalls through a generated trampoline,
  and live detection of the rest.
* **No LLVM frontend.** The pillar offers "custom language syntax **or** a
  language-independent IR (LLVM) frontend"; this takes the first option. There is no
  `llvmlite`, no IR emission and no `.ll` anywhere in the tree. The lexer, parser, compiler
  and VM are hand-written (`jocky/lang/`, ~2,400 lines).
* **Domain fronting is dead and is not claimed.** The runtime lets an agent dial one
  address while presenting a different TLS server name and `Host` header, which is *vhost
  selection at an ingress you control*. It is not fronting: fronting needs an SNI that
  differs from the `Host` and a CDN that routes on the inner header, and every tier-1
  provider closed that — Google in 2018, Cloudflare and AWS in 2020, Azure across Front
  Door and CDN, Fastly by 2024. An earlier version of this file described the feature as
  "frontable mechanics"; that was wrong in two ways (the single parameter set both fields,
  so it could not express the mismatch the technique requires) and the claim has been
  withdrawn. What still works, and is what the code is for, is a shared ingress answering
  for several virtual hosts. Measured evidence for the detection side is in
  [`docs/EVASION.md`](docs/EVASION.md).
* **The evasion evidence is two signature engines, not a market.** Defender and ClamAV
  were the two available; both are signature-based, so neither exercises the behavioural
  or ML layer that is most likely to notice collection activity. No eBPF, ETW-TI, Sysmon
  or LSM instrumentation was in the path. [`docs/EVASION.md`](docs/EVASION.md) states this
  in full, including an AMSI probe whose results were discarded as unreliable rather than
  reported.
* Kernel-level telemetry (eBPF/kprobes, LSM/auditd rules) still sees
  `memfd_create`, the `execve` of `/proc/self/fd/N` and the file reads. Nothing
  user-space can hide those from a privileged observer; what JOCKY removes is the
  *noisy, noisy-by-convention* part (spawning tools, writing files, mangling argv).
* In-memory payloads remain visible in `/proc/<pid>/maps` while they run —
  which is exactly why the same runtime ships the detector that finds them.
* **Linux-only mechanisms on Windows.** Collection, the language, the encoder,
  the CI gate and the management console all run on Windows (verified on
  Windows 11, Python 3.13, non-elevated: 244 kernel drivers, 231 processes, 135
  sockets, and a script compiled to an artifact there and executed from it).
  Fileless memfd execution and Landlock/seccomp confinement do not — there is no
  equivalent mechanism — and `jocky doctor` reports each as platform-unavailable
  rather than as a missing install. The full matrix is in
  [docs/INSTALL.md](docs/INSTALL.md#6-platform-capability-matrix).
* **Kernel load addresses are withheld on Windows** from a non-elevated caller.
  Driver *names*, *sizes* and *paths* are still authoritative (they come from
  `NtQuerySystemInformation`), which is what BYOVD matching keys on; only the
  base address reads zero.

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
jocky/lang/     lexer (+ per-build keyword aliasing), parser, compiler, stack VM
jocky/poly/     polymorphic encoder + source-token mutation stage
jocky/native/   ELF64 emitter: artifacts as runnable, dependency-free executables
jocky/rt/       collectors (procfs, netfs, filefs, sysinfo, detect, raw syscalls)
jocky/exec/     memfd primitives and true fileless execution
jocky/lab/      harness-gated execution techniques (guard-refuses-unowned-targets)
jocky/agent/    TLS management server, polling agent, channel transports (DNS TXT,
                websocket relay — proven on loopback, pending an operator domain)
jocky/runner.py single execution entry point (source / artifact / native / fileless)
jocky/evidence.py proof harness (builds, runs, file deltas, audit hook, detection)
jocky/cli.py    `jocky run|exec|build|fileless|disasm|info|triage|evidence|serve|agent`
scripts/*.jky   triage, hunt, inventory, timeline, watch, smoke, evidence
tests/          language semantics, runtime collectors, live detection, encoder, agent
evidence/       generated proof: raw logs + report.md
docs/DESIGN.md  deeper design notes: language spec, artifact format, telemetry matrix
docs/INSTALL.md install guide: Linux, Windows, Docker, capability matrix, troubleshooting
docs/VERIFY.md  five manual tests you can run to check each claim yourself
docs/           the documentation: language/ (syntax manual), runtime/, security/,
                operations/, execution/, plus the design, architecture, install,
                verification, evidence and evasion reports
docs/PROJECT-AUDIT.md            per-claim audit: what is proven, what is not
docs/AUDIT-2026-09-17-runtime-modules.md  adversarial audit of pcap.py and winject.py
research/       the audits and surveys the design decisions rest on, including the
                twenty-agent review synthesised in docs/project/roadmap.md
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
