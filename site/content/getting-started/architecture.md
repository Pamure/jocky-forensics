# Architecture

JOCKY is a language, a Linux collection runtime, a polymorphic encoder, three
execution modes and a proof harness. The pieces are deliberately separable: the
language has no idea what forensics is, the collectors have no idea a language
exists, and exactly one module bridges them. That is what makes the same
compiler usable for a triage script, an artifact built on one host and executed
on another, and a payload that never touches a filesystem.

```text
                    cli.py  /  __main__.py                <- argv, exit codes
                              |
        +---------------------+----------------------+
        |                     |                      |
    runner.py            evidence.py           agent/server.py
    one entry point      proof harness         TLS server, sqlite store
    for execution        (5 stages)                    |
        |                                             agent/client.py
        |                                             polls, runs in-process
   +----+--------+-------------+-------------+
   |             |             |             |
 lang/         poly/         rt/           exec/
 lexer         wire          procfs        memfd.py
 parser        encoder       netfs         fileless.py
 compiler                    filefs
 vm                          sysinfo
                             raw
                             detect
                             builtins  <- the only bridge to lang/
```

## Language pipeline

A script goes through four stages, all in `jocky/lang/`:

| Stage | Module | Responsibility |
|---|---|---|
| Lex | `lexer.py` | source text → tokens carrying line/column positions |
| Parse | `parser.py` + `nodes.py` | recursive-descent parser → AST nodes; raises `JockySyntaxError` with a position |
| Compile | `compiler.py` | single pass over the AST with label patching → `Program`/`Proto`, holding `OPCODES`, code streams and constants |
| Execute | `vm.py` | stack machine over `(op, arg)` instruction pairs; the opcode table is a dict of methods, so dispatch is one lookup per instruction |

Errors surface with positions, from the lexer through to the parser:

```bash
echo 'let x = 1' > /tmp/typo.jky; echo 'fn bump() { x = x + 1 }' >> /tmp/typo.jky; jocky run /tmp/typo.jky
```

```text
jocky: JockySyntaxError: expected an expression but found op '=' (line 2, col 15)
```

Assignment is the `set` statement (`set x = x + 1`), which is the mistake above.

The compiler emits cell instructions only for locals that a nested function
captures, which you can see directly. This script has one local, `x`, which
`bump()` captures:

```jocky
let x = 1
fn bump() { set x = x + 1 }
bump()
emit {"x": x}
```

```bash
jocky disasm /tmp/tiny.jky
```

```text
=== constants ===
[0] 1
[1] None
[2] 'x'
=== names ===
[0] bump
=== <main> (locals=1) ===
   0  CONST      0
   1  STORE_CELL 0
   2  PUSH_CELL  0
   3  MK_FN      0
   4  STOREG     0
   5  LOADG      0
   6  CALL       0
   7  POP        
   8  CONST      2
   9  LOAD_CELL  0
  10  MK_MAP     1
  11  EMIT       
  12  HALT       
=== bump (locals=1) ===
   0  LOAD_CELL  0
   1  CONST      0
   2  ADD        
   3  STORE_CELL 0
   4  CONST      1
   5  RET        
```

`x` lives in a cell (`STORE_CELL`/`LOAD_CELL`) used by both `<main>` and
`bump`, which is what makes a closure see the writer's updates. `Proto.starts`
records statement boundaries so the encoder can insert junk instructions only
at safe points.

## What the VM guarantees

- **Budgets.** `max_steps` (default 20 000 000 instructions in `VM`, 50 000 000
  from the CLI default in `runner.DEFAULT_MAX_STEPS`), a wall-clock budget
  (60 s default), and a call-depth cap of 256 frames.
- **Budgets cannot be caught.** A script's own `try`/`catch` does not see a
  budget breach; the run stops, the result is marked `truncated`, and the
  errors list records the reason.
- **Closures capture cells, not values.** Two closures over one variable see
  each other's writes, and a loop variable is a single cell shared by every
  closure created in that loop.
- **Typed error model.** Runtime errors are catchable and arrive in `catch` as
  the message string; uncaught errors stop the program but the findings
  collected so far are preserved in `RunResult.findings`.
- **No host coupling.** `VM(natives=…)` takes a mapping of names to functions.
  The VM has no import of `jocky.rt`; the forensic runtime is injected.

The budget contract is observable from the outside. The script below loops
forever inside a `try`/`catch` that would print if the breach were catchable:

```jocky
# limits.jky - a budget breach must not be catchable by the script itself
let n = 0
try {
  while true { set n = n + 1 }
} catch err {
  print("caught inside the script: {err}")
}
emit {"kind": "unreachable", "n": n}
```

```bash
jocky run /tmp/limits.jky --max-steps 100000 --json
```

```json
{
  "findings": [],
  "output": [],
  "errors": [
    "step budget exceeded (100000 instructions)"
  ],
  "steps": 100001,
  "native_calls": 0,
  "duration_ms": 72.232,
  "truncated": true
}
```

where `/tmp/limits.jky` is a `while true` loop wrapped in
`try { … } catch err { print("caught inside the script: {err}") }`. Nothing was
printed by the script: the breach is not catchable, and the exit status is 1.

## Runtime collectors

`jocky/rt/` is plain Python that reads kernel interfaces and returns dicts and
lists. No module here spawns a process, opens a file for writing, or imports
the language — the only exception is `builtins.py`, which is the bridge.

| Module | Reads | Notes |
|---|---|---|
| `procfs.py` | `/proc/<pid>/*` | process inventory, cmdline/exe/cwd, fds, maps, threads, io, deleted-open files, socket→pid map |
| `netfs.py` | `/proc/net/*` | tcp/tcp6/udp/udp6/raw/unix tables, listeners, per-process attribution (imports `procfs`) |
| `filefs.py` | the filesystem | hashing, metadata and POSIX flags, magic sniffing, bounded scans, timeline, SUID/SGID, PATH audit |
| `sysinfo.py` | `/proc`, `/sys` | kernel, distro, uptime, memory, cpu, mounts, module views, containers (imports `procfs`) |
| `raw.py` | `ctypes`/syscalls | direct-syscall probe and execute path, no libc wrapper |
| `detect.py` | the modules above | 18 detection checks with severities; findings built by `_finding(...)` and aggregated by `triage()` |

`detect.py`'s `CHECK_CATALOG` is the single source of truth for check names,
severities, data sources and analyst actions; the
[Detection checks](/docs/runtime/detection) page is generated from it.

## The native bridge

`rt/builtins.py` builds the namespaces scripts call — `proc`, `net`, `fs`,
`sys`, `det`, `ioc`, `mem` — as dotted names mapped to `NativeFn` objects that
the VM arity-checks on every call. It is the only module that imports both
sides (`jocky.lang.vm` for `NativeFn`/`to_str`/`truthy`, `jocky.rt.*` for the
collectors), plus `jocky.exec.memfd` for the memfd self-test natives.

Two natives are deny-by-default and need an explicit grant:
`mem.syscall` (raw syscalls can signal or kill) and `mem.memfd_run` (executes
arbitrary code with the caller's privileges). Without `--allow syscall,exec`
they raise a capability error instead of running.

## The encoder

`jocky/poly/wire.py` defines how a compiled `Program` becomes bytes (portable
across hosts, versioned, self-describing). `jocky/poly/encoder.py` performs the
per-build mutation: opcode permutation, local-slot remapping, constant
encryption and splitting, junk insertion at statement boundaries, and a
keystream-encrypted payload with random padding and a truncated HMAC footer.
Both import `jocky.lang.compiler` for the opcode table — the encoder consumes
the compiler's output and never touches the AST or the VM.

The seed identifies the build (`build_hash`), fresh entropy identifies the
instance, so `--deterministic --seed-hex <hex>` reproduces identical bytes while
a normal build never repeats. See
[Polymorphic artifacts](/docs/execution/artifacts) for the transform table and
for what the encoder does *not* hide.

## Execution modes

`runner.py` is the single execution entry point used by the CLI, the agent, the
harness and the tests. It compiles source, decodes artifacts, runs programs and
wraps all of it in a `RunResult`.

| Mode | Program text | Process image | Implementation |
|---|---|---|---|
| `run` | `.jky` file on disk | `/usr/bin/python3` | `run_source` compiles and runs in-process |
| `exec` | encrypted artifact on disk | `/usr/bin/python3` | `run_artifact` decodes via `PolyEncoder` and runs in-process |
| `fileless` | payload in a memfd | `/memfd:python3 (deleted)` | `exec/fileless.py` forks, then `execve`s `/proc/self/fd/<elf_fd>` |

`exec/memfd.py` owns the primitives (`create_memfd`, the interpreter ELF, a zip
of the runtime package, memfd process inspection). `fileless.py` forks once,
passes the package and payload as inherited file descriptors, and execs the
in-memory interpreter with a `-c` bootstrap that imports the runtime through
`zipimport` and reads the payload, both via `/proc/self/fd`. A watcher thread
samples the child's `/proc` entries around the exec, so the evidence is recorded
by the tool itself rather than by a human with a stopwatch.

This is the bootstrap's body, read from a live memory-resident process:

```python
sys.path.insert(0, "/proc/self/fd/" + os.environ["JKY_PKG"])
from jocky.runner import policy_ctx, run_bytes
with open("/proc/self/fd/" + os.environ["JKY_PAYLOAD"], "rb") as handle:
    data = handle.read()
result = run_bytes(data, wall_clock_ms=float(os.environ.get("JKY_WALL", "60000")),
                   ctx=policy_ctx(os.environ.get("JKY_ALLOW")))
```

`--private` opts into `PR_SET_DUMPABLE=0`, which makes the process invisible to
same-uid inspection — including JOCKY's own triage. The default is visible, so
the detection claim stays checkable.

## Management

`agent/server.py` is a TLS HTTP server (`ssl.PROTOCOL_TLS_SERVER`) with a
shared-token check (`X-JKY-Token`, compared with `hmac.compare_digest`), a
route table (`/v1/health`, `/v1/enroll`, `/v1/jobs/submit`, `/v1/jobs/poll`,
`/v1/jobs/result`, `/v1/status`, `/v1/findings`) and a sqlite store with
`agents`, `jobs` and `findings` tables, so every finding keeps its job and
agent provenance across restarts. `agent/client.py` polls for jobs, executes
them in-process through `runner` and posts results back; it can send a
different SNI/Host than the address it dials, which is the client-side half of
domain fronting (no CDN is bundled). See
[Server & agents](/docs/operations/management).

## Case integrity

`canon.py` decides how a value becomes bytes (sorted-key compact JSON, UTF-8),
so a digest computed during collection can be recomputed later on another
machine. `case.py` builds on it: a per-file SHA-256 manifest, a hash chain, a
separately stored chain head and an optional HMAC signature by the analyst,
surfaced as `jocky attest`, `jocky verify` and `jocky sign`. Attestation is an
analyst-side step that runs *after* collection: signing during a run would spawn
`openssl` and break the measured invariant "0 child processes during a run".

## Where measurement lives, and why

Every number this project publishes comes from one harness,
`jocky/evidence.py`. A five-iteration pass takes about eleven seconds and
writes the whole bundle:

```bash
jocky evidence --iterations 5 --out /tmp/ev
```

```text
artifacts.json
audit.json
detection.json
polymorphism.csv
report.md
runs.json
```

The checked-in bundle under `evidence/` was produced by the same command with
`--iterations 1000 --out evidence`. Each file has one job:

| File | Contents |
|---|---|
| `evidence/report.md` | the narrative: build counts and unique hashes, execution latencies, file deltas, audited events, the live detection result |
| `evidence/polymorphism.csv` | one row per build: size, digests, seed |
| `evidence/runs.json` | one entry per execution: duration, findings hash, errors |
| `evidence/artifacts.json` | filesystem deltas per mode, fileless process evidence |
| `evidence/audit.json` | events counted by a Python audit hook during a real collection run |
| `evidence/detection.json` | what the detector saw while a fileless job was alive |

The harness exists because a claim like "no external processes are spawned" is
worthless as an assertion: it is easy to write and impossible to check. So the
harness measures it — a Python audit hook counts child-process creation,
`execve`, write-mode `open` and socket calls during a real triage run, and the
report quotes the counters. The same pattern covers every other headline claim:
builds are hashed individually to prove uniqueness, 25 freshly built artifacts
are re-executed to prove semantic equivalence, the filesystem is snapshotted
before and after to prove fileless mode writes nothing, and the detector is
pointed at the runtime's own fileless process to prove the two sides agree.

`evidence/report.md` on this checkout was generated on 2026-09-15 19:14:23 on
the development host (kernel `6.6.87.2-microsoft-standard-WSL2`, Python 3.12.3)
and reports, among other rows:

```text
## 1. Polymorphic builds
- builds: **1000**, unique SHA-256: **1000** (all unique)
- artifact sizes: 3625–4175 bytes, 367 distinct sizes (per-build padding/structure differs)
- build throughput: 296.0/s
- semantic equivalence: 25 freshly built artifacts re-executed, findings hash identical to the reference run (1 finding(s), 0 failures)

## 2. Repeatability of a single build
- runs: **1000**, distinct finding-hashes: **1**, errors: 0
- latency ms — min 12.298, median 16.121, p95 21.358, max 28.348

## 4. Process and write telemetry (audit hook)
- child processes spawned during collection: **0**
- execve calls: 0 · write-mode opens: 0 · socket calls: 0

## 5. Detection proves the technique
- memfd-backed processes observed while the fileless job ran: **1**
- detector findings: **1** (executable memfd mappings: 1)
```

Numbers are timestamped and host-specific on purpose: they describe a
measurement, not a specification. The
[Evidence harness](/docs/operations/evidence) page explains each stage and how
to re-run it; [Honest limits](/docs/security/limits) lists what none of this
measures.

## Module map

```text
jocky/
  __init__.py      version and the four-layer description of the package
  __main__.py      `python -m jocky` → cli.main
  cli.py           argparse front end; imports subcommand modules lazily
  runner.py        one execution entry point: compile, run, build, fileless
  evidence.py      proof harness: 5 stages, raw logs, report.md
  diagnostics.py   the checks behind `jocky doctor`
  scaffold.py      `jocky init`: example scripts, README, .gitignore
  canon.py         canonical JSON serialisation and digests
  case.py          case-directory integrity: manifests, hash chain, signing
  errors.py        exception hierarchy shared by every layer
  lang/            lexer.py parser.py nodes.py compiler.py vm.py
  poly/            wire.py (byte format) encoder.py (per-build mutation)
  rt/              procfs.py netfs.py filefs.py sysinfo.py raw.py detect.py builtins.py
  exec/            memfd.py (primitives) fileless.py (fork + /proc/self/fd exec)
  agent/           server.py (TLS + sqlite) client.py (polling agent)
```

Alongside the package: `jocky/examples/*.jky` (the five scripts `jocky init`
copies, shipped as package data), `scripts/*.jky` (triage, hunt, inventory,
timeline, watch, smoke, evidence), `tests/` (language, runtime, live detection,
encoder, agent, diagnostics, scaffold, security, sandbox) and `evidence/` (the
generated proof, consumed by this documentation).

## Import layering

The dependency direction is one-way, which is what keeps the pieces testable
and portable:

```text
errors.py            <- imported by every layer, imports nothing
  lang/*             <- lexer, nodes, parser, compiler, vm; imports only errors + lang
    poly/*           <- imports lang.compiler (the opcode table); never the VM
    rt/collectors    <- procfs imports nothing; netfs/filefs/sysinfo import procfs;
                        detect imports those four; raw imports nothing
      rt/builtins    <- imports rt.* + lang.vm + exec.memfd  (the only bridge)
  exec/*             <- fileless imports runner (for the in-memory child)
runner.py            <- imports lang, poly.encoder, rt.builtins, exec.fileless
  cli.py             <- imports runner plus, lazily, evidence/scaffold/diagnostics/agent/case
  evidence.py        <- imports runner, exec.fileless, rt.detect, rt.procfs
  agent/client.py    <- imports runner
  agent/server.py    <- imports canon only
  case.py            <- imports canon
```

Consequences worth knowing:

- `jocky.lang` depends only on `jocky.errors`, so the compiler and VM work with
  no collectors, encoder or network — the runtime is injected as `natives`.
- `jocky.rt.procfs` imports nothing from the package, and `filefs`, `netfs` and
  `sysinfo` import only `procfs`, so collectors can be called directly from
  Python or from a test without a VM.
- `jocky.poly` depends on `jocky.lang.compiler` for the opcode table, and
  nothing in `jocky.lang` depends on `jocky.poly`: the artifact format consumes
  the compiler rather than being part of it.
- The CLI imports heavyweight submodules inside each command function, so
  `jocky --version` and `jocky doctor` start without loading the agent, the
  harness or the TLS stack.

## Next steps

- [Collectors](/docs/runtime/collectors) — what each namespace returns.
- [Execution modes](/docs/execution/modes) — choosing between `run`, `exec` and `fileless`.
- [Polymorphic artifacts](/docs/execution/artifacts) — the artifact format in detail.
- [Contributing](/docs/project/contributing) — extension points and test layout.
