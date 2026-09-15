# Changelog

Notable changes to JOCKY, newest first, in Keep a Changelog form. The repository's `CHANGELOG.md` is the file of record; this page is the same history for the site.

The version string lives in `jocky/__init__.py`: `pyproject.toml` reads it dynamically,
`jocky --version` prints it, and the site builds its version banner from it and `git tag`.

```bash
$ ./venv/bin/jocky --version
jocky 1.2.0
```

Releases are annotated tags (`git tag -l` lists `v1.1.0` and `v1.2.0`, both dated
2026-09-15); the generated [releases page](/docs/project/releases) carries their commit
ids and notes, and [Versioning & releases](/docs/operations/versioning) explains the
compatibility policy. What is planned next is in the [roadmap](/docs/project/roadmap).

## [Unreleased]

Commits after `v1.2.0` are documentation and site work — the remaining pages of this site,
verification passes over the existing ones, and site infrastructure — plus one CLI rendering
fix. The suite collects 125 tests across nine files
(`./venv/bin/python -m pytest tests/ --collect-only -q`).

### Added

- Content pages for getting started, language, runtime, execution, operations, security and
  project sections, each command and output taken from a real run against this tree.
- A sitemap, `robots.txt` and a 404 page generated from the same navigation manifest as the
  pages, so a new page cannot be missing from the crawler entry point.

### Fixed

- Findings render identically on the terminal and through `--json`. Both paths now
  serialise through `to_plain`, so a finding that carries a function no longer prints a
  dataclass repr (with VM internals) on one side and `<fn <lambda>>` on the other:
  `{"kind": "fn_finding", "callable": "<fn <lambda>>", "name": "demo"}`.

## [1.2.0] — 2026-09-15

### Added

- **Sandbox levels** — `jocky run --sandbox=off|vm|ro|strict`, implemented on Landlock
  through raw syscalls with the standard library only. `vm` keeps writes inside the
  working directory and the drop zones, `ro` denies every write, and `strict` also denies
  `socket(2)` with a seccomp filter. `tests/test_sandbox.py` exercises the levels in
  forked children; `/proc` and `/etc` stay readable while writes fail with `EACCES`.
- **Confinement reporting in `jocky doctor`** — a new group reports Landlock availability
  and ABI, so "you are not sandboxed" is never a surprise:
  `[ok  ] sandbox (Landlock)           Landlock ABI 3 (filesystem rights only; --sandbox=strict adds seccomp)`.

- **Zero-dependency documentation build** — `site/tools/build_static.py` renders the same
  content and stylesheet with only the standard library, for hosts without a JavaScript
  toolchain, and `site/tools/gen.mjs` invokes the generators so a builder image without
  Python warns and keeps the committed pages instead of failing.
- **Documentation and installation site** under `site/` — SvelteKit, fully prerendered,
  with the reference pages generated from the source tree and the release page generated
  from `git tag`.

### Fixed

- `CertificatePinError` was referenced in the agent client but never defined, so a
  certificate-pin mismatch raised `NameError` from inside `http.client` and escaped
  `client.run` instead of being reported as a trust failure.
- Landlock and seccomp syscall plumbing: attribute buffers were freed before the syscall
  ran (`EINVAL`), and `struct sock_fprog` was packed with the pointer at the wrong offset
  (`EFAULT`). Both made the sandbox silently unavailable rather than obviously broken.

## [1.1.0] — 2026-09-15

The first packaged release: the working forensic runtime, hardened against a twenty-agent
limitation and state-of-the-art review, with the evidence harness, the management
interface and the installation story.

### Added

- **`jocky doctor`** — probes every prerequisite (procfs, `/proc/net`, memfd, direct
  syscalls, TLS, sqlite, fileless end-to-end) before an investigation starts and prints
  the remediation for each failure. A full run ends with a verdict such as
  `ready: 12 ok, 1 warning(s), 0 failure(s)`.
- **`jocky init` / `jocky examples`** — scaffold a case directory containing the bundled,
  runnable scripts (`triage`, `hunt`, `inventory`, `timeline`, `watch`), a README and a
  `.gitignore` for runtime state.
- **`jocky attest` / `jocky verify` / `jocky sign`** — a per-file SHA-256 manifest, a hash
  chain over it, an optional off-host anchor for the chain head and an optional HMAC
  signature, so "a reviewer can re-check the logs" is a verifiable claim.
- **`jocky build --deterministic --seed-hex <hex>`** — byte-identical rebuilds for
  provenance work; unique-per-build artifacts remain the default.
- **Installable package** — `pip install .` provides the `jocky` console script, and the
  `Dockerfile` builds a minimal image that deliberately contains no `ps`, `ss` or `lsof`.
- **`--allow syscall,exec` capability grants**, and agent options `--pin`, `--verify-ca`,
  `--sni`, `--token-file`, plus `--private` fileless mode.

### Changed

- **Privileged natives are deny-by-default.** `mem.syscall` and `mem.memfd_run` require an
  explicit grant; the review reproduced a live process kill through
  `mem.syscall(62, pid, 9)` and a shell escape through `mem.memfd_run`.
- **Agent TLS defaults to pinning.** The self-signed server certificate is fingerprinted
  at enrolment and enforced afterwards; `--insecure` is explicit, prints a warning and
  disables pinning.
- **Job results are authenticated.** `POST /v1/jobs/result` accepts only a known agent
  reporting on a job it claimed; replays are acknowledged idempotently without writing
  duplicate findings, and everything else is `409`. Jobs carry a `payload_sha256` that is
  echoed back with the result.
- **State is owner-only** — the state directory is `0700` and `store.db` is `0600`,
  because findings are case material.
- **`det.triage()` reports visibility coverage** and emits a `partial_visibility` finding
  when part of the process table is unreadable, so a blind scan cannot be mistaken for a
  clean host.
- **Fileless mode requests `MFD_EXEC`** where the kernel understands it (hardened hosts
  with `vm.memfd_noexec >= 1`), sets the process name, disables core dumps and writes no
  bytecode caches.
- **The polymorphism ceiling is stated honestly** in the documentation: builds are
  uniquely hashed, the statement-level control-flow graph is unchanged between builds, and
  a standalone unpacker recovers the program in about a millisecond.

### Fixed

- The lexer crashed with `KeyError` on a script ending in `0` (or in `"{0}"`).
- The constant pool merged `1`, `1.0` and `true` into one entry, so a script could emit
  `false` where it wrote `0`.
- Unknown string escapes silently dropped their backslash, corrupting detection patterns
  such as `\d+`.
- `sys.users()` raised `KeyError: 'tty'`, and `proc.io()` never returned counters because
  the path was a literal `"/proc/{pid}/io"` instead of being built from the pid.
- Cross-frame error unwinding: an error raised inside a function bypassed the caller's
  `try`/`catch`.
- The module cross-check no longer reports built-in kernel subsystems as hidden modules
  (`/sys/module` lists them, `/proc/modules` never does).
- Fileless evidence recorded `memfd_maps` as the last map field only, so paths in the
  report read `"(deleted)"`; the full path is captured now.

## [1.0.0] — untagged baseline

The runtime before the first tag: a purpose-made forensic language with a polymorphic
artifact format, fileless execution, a detection library that finds the same techniques, a
TLS management server and an evidence harness that measures the claims.

### Added

- **Language and VM** (`jocky/lang/`) — hand-written lexer → recursive-descent parser →
  bytecode compiler → stack VM. `let`/`set`, `if`/`elif`/`else`, `while`, `for … in`, `fn`
  declarations and lambdas, closures with shared mutable capture, `try`/`catch`, string
  interpolation, lists and maps, member/method dispatch, and `emit` for structured
  findings. The VM enforces step, wall-clock and call-depth budgets; hitting one raises an
  uncatchable `JockyLimitError` and marks the result truncated.
- **Polymorphic encoder** (`jocky/poly/`) — per-build opcode permutation, local-slot
  remapping, per-constant encryption and splitting, junk insertion at statement
  boundaries, keystream-encrypted payload, random padding and an integrity footer.
- **Runtime collectors** (`jocky/rt/`) — process, network, filesystem and system views read
  straight from `/proc`, `/proc/net` and `/sys`, exposed as arity-checked natives in the
  `proc`, `net`, `fs`, `sys`, `det`, `ioc` and `mem` namespaces. No external binary is
  spawned at any point.
- **Detection library** (`jocky/rt/detect.py`) — fileless processes, executable memfd
  mappings, deleted executables, execution from world-writable drop zones, rwx regions,
  unusual listeners, deleted-open files, `LD_*` injection, suspicious command lines, hidden
  kernel modules, hijackable `PATH` entries and persistence artefacts, each with a
  severity, evidence and a recommended action.
- **Execution modes** — `jocky run` (source), `jocky exec` (polymorphic artifact) and
  `jocky fileless` / `jocky memfd`, which write the interpreter, a zip of the package and
  the payload to memfds and exec `/proc/self/fd/<fd>`.
- **Management** (`jocky/agent/`) — TLS server with token auth and a sqlite job and finding
  store, plus a polling agent that executes jobs in-process and reports results back.
- **Evidence harness** (`jocky/evidence.py`) — build, run, footprint, audit-hook and
  detection measurements written as raw logs plus `evidence/report.md`.
- **Bundled scripts** (`scripts/*.jky`, `jocky/examples/*.jky`) — triage, hunt, inventory,
  timeline, watch, smoke and the harness script.

### Measured

These numbers come from `evidence/report.md`, produced by
`./venv/bin/python -m jocky evidence --iterations 1000` on the development host; each row
points at the raw log it was computed from.

| Measurement | Result | Raw log |
|---|---|---|
| Polymorphic builds of one script | 1000 builds → **1000 unique SHA-256**, 3625–4175 bytes, 296.0 builds/s | `polymorphism.csv` |
| Semantic equivalence of fresh builds | 25 rebuilt artifacts re-executed, findings hash identical to the reference run, **0 failures** | `runs.json` |
| Repeatability of one build | 1000 runs → **1 distinct findings hash**, 0 errors, median 16.121 ms, 55.2 runs/s | `runs.json` |
| Fileless process image | `/memfd:python3 (deleted)` with 4 memfd-backed mappings | `artifacts.json` |
| On-disk footprint | fileless run creates **0 files**; a cold source-mode run writes 74 bytecode-cache files | `artifacts.json` |
| Process telemetry during collection | **0 child processes, 0 execve, 0 write-mode opens** (405 read-mode opens) | `audit.json` |
| Self-detection | JOCKY's own triage reported the fileless job while it ran (`detected: true`) | `detection.json` |

### Limitations

Recorded with the baseline rather than discovered later, and expanded in
[Honest limits](/docs/security/limits): kernel-level telemetry still sees `memfd_create`,
`execveat` and the file reads; in-memory payloads remain visible in `/proc/<pid>/maps`
while they run — which is why the same runtime ships the detector; domain fronting
implements the client-side mechanics and needs a real CDN to mean anything; collection is
Linux-only.
