# Changelog

All notable changes to JOCKY are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html) with an explicit
compatibility policy (see `docs/DESIGN.md` and the versioning page):

* **major** — the language, the artifact format or the management HTTP API
  changes incompatibly;
* **minor** — backwards-compatible features (new natives, new checks);
* **patch** — fixes only.

## [1.2.0] — 2026-09-15

### Added
- **Sandbox levels** (`--sandbox=off|vm|ro|strict`) implemented on Landlock
  through raw syscalls, standard library only. `vm` keeps writes inside the
  working directory and the drop zones; `ro` denies every write; `strict` also
  denies `socket(2)` with a seccomp filter. Verified in forked children: `/proc`
  and `/etc` stay readable, writes fail with `EACCES`, sockets with `EPERM`.
- `jocky doctor` reports Landlock availability and ABI (new *confinement*
  group), so "you are not sandboxed" is never a surprise.
- Zero-dependency documentation build (`site/tools/build_static.py`) for hosts
  without a JavaScript toolchain, and `site/tools/gen.mjs` so a docs build
  survives a builder image without Python.
- Documentation and installation site under `site/` (SvelteKit, prerendered),
  with reference pages generated from the source tree and releases generated
  from `git tag`.

### Fixed
- `CertificatePinError` was referenced in the agent client but never defined, so
  a pin mismatch raised `NameError` from inside `http.client` and escaped
  `client.run` instead of being reported as a trust failure.
- Landlock/seccomp syscall plumbing: attribute buffers were freed before the
  syscall ran (`EINVAL`) and `struct sock_fprog` was packed with the pointer at
  the wrong offset (`EFAULT`). Both are structure-level mistakes that made the
  sandbox silently unavailable.

## [1.1.0] — 2026-09-15

First publicly packaged release: the working forensic runtime from the initial
build, hardened against the findings of a 20-agent limitation and
state-of-the-art review, plus the documentation and installation site.

### Added
- `jocky doctor` — probes every prerequisite (procfs, memfd, direct syscalls,
  TLS, sqlite, fileless end-to-end) and prints the remediation for each failure.
- `jocky init` / `jocky examples` — scaffold a case directory with the bundled,
  runnable scripts (`triage`, `hunt`, `inventory`, `timeline`, `watch`).
- `jocky attest` / `jocky verify` / `jocky sign` — hash-chain manifest for case
  directories, with an off-host head anchor and an optional HMAC signature, so
  "a reviewer can re-check the logs" is a verifiable statement.
- `jocky build --deterministic --seed-hex …` — byte-identical rebuilds for
  provenance work (uniqueness stays the default).
- Documentation and installation site (`site/`): SvelteKit, fully prerendered,
  reference pages generated from the source tree (`site/tools/gen_reference.py`)
  and releases generated from `git tag` (`site/tools/gen_versions.py`).
- Installable package: `pip install .` provides the `jocky` console script;
  `Dockerfile` builds a minimal image that deliberately contains no `ps`/`ss`/`lsof`.
- `--allow syscall,exec` capability grants, `--pin`/`--verify-ca`/`--sni`/
  `--token-file` agent options, `--private` fileless mode.

### Changed
- **Privileged natives are deny-by-default.** `mem.syscall` and `mem.memfd_run`
  require an explicit `--allow` grant; research reproduced a live process kill
  through `mem.syscall(62, pid, 9)` and a shell escape through `mem.memfd_run`.
- **Agent TLS defaults to pinning.** The self-signed server certificate is
  fingerprinted at enrolment and enforced afterwards; `--insecure` is now
  explicit, prints a warning, and disables pinning.
- **Job results are authenticated.** `POST /v1/jobs/result` accepts only a
  known agent reporting on a job it claimed; replays are acknowledged
  idempotently without writing duplicate findings, everything else is 409.
  Jobs carry a `payload_sha256` that is echoed back with the result.
- State directory `0700`, `store.db` `0600`: findings are case material.
- `det.triage()` reports process-visibility coverage and emits a
  `partial_visibility` finding when part of the table is unreadable, so a blind
  scan cannot be mistaken for a clean host.
- Fileless mode requests `MFD_EXEC` where the kernel understands it (hardened
  hosts with `vm.memfd_noexec >= 1`), sets the process name, disables core
  dumps, and no longer writes bytecode caches.
- Documentation states the measured polymorphism ceiling honestly: builds are
  uniquely hashed, the statement-level control-flow graph is unchanged, and a
  standalone unpacker recovers the program in about a millisecond.

### Fixed
- The lexer crashed with `KeyError: ''` on a script ending in `0` (or `"{0}"`).
- The constant pool merged `1`, `1.0` and `true` into one entry, so a script
  could emit `false` where it wrote `0`.
- Unknown string escapes silently dropped the backslash, corrupting detection
  patterns such as `\d+`.
- `sys.users()` raised `KeyError: 'tty'`; `proc.io()` never returned counters
  because the path was a literal `"/proc/{pid}/io"`.
- Cross-frame error unwinding: an error raised inside a function bypassed the
  caller's `try`/`catch`.
- The module cross-check no longer reports built-in kernel subsystems as hidden
  modules (`/sys/module` lists them, `/proc/modules` never does).
- Fileless evidence recorded `memfd_maps` as the last map field only, so the
  paths read `"(deleted)"`; the full path is captured now.

## [1.0.0] — untagged baseline

### Added
- JOCKY language: lexer, recursive-descent parser, bytecode compiler and stack
  VM with closures (shared mutable capture), `try`/`catch`, string
  interpolation, map literals, and step/wall-clock/call-depth budgets.
- Polymorphic artifact encoder: opcode permutation, slot remapping, constant
  encryption and splitting, junk insertion, keystream payload, integrity footer.
- Forensic runtime: `/proc`, `/proc/net` and `/sys` collectors, detection
  library (fileless processes, memfd mappings, deleted executables, temp
  executables, rwx regions, unusual listeners, deleted-open files, `LD_*`
  injection, suspicious command lines, hidden modules, hijackable `PATH`,
  persistence), IOC correlation, direct syscalls, memfd primitives.
- Central management: TLS server with sqlite job/finding store, token auth,
  polling agent with a local journal.
- Evidence harness: 1000 builds → 1000 unique hashes, 1000 runs → 1 output
  hash, audit-hook telemetry (0 child processes, 0 write-mode opens), and a
  live fileless-detection proof. Results in `evidence/report.md`.

[Unreleased]: https://example.invalid/jocky/compare/v1.0.0...HEAD
[1.0.0]: https://example.invalid/jocky/releases/tag/v1.0.0
