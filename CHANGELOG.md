# Changelog

All notable changes to JOCKY are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html) with an explicit
compatibility policy (see `docs/DESIGN.md` and the versioning page):

* **major** — the language, the artifact format or the management HTTP API
  changes incompatibly;
* **minor** — backwards-compatible features (new natives, new checks);
* **patch** — fixes only.

## [Unreleased]

### Added
- `--ndjson` on `run` and `exec`: findings stream as one JSON object per line with
  a summary line last. The `--json` path materialises every finding into a single
  document (a measured 300k-finding run costs ~400 MB and one giant `json.dumps`);
  NDJSON keeps memory flat.

### Changed
- `expect_throws(closure, label, substring)` can require the error text to
  contain `substring`: "something raised" is a weak assertion when the
  interesting part is *which* error came back. A mismatch reports the actual
  message (`raised 'division by zero', which does not contain 'modulo by zero'`).

### Fixed
- **A single long native could overrun the wall-clock budget silently.** The
  deadline was sampled only between VM steps, so `ioc.match(…, "/usr", 4000)`
  ran 380 ms under `--wall-ms 20` and still reported `truncated: false`. The
  deadline is now also checked when a native returns, so the overrun is reported
  as an uncatchable limit (measured: the same call now reports
  `truncated: true` at 97 ms instead of running to completion).

## [1.4.0] — 2026-09-15

### Added
- **`jocky test <dir>`** and five in-language assertion natives (`assert`,
  `expect`, `expect_throws`, `fail`, `skip`), so a `.jky` file can test its own
  behaviour: `jocky test tests/lang --sandbox=strict --json`. Checks are
  reported per file, failures keep the file running, and a budget-exhausted run
  is a failure rather than a passing expectation.
- A **conformance corpus** of 12 files and 456 checks in `tests/lang/`, covering
  arithmetic, strings, collections, control flow, functions, closures, the error
  model, types, the standard library, iteration, the capability posture and the
  collector contracts — written as invariants so it passes on any Linux host.
- `tests/test_language_conformance.py` pins that the corpus is green *and* that
  the runner fails loudly on a wrong expectation, a syntax error, an uncaught
  runtime error and a truncated run.

### Changed
- `list.sort()` and `list.reverse()` return new lists, matching the global
  `sort()` helper; `push()` and index assignment stay the only mutators. Sorting
  a collector's output for display no longer reorders the evidence in place.
- `float()` and `str.to_float()` are permissive like `int()`: unparseable text
  becomes `0.0` instead of raising, which is what a triage script wants when a
  log field is empty.
- `contains(needle, haystack)` now covers map keys, not just strings and lists.
- Member names may be keywords, so `m.set(...)` reaches the map method of that
  name (previously a parse error, which left that method unreachable).

### Fixed
- Confinement no longer breaks the runtime's own lazy imports: `--sandbox=strict`
  denied read access to the `jocky` package directory, so a script calling
  `mem.is_memfd()` died with `EACCES` on `jocky/exec/__init__.py`. The package
  directory is granted as a read root in every level.
- Sandbox `apply()` accepts `extra_read`/`extra_write`, so a caller that must
  keep reading after a ruleset is installed (the test runner reading its corpus)
  can say so.

## [1.3.0] — 2026-09-15

### Added
- `jocky serve --token-file` (and `JOCKY_TOKEN`), matching the agent: passing a
  token in `argv` exposes it to every local user through
  `/proc/<pid>/cmdline`, which is mode `0444` by default.

### Changed
- Agent state is owner-only: the state directory is created `0700` and
  `agent.json` plus `journal.jsonl` are `0600`. They hold the pinned server
  fingerprint and the job journal — provenance material, not public data.

### Fixed
- Documentation named the wrong syscall. `README.md` and the
  `jocky/exec/fileless.py` docstring said `execveat`; an independent ptrace
  counter showed `execve` 2, `execveat` 0, because the runtime calls
  `os.execve()` against `/proc/self/fd/<fd>`. The claim was right, the syscall
  name was wrong.

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
