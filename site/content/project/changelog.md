# Changelog

Notable changes to JOCKY, newest first, in Keep a Changelog form. The repository's `CHANGELOG.md` is the file of record; this page is the same history for the site.

The version string lives in `jocky/__init__.py`: `pyproject.toml` reads it dynamically,
`jocky --version` prints it, and the site builds its version banner from it and `git tag`.

```bash
$ ./venv/bin/jocky --version
jocky 1.6.1
```

Releases are annotated tags (`git tag -l` lists `v1.1.0` through `v1.6.1`); the
generated [releases page](/docs/project/releases) carries their commit ids and
notes, and [Versioning & releases](/docs/operations/versioning) explains the
compatibility policy. What is planned next is in the
[roadmap](/docs/project/roadmap).

## [1.6.1] — 2026-09-16

Fixes found by running the runtime against a **real Windows 11 host** rather
than the Linux stub-DLL simulation. The language and collection were correct;
the driver inventory, one ctypes call, and every path that assumed Linux were
not.

### Fixed
- **`winapi.modules()` returned no usable drivers.** `EnumDeviceDrivers`
  succeeds on Windows 10/11 while filling its buffer with zero base addresses
  for a non-elevated caller, and the name lookup then answers `ntoskrnl.exe` for
  every entry — 244 drivers, 0 distinct names. Every BYOVD check built on it
  would have been a blind scan that *looked* clean. Now uses
  `NtQuerySystemInformation`: same host, same token, 244 distinct names with
  real sizes and paths.
- **`winapi.list_processes()` failed with no arguments.** A
  `class _TOKEN_USER(Structure)` shadowed the `_TOKEN_USER = 1`
  information-class constant, so `GetTokenInformation` got a struct type where a
  DWORD belongs. A small `limit=` hid it; the default call raised.
- **`jocky build -o FILE --repeat N` wrote nothing** while exiting 0.
- **Non-Linux platforms raised host exceptions instead of reporting** —
  `os.uname()` and `ctypes.CDLL(None)` surfaced as `AttributeError`/`TypeError`
  in `jocky doctor`. Each Linux-only mechanism now names the platform.
- Windows crash-dump stack drivers (`dump_*.sys`) are resident with no image on
  disk **by design** (3 of 244 on a healthy host); graded `info`, not `high`.

### Added
- `byovd_deleted_driver_file` and a coverage finding naming the checks that do
  not apply on a platform.
- [Install guide](/docs/getting-started/installation) covering Linux, Windows
  and Docker, with a measured capability matrix.

### Verified on real Windows
```
process table (winapi)   231 process(es) via Toolhelp32 + NtQuerySystemInformation
network tables           135 socket(s) via GetExtendedTcpTable/GetExtendedUdpTable
kernel drivers           244 (244 distinct names)
script -> artifact -> executed from artifact, 0 errors
jocky ci                 64 builds -> 64 unique hashes, 0 mismatches
```

## [1.6.0] — 2026-09-16

Closes the remaining SIH26148 deliverables: the automated CI/CD pipeline
(pillar 2), BYOVD/kernel integrity (pillar 3), the web management console
(pillar 4) and Windows collection (deliverable 1), on top of a security and
robustness pass. The repository's `CHANGELOG.md` carries the full itemised list;
this is the summary.

### Added — SIH26148 pillars
- **`jocky ci` + `.github/workflows/polymorphism.yml`** — the automated
  polymorphic pipeline. Builds 256 artifacts per push, fails on any hash
  collision, and re-executes a sample to compare findings against a source run,
  so uniqueness cannot drift from semantics. Measured: 256/256 unique, 0
  mismatches, ~508 builds/s.
- **`jocky/rt/byovd.py`** — kernel-module integrity: a curated 20-entry
  abused-driver list (Linux CVEs verified against the CISA KEV feed), the
  out-of-tree/unsigned/force-loaded taint classes, modules loaded long after
  boot, modules whose backing `.ko` was deleted, and the global taint bits.
  Read-only by design. New natives `det.byovd()`, `sys.taint()`,
  `sys.module_integrity()`, `sys.vulnerable_drivers()`.
- **The web console** at `GET /` — fleet status, job queue, findings with
  severity filters, job submission. One self-contained document: no CDN, no
  build step, CSP `default-src 'none'`, DOM built with `textContent`.
- **`jocky/rt/winapi.py`** — Windows collection through pure `ctypes`, emitting
  the same key names as `procfs`/`netfs`. No `tasklist`, `netstat`, `wmic` or
  PowerShell.
- **`scripts/solutions/07_byovd_kernel_integrity.jky`** and
  **`scripts/quickstart.jky`**.

### Security
- Hard allocation caps in the VM (`MAX_COLLECTION_SIZE`), the pattern engine
  (`MAX_REPEAT`) and the artifact reader (`_MAX_COLLECTION_ITEMS`), each closing
  a vector where the *input* decided the allocation size.
- Per-IP rate limiting on server auth failures; job `kind` validated at submit
  time; CSP/nosniff/no-referrer on the console.

### Changed
- `pyproject.toml` `Source`/`Issues` point at the real repository.
- `__version__` is now `1.6.0` — `v1.5.0` had been tagged while `__version__`
  still said `1.4.0`.

## [1.5.0] — 2026-09-15

### Added
- **Sigma rules run as written** (`sigma.check`/`sigma.summary`, `jocky sigma <rule> <input>`):
  a documented YAML subset — `contains`/`startswith`/`endswith`/`re`/`all`/`cased`/`base64`
  modifiers, wildcards, `and/or/not`, `N of them`, `1 of selection*` — evaluated on
  the linear-time engine. The engine that normally runs Sigma (Python `re` in
  Zircolite, .NET regex in Chainsaw/Hayabusa) backtracks: a rule containing
  `(\w+\s?)+whoami` against a crafted 80 KB log line was **still running after
  20 s** there and answers in **745 ms** here, and the step budget bounds even
  that. Unsupported constructs (`|cidr`, correlation rules, aggregations) are
  refused by name rather than half-applied.
- **YARA-subset signatures** (`yara.check`/`yara.summary`, `jocky yara <rule> <file>`):
  hex strings with `??`/`?A` wildcards, `[n-m]` jumps and `(a | b)` alternatives,
  text strings with `nocase`/`wide`/`ascii`/`fullword`, regex strings, and the
  `any/all/N of them`, `$a at N`, `filesize` conditions — over byte strings from
  `fs.read_bytes`. `xor`, `base64`, the module functions (`uint16(0)`, `pe.*`), `for` loops
  and `~` (not-byte) are refused by name.
- **Correlation primitives**: `index_by(rows, key_fn)` and `group_by(rows, key_fn)`
  — the one-pass index that turns a nested-loop join into a lookup (VQL's
  `memoize`, osquery's join), so process↔socket↔file correlation is O(n+m).
- `fs.strings(path, min_len?, limit?, offset?, wide?)` — printable runs with
  offsets, including UTF-16LE (`wide=True`), which a plain ASCII scan misses;
  and `fs.entropy(path, offset?, limit?)` — the "is this packed?" signal, with a
  `packed_likely` hint that is explicitly a hint, not a verdict.
- `fs.grep_stats(...)` returns `{matches, lines, scanned_bytes, truncated}` so
  "no match" is distinguishable from "the walk stopped".
- `fs.read`/`fs.read_bytes` take an explicit ceiling (256 MiB) instead of letting
  the script pick an allocation size.

### Changed
- **`--ndjson` streams for real.** Findings are handed to a sink as they are
  emitted (`VM(emit_sink=…)`) instead of being accumulated and printed after the
  run: 150,000 findings went from 56.6 MB to **20.9 MB peak RSS**, flat in the
  finding count. `result.finding_count` reports the total either way.
- **`--stamp-findings` anchors streamed findings too** (one timestamp per run,
  applied in the sink), and now covers `fileless`/`memfd`.
- Confinement reads include the drop zones (`/tmp`, `/var/tmp`, `/dev/shm`):
  that is where dropped payloads live, and denying triage scripts access to them
  hid the artefacts the run exists to find. Reading them widens no privilege.
- The evidence chain no longer skips `.git` or `__pycache__` implicitly: a
  planted `.git/hooks/post-checkout` was invisible to `attest` **and** to
  `verify`'s added-file check, so a directory that verified clean could carry a
  payload that runs on the analyst's next `git` command. Unwanted subtrees are
  excluded explicitly via `exclude=` and reported, never silently dropped.
- `fs.read` on an unreadable path **raises** instead of returning
  `<unreadable: PermissionError>`: a detection script treated that marker as
  content, so a confined run reported a clean sweep where it was blind.
- **`det.triage()` collects `/proc` once.** Each check walked the process table
  on its own — five sweeps of the same data per run. A shared snapshot now
  serves every check (measured on the development host: 752 ms → 290 ms
  internal, 0.63–0.90 s → 0.29–0.42 s wall, with identical checks, severities
  and counts). Each check is still callable on its own and collects its own
  minimum when run without a snapshot.
- **The `$PATH` audit does one pass per entry.** It resolved every entry with
  `realpath` (six bridge round trips per `/mnt/c` entry under WSL), worked
  duplicate entries twice, and re-read `/proc/mounts` for every fstype lookup.
  Entries on a filesystem without POSIX mode bits are no longer resolved, since
  their verdict cannot change: 591 ms → 89 ms on the development host, same
  findings.

### Fixed
- **A pattern repeat count could hang the compiler forever.** `(?:){1000000000000000000}`
  (or the same inside an untrusted Sigma rule) looped the attacker's count over
  an empty body — invisible to the instruction-count bound because nothing was
  emitted. Repeats are now bounded like the program is, and an empty-bodied
  repeat is a no-op. All oversized counts raise in under a millisecond.
- **Zero-width matches deleted text** in `re.replace`/`re.split`:
  `re.replace(r"\s*", "a b c", "")` returned the empty string (host `re`: `abc`)
  and `re.split("", "ab")` returned `['', '', '', '']` (host: `['', 'a', 'b', '']`).
  Both now agree with the host engine on every shape tested.
- **Back-references compiled to literal digits**: `(\w+)-\1` matched `a-1` and
  never `a-a`. `\1`…`\9` now raise the documented offset-bearing error.
- `list.unique()` stringified its results, so `[1, 2, 1].unique()[0] + 1` was
  `"11"`: values keep their types now, maps/lists dedupe by value.
- `tl.merge` defaulted to sorting by `time`, while findings carry `ts` — the
  documented correlation recipe silently returned rows in input order. It now
  picks `ts` when the rows have it.
- `\B` matched at position 0 of an empty text where the host engine reports no
  boundary.
- `fs.grep` built a whole record before applying its byte cap (a 500 MB line cost
  1 GB of RAM) and never returned on a stream with no newline; long lines are now
  matched on their first MiB and the walk stops at the cap (with `truncated`
  reported), and the long natives check the wall-clock deadline every chunk.
- A single multiplication could burn minutes under a wall-clock budget
  (`x = x * x` in a loop: 255 s under `--wall-ms 2000`): integer results are
  capped at 65,536 bits, far above any forensic arithmetic and reported as a
  catchable error.
- Crafted artifacts with out-of-range operands (`JMP -1` wrapped to the last
  instruction and spun out the step budget; `MK_FN 1e9`, `CONST 99`) surfaced
  host `IndexError`s; they are now refused at decode as `JockyArtifactError`.
- The sandbox report claimed path rules it had not installed (a missing path was
  silently skipped but still listed); skipped rules are reported separately as
  `rules_skipped`.
- Error messages no longer leak host type names (`cannot compare nil < int`, not
  `NoneType`).
- **Pattern matching (`re`) and log searching (`fs.grep`)**, on JOCKY's own
  linear-time engine rather than the host's backtracking one. Detection matches
  attacker-authored text, so `(a+)+b` against 20,000 `a`s is a live concern:
  it answers in ~50 ms here and does not finish at all under Python's `re`.
  `re.test/full/find/captures/replace/split/escape` cover the subset that can
  be matched in `O(len(text) × len(pattern))`; lazy quantifiers,
  back-references and look-around are rejected with the offset in the message,
  never silently reinterpreted. Correctness is pinned by differential testing
  against `re` — 8,000+ comparisons of both the verdict and the match span —
  and the documented semantics: matching is leftmost-longest, and `\w` is ASCII.
- **Raw strings (`r"…"`)**: no escape decoding and no interpolation, so
  `r"^\d{2}:\d{2}$"` is the pattern character for character. A repeat count in
  a normal string is read as interpolation, so `"\d{2}"`-style patterns either
  needed escaping or failed to parse.
- **`time` and `tl` namespaces**: UTC `parse`/`iso`/`format`/`filetime`/`delta`
  and event-timeline `merge`/`window`/`bucket`, with `nil`/row-preserving
  degradation on unparseable input.
- **Byte-level reads**: `fs.read_bytes(path, offset?, limit?)` returns a
  latin-1 *byte string* — one character per byte, a bijective mapping, so
  nothing is dropped or replaced the way `fs.read`'s UTF-8 `errors="replace"`
  decode drops it — and `fs.hash_bytes_raw` digests exactly those bytes
  (`fs.hash_bytes` keeps its UTF-8 semantics for text a script built itself).
  `fs.read` gained an optional third argument, `offset`, so a large text file
  can be paged. Binary scanning is now a script concern, not a native one:
  `re.test(r"\x7fELF", fs.read_bytes(path, 0, 4))`.
- **`\xNN` escapes in patterns**, with class ranges decoding both endpoints
  (`r"[\x00-\x1f]+"`), plus `\0`, `\a`, and `\b` as a backspace inside a class.
  An unknown *letter* escape (`r"\q"`) is now an error instead of a literal `q`,
  matching Python's `re`: a typo that silently matches nothing is the worst
  failure mode a detection rule can have.
- **`ord()` and `chr()`** — the bridge between a character and its code point,
  which is also the bridge between a byte string and the byte values in it:
  `ord(fs.read_bytes(path, 0, 1))` is the first byte as a number, `hex(ord(b))`
  renders it, and `chr(0x7f)` builds byte strings in script. Byte scans written
  before this had to search a 256-character alphabet for a character's position.
- `procfs.list_processes(detail_limit=…)` applies the expensive fields (`fds`,
  `maps`, `environ`) to the first *N* processes only, so a bounded sample of
  deep state no longer costs a deep read of every process on the host.
- **`--stamp-findings` on `run`, `exec`, `triage`, `fileless` and `memfd`** adds
  a `ts` (epoch seconds) to every finding map that lacks one, so a run can be
  correlated with journald/auditd output instead of being a timeless list —
  `time.iso(f.ts)` renders it and `tl.merge` puts it on one timeline with parsed
  log lines. Only maps are stamped, a script's own `ts` always wins (it knows
  when the event happened; the runner only knows when it collected), and every
  finding of a run shares the collection moment.
- An optional Pygments lexer (`jocky[pygments]`, entry point `jocky`) for
  editor highlighting, plus a grammar-aware fuzz harness (`tests/fuzz_language.py`)
  that runs generated programs through the full pipeline.
- **Deeply nested source no longer escapes as a host exception.** The recursive
  descent parser and the expression compiler had no limit of their own, so
  `"(" * 200 + "1" + ")" * 200`, a 600-link method chain or 200 nested
  `{interpolations}` raised the interpreter's `RecursionError` out of
  `compile_source` — a traceback instead of a diagnostic, reachable from any
  script or artifact source. Both phases now report their own limit
  (`JockySyntaxError`/`JockyCompileError`, "nests too deeply"), with the shapes
  pinned in `tests/test_language.py` and in the fuzz harness's defect recipes.
  Found by the grammar-aware fuzzer (`tests/fuzz_language.py`), which produced
  no other host-level exception in 23,000 generated programs.
- `_mount_table()` re-read and re-sorted `/proc/mounts` on **every** fstype
  query; it is now parsed once per process (`filefs.reset_mount_cache()` for
  callers that mount something mid-run).
- `expect_throws(closure, label, substring)` can require the error text to
  contain `substring`: "something raised" is a weak assertion when the
  interesting part is *which* error came back. A mismatch reports the actual
  message (`raised 'division by zero', which does not contain 'modulo by zero'`).
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

[Unreleased]: https://github.com/Pamure/jocky-forensics/compare/v1.5.0...HEAD
[1.5.0]: https://github.com/Pamure/jocky-forensics/releases/tag/v1.5.0
[1.4.0]: https://github.com/Pamure/jocky-forensics/releases/tag/v1.4.0
[1.3.0]: https://github.com/Pamure/jocky-forensics/releases/tag/v1.3.0
[1.2.0]: https://github.com/Pamure/jocky-forensics/releases/tag/v1.2.0
[1.1.0]: https://github.com/Pamure/jocky-forensics/releases/tag/v1.1.0
[1.0.0]: https://github.com/Pamure/jocky-forensics/releases/tag/v1.0.0
