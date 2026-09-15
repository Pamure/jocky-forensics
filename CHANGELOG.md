# Changelog

## Unreleased — hardening pass

### Security
- `jocky/lang/vm.py`: hard cap `MAX_COLLECTION_SIZE = 10_000_000` on string/list concatenation, string/list repetition, and `MK_LIST`/`MK_MAP` counts. Closes an unbounded-allocation vector (`"a" * 10**9`).
- `jocky/rt/pattern.py`: hard cap `MAX_REPEAT = 100_000` on `{n}`/`{n,m}` quantifier bounds at compile time. Turns a crafted pattern into a clear error instead of a step-budget exhaustion.
- `jocky/rt/filefs.py`: `scan()` refuses to walk the pseudo filesystems (`/proc`, `/sys`, `/dev`, `/run`) *when passed as the root*, so a script that mistakenly scans them gets a diagnostic rather than a silent zero-finding run. Drop zones (`/dev/shm`, `/tmp`, `/var/tmp`) are still scanned — the previous prefix-based guard over-blocked them.
- `jocky/poly/wire.py`: `Reader.count()` now also enforces `_MAX_COLLECTION_ITEMS` on top of the remaining-bytes check, so a crafted artifact cannot claim millions of items even when the buffer is huge. `Reader.blob()` enforces `_MAX_FIELD_SIZE`.
- `jocky/agent/server.py`: token comparison reviewed end-to-end — only `hmac.compare_digest` is used. Added per-IP rate limiting: `MAX_AUTH_FAILURES = 10` failed auths in `AUTH_WINDOW_SECONDS = 60` returns `429 Too Many Requests` before the token is touched.
- `jocky/sandbox.py`: `apply()` rejects an unknown level with `ValueError` naming the valid choices.

### Robustness
- `jocky/rt/filefs.py`: `grep_file()` deadline check now runs every 1000 lines inside the inner split loop, and any line longer than `MAX_LINE_BYTES` is truncated before matching — a single very long line no longer bypasses both the byte cap and the wall-clock budget.
- `jocky/rt/procfs.py`: `read_fds()` distinguishes `PermissionError` (root-owned process), `FileNotFoundError` (process vanished), and other `OSError`s, and never propagates them out of a `/proc` walk.
- `jocky/rt/netfs.py`: `_read_unix()` wraps each row parse in `try/except`, so one malformed line does not abort the table read.
- `jocky/rt/detect.py`: `triage()` deduplicates findings sharing `(check, evidence.pid)`, keeping the highest-severity instance. Overlapping process checks no longer report the same pid twice.

### Usability
- `jocky/cli.py`: `run`, `exec`, `build`, `triage`, `evidence`, and `attest` subcommands gained worked examples in `--help`.
- `scripts/quickstart.jky`: a fully commented tour of the language and every forensic namespace, runnable end-to-end in all four modes (`run`, `exec`, `fileless`, `--ndjson`).

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

[Unreleased]: https://example.invalid/jocky/compare/v1.0.0...HEAD
[1.0.0]: https://example.invalid/jocky/releases/tag/v1.0.0
