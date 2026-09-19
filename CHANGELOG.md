# Changelog

## [1.8.0] — 2026-09-18

Closes the four measurable pillar gaps from the problem statement with working
code, keeping the project's rule intact: every claimed number below is produced
by a command in this release and re-verified by the suite.

### Pillar 1/2 — native executable output, altered per build (new: `jocky/native/`)
- `jocky/native/emit_elf.py` emits real **ELF64 x86-64 executables** from a seeded
  build descriptor: `jocky build --target native`. Hand-assembled syscall stub
  (`write`, `exit` — raw `syscall` instructions, no libc), two `PT_LOAD` program
  headers, **no `PT_INTERP`/`PT_DYNAMIC` and an empty import list** — the honest
  ELF reading of "altered import table": there is nothing to match. `.text` lands
  on a per-build page (`0x400000 + 0x1000·(seed[0] mod 64)`), so the entry point
  varies across builds.
- `jocky/native/runner.py`: `jocky exec image.native` recovers the embedded
  artifact and runs it in the existing VM. The stub proves the container; scripts
  still execute in bytecode (AOT native codegen is the open remainder, stated in
  the module docstring, not implied).
- Measured: **64 seed-distinct builds → 64 unique SHA-256 and 64 distinct entry
  addresses; all 64 execute on the host (exit 0, marker printed)**; tampered
  entry point → nonzero exit; `read_artifact` round-trips exactly; non-native
  blobs rejected with `ValueError`, never a `struct.error`.

### Pillar 1 — per-build token generation (new: `jocky/poly/sourcemut.py`)
- `jocky build --alias-tokens` rewrites every keyword spelling from a
  seed-derived alias table before compile; `jocky.lang.Lexer` gained an optional
  `keyword_table` (canonical keywords always win; strings, raw strings, comments
  and interpolation bodies are never touched).
- Measured: **38 library scripts × 3 seeds = 114 mutated runs, every one**
  compiling to a byte-identical `Program` and running clean (no errors, not
  truncated); without the table the changed source is rejected by the parser;
  an alias colliding with an existing identifier is refused with a named seed.

### Pillar 3 — the harness the offensive techniques must live in (new: `jocky/lab/`)
- `HarnessGuard`: spawns targets itself, and `assert_owned(pid)` accepts only
  self, harness-spawned children, or own ancestors, validated via a `/proc` ppid
  walk — every other PID, including the harness's *previous* children after
  cleanup, is refused. Offensive entry points route through it. Windows
  techniques (`hollow_process`, `reflective_load`, `hijack_thread`,
  `byovd_probe`) raise `LabRefusal` on Linux unconditionally, and on Windows
  until the Hyper-V Phase-0 test-signing VM is attached; no silent success.
- `jocky/lab/byovd.py` ships only the authored test-driver *contract*
  (`jockyprobe.sys`, one echo IOCTL, testsigning requirements) — nothing loads
  or modifies any module.
- Measured: 22 tests, incl. guard parity (own child accepted, foreign PID
  refused, double cleanup idempotent) and an end-to-end fileless run under the
  guard. Zero stray processes/directories after the suite.

### Pillar 4 — trusted-channel transports, proven on loopback (new: `jocky/agent/channel/`)
- `dns_txt.py`: RFC-1035 DNS over UDP with stdlib `socket`+`struct` only —
  base32 job polling, base64 TXT answers, a 421-byte payload with **no 8-byte
  window of plaintext on the wire**.
- `ws_relay.py`: RFC-6455 websocket relay, hand-rolled handshake, mandatory and
  verified client masking; streamed **1 GiB in 16,385 frames** with the SHA-256
  asserted server-side; close handshake with status 1000.
- Both bind `127.0.0.1` only and refuse non-loopback binds. Attaching a real
  DNS zone / CDN websocket endpoint is operator-side and documented, not coded.

### Tests
- New: `tests/test_native.py` (9), `test_token_mutation.py` (11),
  `tests/test_lab.py` (22), `tests/test_channels.py` (9). One integration fix
  the wiring exposed: `runner.compile_source`/`build_artifact` now accept and
  forward `keyword_table` to the lexer.

## [1.7.1] — 2026-09-17

Closes every finding from an adversarial audit of the two newest runtime
modules (`docs/AUDIT-2026-09-17-runtime-modules.md`): **9 in `jocky/rt/pcap.py`, 6 in
`jocky/rt/winject.py`** — two of them high-severity correctness defects that
fabricated data rather than merely omitting it.

Every fix carries a regression test, and **every regression test was shown to
fail against the code as audited** by reverting that fix in place and
re-running: 11 of 11 `pcap.py` reverts and 5 of 6 `winject.py` reverts produced
the expected failure. The sixth — the 32-bit address-space ceiling — cannot be
falsified on a 64-bit host, and its test says so rather than pretending.

### Fixed — `jocky/rt/pcap.py`
- **IPv6 fragment offsets were read from the wrong field (high).** The fragment
  header is `(next_header, reserved, offset_flags, identification)`, and the
  parser read `header[3]` — the *identification* — as the offset word. A
  non-first fragment whose identification happened to land the misread on zero
  was treated as a first fragment, and **TCP/UDP ports were decoded out of raw
  fragment bytes**. The audit's repro decoded `fragment_offset=11206656` for a
  real offset of 800, and produced `src_port=443 dst_port=1337` from a
  continuation fragment that carries no transport header at all. Now reads
  `header[2]`, masked to the 13-bit field the format defines, and keeps the
  identification as its own key.
- **A second pcapng section inherited the first section's interface table
  (high).** Interface IDs restart at every Section Header Block, and the reader
  never reset them. A merged capture — a routine artefact — decoded every packet
  of section 2 against section 1's linktype *and* its `if_tsresol`, moving every
  timestamp silently. `result["interfaces"]` is now scoped per section.
- **A SHB declaring `block_length` 12–15 crashed the reader (high).**
  `struct.error: unpack requires a buffer of 4 bytes` escaped from a module whose
  contract is "malformed blocks are recorded, never raised" — one corrupt SHB
  mid-file killed the entire read. The guard now applies the SHB's real 28-byte
  minimum (16–27 were silently accepted before), and the *opening* SHB's trailing
  length is now compared against its header value like every other block's.
- **`snaplen = 0` emptied every Simple Packet Block.** Zero means *no limit*, not
  *capture nothing*; a whole capture read as empty frames.
- **`live_capture` raised instead of reporting.** Binding a missing interface let
  `ENODEV` escape past a `try` that had only a `finally`; a negative `snaplen`
  raised `ValueError` out of `recv`, a type the loop's `except OSError` never
  caught; and `snaplen = 0` made `recv(0)` return instantly, spinning the loop at
  ~478,000 calls in 0.2 s. The snaplen is normalised, the bind is guarded, and
  the adjustment is recorded in `snaplen_adjusted_from`.
- **JA3 fingerprints carried GREASE.** RFC 8701 values are randomised per
  connection, so leaving them in made the hash unique to that one handshake —
  and matched nothing in any threat-intel feed, which is the field's entire
  stated purpose. Filtered now, from all four lists.
- **A request with headers over 64 KiB vanished with no marker.** The request
  line matched, the terminator search hit its cap, and the request *and the rest
  of the stream* were dropped. Now emitted with `headers_truncated: True`.
- **The obsolete Packet Block reported its claimed length, not the truth.** It
  now mirrors the EPB path: actual bytes decoded, plus a truncation marker.
- **Live-captured packets carried no `incl_len`.** `flows()` billed file traffic
  by wire bytes and live traffic by payload bytes, so one flow read 42 bytes from
  a file and 0 from a capture of the same traffic.

### Fixed — `jocky/rt/winject.py`
- **`unbacked_executable_threads` swallowed its own `skipped` list (high).** The
  detector built the rows — including the "module map incomplete" refusals its
  own comments call load-bearing — and then called `_partial_finding` without
  them. Those processes disappeared and the sweep returned `[]`, which reads as
  *clean*. The three sibling detectors all passed `skipped`; this one now does.
- **A failed process snapshot was a silently clean sweep (high).** All four
  detectors resolved names from `_snapshot_processes()`; when it returned `[]`
  they targeted nothing and returned `[]` — while on the measured non-elevated
  host 140 of 254 processes were denied. "Nothing found" and "nothing seen" now
  differ: a failed snapshot emits `partial_visibility` with
  `snapshot_failed: True`.
- **Entry-point severity was decided by whichever *other* section was noisiest.**
  Grading followed the single highest-ratio section, so a >5% rewrite of the
  entry-point section was graded `info`/`section_content` whenever `.rdata` had
  been churned harder — and this module's own measurement puts healthy `.rdata`
  at up to 70%. The entry-point section is now tested first, on its own ratio.
- **`_regions` never returned `None`,** contradicting its docstring and leaving
  two callers' branches dead: a first-query refusal was downgraded from a denial
  to a "truncated walk" skip whose recorded error was dropped. It now returns
  `None` when not one region was readable.
- **The address-space ceiling was the x64 constant on every build.** Under a
  32-bit interpreter the walk stepped past the real 0x7FFF0000 ceiling, every
  query failed, and *every* process reported a truncated walk. Derived from
  pointer size now, mirroring the `_MEMORY_BASIC_INFORMATION` choice.
- **`_BOUND` was set before `_bind` ran.** One missing export left the flag
  `True`, so every later call skipped binding and ran with undeclared prototypes
  — 64-bit handles truncated at the call site, nothing pointing at the cause.

### Tests
- `tests/test_pcap_audit_fixes.py` (new, 17 tests) and 10 new regression tests in
  `tests/test_winject.py`. Every one fails against the audited code — verified by
  reverting each fix individually — and each asserts observable behaviour (a
  decoded offset, a graded severity, a reported gap), not the implementation.
- Full suite: **676 passed, 1 skipped**.

### Fixed — a flaky CI gate
- `tests/test_poly.py::test_indirect_jumps_compute_their_target` seeded the encoder
  from `os.urandom` and then asserted a **floor** on how many indirect jumps the
  builds happened to contain. Jump indirection is applied with probability `rate`
  per candidate site, so the total was a random variable: measured over ten runs it
  ranged **8..16**, and the assertion was `>= 8`. The gate failed on a low draw —
  observed once in this session — which is a coin flip, not a signal. The test now
  seeds each build from `sha256("<program>:<index>")` with `deterministic=True`, so
  the coverage is reproducible (**13 sites**) while every structural assertion still
  runs against a real encoded artifact. Verified 20/20 runs green.

### Housekeeping — the repository said things that were no longer true
- **Removed the static documentation site.** `site/` was a SvelteKit app whose
  markdown content was the real documentation; the content moved to `docs/`
  (`language/`, `runtime/`, `security/`, `operations/`, `execution/`, plus
  `docs/ARCHITECTURE.md`) and the build machinery — `node_modules`, Svelte
  components, layouts, routes, `package.json` — was deleted. Nothing in the tree
  was consuming it.
- **Fixed the fallout from that move**, because the site was load-bearing in ways
  that were not obvious: 66 links written as site-absolute slugs (`/docs/language/…`)
  are now relative paths that resolve on the repository host; five "generated — do
  not edit by hand" banners pointed at a generator that no longer exists and told
  the reader *not* to maintain the page, which is the opposite of true; the
  versioning page documented a version generator in full; `pyproject.toml`
  advertised the deleted site as its `Documentation` URL; the Pygments lexer's
  metadata did too. All corrected, and a link check over 31 files resolves every
  relative link.
- **Deleted the working-directory residue**: a Windows NTFS alternate-data-stream
  artefact tracked as a literal file (`GUIDE.md:Zone.Identifier`), a 13-line ad-hoc
  probe (`memprobe.py`), and two internal notes (`adviceFORyou.md`,
  `knowledge.md`). `.gitignore` now covers `*:Zone.Identifier` so it cannot come
  back.
- **`CONTRIBUTING.md` claimed "no CI configuration in the tree, no workflow files"**
  while `.github/workflows/polymorphism.yml` was running the suite on every push.
  It also stated that tests validate the reference pages; they do not. Both fixed.
- **`README.md` now discloses the two requirements it did not implement**, in the
  limits section rather than only in the evidence ledger: an artifact is bytecode,
  not a PE/ELF, so pillar 2's "dynamic entry-point alterations" and "altered import
  tables" have no subject; and the offensive half of pillar 3 (process hollowing,
  reflective DLL injection, API unhooking, thread hijacking, BYOVD exploitation) is
  absent by decision — the repository detects those techniques, it does not perform
  them. The absence of an LLVM frontend (the pillar's alternative is taken) is
  stated too.
- **Kept deliberately**: `research/`. It is not residue — 13 citations in the
  documentation and 4 in the source point into it, and `docs/project/roadmap.md` is
  a synthesis whose every item names the report it came from. Deleting it would have
  left those citations dangling and removed the provenance for the security posture.

## [1.7.0] — 2026-09-16

Closes the remaining gaps against the SIH26148 deliverables: a **comparative
evasion evaluation** (deliverable 5), **network forensics** (the "network" half
of the problem title), **control-flow obfuscation** (pillar 2's "alter basic
control-flow graphs"), and **Windows injection detection** (pillar 3 on the
platform where those techniques dominate). Also fixes a language bug that turned
a nested `break` into an infinite loop.

### Added
- **`docs/EVASION.md` — the comparative evasion evaluation.** Microsoft
  Defender, signature `1.459.226.0`, real-time protection on: 29 polymorphic
  artifacts scanned clean, zero detections across artifact execution and a full
  collection run that opened 254 processes. Both harnesses carry an **EICAR
  positive control that was detected**, so "clean" is a result rather than a
  broken test. The report also records what was *not* tested (other vendors,
  kernel telemetry, network inspection) and a measurement that was discarded as
  unreliable — see the AMSI section, where a direct `AmsiScanBuffer` probe
  returned NOT_DETECTED for known-malicious strings and was therefore not used
  as evidence.
- **`jocky/rt/pcap.py` — offline network forensics.** libpcap (both endiannesses,
  microsecond and nanosecond) and pcapng readers, packet decoding across
  Ethernet/IPv4/IPv6/TCP/UDP/ICMP, bidirectional flow reconstruction, DNS query
  extraction (with bounded compression-pointer following), TLS ClientHello SNI +
  JA3 fingerprints, and cleartext HTTP request parsing. Exposed as the `pcap`
  namespace; playbook at `scripts/solutions/08_network_capture_analysis.jky`.
  Fuzzed with **304,000 entry-point calls over random and mutated input, zero
  exceptions** — malformed content is reported in-band, never raised.
- **Control-flow obfuscation** in `jocky/poly/encoder.py`: branch inversion,
  opaque predicates, unreachable dead-code injection and **true jump
  indirection**, all spliced through the existing index-remapping machinery.
  Measured: **64 builds → 64 distinct control-flow signatures** (was 1), at +34%
  artifact size, with the CI gate still passing 128/128 unique and 0 mismatches.

  Jump indirection needed a new opcode. `JMPI` pops its destination from the
  operand stack, so the encoder can rewrite `JMP t` as
  `CONST a; CONST b; ADD; JMPI` with `a + b == t`: the target is *computed*, not
  read, which is what the technique means. Verified independently — 32 builds
  produced **239 `JMPI` sites, every one shaped `CONST/CONST/ADD/JMPI`**, none
  carrying an operand. `JMPI` was appended to the end of `OPCODES` rather than
  slotted with the other branches, because the canonical wire format numbers
  opcodes by position and inserting mid-tuple would silently renumber images
  written by earlier builds.

  The transform also has to run **after** every pass that shifts instruction
  indices, which the CI gate caught: the destination is a pool value rather than
  a remappable operand, so leaving it inside the earlier control-flow pass
  produced `7 mismatch(es)` and an `IndexError`. It now sits immediately after
  `_insert_junk`.
- **`jocky/rt/winject.py` — Windows process-injection detection.** Process
  hollowing (mapped image vs file on disk), private executable memory,
  unbacked thread start addresses, and modules loaded from temporary paths. This
  is the **detection** half of pillar 3; the execution half remains out of scope
  by design (`docs/DESIGN.md` §10).
- `docs/VERIFY.md` — five manual tests, one per claim, with the numbers measured
  on Windows 11 and Linux.
- `docs/INSTALL.md` — install guide for Linux, Windows and Docker, with a
  measured platform capability matrix.

### Fixed
- **`break` inside a nested `for` was miscompiled into an infinite loop.** `for`
  leaves its iterator on the operand stack and `ITER_NEXT` pops it on exhaustion;
  `break` emitted a bare `JMP` and never popped, so the enclosing loop's
  `ITER_NEXT` found the *inner* iterator, rebound the outer variable to inner
  values, and never terminated. Found by writing real scripts, not by a test.
  Three regression tests added, including the mirror case (`while` inside `for`,
  which must *not* pop).
- **`winject` flagged normal processes.** Measured on a healthy Windows 11 host,
  the hollowing check produced **107 high-severity findings** — `brave.exe`,
  `RuntimeBroker.exe`, `taskhostw.exe` — because `ImageBase` is rewritten by the
  loader under ASLR, so every relocated process "differed". With that field
  excluded, the remaining differences were section bytes the loader writes
  (`.fptable`, `fothk`, `.rdata`, `.idata`) at a median of 1% per process, so
  content-only mismatches now grade `info` and only the structural classes keep a
  severity. Private-executable-memory findings grade `medium` only when the
  region carries a PE header — all 41 on that host were V8's JIT heap.
- **`jocky doctor` called a working Windows install "NOT ready".** Two
  Linux-only mechanisms were reported as failures. Added a not-applicable status:
  `ready: 7 ok, 2 warning(s), 0 failure(s), 4 not applicable on this platform`.
- `sys.uptime()` returned **0 seconds** on Windows (`/proc/uptime` does not
  exist); it now reads `GetTickCount64` through the platform backend.
- `07_byovd_kernel_integrity.jky` reported a clean Windows host as
  kernel-tainted: `sys.taint()` returns `nil` there and `nil != 0` is true.

### Changed
- **Domain fronting is no longer claimed.** The agent's `--sni`/`--host-header`
  are documented as vhost selection at an ingress you control. Fronting requires
  an SNI that differs from `Host` *and* a CDN that routes on the inner header;
  Google closed it in 2018, Cloudflare and AWS in 2020, Azure and Fastly by 2024,
  and the previous single-parameter implementation could not express the mismatch
  even before that. Corrected in the CLI help, module docstring, README,
  DESIGN.md and four site pages.
- `jocky build -o FILE --repeat N` now writes the artifact instead of silently
  producing nothing while exiting 0.


## [1.6.1] — 2026-09-16

Fixes found by running the runtime against a **real Windows 11 host** (Python
3.13, non-elevated) rather than the Linux stub-DLL simulation, plus platform
degradation work. Collection and the language were correct; what was broken was
the driver inventory, one ctypes call, and every path that assumed Linux.

### Fixed
- **`winapi.modules()` returned no usable drivers on Windows.**
  `EnumDeviceDrivers` succeeds on Windows 10/11 while filling its buffer with
  **zero** base addresses for a non-elevated caller, and
  `GetDeviceDriverBaseNameW(0, …)` then answers `ntoskrnl.exe` for every entry —
  244 drivers with 0 distinct names on the test host. Every BYOVD check built on
  it would have been a blind scan that *looked* clean. Now uses
  `NtQuerySystemInformation(SystemModuleInformation)`: same host, same token,
  **244 distinct names** with real image sizes and paths.
- **`winapi.list_processes()` failed outright with no arguments.**
  `class _TOKEN_USER(ctypes.Structure)` shadowed the `_TOKEN_USER = 1`
  information-class constant, so `GetTokenInformation` received a struct type
  where a DWORD belongs (`ctypes.ArgumentError`). Only processes the account
  could open reached that line, so a small `list_processes(limit=…)` hid it
  while the default call — what a script actually makes — raised. The dead
  struct is deleted and two tests pin the name as an `int` and the prototype's
  argument as a DWORD.
- **`jocky build -o FILE --repeat N` silently wrote nothing.** The repeat path
  returned after printing its uniqueness report, so an explicit `-o` produced
  exit 0, a JSON report, and no artifact. It now writes the last build and
  reports `path` and `written_bytes`.
- **Non-Linux platforms raised host exceptions instead of reporting.**
  `jocky/rt/raw.py` reached `os.uname()` (Unix-only) and `jocky/sandbox.py`
  called `ctypes.CDLL(None)` (no libc to bind on Windows), surfacing as
  `AttributeError`/`TypeError` in `jocky doctor`. Both now report the mechanism
  as platform-unavailable, and `_check_procfs` probes the backend the platform
  actually has, so a Windows host verifies `winapi` instead of reporting a
  missing `/proc` as a failure to fix.
- `tests/test_diagnostics.py` patched only `sys.modules`, but
  `from jocky.rt import winapi` resolves the package attribute first once the
  real module has been imported — so the tests exercised the real module and
  passed alone while failing in the full suite.
- BYOVD: Windows crash-dump stack drivers (`dump_*.sys`) are resident with no
  image on disk **by design** — measured: exactly 3 of 244 on a healthy host.
  Reported at `info` with the reason, not `high`, so the ghost-driver check
  keeps its signal.

### Added
- `byovd_deleted_driver_file` (Windows counterpart of the deleted-`.ko` check)
  and a coverage finding naming the checks that do not apply on a platform, so
  "no unsigned drivers" cannot be read as "no such notion here".
- `docs/INSTALL.md` — install guide for Linux and Windows, Docker, a measured
  platform capability matrix, and troubleshooting.
- `scripts/solutions/07_byovd_kernel_integrity.jky`.

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
robustness pass.

### Added — SIH26148 pillars
- **`jocky ci` + `.github/workflows/polymorphism.yml`** — the automated
  polymorphic pipeline (pillar 2, deliverable 4). Builds 256 artifacts per
  push, fails on any hash collision, and re-executes a sample to compare
  findings against a source run, so uniqueness cannot drift from semantics.
  Wall-clock-varying finding paths are measured (not assumed) and published as
  `volatile_fields`; a script whose finding *shape* varies fails explicitly
  rather than passing vacuously. Measured: 256/256 unique, 0 mismatches, ~508
  builds/s, 1.4 s for the whole gate.
- **`jocky/rt/byovd.py`** — kernel-module integrity (pillar 3): matches against
  a curated 20-entry abused-driver list, out-of-tree/unsigned/force-loaded
  taint classes, modules loaded long after boot, modules whose backing `.ko` was
  deleted, and the global taint bits. Every Linux CVE was verified against the
  CISA Known Exploited Vulnerabilities feed; the Windows drivers against the
  CVE records and LOLDrivers. Read-only by design — nothing loads or modifies a
  module. New natives: `det.byovd()`, `sys.taint()`, `sys.module_integrity()`,
  `sys.vulnerable_drivers()`.
- **`jocky/agent/dashboard.py` + `GET /`** — the web management console
  (pillar 4, deliverable 3). Fleet status, job queue, findings table with
  severity filters, job submission. One self-contained document (no CDN, no
  build step, CSP `default-src 'none'`), DOM built with `textContent` so
  attacker-influenced agent names cannot become stored XSS.
- **`jocky/rt/winapi.py`** — Windows collection (deliverable 1) through pure
  `ctypes`, emitting the same key names as `procfs`/`netfs` so scripts run
  unchanged. No `tasklist`, `netstat`, `wmic` or PowerShell. Dispatched through
  `_proc_backend`/`_net_backend`/`_sys_backend` in `builtins.py`.
- **`scripts/solutions/07_byovd_kernel_integrity.jky`** — playbook covering the
  BYOVD precondition (`out_of_tree and unsigned`), taint corroboration and the
  pivot to attribution.
- **`scripts/quickstart.jky`** — a fully commented tour of the language and
  every forensic namespace, runnable in all four modes.

### Security
- `jocky/lang/vm.py`: hard cap `MAX_COLLECTION_SIZE = 10_000_000` on string/list concatenation, string/list repetition, and `MK_LIST`/`MK_MAP` counts. Closes an unbounded-allocation vector (`"a" * 10**9`).
- `jocky/rt/pattern.py`: hard cap `MAX_REPEAT = 100_000` on `{n}`/`{n,m}` quantifier bounds at compile time. Turns a crafted pattern into a clear error instead of a step-budget exhaustion.
- `jocky/rt/filefs.py`: `scan()` refuses to walk the pseudo filesystems (`/proc`, `/sys`, `/dev`, `/run`) *when passed as the root*, so a script that mistakenly scans them gets a diagnostic rather than a silent zero-finding run. Drop zones (`/dev/shm`, `/tmp`, `/var/tmp`) are still scanned — a prefix-based guard would have over-blocked them.
- `jocky/poly/wire.py`: `Reader.count()` also enforces `_MAX_COLLECTION_ITEMS` on top of the remaining-bytes check, so a crafted artifact cannot claim millions of items even when the buffer is huge. `Reader.blob()` enforces `_MAX_FIELD_SIZE`.
- `jocky/agent/server.py`: per-IP rate limiting on authentication failures (`MAX_AUTH_FAILURES = 10` in `AUTH_WINDOW_SECONDS = 60` → `429` before the token is touched); token comparison reviewed end-to-end, only `hmac.compare_digest`. Job `kind` is validated at submit time against `JOB_KINDS`, so a typo is refused with an actionable message instead of becoming a job the agent later reports as failed. Console responses carry CSP/nosniff/no-referrer; `/favicon.ico` answers publicly so a browser's per-load request cannot spend the operator's auth budget.
- `jocky/sandbox.py`: `apply()` rejects an unknown level with `ValueError` naming the valid choices.

### Robustness
- `jocky/rt/filefs.py`: `grep_file()` deadline check runs every 1000 lines inside the inner split loop, and any line longer than `MAX_LINE_BYTES` is truncated before matching — a single very long line no longer bypasses both the byte cap and the wall-clock budget.
- `jocky/rt/procfs.py`: `read_fds()` distinguishes `PermissionError` (root-owned process), `FileNotFoundError` (process vanished), and other `OSError`s, and never propagates them out of a `/proc` walk.
- `jocky/rt/netfs.py`: `_read_unix()` wraps each row parse in `try/except`, so one malformed line does not abort the table read.
- `jocky/rt/detect.py`: `triage()` deduplicates findings sharing `(check, evidence.pid)`, keeping the highest-severity instance.
- `jocky/rt/byovd.py`: in-tree module CVEs grade `info` and late loads grade `info`. On a normal host this is the difference between two permanent unactionable findings per run and none — `ip_tables` loads anywhere iptables is used, and `tls` loads the first time something enables kTLS.

### Changed
- `jocky/cli.py`: `run`, `exec`, `build`, `triage`, `evidence`, and `attest` subcommands gained worked examples in `--help`; `serve` prints the console URL.
- `pyproject.toml`: `Source`/`Issues` point at the real repository (was a placeholder).
- `__version__` is now `1.6.0`, matching the newest tag (`v1.5.0` had been tagged while `__version__` still said `1.4.0`).

### Fixed
- 8 unused imports removed (`binascii`, `field`, `Iterable`×2, `Optional`×2, `Tuple`×2).
- Placeholder URLs removed from `CHANGELOG.md`, `site/content/project/changelog.md` and the site landing page's clone command.

All notable changes to JOCKY are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html) with an explicit
compatibility policy (see `docs/DESIGN.md` and the versioning page):

* **major** — the language, the artifact format or the management HTTP API
  changes incompatibly;
* **minor** — backwards-compatible features (new natives, new checks);
* **patch** — fixes only.

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

[Unreleased]: https://github.com/Pamure/jocky-forensics/compare/v1.7.0...HEAD
[1.7.0]: https://github.com/Pamure/jocky-forensics/compare/v1.6.1...v1.7.0
[1.6.1]: https://github.com/Pamure/jocky-forensics/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/Pamure/jocky-forensics/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/Pamure/jocky-forensics/releases/tag/v1.5.0
[1.4.0]: https://github.com/Pamure/jocky-forensics/releases/tag/v1.4.0
[1.3.0]: https://github.com/Pamure/jocky-forensics/releases/tag/v1.3.0
[1.2.0]: https://github.com/Pamure/jocky-forensics/releases/tag/v1.2.0
[1.1.0]: https://github.com/Pamure/jocky-forensics/releases/tag/v1.1.0
[1.0.0]: https://github.com/Pamure/jocky-forensics/releases/tag/v1.0.0
