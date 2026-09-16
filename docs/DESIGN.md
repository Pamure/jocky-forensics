# JOCKY design notes

Companion to `README.md`. Everything here describes behaviour that is
implemented and measured; numbers quoted in the evidence section come from
`python -m jocky evidence`.

---

## 1. Language

### 1.1 Syntax

```
program    := stmt*
stmt       := let | set | if | while | for | fn | return | break
            | continue | emit | try | block | expr-stmt
let        := 'let' IDENT '=' expr
set        := assignable '=' expr            # name | obj.member | obj[expr]
if         := 'if' expr block ('elif' expr block)* ('else' block)?
for        := 'for' IDENT 'in' expr block
fn         := 'fn' IDENT? '(' params ')' block
try        := 'try' block 'catch' IDENT block
emit       := 'emit' expr
expr       := or
or         := and ('or' and)*
and        := not ('and' not)*
not        := 'not' not | comparison
comparison := additive (('=='|'!='|'<'|'<='|'>'|'>='|'in') additive)*
additive   := mult (('+'|'-') mult)*
mult       := unary (('*'|'/'|'%') unary)*
unary      := '-' unary | postfix
postfix    := primary ('(' args ')' | '[' expr ']' | '.' IDENT)*
primary    := INT | FLOAT | STRING | 'true' | 'false' | 'nil' | IDENT
            | '(' expr ')' | '[' items ']' | '{' pairs '}' | lambda
```

Literals: decimal/hex/bin/octal ints with `_` separators, floats, double-quoted
strings with `\n \t \r \0 \\ \" \{ \} \xNN` escapes and `{expr}` interpolation
(`{{`/`}}` escape literal braces), and raw strings (`r"…"`) that decode nothing
at all.  Maps use identifier-or-string keys:
`{"kind": "x", count: 3}`.

Comments run from `#` to end of line.  Newlines are insignificant.

### 1.2 Semantics that matter

| Area | Rule |
|---|---|
| Scoping | Function-scoped locals, no block scoping. Unknown names resolve to globals and raise `undefined name` if absent. |
| Closures | Captured **by reference to a cell**, so two closures over one variable observe each other's writes. A loop variable is a single cell, so closures created in a loop share the final value (same late-binding behaviour as Python lambdas). |
| Truthiness | `nil`, `false`, `0`, `0.0`, `""`, `[]`, `{}` are falsy. |
| `and`/`or` | Short-circuiting, evaluate to an operand (not a coerced boolean). |
| Equality | Structural for lists and maps; numeric across int/float. |
| Numbers | int/float; `/` is true division; division or modulo by zero is a catchable error. |
| `emit` | Appends a structured finding to the run result — the primary output channel for forensic scripts; `print` writes human text to stdout. |
| Errors | Runtime errors are catchable via `try`/`catch`; the caught value is the message string. Uncaught errors stop the program and appear in `result.errors` with the program's findings preserved. |

### 1.3 Safety limits

`VM(max_steps=…, max_frames=…)` plus an optional wall-clock budget.  Hitting a
limit raises an *uncatchable* `JockyLimitError` and marks the result
`truncated=True`, so a hostile or broken script cannot hang a collection run or
paper over the limit in a `catch`.

The matcher has its own budget: a single `re.*` call that exceeds 4,000,000
thread-steps raises a *catchable* error, because a script that searches
attacker-authored text must not be able to wedge the run it is part of.

The front end reports its own recursion limit rather than letting the
interpreter's stack decide: source that nests deeper than Python can recurse
(`"(" * 200 + "1" + ")" * 200`, a 600-link `.to_str()` chain, nested
`{interpolation}`) raises `JockySyntaxError`/`JockyCompileError` with a "nests
too deeply" message.  Without that guard a host `RecursionError` escaped
`compile_source`, which meant a script could take the process down with a
traceback instead of a diagnostic — found by the fuzz harness in
`tests/fuzz_language.py`, pinned in `tests/test_language.py`.

### 1.4 Patterns

`re.*` and `fs.grep` run JOCKY's own matcher (`jocky/rt/pattern.py`): the
pattern is parsed, compiled to an NFA, and simulated over the input, so the cost
is `O(len(text) × len(pattern))` whatever the pattern looks like.  The text
being matched is attacker-authored — command lines, file names, log lines — and
a backtracking engine turns that into a denial-of-service primitive: `(a+)+b`
against 20,000 `a`s never returns under the host `re`, and answers in ~50 ms
here.

Unsupported by design, each a syntax error naming the offset: lazy quantifiers,
back-references, look-around.  Where an engine's semantics could differ, the
choice is documented and tested rather than incidental — matching is
leftmost-longest (POSIX-like, so "does this text contain the shape?" always
answers the same way), and `\w`/`\b` are ASCII.

Correctness rests on differential testing against the host `re` over the
supported subset — more than 8,000 comparisons of both the verdict *and* the
match span in `tests/test_pattern.py` — not on spot checks.  Patterns are
written as raw strings (`r"^\d{2}:\d{2}$"`), since a repeat count inside a
normal string is interpolation.

---

## 2. Bytecode

Stack machine; instructions are `(op, arg)` pairs.

| Group | Ops |
|---|---|
| Stack/const | `CONST i`, `POP`, `DUP` |
| Locals | `LOADL s`, `STOREL s`, `LOAD_CELL s`, `STORE_CELL s`, `PUSH_CELL s` (cell ops are emitted only for slots captured by a nested function) |
| Globals | `LOADG i`, `STOREG i` |
| Arithmetic | `ADD SUB MUL DIV MOD` (also string/list concatenation and repetition) |
| Comparison | `EQ NE LT LE GT GE IN` |
| Unary | `NEG NOT` |
| Control | `JMP t`, `JMPF t`, `JMPT t` |
| Calls | `CALL argc`, `RET`, `MK_FN proto` |
| Data | `MK_LIST n`, `MK_MAP n`, `GET_IDX`, `SET_IDX`, `GET_MEM i`, `SET_MEM i` |
| Iteration | `ITER_INIT`, `ITER_NEXT t` (iterator handle lives on the operand stack) |
| Errors | `TRY_ENTER (start,end,handler,slot)`, `TRY_EXIT` — dynamic handler stack with the operand-stack depth recorded at entry, so `catch` unwinds partial expressions correctly and can cross function frames |
| Output | `EMIT`, `HALT`, `NOP0..NOP7` (junk slots used by the encoder) |

Compilation is single-pass over the AST with label patching; `Proto.starts`
records statement boundaries so the encoder can insert junk only at safe
points.

---

## 3. Artifact format and polymorphism

```
"JKY1" | version | header_len | header (obfuscated) | payload_len |
encrypted payload | pad_len | padding | HMAC-SHA256 (truncated)
```

The header carries the per-build opcode permutation, the profile id, the payload
key and integrity material; it is XOR-obfuscated with its own key.  The payload
holds the encrypted constant pool and the code streams.

Per-build transforms and what each one buys:

| Transform | Effect on the bytes | Defeats |
|---|---|---|
| Opcode permutation | every instruction byte changes | opcode histogram/pattern signatures |
| Local-slot permutation | operand bytes change per function | byte-sequence signatures over operand patterns |
| Constant encryption (per-constant cipher + key) | no literal strings/numbers appear | plaintext markers (paths, patterns) in the artifact |
| Constant splitting (`1000` → `512+488`, `"long-string"` → 3 concats) | instruction stream grows/shifts | signatures keyed to literal representation |
| Junk insertion at statement boundaries | code length varies by build | length fingerprints |
| Keystream-encrypted payload + random padding + random seed | whole-file entropy and size vary | file hashes, chunk hashing, similarity/fuzzy hashing |

Measured ceiling (see `research/findings/lim-polymorph.md` and
`res-obfuscation.md`): **the statement-level control-flow graph is identical
across builds.** The assembly-level permutation, slot remapping and junk
insertion change bytes and counts, not shape. A ~120-line standalone unpacker
recovers constants, names and a full listing in about a millisecond, and the
artifact ships its own opcode bijection in the header because the VM has to be
able to read it.

What it does **not** defeat: control-flow-shape matching, kernel/EDR telemetry
of the decryption step, and memory scanning of the decoded program once it runs.
The honest claim is "unique bytes and no plaintext program on disk", not
"signature- or analysis-resistant".

---

## 4. Execution modes and their telemetry

| Mode | Program text | Process image | Child processes | Typical use |
|---|---|---|---|---|
| `run` (source) | `.jky` file on disk | `/usr/bin/python3` | none | development, analysis workstations |
| `exec` (artifact) | encrypted artifact on disk | `/usr/bin/python3` | none | field deployment where a file is acceptable |
| `fileless` | payload memfd | `/memfd:python3 (deleted)` + memfd mappings | none | running against a monitored target |

Fileless mechanics: the interpreter ELF, a zip of the `jocky` package and the
payload are each written to their own `memfd_create()` object; the child execs
`/proc/self/fd/<elf_fd>` with a `-c` bootstrap that imports the package via
`zipimport` from `/proc/self/fd/<pkg_fd>` and reads the payload from
`/proc/self/fd/<payload_fd>`.  Nothing is written to a filesystem, and the
bootstrap itself only ever exists in argv.

Measured consequences (see `evidence/artifacts.json`, `evidence/audit.json`):
zero files created in fileless mode, zero child-process events during
collection, `/proc/<pid>/exe` = `/memfd:python3 (deleted)`.

---

## 5. Detection library

Detection is deliberately the mirror image of the execution side: whatever
technique the runtime can use, `jocky/rt/detect.py` can find.

| Check | Data source | Severity | Rationale |
|---|---|---|---|
| `fileless_process` | `/proc/<pid>/exe` contains `/memfd:` or ends `(deleted)` | high | no on-disk image: dump `/proc/<pid>/exe` before the process dies |
| `memfd_mapping` | `/proc/<pid>/maps` with `memfd:` + `x` permission | high | executable anonymous memory |
| `deleted_executable` | `exe` ending `(deleted)` | medium | binary unlinked after start (often a loader dropping its dropper) |
| `temp_executable` | `exe` under `/tmp`, `/dev/shm`, `/var/tmp` | high | execution from world-writable drop zones |
| `rwx_memory` | anonymous `rwx` mappings | low | JIT runtimes look identical — correlation input, not a verdict |
| `unusual_listener` | `/proc/net/tcp{,6}` LISTEN outside a baseline port set | low | attack surface enumeration |
| `deleted_open_file` | `/proc/<pid>/fd/*` → `(deleted)`, `memfd:` excluded | medium | payload held open after unlink; recover via the fd |
| `ld_preload` / `ld_env_injection` | `/etc/ld.so.preload`, process `environ` | high / medium | userland rootkit technique |
| `suspicious_cmdline` | process cmdline vs pattern table | mixed | download-and-execute, reverse shells, log tampering, inline interpreters |
| `hidden_module` | `/proc/modules` vs **loadable** `/sys/module` subset | critical / high | the two kernel views disagree ⇒ one was tampered with |
| `world_writable_path` / `hijackable_path` | `$PATH` resolved through symlinks + mount type | low | PATH planting; drvfs/9p/network mounts are exempt because their mode bits are meaningless |
| `persistence` | cron, systemd, `rc.local`, `profile.d`, `authorized_keys` | high | recently modified persistence artefacts |

Aggregation (`det.triage`) runs every check, counts by severity, and reports
scanned process/socket totals so a "clean" result is distinguishable from a
failed run.  `ioc.match` correlates indicator sets against live processes,
sockets and (optionally) files with hashing.

A finding is a map — `{"check", "severity", "title", "evidence",
"recommendation"}` — with no time of its own; `--stamp-findings` adds a `ts`
when one is missing (`runner.stamp_findings`), which is what lets a run be
correlated with journald/auditd output through `time.iso` and `tl.merge`.
Script-set values are never overwritten: a script that watched an event knows
when it happened, the runner only knows when it collected.

Process checks share one collection pass (`det.Snapshot`): each of them used to
walk `/proc` on its own, which cost five sweeps of the same data per run
(measured: 752 ms → 290 ms internal on the development host, same findings).
Every check is still callable on its own, and then collects its own minimum.
The `$PATH` audit is likewise one pass per entry: it resolves each entry once,
skips duplicate entries, and does not resolve entries on filesystems whose mode
bits are already meaningless (drvfs/9p/network mounts), which on WSL took the
check from 591 ms to 89 ms.

False positives are treated as defects: each check was tuned against the
development host until the finding set was explainable, and the module-view
check specifically excludes built-in kernel subsystems (they never appear in
`/proc/modules`, so including them produced hundreds of bogus "hidden module"
findings).

---

## 6. Management interface

* **Transport** — HTTPS (`ssl.PROTOCOL_TLS_SERVER`), self-signed certificate
  generated with `openssl` on first run; the client verifies by default and can
  be told to accept the generated certificate.
* **Auth** — shared token in `X-JKY-Token`, compared with `hmac.compare_digest`;
  missing/incorrect tokens get 401, bodies are capped, unknown routes 404.
* **State** — sqlite (`agents`, `jobs`, `findings`) under `--state`, so
  investigations survive restarts and every finding keeps its job/agent
  provenance.
* **Flow** — operator `POST /v1/jobs/submit` → agent polls `POST /v1/jobs/poll`
  → executes in-process (`run` or `fileless`) → `POST /v1/jobs/result` stores
  findings → operator reads `GET /v1/status` / `GET /v1/findings`.
* **Frontable mode** — the client can send a different SNI/Host than the
  address it dials, which is the client-side mechanic domain fronting needs.
  No CDN is involved locally; the code says so instead of implying otherwise.
* **Console** — `GET /` serves a single-page operator interface
  (`jocky/agent/dashboard.py`): fleet status, job queue, findings table with
  severity filters, and a job submission form. It is one Python string with
  inline CSS and JS because the container image copies only the `jocky`
  package — a `templates/` directory would not be shipped, and a CDN reference
  would render blank on the air-gapped range this is built for. It is served
  **without** a token: the page holds no data and no credential, and everything
  it displays is fetched afterwards with the operator's own token. Security
  headers are sent with it (`default-src 'none'`, no frames, no forms), and the
  DOM is built with `createElement`/`textContent` throughout, because agent
  names and finding titles are attacker-influenced and a console that rendered
  them as markup would be a stored-XSS hole in the operator's browser.
  `/favicon.ico` answers 204 publicly: browsers request it per page load, and
  letting it hit the auth path would spend the per-IP failure budget and lock
  the operator out of their own console after ten reloads.

---

## 7. Kernel-module integrity (BYOVD)

BYOVD — bring your own vulnerable driver — is the technique that defeats
endpoint protection from below: install a driver the vendor already signed, then
use its IOCTL surface to reach kernel memory, where EDR callbacks live. Nothing
about the driver is malicious in isolation, so signature scanning cannot find
it. `jocky/rt/byovd.py` looks for the *state* that exploiting it produces:

| Check | Source | Severity |
|---|---|---|
| `byovd_known_vulnerable_module` | `/proc/modules` vs a curated 20-entry list | critical/high for `third_party`; info for `in_tree` |
| `byovd_out_of_tree_module` | taint `O` | medium |
| `byovd_unsigned_module` | taint `E` | high |
| `byovd_forced_module` | taint `F` | high |
| `byovd_late_loaded_module` | `/sys/module/<name>` mtime vs boot | info |
| `byovd_deleted_module_file` | module loaded, backing `.ko` gone | high |
| `byovd_kernel_taint` | `/proc/sys/kernel/tainted` bits 12/13 | medium |

Two grading decisions carry the design. **`scope` decides severity**: a
`third_party` driver is the BYOVD shape — a signed binary the attacker brought
with them — so a match is the finding; an `in_tree` module ships with the
distribution kernel, and `ip_tables` loads on any host that uses iptables, so
grading it high would place a permanent unactionable item in every triage
result and teach the operator to ignore the detector. In-tree matches are
reported at `info` with the CVE intact: "this kernel build exposes a publicly
exploited module" is a patching question, not evidence of compromise. **A load
timestamp is correlation input, not a verdict**, for the same reason
`rwx_memory` is graded `low`: modules load on demand when a filesystem type is
first mounted or a TLS socket enables kTLS, so `byovd_late_loaded_module` is
`info` and its recommendation is to correlate with process and package activity.

Every Linux CVE in the table was checked against the CISA Known Exploited
Vulnerabilities feed, so "abused in the wild" is a claim with a citation rather
than an adjective; the Windows drivers were checked against the CVE record and
cross-referenced with the LOLDrivers dataset. The check is read-only — nothing
in the module loads, unloads or modifies a module. Loading a vulnerable driver
to test a detector is the difference between studying a technique and deploying
one.

---

## 8. Cross-platform collection

`jocky/rt/winapi.py` gives Windows the same collectors through pure `ctypes` —
no `tasklist`, `netstat`, `wmic`, `driverquery` or PowerShell, for the same
reason the Linux side never runs `ps` or `ss`: a triage that shells out leaves
artefacts in the evidence and can be hooked. It emits the **same key names** as
`procfs`/`netfs`, so a script runs unchanged on either platform.

Dispatch lives in one place (`jocky/rt/builtins._proc_backend`, `_net_backend`,
`_sys_backend`) and is resolved once per process, because probing for the
Windows DLLs on every call would put a syscall in the middle of a script loop.
The three resolvers exist because the Linux collectors are split across three
modules — asking `procfs` for `listeners()` or `modules()` is an
`AttributeError`, and the split makes that mistake impossible to make twice.

Off Windows the module imports cleanly, `available()` is `False`, and every
collector returns its empty value without raising. The pure helpers (byte-order
decoding, `SOCKADDR` and SID layouts) are module-level functions over plain
`int`/`bytes`, which is what makes the parts that are easy to get wrong
unit-testable on Linux with synthetic buffers. Permission denials are never
raised and never silently dropped: they are recorded through `access_errors()`
and flagged on the affected row, so "there is nothing here" stays
distinguishable from "this account was not allowed to look".

---

## 9. The CI gate

Pillar 2 of the problem statement asks for a *CI/CD pipeline*, not just a
mutation engine, so `jocky ci` (`.github/workflows/polymorphism.yml`) runs on
every push: it builds 256 artifacts from one script, fails on any hash
collision, and re-executes a sample to compare their findings against a source
run. Uniqueness alone is not a property worth defending — a build that produces
unique bytes *and different behaviour* is a broken build — so the two claims are
checked together.

The interesting part is the comparison. A script can legitimately emit
wall-clock data (`smoke.jky` emits `sys.uptime().seconds`), which differs on
every run, so a naive findings comparison could never pass and would be
"fixed" by weakening it. Instead `verify_equivalence` runs the source twice
more, diffs the three runs path-wise, and blanks exactly the paths that vary —
publishing them as `volatile_fields`. A deterministic script gets an empty
exclusion set and the gate stays strict. If the findings' *shape* varies between
two source runs, every path would be blanked and the check would become
vacuous, so that case fails explicitly rather than printing a green result that
proves nothing.

---

## 10. Non-goals

* **Kernel-mode evasion** (loading a driver, removing EDR callbacks) — out of
  scope for a user-space forensic toolkit and ethically out of scope for this
  project. The BYOVD work above is the detection half: it finds the state an
  exploited driver leaves behind, and never creates one.
* **Windows *execution*** — the collection layer is implemented (§8), but
  fileless memfd execution and the Landlock sandbox are Linux mechanisms with
  no Windows equivalent here. The language, encoder, CI gate and agent protocol
  are platform-neutral and already portable.
* **Tamper-proof evidence handling beyond hashing/verification**: the harness
  writes raw logs and hashes them, but chain-of-custody tooling is a different
  problem.

---

## 11. Extension points

* **New native** — add a `NativeFn` to the relevant namespace in
  `jocky/rt/builtins.py`; arity is checked by the VM.
* **New detection check** — add a function to `jocky/rt/detect.py` returning
  finding dicts via `_finding(...)`, then include it in `triage()`.
* **New artifact transform** — add a `Mutation` to `jocky/poly/encoder.py`
  (transform + inverse) and register it in the pipeline; the round-trip test
  suite covers semantics automatically.
* **New collection source** — mirror `jocky/rt/procfs.py`: plain functions
  returning dicts/lists, defensive against races, no external commands.
