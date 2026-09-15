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
(`{{`/`}}` escape literal braces).  Maps use identifier-or-string keys:
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

---

## 7. Non-goals

* Kernel-mode evasion (driver loading, callback removal) — out of scope for a
  user-space forensic toolkit and ethically out of scope for this project.
* Windows collection (procfs-specific collectors); the language, encoder and
  agent protocol are platform-neutral and would port.
* Tamper-proof evidence handling beyond hashing/verification: the harness
  writes raw logs and hashes them, but chain-of-custody tooling is a different
  problem.

---

## 8. Extension points

* **New native** — add a `NativeFn` to the relevant namespace in
  `jocky/rt/builtins.py`; arity is checked by the VM.
* **New detection check** — add a function to `jocky/rt/detect.py` returning
  finding dicts via `_finding(...)`, then include it in `triage()`.
* **New artifact transform** — add a `Mutation` to `jocky/poly/encoder.py`
  (transform + inverse) and register it in the pipeline; the round-trip test
  suite covers semantics automatically.
* **New collection source** — mirror `jocky/rt/procfs.py`: plain functions
  returning dicts/lists, defensive against races, no external commands.
