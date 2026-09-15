# Roadmap

This page is the synthesis of a twenty-agent review: ten audits of JOCKY's own
limitations and ten surveys of 2024–2026 practice, each written against the
source tree and the primary literature. Every report is in
[`research/findings/`](https://github.com/) in the repository, and every item
below names the report it came from.

Shipped items are in [v1.1.0](/docs/project/changelog); everything else is
ordered by a blunt question: *does this change what an investigator can
conclude, or only how comfortably they conclude it?*

## Shipped in v1.1.0

| Change | Why it was needed | Source |
|---|---|---|
| Capability-gated `mem.syscall` / `mem.memfd_run` (`--allow`) | A script could kill a live process with `mem.syscall(62, pid, 9)` and escape to a shell through `mem.memfd_run` | `lim-security.md` |
| Certificate pinning, `--insecure` opt-in, `--token-file` | TLS verification was off by default and no flag could turn it on; the token travelled in `argv` | `lim-security.md`, `res-agent-security.md` |
| Authenticated, idempotent job results + `payload_sha256` | Any caller could post findings for any job id, and a replay duplicated them | `lim-security.md` |
| Owner-only store and state directories | `store.db` was world-readable case data | `lim-security.md` |
| `jocky attest` / `verify` / `sign` | The evidence bundle was unhashed, so "a reviewer can re-check the logs" was unenforceable | `res-evidence-integrity.md` |
| Deterministic builds (`--deterministic --seed-hex`) | Rebuild-and-compare provenance was impossible: every encode mixed fresh entropy | `res-evidence-integrity.md` |
| `memfd_fd_holder`, `injection_primitives` checks | A memfd *script* execs the on-disk interpreter and was invisible to every fileless check | `res-fileless-state-of-art.md` |
| Partial-visibility reporting in triage | As uid 1000, 75 of 90 processes were uninspectable and the result still looked clean | `lim-detection.md` |
| `MFD_EXEC` for fileless mode | With `vm.memfd_noexec >= 1` the old flags failed with EPERM | `res-fileless.md` |
| Lexer, constant-pool, escape, unwinding and `sys.users()` fixes | Reproduced crashes and silent type confusion in evidence data | `lim-language-vm.md`, `lim-frontend.md`, `lim-detection.md` |
| Docs site, `jocky doctor`, `jocky init`, packaging, Dockerfile | Installing JOCKY required knowing about a venv path; doctor turns "it does not work" into a named missing prerequisite | `lim-dx.md` |

## Next: tier 1 — changes what an investigator can conclude

| Item | What it unlocks | Effort | Source |
|---|---|---|---|
| **Sandbox levels** (`--sandbox=vm|ro|strict`) implementing Landlock + seccomp through raw syscalls | Running an *untrusted* script on an analyst box: measured on this host, Landlock ABI 3 denies `/etc/shadow` and writes while leaving collection intact; strict mode blocks `memfd_run` and sockets entirely | M | `res-sandboxing.md` |
| **Memory acquisition** (`/proc/<pid>/mem`, `/proc/kcore`, `process_vm_readv`) | The one capability every DFIR standard expects and JOCKY lacks; today the detector *advises* `dd if=/proc/<pid>/mem` without doing it | M | `lim-forensic-depth.md`, `res-live-response.md` |
| **Sandboxed agent jobs** | `jocky run/exec` take `--sandbox`, but a job handed to an agent executes unconfined in the agent process; the fix is fork-per-job, which changes the agent's process model and therefore its "no child processes" property — a deliberate design decision, not a flag | L | `security/limits.md`, `lim-security.md` |
| **Per-agent credentials and signed job bundles** | The management token is still one shared secret for every agent; proposals (per-agent enrolment secrets, HMAC-signed job envelopes with nonce/expiry, optional Ed25519) exist but are unimplemented, and `lim-security.md`'s repro showed a fabricated agent id can still claim a queued job | M | `res-agent-security.md`, `lim-security.md` |
| **Time on every finding** (`event_time`, `collected_at`, monotonic ordering) | Findings cannot be merged into a timeline without it, which blocks correlation with journald/auditd | S | `lim-forensic-depth.md` |
| **Log ingestion** (journald JSON, auditd `EXECVE`, auth.log, wtmp/btmp) | Persistence and tampering checks currently see only mtimes and live command lines | M | `lim-forensic-depth.md`, `lim-detection.md` |
| **Behavior fingerprints of builds** (post-decode opcode+arg digest, SimHash) | Gives defenders and CTI a stable handle on a family across polymorphic builds — the honest answer to "what survives obfuscation" | S | `res-llm-forensics.md`, `lim-polymorph.md` |
| **Control-flow flattening for artifacts** (bounded: statement-block dispatch with opaque predicates) | Today the statement CFG is *identical* across builds; this is the only transform with a measured effect on shape | L | `res-obfuscation.md`, `lim-polymorph.md` |

## Next: tier 2 — depth and interop

| Item | Notes | Effort | Source |
|---|---|---|---|
| **OCSF `detection_finding` export** (`jocky export --format ocsf`) | OCSF 1.9 maps severity 1:1 and carries evidence keys verbatim; STIX 2.1 is lossy (`file.is_deleted` has no SCO field), Sigma cannot express `deleted_open_file`, and OpenIOC/YARA-L are dead ends for this use | S | `res-ioc-formats.md` |
| **`jocky report`** (markdown/JSON triage narrative) with sanitised LLM view | Machine-readable findings for agents; sanitise C0/C1, bidi and markdown in attacker-controlled strings first — the prompt-injection studies are unambiguous that raw host strings are hostile input | M | `res-llm-forensics.md` |
| **Module-system + `needs` capability declarations** | Playbooks cannot be composed today, and capabilities are granted per *run* rather than per *script*; compile-time rejection is the safest form | M | `res-dsl-design.md` |
| **Perf: merged `/proc` sweep + caching** | Measured 3,288 `/proc` calls per triage; a shared sweep cuts the process part 3.9× and the fd sweep 4.2×, and `world_writable_path()` alone can consume 700 ms on a `$PATH` full of DrvFs mounts | M | `lim-scale.md` |
| **Streaming findings** (bounded, cursor-based) | 10k findings cost ~9 MB of Python objects + JSON; the agent can also drop results it cannot deliver | M | `lim-scale.md`, `res-live-response.md` |
| **Bytecode line table** | Runtime errors carry no line/column; a hunt that fails on a target host cannot be localised | M | `lim-frontend.md`, `lim-dx.md` |
| **Store error denominators in `triage`** | A check that raised is currently indistinguishable from a check that found nothing | S | `lim-detection.md` |

## Next: tier 3 — platform and ecosystem

| Item | Notes | Effort | Source |
|---|---|---|---|
| **Windows/macOS collectors** | The language, encoder and agent protocol are portable; `jocky/rt` is not, and today the package is unimportable on Windows (`os.sysconf` at import time is now guarded, but the collectors are procfs-only) | L | `lim-platform.md` |
| **Pygments/TextMate grammar + completions** | No editor support at all today | S | `lim-dx.md` |
| **CI with a reproducible environment** (no in-tree `venv`, lock file, pinned base image) | Nothing is verified on push; the Docker image build is untested in this environment | S | `lim-dx.md` |
| **Signing with a non-symmetric key** (minisign/`ssh-keygen`/cosign adapter; optional RFC 3161 timestamping) | HMAC proves integrity to whoever holds the key; non-repudiation needs a signature primitive the standard library does not provide | M | `res-evidence-integrity.md` |

## Capability research (2026-09)

Six studies asked what a forensic language should be able to do and where JOCKY
stands. Reports: `research/findings/cap-*.md`. Shipped from them in v1.4.0: the
in-language test facility, denial auditing, the sandbox package read grant, and
three language-consistency fixes the corpus exposed.

| Gap | Evidence | Effort | Source |
|---|---|---|---|
| **Pattern matching in the language** — string matching is literal-only, and the nine intrusion regexes are hard-coded in `detect.py`, unreachable from scripts (`regex` → undefined name) | `fs.grep`/`match`/`capture` proposed | M | `cap-forensic-features.md` |
| **Time on findings + timeline merge** — mtimes are raw floats, findings carry no `ts`, `fs.timeline` sorts one root | blocks correlation with journald/auditd | M | `cap-forensic-features.md` |
| **Structured ingestion** — JSON is the only parser; no CSV/JSONL/XML/Protobuf | triage of exported artifacts | S–M | `cap-forensic-features.md` |
| **`needs` capability declaration + `jocky capabilities <script>`** — grants are per-run, never declared, and a script can currently *catch* a refusal (now audited in the result, but not pre-declared) | Deno/WASI/Starlark comparison | M | `cap-capability-models.md` |
| **Per-path read narrowing** — `fs.read` reaches anything readable; Landlock grants are additive to fixed read roots | NIST SP 800-61r3 least-privilege | M | `cap-capability-models.md` |
| **Cost model for natives** — a native costs one step regardless of bytes read, so `fs.scan` can exhaust memory "within budget" | `cap-performance-envelope.md` | S | `cap-forensic-features.md` |
| **Editor tooling** — no Pygments lexer, TextMate/tree-sitter grammar, LSP, formatter or REPL; a prototype lexer tokenised 1,082 lines with zero errors in 22 rules | 24 `.jky` files exist to highlight | S (lexer) / L (LSP) | `cap-tooling.md` |
| **Fixture replay** — `jocky test --record` so a corpus can run against captured `/proc` snapshots instead of the live host | today every collector test depends on the host | M | `cap-dsl-survey.md` |

Closest external analogue: **Velociraptor VQL** — a host-native query language
with versioned artifacts served from a central server; JOCKY's namespaces mirror
its plugins and `serve`/`agent` mirror hunts, while JOCKY adds the bytecode VM,
per-build polymorphic artifacts and two capability-gated natives
(`cap-dsl-survey.md`).

## Explicitly out of scope

Recorded so the boundary is not rediscovered as a "gap" every review:

- **Kernel-mode evasion** (driver loading, callback removal). Linux 6.6 exposes
  `security_bprm_check`, `file_mprotect`, `mmap_file`, `task_alloc` and
  `ptrace_access_check`; the floor cannot be lowered from user space, and stock
  Falco/Tracee/Tetragon/Elastic rules already cover the memfd path used here.
  `res-ebpf-detect.md` proposes a `jocky observe` command that reports which of
  JOCKY's own actions a given policy would flag — honest self-audit instead of a
  bypass claim.
- **Instruction virtualization / MBA / self-modifying bytecode.** The decoded
  program still runs in an interpreter the analyst controls, LLM-assisted
  reversing halves the cost of nesting (measured: 40% of Tigress targets solved
  blind), and the real ceiling is "uniquely hashed, not analysis-resistant".
- **Container escapes, injectors, io_uring staging, `O_TMPFILE` execution.**
  Documented as detectable-but-not-implemented (`res-fileless-state-of-art.md`).
- **Domain fronting without a CDN.** The client implements the frontable
  mechanic (separate SNI and Host); a local deployment has no CDN to front.
