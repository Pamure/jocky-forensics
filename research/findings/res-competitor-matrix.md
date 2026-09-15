# res-competitor-matrix — who else does DFIR-by-DSL, and where JOCKY stands now

## Scope
Primary sources read **2026-09-16** (docs/READMEs, not blog summaries). This note
records the competitive picture for SIH26148 and what the runtime does about each
gap; it was written together with the Sigma/YARA/correlation work it justifies.
Two claims here are measured rather than quoted: the Sigma-vs-backtracking gap
and JOCKY's own triage envelope (`cap-performance-envelope.md`,
`cap-pattern-engine.md`).

## The field, in four architectures
1. **Agent + query language platforms** — Velociraptor **VQL** (`SELECT … FROM
   plugin(args) WHERE …`, YAML artifacts compiled server-side, `memoize()` as the
   join primitive), **osquery** (SQL over virtual tables, `JOIN`, published
   profiler thresholds: duration 0.8/1/3 s, 10 % CPU, 200 MB), **GRR** (server-side
   Python flows), **LimaCharlie LCQL** (pipe DSL with stateful `with child`).
   Strength: fleet scale and a paper trail. Weakness: a managed agent is
   *detectable by design*.
2. **Evidence-parser frameworks** — **Dissect** (`target-query -f <plugin>`, 300+
   plugins across disk images, `flow.record` typed records, `target-shell`,
   `-f yara` via an extra), **KAPE** + **Eric Zimmerman tools** (no language:
   targets/modules and standalone parsers).
   Strength: breadth of artifact parsing, offline images, Windows depth.
3. **Rule engines over logs** — **Sigma** (spec 2.1.0) evaluated by **Chainsaw**
   (Rust + Tau), **Hayabusa** (Rust, Sigma v2 correlation), **Zircolite**
   (pySigma → SQLite, adaptive execution, RestrictedPython field transforms),
   **DeepBlueCLI** (hardcoded PowerShell). Strength: the community's rule corpus.
4. **Pattern DSLs** — **YARA/YARA-X** (hex strings with `??`/`~`/`[4-6]` jumps and
   alternatives, `nocase/wide/ascii/base64`, modules), **Zeek** (its own event
   language, plus a JavaScript alternative). Strength: byte-level signatures.

**JOCKY's axis** is the one nobody else claims: in-memory execution
(`/proc/<pid>/exe` reads `/memfd:python3 (deleted)`), per-build polymorphic
artifacts, zero child processes, Landlock confinement, and a *bounded* matcher —
the analysis tool that is itself hard to see, whose detection logic cannot be
turned into a denial of service.

## What JOCKY now does about the gaps that mattered

| Gap | Who had it | What landed |
|---|---|---|
| Rule-format interop | Chainsaw / Hayabusa / Zircolite (Sigma), YARA everywhere | **`sigma.check`/`jocky sigma`** (documented YAML subset, modifiers, `N of them` grammar) and **`yara.check`/`jocky yara`** (hex wildcards, jumps, alternatives, `nocase/wide/ascii/fullword`, `at`/`filesize`). Unsupported constructs are refused by name. |
| Byte patterns | YARA, bstrings | `\xNN` escapes with class-range endpoints, `fs.read_bytes` (latin-1 byte strings), `fs.strings` (ASCII **and** UTF-16LE), `fs.entropy`, and byte-mode `fs.grep` that detects when a pattern needs byte semantics (the alternative silently matched nothing). |
| Joins / correlation | osquery `JOIN`, VQL `memoize`, LCQL `with …` | `index_by(rows, key_fn)` and `group_by(rows, key_fn)`: one pass, then lookups (O(n+m) instead of a hand-rolled O(n×m) loop). |
| Streaming results | VQL, osquery, Dissect all stream rows | `VM(emit_sink=…)` + `--ndjson`: findings leave as they are emitted (150 k findings: 56.6 MB → **20.9 MB** peak RSS). |
| Rule-format *safety* | nobody: Sigma engines backtrack | Sigma and YARA both evaluate on the linear-time NFA with a step budget. Measured: `(\w+\s?)+whoami` against an 80 KB crafted line — **>20 s and counting** under Python `re` (the Zircolite engine class), **745 ms** here. |
| Evidence integrity | Velociraptor datastore, KAPE metadata | `attest`/`verify`/`sign` hash chain with an off-host anchor — and, as of this round, **no silently skipped subtrees**: `.git/hooks/*` is chained and a planted `.git/config` fails verification. |
| Metric the jury can read | osquery publishes thresholds | JOCKY's triage: **0.29–0.42 s** wall for 12 checks over ~120 processes, well inside osquery's own "ok" band (0.8 s) and far below its sample join (1.02 s). |

## What remains, ranked (and who wins today)

1. **Windows/macOS collectors** — Dissect, Velociraptor, osquery, Artemis win.
   JOCKY is procfs/Linux-only; this is a scope answer, not a bug.
2. **Offline image mode** — Dissect wins on breadth (300+ parsers). The cheap
   partial answer is rooting the existing collectors at `--root <mountpoint>`
   (`fs.scan` already takes a root; `det.persistence` and friends do not).
3. **Notebook/REPL surface** — VQL notebooks, Dissect's `target-shell`, Zircolite's
   Mini-GUI win. A 60-line `jocky repl` over `run_source` plus a Timesketch/CSV
   exporter is the smallest credible answer.
4. **Scheduling / recurring hunts** — osquery `schedule`, VQL hunts, LCQL D&R.
   JOCKY's agent polls and runs what is queued; there is no server-side scheduler
   and no run-to-run diff.
5. **Signed tasking** — Velociraptor (own PKI), GRR (mTLS enrolment). JOCKY's
   agent verifies the transport and the token but executes the job payload
   without checking the `payload_sha256` it is handed; that check is a few lines
   and belongs next.
6. **Untrusted-rule sandboxing** — Zircolite runs field transforms under
   RestrictedPython. JOCKY's rules are pure data on a bounded engine (the safest
   starting point) but the *scripts* are the privileged party, so a rule corpus
   is only as dangerous as the engine that reads it.

## Honest boundaries
- YARA and Sigma support are **subsets**, documented as such, and the refusals are
  tested. "Reads your rules" is not "implements the specification".
- The linear-time engine trades speed on trivial patterns (Python-level VM) for
  bounded worst cases; a hostile 200 KB line still costs ~1.5 s, where a
  backtracking engine costs forever.
- Nothing here matches Dissect's artifact breadth or Velociraptor's fleet
  orchestration, and this note claims neither.

## Citations (read 2026-09-16)
- VQL: <https://docs.velociraptor.app/docs/vql/>, JOIN/`memoize`:
  <https://docs.velociraptor.app/docs/vql/join/>, artifacts:
  <https://docs.velociraptor.app/docs/vql/artifacts/>
- osquery performance safety:
  <https://osquery.readthedocs.io/en/stable/deployment/performance-safety/>
- Dissect: <https://docs.dissect.tools/en/latest/>,
  <https://github.com/fox-it/dissect>
- Sigma specification 2.1.0:
  <https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/specification/sigma-rules-specification.md>
- Chainsaw: <https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/README.md>,
  Hayabusa: <https://raw.githubusercontent.com/Yamato-Security/hayabusa/main/README.md>,
  Zircolite: <https://raw.githubusercontent.com/wagga40/Zircolite/master/README.md>
- YARA writing rules: <https://yara.readthedocs.io/en/stable/writingrules.html>
- LCQL: <https://docs.limacharlie.io/4-data-queries/lcql-examples/>,
  GRR flows: <https://grr-doc.readthedocs.io/en/latest/quickstart.html>,
  Artemis: <https://raw.githubusercontent.com/puffycid/artemis/main/README.md>
- KAPE/EZ tools: <https://ericzimmerman.github.io/KapeDocs/>, <https://ericzimmerman.github.io/>
- JOCKY side: `jocky/rt/sigma.py`, `jocky/rt/yararules.py`, `jocky/rt/pattern.py`,
  `jocky/rt/builtins.py` (`index_by`/`group_by`), `cap-pattern-engine.md`,
  `cap-performance-envelope.md`.
