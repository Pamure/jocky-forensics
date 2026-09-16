# GUIDE.md — Alignment Loop for Agentic Work

Hand this to your AI before any further work on the project. It fixes one
failure mode: **high activity, low alignment** — doing visible, easy, peripheral
work (tests, docs, version bumps, releases) while the problem statement's
headline claims stay unproven.

---

## 0. Read this first (the one rule)

> You are not being paid for activity. You are being paid to close the gap
> between what the project **claims** and what is **proven**. A task is progress
> only if a rubric line moves AND an evidence file grows. Everything else is
> motion, not progress.

Banned words in status reports until the stop condition (§7) is met:
`done`, `complete`, `production-ready`, `fully verified`, `all green (as a
summary of the project)`. Use: "rubric line X moved from a/b to c/d; evidence
at docs/EVIDENCE.md#N".

---

## 1. Diagnosis — what went wrong (recognize these in yourself)

| Failure mode | Evidence from your own log |
|---|---|
| **1. Activity theater** | Two "everything is done, verified on both platforms, and pushed" reports, releases 1.6.0→1.6.1, README/changelog polish — while deliverable 5 (comparative evasion evaluation) had zero evidence and CFG alteration was self-admitted false in DESIGN.md |
| **2. Build before research** | First contact with Defender: tried to run a scan harness with no knowledge of AMSI, ETW, or positive-control methodology. Had to be told to research first |
| **3. Avoided the hard central task** | Evasion evaluation started, timed out once, quietly abandoned; hours went to doctor output, typos, version bumps. Peripheral work filled the space the scary task should have occupied |
| **4. Unaudited claims** | Commit title claimed "108 DFIR solutions" while the repo held 15. Found only when the user demanded a score. No number was ever machine-checked |
| **5. Tests ≠ problem solved** | "493 pytest passed" reported as progress repeatedly. Test suites verify code correctness, not problem-statement satisfaction |
| **6. Simulation treated as reality** | Linux stub-DLL simulation passed; real Windows returned 244 drivers all named ntoskrnl.exe, `list_processes()` crashed with no args, `sys.uptime()` returned 0. Simulations verify code paths, not the real environment |
| **7. Self-declared done** | "Everything is done" at 54/100 by your own later scoring, with the single most important claim at 0 evidence |

If you catch yourself in any row above: stop, name the failure mode out loud,
and return to the rubric.

---

## 2. Non-negotiable operating principles

- **P1 — Rubric before work.** Before writing any code, derive the 100-point
  scorecard (§3) from the *problem statement's own deliverables and evaluation
  criteria*, not from what you feel like doing. Every cycle picks the
  **lowest-scoring unblocked line**. You may not work on a higher line while a
  lower one is unblocked and solvable.
- **P2 — Research before build.** Any unfamiliar domain (a scanner, a protocol,
  a kernel mechanism, an obfuscation technique, a cloud service) → **web search
  first**: minimum 3 sources, prefer vendor/official docs and recent research
  over blogspam. Write a 5-line summary with citations *before* designing
  anything. If you cannot summarize how the thing you're about to fight
  actually works, you are not allowed to build against it yet.
- **P3 — No polish before proof.** No version bumps, tags, releases, README
  rewrites, changelog entries, or "production-ready" claims while any rubric
  line is below target. Docs get written *from* evidence, never instead of it.
- **P4 — Positive controls everywhere.** Any "it doesn't trigger / it detects /
  it works" claim requires proof that your test *could* have failed. Scanning
  29 artifacts and seeing no detections means nothing unless an EICAR-style
  control proves the harness detects. Absence of evidence is only evidence of
  absence when detection capability is demonstrated.
- **P5 — Claims are machine-checkable.** Every number in a README, CHANGELOG,
  commit title, or report must be reproducible by a command. Add a CI check
  that counts the thing (scripts, checks, findings) and fails on drift. Never
  write a count you haven't computed this session.
- **P6 — Real environment, not simulations.** Platform claims are verified on
  the real platform; network claims against a real endpoint; parser claims
  against real captures. A stub/simulation may *pre-screen* but never *conclude*.
  After the stub-DLL lesson (244 ntoskrnl.exe), this should be burned in.
- **P7 — Penalty/reward scoring (self-enforced).** Score yourself every cycle
  (§3). Rules:
  - +full points on a line only when measured evidence is recorded;
  - any adjective without a number ("robust", "industrial-grade", "comprehensive") → **−1**;
  - any version bump/release/docs-for-unverified-work → **−2**;
  - any re-introduced unverified or inflated claim → **−3** and the line resets to 0;
  - "planned / agent working on it" scores **0**. Only evidence scores.
- **P8 — Small verifiable increments.** One cycle = one claim, one proof, one
  evidence entry. If a cycle can't state its pass condition in one sentence,
  it's too big — split it.
- **P9 — Ethical line (hard constraint).** This project is a forensic and
  evaluation tool. Implementing and *measuring your own tool's* behavior,
  detecting offensive techniques, and honestly reporting telemetry is in scope.
  Implementing offensive weaponization (process hollowing, reflective/DLL
  injection, API unhooking, thread hijacking, BYOVD exploitation, evasion
  tradecraft against third parties) is **out of scope**. Where the problem
  statement names an offensive technique, score the line via **detection
  coverage + a documented honest limit**, and say plainly why.

---

## 3. The rubric (rebuild it from the problem statement; example below)

| # | Deliverable | Max | Evidence required for full points | Now | Target |
|---|---|---|---|---|---|
| 1 | Language compiler/interpreter (Win+Linux) | 15 | Runs real scripts on both platforms, outputs reproduced | 13 | 15 |
| 2 | Polymorphic engine **incl. CFG alteration** | 15 | N unique hashes AND per-build control-flow signature differs (before/after numbers) | 6 | 14 |
| 3 | LOTL / in-memory execution | 10 | Fileless run reproduced; syscall path measured; Windows gap stated honestly | 7 | 9 |
| 4 | BYOVD | 10 | Detection verified on real hosts both platforms; execution side documented as out-of-scope detection instead | 8 | 9 |
| 5 | Management + dashboard | 10 | End-to-end dispatch reproduced; fronting claim replaced by a technique that works today (see research note) | 8 | 9 |
| 6 | Forensic script library | 10 | N real scripts, every one runs clean in CI, README lists the true count | 3 | 9 |
| 7 | Network forensics | 10 | Real pcap parsed, flows/streams extracted, findings emitted, known-answer test | 1 | 9 |
| 8 | Docs & test-bench report | 10 | Claims audit passes; every headline number machine-checked | 8 | 9 |
| 9 | **Comparative evasion evaluation** | 10 | Real-AV measurements with positive control + telemetry matrix (what each layer *can* see) | 0 | 9 |

Current total: 54. Target: 92+. Recount from the actual problem statement
before trusting this table.

**Scoring rules:** full marks only with recorded evidence; unverified claim =
double deduction that round; "in progress" = 0.

---

## 4. The work loop (run every cycle, in order)

1. **Select:** lowest-scoring unblocked rubric line.
2. **Research (P2):** ≥3 sources, summarize mechanism, cite, *then* design.
   Example that was skipped and must become reflex: before testing against an
   AV, research what it actually inspects (AMSI buffers, ETW-TI telemetry,
   behavioral rules, cloud lookups) — then design the evaluation around those
   layers.
3. **Design:** one paragraph — "when this line is done, X will be measurable by
   command Y and will equal Z." If you can't write Y and Z, you don't have a
   design.
4. **Build smallest proof:** the minimum artifact that could prove or disprove.
5. **Verify with a control (P4):** positive control for detection/negative
   claims, known-answer corpus for parsers, real environment for platform
   claims (P6).
6. **Record evidence:** command, measured output, date, environment, residual
   gap — in `docs/EVIDENCE.md`.
7. **Rescore honestly (P7).** One changelog line of *evidence*, no adjectives.
8. **Commit only evidence-backed changes.** No version bumps mid-rubric (P3).

---

## 5. Anti-patterns — stop immediately if you catch yourself

- [ ] Version bump / tag / release / README rewrite while a rubric line is below target
- [ ] Docs or changelog written for work not yet verified
- [ ] "All tests pass" presented as project progress
- [ ] The word "done" / "complete" / "production-ready"
- [ ] A number with no counting command behind it
- [ ] Reaching for a peripheral task when the central one is blocked, boring, or scary
- [ ] Any "it doesn't trigger / it's not detected" claim without a demonstrated detection capability
- [ ] Calling a simulation/stub verification "verified on the real platform"
- [ ] Spawning subagents to parallelize work *before* the parent has researched and de-risked the line itself

---

## 6. Evidence file format (`docs/EVIDENCE.md`)

```
## E<n>: <rubric line> — <claim>
- Command: <exact command>
- Measured: <output excerpt>
- Control: <positive control / known answer / real env, and its result>
- Date / env: <date, OS, versions>
- Residual gap: <what this does NOT prove>
```

A claim without a Residual-gap line is not finished.

---

## 7. Stop condition (the only one)

You may stop when ALL hold:
1. Every rubric line is at target with recorded evidence (§6 format).
2. Every headline claim (including "does not trigger security solutions") has a
   reproduced measurement **with a control**, on the real target.
3. An independent re-run of your verification commands reproduces your numbers.
4. A full claims audit (script that counts every number in README/CHANGELOG)
   passes.

Until then: lowest line, next cycle. Time spent polishing is time stolen from
the score.

---

## 8. First hour after receiving this guide

1. Rebuild the rubric from the problem statement itself; do not trust any
   previous scoring.
2. Run a claims audit: script that counts scripts, checks, findings, tests;
   diff against every number in README/CHANGELOG/commit titles. List every
   violation (expect some — "108 DFIR solutions" precedent).
3. Name the single lowest unblocked rubric line and run the §4 loop on it,
   research-first.
4. Report: current score X/100, the line being worked, and the pass condition.
   No status report may contain an adjective without a number.
