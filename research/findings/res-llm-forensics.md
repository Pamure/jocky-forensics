# LLM/ML in DFIR and malware analysis (2024–2026) — what JOCKY should adopt

## Scope

LLM/ML in DFIR triage, detection generation, obfuscated-payload analysis and
summarisation; implications for JOCKY's polymorphism; three adoptions: a findings
schema for LLM consumers, a `jocky report` narrative, and injection hardening for a
generator reading attacker-controlled strings. Symbols anchor citations; `detect.py`
is edited concurrently.

## Findings

1. **Triage assists, never investigates.** DFIR-Metric (700 MCQs, 150 CTF, 500 NIST
 CFTT cases): near-zero accuracy on practical disk/memory work; hallucination is the
 blocker [1]. → Keep `detect.triage` authoritative, prose downstream.
2. **Generated rules: fewer FPs, worse recall, priced.** Held-out ADÉ run over 45k
 emails: BEC reply-to 35 hits/0 FP vs human 1558/1; Coinbase 116 TP/16 FP;
 $1.51–5.13 per rule [2]. → Never auto-adopt into `CMD_PATTERNS`; retro-hunt first.
3. **LLM deobfuscation threatens polymorphism; models accept decoys.** Opus 4.6
 solved 40% of 20 Tigress targets (0% multi-layer) at $2.39/success vs $4.83/failure;
 JIT and nested VMs survived, while a vibecoded decoy scored 0/5 blind for $5.2 by
 faking a benign `main` [3]. → JOCKY is single-transform grade with a public codec
 (`jocky/poly/encoder.py`; clear-text VM, `jocky/lang/vm.py`): static reading beats
 emulation; only nesting, cost inflation and decoys help.
4. **Injection is architectural.** A 78-study SoK reports >85% attack success under
 adaptive attacks and <50% mitigation for most defenses [4]; tool poisoning defeats
 both defense classes [8]; ARGUS reaches 28.8%→3.8% only via causal provenance [5].
 → A generator over findings is an injection sink, not a wording problem.
5. **Findings are untyped, unversioned, free-text severity.** `_finding` emits five
 keys with no id/time/source/MITRE (`detect.py:_finding`); `Finding.from_raw` defaults
 everything, accepts bare strings and coerces severity to `str`
 (`server.py:158-190`); `triage()` counts whatever arrives (`detect.py:454`). →
 Nothing stable to ground citations on.
6. **Embedding similarity succeeds hash uniqueness.** Opcode ML works [6]; EMBERSim
 is the reference BCS databank [7]. Stdlib-only excludes numpy/FAISS, but a decoded
 opcode+arity fingerprint with pure-Python SimHash restores cross-build clustering.
7. **Summarisation is where hallucination bites:** fluent reports omit unchecked
 sources and invent links; grounding plus strict schemas are the controls [1][5]. →
 Template-first report, sentences tied to finding ids.
8. **Cost asymmetry is the durable defence:** 3.6–4.2 KB artifacts, 17.7 ms median
 (`README.md`, `evidence/report.md`) vs $2.39–4.83 per LLM analysis [3]. → Measure
 cost per recovered semantic.

## Concrete improvements

**A. `findings.v1` schema.** Fields `schema_version`, `id`, `check`, `severity`
(enum), `title`, `observed_at`, `source`, `evidence`, `recommendation`, `mitre[]`,
`taint[]`; validated in `_finding`/`Finding.from_raw`, invalid records rejected.
*S–M.* Risk: free-form emit scripts change behaviour.

**B. `jocky report`.** `--findings X.json | --state DIR`, `--format md|json|prompt`;
deterministic, grouped by check, severity-ordered, printing scanned counters so
"clean" ≠ "failed"; `prompt` is the sanitised LLM view. *M.* Risk: keep `--llm` off
by default.

**C. Taint and sanitiser.** Attacker bytes already reach evidence (`cmdline[:400]`,
`environ`, persistence paths). New `jocky/rt/sanitize.py` strips C0/C1, bidi,
invisibles and markdown, truncates, wraps values in nonce-delimited data-only blocks,
sets `taint:["untrusted"]`, and adds a `prompt_injection_lure` check; the model gets
no tools. *M.* Risk: sanitise the prompt view only.

**D. Behaviour fingerprint.** sha256 over `(opcode, arg-kind)` of the decoded stream
plus the finding hash, stored in artifact metadata and sqlite; SimHash/cosine
grouping. *S*, embeddings *L*. Risk: compute post-decode.

**E. Cost-of-understanding stage.** Hand N artifacts to an LLM with repo access;
record dollars, turns, success per profile. *M.* Risk: keep out of default
`evidence`.

Not fixable: kernel telemetry exposes `memfd_create`/`execveat`; no transform hides
semantics from a model that can read `jocky/lang/vm.py`.

## Verification approach

- Schema: `triage()` and 1k emitted payloads validate; bare-string emits rejected,
 not stored as `check:"unknown"`.
- Report: golden file; two runs byte-identical; run against a real `--state` sqlite.
- Injection: fixture cmdline `IGNORE PREVIOUS INSTRUCTIONS…` must appear in
 `--format prompt` only inside the nonce block, controls stripped; canary not obeyed
 on ≥3 models.
- Fingerprint: 1000 builds → one fingerprint; 20 scripts stay apart.
- Cost benchmark: median dollars, turns, success per profile.

## Citations

1. DFIR-Metric — arXiv:2505.19973, 2025-05-26.
2. LLM-generated detection rules (Sublime ADÉ) — arXiv:2509.16749, 2025-09-20.
3. The Cost of Understanding (Elastic Security Labs) — 2026-04-21.
4. Prompt injection in agentic coding assistants (SoK) — arXiv:2601.17548, 2026-01-24.
5. ARGUS (context-aware prompt-injection defense) — arXiv:2605.03378, 2026-05-05.
6. OpCode-based malware classification — arXiv:2504.13408, 2025-04-18.
7. EMBERSim (CrowdStrike) — 2024-06-06, canonical but dated.
8. Prompt injection to tool selection (ToolHijacker) — arXiv:2504.19793, 2025-04-28.
