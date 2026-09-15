# Modern obfuscation for JOCKY bytecode payloads

## Scope
CFF, opaque predicates, MBA, instruction virtualization, constant unfolding, self-modifying bytecode, and deobfuscation tooling — assessed against `jocky/poly/encoder.py` and `jocky/lang/vm.py`. *Measured* figures are mine: 30 builds, 15×7 script-builds; no suite, harness or linter ran.

## Findings

**1. The payload is self-decoding: obfuscation here is formatting, not secrecy.** `PolyEncoder.decode` (encoder.py:569) runs in-process before execution (runner.py:60-80); `decode(art).disassemble()` (compiler.py:130) produced a 281-line listing with all constants in clear, **1.3 ms measured**. Encoder admits this (encoder.py:54-62). *Impact:* it must be inverted to execute, so it cannot exceed its inverse.

**2. Current transforms are control-flow invariant.** `_insert_junk` prepends `NOPk` only at `proto.starts` (encoder.py:278-293); `_split_constants` rewrites only `CONST` sites (encoder.py:254-276); no edge changes. **Measured:** 15 builds × 7 scripts gave one identical statement-block CFG per script; sizes varied (hunt: 211–230 instructions, 2624–2892 bytes). *Impact:* DESIGN.md §3's "defeats control-flow shape matching" is false.

**3. Opaque predicates must not range over user values.** JOCKY has no bitwise ops (compiler.py:83-93) and `%` is Python modulo on arbitrary-precision ints (vm.py:415-420): `(n*n - n) % 2 == 0` is opaque for every int, but `i * 0 == 0` is false for a string. *Impact:* keep guards on transform-introduced ints only.

**4. Classical MBA is inexpressible — refuse it.** Only ADD/SUB/MUL/DIV/MOD/NEG/NOT exist (compiler.py:84-88); MBA tooling assumes bitwise ⊕∧∨ over modular words, solving 99.86% of wild expressions (trailofbits.com, 2026-04-03). *Impact:* arithmetic identities and De Morgan rewrites only — the decoder folds them free.

**5. A second interpreter layer is detectable, not resistant.** Pushan recovers complete virtualized CFGs from Tigress/VMProtect/Themida (arXiv 2603.18355, 2026-03-18); Tigress dispatch/handler/VM structures are statically detectable (arXiv 2601.12916, 2026-01-23). JOCKY's dispatch is one dict lookup (vm.py:170, 269) behind one hookable method (vm.py:255). *Impact:* refuse — one liftable layer at real cost.

**6. Self-modifying bytecode breaks JOCKY's integrity story.** HMAC covers the encoded bytes (encoder.py:47-53); `inspect` reports `nops`/`nconst`/`artifact_hash` (encoder.py:580), desynced by mutation; the harness compares a reference findings hash (evidence.py:183). *Impact:* refuse — forfeits "unique bytes, identical findings" and dies to `sys.settrace`.

**7. Tooling and LLMs raise the bar.** Compiler-optimisation lifting (SATURN, arXiv:1909.01752, 2019, canonical-but-dated) and the Miasm/Triton/angr symbolic stack strip MBA and flattening; LLMs beat bogus control flow and flattening, failing only on combined transforms (arXiv 2505.19887, 2025-05-26); fine-tuned models undo seven chained transforms, −89.21% Halstead (DIMVA, 2025-07-11). In-process decryption is no barrier: PyArmor v8+ falls to static key recovery (cyber.wtf, 2025-02-12). *Impact:* one transform is a speed bump.

**8. Budget.** `DEFAULT_MAX_STEPS = 50_000_000` (runner.py:27) against 155 instructions in `scripts/hunt.jky`; run ≈41 ms (procfs-bound), decode 0.83 ms. *Impact:* a K-chain dispatcher (~4K extra steps per block) is invisible.

## Concrete improvements
1. **Per-build CFF of statement blocks with opaque dispatch** (L, medium risk). Record `Proto.ends` beside `starts` (compiler.py:110) for exact extents under every terminator (`break`/`continue` lower to `JMP`, compiler.py:266-271); split each proto into K = min(8, blocks), permute block order per build, add one state slot past `nlocals` (vm.py:326), end each block by setting state and jumping to a `LOADL S; CONST b; EQ; JMPF` dispatcher chain. Guards stay on transform-introduced ints.
2. **Wire `jocky disasm` for artifacts** (S, low risk): `cmd_disasm` takes only source (cli.py:119-121); exposes the ceiling, giving maintainers the inverse tool.
3. **Assert CFG polymorphism** (S, low risk): require ≥2 block-graph signatures over N builds — today 1.
4. **Ship `strip_cff`** (M, low risk) for detection (DESIGN §5's mirror image).
5. **Reject MBA, virtualization, SMC** (S, low risk) with findings 4-6 as rationale.

## Verification approach
- **Exact inverse**: 200 builds × 7 scripts, `strip_cff(flatten(prog)) == prog` across `Proto.code`, `handlers`, `starts` — catches all remapping bugs.
- **Behavioural**: extend findings-hash equivalence (tests/test_poly.py:64-90) with a corpus forcing risky shapes: flattened `break`/`continue`, `try`/`catch` across blocks, early `return`, loop closures, `emit` in `catch`, one `JockyLimitError` truncation.
- **Cost**: flattened steps ≤3× unflattened on that corpus.
- **Effectiveness**: block-graph distinctness over 30 builds (today fails) plus existing uniqueness assertions (tests/test_poly.py:81).

## Citations
- CoBRA MBA simplifier — trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/ (2026-04-03)
- LLM assembly deobfuscation — arXiv:2505.19887 (2025-05-26)
- Beste et al., LLM code deobfuscation, DIMVA — cispa.de/en/research/publications/84747 (2025-07-11)
- Pushan, trace-free devirtualization — arXiv:2603.18355 (2026-03-18)
- Static detection of Tigress VM structures — arXiv:2601.12916 (2026-01-23)
- Pyarmor v8+ unpacking (in-process decryption is dumpable) — cyber.wtf/2025/02/12/unpacking-pyarmor-v8-scripts/ (2025-02-12)
- SATURN, compiler-optimisation deobfuscation — arXiv:1909.01752 (2019, canonical-but-dated)
