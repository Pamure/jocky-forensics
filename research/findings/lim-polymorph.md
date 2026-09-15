# lim-polymorph — polymorphic encoder: what it really buys

## Scope
`jocky/poly/encoder.py`, `jocky/poly/wire.py`, `tests/test_poly.py`, claims in `docs/DESIGN.md:100-114` / `README.md:131`. Probed inline on the current tree (CPython 3.12.3, Linux 6.6.87.2-WSL2): 20 builds × 7 scripts, plus `evidence/polymorphism.csv` (1000 builds).

## Findings
1. **The permutation ships in the artifact, unkeyed.** The opcode bijection is header JSON (`encoder.py:535-541`); `header_key` is the clear 16 bytes before it, and the payload key is `header["key"]` (`encoder.py:539,631-633`). Measured: `opmap_size = 50 = len(OPCODES)` (`compiler.py:83-87`) in all 20 artifacts, contents all distinct. The artifact hands over its own decoder table.
2. **Recovery needs no cryptanalysis.** A ~120-line standalone unpacker (no `jocky` imports) recovered 44 constants, 17 globals, 2 protos and a listing of `scripts/triage.jky` in 0.99 ms; `PolyEncoder.decode` 0.52–0.94 ms. "Recoverable in minutes" overstates the cost.
3. **Canonicalisation collapses all builds to one program.** Strip `NOP*`, fold `CONST;CONST;ADD`, remap `JMP/JMPF/JMPT/ITER_NEXT/TRY_ENTER` (`encoder.py:196-227`), render constant values: **1 digest per script, 7/7 scripts, 20 builds each**. One normalised-stream signature covers every future build; `README.md:131` counts hashes, not signature resistance.
4. **A 5-byte static signature has 100% recall.** `JKY1`+version are unconditional (`encoder.py:550-551`), 20/20 builds matched; harness sizes 3625–4175 B, σ 98.6, 367 distinct/1000. Magic-at-0 plus size band is complete coverage.
5. **The metric cannot see any of this.** Uniqueness is `len({sha256})` (`evidence.py:161,174-175,366`; `cli.py:82`); no similarity distance exists: the result is unfalsifiable by construction.
6. **Splitting keeps the originals.** `_split_constants` appends parts but never unreferences the original, still serialised (`encoder.py:254-276,359-372`). Orphans: 4–15 per script (`evidence.jky` 18/72, 8 whole strings). Every literal survives intact in artifact and memory.
7. **Junk is labelled and shape-preserving.** `NOP0..NOP7` are real opcodes (`compiler.py:83-87`), 1–3 per statement start (`encoder.py:278-292`), and `proto.starts` is serialised (`encoder.py:374-390`). Junk is 8.9–16.1% of decoded instructions. `DESIGN.md:110`'s "defeats control-flow shape matching" is false.
8. **No CFG work, no binding, forgeable MAC.** Operands get only a per-proto slot bijection (`encoder.py:295-325`); the payload is one SHA-256-counter XOR stream keyed from the header (`encoder.py:533`); `mac_key` is plaintext `blob[:32]` (`encoder.py:631`). After rewriting `seed`→`ff…ff` and `nops` 145→146 I recomputed the MAC and `decode`/`inspect` accepted it.
9. **Costs.** Artifact 3.4–6.9× the canonical wire image (triage 2896 vs 579 B); header ≈⅓; 36–49% of payload is per-constant key material (`encoder.py:334-338`), worthless given (1). Entropy 7.89–7.93 bits/byte: heuristics flag it.
10. **Memory needs no unpacking.** A child that only read an artifact and decoded it exposed both string literals in its own `/proc/<pid>/mem` (24.4 MB scanned); neither is in the artifact bytes.

## Concrete improvements
1. **Out-of-band keying.** HKDF the header/payload/MAC keys from a per-deployment secret; the header carries a nonce only; drop `seed`/`build` (`encoder.py:537-539`), which leaks the operator seed. Effort S, risk medium (`decode`/`inspect` become key-gated). The only change that moves the threat model.
2. **Fix the measurement first.** Canonical digest (3), similarity distance and magic/size-band counter in `evidence.py` and `jocky build --repeat`. Effort S; makes `README.md:131` falsifiable.
3. **Constant hygiene.** GC unreferenced pool entries; derive per-constant keys from the payload key by index instead of storing 16 bytes each (~40% of payload). Effort S–M, risk low (`tests/test_poly.py:160` changes).
4. **Only then raise cost:** flattened protos with permuted block order and key-derived opaque predicates, then superoperator fusion so instruction boundaries need the codebook (both L; step-budget semantics, `TRY_ENTER`/`ITER_NEXT` retargeting, 2–4× runtime). Without (1) they repeat finding 1, and flattening is auto-removable — linear gain, not exponential.
5. **Detector parity.** `det.jocky_artifacts()` (magic + size band + entropy) and opt-in `det.memory_literals(pid, needles)`. Effort S–M, risk low.
6. **Correct `DESIGN.md:110` and `README.md:131`.**

**Not fixable:** an artifact an endpoint decrypts alone, a local analyst does too; decoded code is resident while running; kernel telemetry sees the reads. Honest ceiling: uniquely-hashed, not signature-resistant.

## Verification approach
Rebuild one script 20×, normalise each artifact (decode → strip NOPs → fold → remap operands → render values), assert one digest, and report magic-prefix matches plus the size band. Decode without a key must fail; with it must succeed; re-sealing without it must fail. Then red-team: `JKY1` at offset 0 and the canonical-form rule must both match all `jocky build --repeat 1000` artifacts.

## Citations
- `docs/DESIGN.md:100-114`, `README.md:131`, `evidence/polymorphism.csv` — audited above.
- YARA process-memory scanning: yara.readthedocs.io/en/stable/commandline.html (canonical; retrieved 2026-09-15).
- CFF detectable and auto-removable: synthesis.to/2021/03/03/flattening_detection.html (2021-03-03, canonical-but-dated); tooling github.com/eset/stadeo (2020-03-19).
- Similarity digests vs `sha256` uniqueness: github.com/trendmicro/tlsh (2015, canonical-but-dated).
