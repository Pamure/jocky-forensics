# Evidence integrity & supply-chain security for JOCKY

## Scope

Repo-side audit of JOCKY's evidence path (harness, artifact envelope, agent store, CLI) against 2024–2026 integrity practice: hash logging, RFC 3161 time, report signatures, TUF/in-toto/SLSA bundles and updates, transparency logs, reproducible builds; stdlib-only marked against third-party/service.

## Findings

1. **Proof bundle not self-verifying.** The harness hashes artifact bytes only (`jocky/evidence.py:156-159`); `report.md` starts with a local clock line (`:348`). The "raw logs a reviewer re-checks" claim (`:3-8`) is trust-only — edits to `runs.json`/`audit.json` are undetectable. [1][5]
2. **Artifact HMAC ≠ authenticity.** The MAC key ships inside the artifact (`jocky/poly/encoder.py:53-62`), read back when verifying (`:634-637`); `tests/test_poly.py:129` pins only that self-keyed path. Anyone can re-MAC an edited artifact, so `jocky verify` must not claim provenance.
3. **`seed=` ≠ reproducible builds.** A seed is accepted (`encoder.py:504-512`) but `encode()` adds fresh `os.urandom(32)` to the RNG (`:520`). Rebuild-and-compare provenance (SLSA L3) is unreachable; docs never say the seed only keys the build. [7]
4. **Findings unbound to jobs.** No payload digest; `findings` has no hash or chain column (`agent/server.py:211-232`, `:395-398`). No one can prove which job bytes caused a finding; sqlite edits are silent — the gap transparency receipts close. [1][2]
5. **Jobs authorized by shared token alone** (`agent/client.py:12-14`), unsigned, no layout: token theft becomes unattributable code execution. [3]
6. **Signing must not run on-target.** The audit hook counts child processes and execs (`evidence.py:9-14`), underpinning the README's "0 child processes" row, so signing and timestamping belong on the analyst host after collection.
7. **No trusted time:** local-clock timestamps only (`agent/server.py:73-75`); host compromise backdates a case. RFC 3161 tokens or log receipts fix it, and neither is stdlib-reachable offline. [4][10]
8. **Reproducibility is narrow:** only findings lists are hashed (`evidence.py:93-94`), while results embed `duration_ms`/`metrics` (`agent/client.py:292-300`) — verify false-alarms without a canonical subset defined.
9. **Updates unauthenticated:** no TUF metadata, pinned digest or downgrade protection, though TUF is maintained (v1.0.36). [6]

## Concrete improvements

1. **Hash-chain manifest + `jocky verify <case-dir>`.** JSONL `{seq,path,size,sha256,prev}` streamed with `hashlib.file_digest`; verify re-walks the chain, set-compares entries against the directory, and matches the head against a copy in the agent sqlite, which is what defeats tail truncation. M · low. [9]
2. **`jocky/canon.py` canonical digest** (findings + errors + truncated + source/artifact digest; timings excluded), shared by harness and verify. S · low.
3. **`jocky sign`:** HMAC-SHA256 over the head with a 0600 operator key and `hmac.compare_digest` (docs must say this proves key possession, not identity); optionally pipe the head to `--signer <cmd>` — minisign, `ssh-keygen -Y sign`, `openssl dgst -sign`, `cosign sign-blob` — analyst-side only, no Python dependency. S–M · medium.
4. **Optional RFC 3161:** document `openssl ts`/`rfc3161ng`/public TSAs rather than hand-rolling DER (~300 lines); ship offline verification only. L · medium-high. [4][10]
5. **in-toto-shaped job statements** (`_type`, `subject.digest.sha256`, `predicateType`): plain JSON, stdlib; DSSE/Ed25519 optional. S · low. [3][8]
6. **`--deterministic` build** dropping `os.urandom` at `encoder.py:520` for byte-identical rebuilds; default path untouched. S · low.
7. **Pinned-digest, monotonic-version updates**, documented as a TUF subset; full TUF (`python-tuf`) optional. S–M · low. [6]

## Verification approach

- `python -m jocky evidence --iterations 50 --out /tmp/ev` then `jocky verify /tmp/ev` → PASS; a flipped byte in `runs.json` → FAIL naming file and link; middle-line deletion → chain break; trailing deletion → caught only via the stored external head.
- Key A verifies, key B fails, a mutated signature fails.
- Two `--deterministic --seed X` builds share one SHA-256; the polymorphism row (1000/1000 unique) stays green by default.
- Two runs of `scripts/evidence.jky` give equal canonical digests despite differing `duration_ms`.
- A re-MAC'd tampered artifact still passes the envelope check — pinning the documented limit.
- `openssl ts -verify` on an emitted token; `cosign verify-blob --bundle` when cosign exists.

## Citations

1. RFC 9943, *Trustworthy and Transparent Digital Supply Chains*, 2026-06-30 — https://www.rfc-editor.org/info/rfc9943/
2. RFC 9942, *COSE Receipts*, 2026-06-30 — https://www.rfc-editor.org/info/rfc9942/
3. CNCF, *in-toto graduation*, 2025-04-23 — https://www.cncf.io/announcements/2025/04/23/cncf-announces-graduation-of-in-toto-security-framework-enhancing-software-supply-chain-integrity-across-industries/
4. RFC 3161 (Aug 2001, updated by RFC 5816) — https://www.rfc-editor.org/info/rfc3161/
5. NIST SP 800-86 (Aug 2006, no revision) — https://csrc.nist.gov/pubs/sp/800/86/final
6. TUF spec v1.0.36, 2026-08-10 — https://github.com/theupdateframework/specification/releases/tag/v1.0.36
7. SLSA v1.1 approved, 2025-04-21 — https://slsa.dev/blog/2025/04/slsa-v1.1
8. Sigstore, *PyPI attestations GA*, 2024-11-14 — https://blog.sigstore.dev/pypi-attestations-ga/
9. `hashlib.file_digest` (3.11+) — https://docs.python.org/3/library/hashlib.html#hashlib.file_digest
10. Sigstore docs, RFC 3161 timestamping — https://docs.sigstore.dev/cosign/verifying/timestamps/
