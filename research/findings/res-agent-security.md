# Secure C2 design for a legitimate forensic agent

## Scope

Transport auth, per-agent credentials/rotation, signed bundles, replay, ECH/HTTP-3, frontable SNI, rate limits, updates. Repros: real modules, temp dirs.

## Findings

1. **Verification off by default, unreachable.** `client.run(insecure=True)` (`client.py:309`) is the CLI's only path (`cli.py:160-162`); `--help` has no `--insecure`/`--sni`, so the knob its comment cites (`client.py:135-139`) and README's "says so in `--help`" are fiction. Token (`client.py:150`) and payloads cross unauthenticated: an on-path attacker owns the fleet.
2. **No per-agent credential; identity self-declared.** Poll/result accept any `agent_id` (`server.py:631-656`); `jobs` has no claimant column (`:200-235`). Repro: with the token alone I claimed an untargeted job as `agt_deadbeefdeadbeef`; its findings stored under that id — forgery attributable to any host.
3. **Replay, and bundles with no integrity.** `finish_job` guards on `job_id` alone (`server.py:362-365`) and findings insert unconditionally (`:394-398`): an identical re-POST answered `{"stored":true}` and duplicated the row. The wire shape is `{job_id,kind,payload_b64}` (`:148-156`) — no digest, nonce, expiry or signature — and `next_job` sets `running` with no lease (`:326-353`).
4. **Certs come from the `openssl` binary, not stdlib.** `ensure_cert` (`server.py:105-146`): RSA-2048/sha256, 365 days, SAN `localhost,127.0.0.1` only, self-signed, `CA:TRUE`; no rotation or revocation. Stdlib has no certificate issuer: `hasattr(ssl,"create_certificate")` is false and `hashlib` lacks RSA/Ed25519 (measured) — issuance means the `openssl` CLI or `cryptography`.
5. **Peer verification works today.** Measured: `load_verify_locations(<state>/agent.crt)` + `CERT_REQUIRED`, `check_hostname=False` → 200; another self-signed cert → `CERTIFICATE_VERIFY_FAILED`; a `CA:FALSE` leaf → rejected (only because `req -x509` yields `CA:TRUE`). `CERT_NONE` still yields DER via `getpeercert(binary_form=True)`.
6. **"Frontable" cannot express fronting — and fronting is dead.** One parameter sets both SNI and `Host` (`client.py:101-113,154-156`); measured: server saw `SNI=front.example`, `Host: front.example`. Fronting needs SNI ≠ Host; SWGs detect and block that [8], CDNs refuse it. Legitimately left: dial-by-IP, vhost selection at a shared ingress.
7. **ECH/HTTP-3 are unusable.** ECH = RFC 9849/9848 (2026-03) [6] needs a public name the edge keys; OpenSSL gained ECH only after 3.5 [7] while this runtime is OpenSSL 3.0.13 with no `ssl` ECH knobs; no QUIC/HTTP-3 in stdlib (measured).
8. **Operational gaps.** `Handler.timeout is None`, threads unbounded (`server.py:505-508,731-733`) — 24 idle TLS connections produced 24 threads (measured). Client retries fixed-interval (`client.py:357-375`). `identity.json`/`journal.jsonl` are 0644 in a 0755 dir and unsigned (`client.py:273-279,319`).

## Concrete improvements

1. **Pin-then-verify (now, stdlib).** `--server-cert` pins `<state>/agent.crt` (0600, in `Identity`); `load_verify_locations` + `CERT_REQUIRED`; `--insecure` explicit, default off. S · low.
2. **Per-agent secret + signed bundles.** Enrol returns `agent_secret` (server keeps a hash); the bundle gains `digest`, `nonce`, `expires`, `sig` = HMAC-SHA256 over the canonical tuple, RFC 9421-shaped [1]; agent verifies before `_execute`. Ed25519 (`cryptography>=42`) drops the server-side secret. M · medium.
3. **Idempotent, bound results.** Guard the UPDATE on `status='running'` (rowcount 0 → 409, no insert); add `jobs.claimed_by` + claim nonce; reject non-claimants. S · low.
4. **Private CA + mTLS.** Offline CA (`CA:TRUE,pathLen:0`); 30-day leaves (`CA:FALSE`, `digitalSignature`, EKU `clientAuth`+`serverAuth`, single SAN — SPIFFE X509-SVID [2]), rotated at ⅔ life via the poll. Issued by the `openssl` CLI or `cryptography>=42` (`CertificateBuilder`+CRL, both exercised). L · medium-high (lockout risk).
5. **Rate limit + backoff.** `Handler.timeout=30`, bounded semaphore, per-IP token bucket → 429 + `Retry-After`; client capped backoff with full jitter [3]. S · low.
6. **Harden state, retire fronting.** 0700 dir and 0600 files; document `--sni` as an ingress/vhost selector, add `--host-header`; delete "frontable" from README/DESIGN. S · low.
7. **Signed updates.** Verifiable metadata, monotonic version + expiry, agent-side check against an embedded key (TUF rules [4]); PEP 740 attestations if pip is the channel [5]. M · medium.

## Verification approach

- `serve` on port 0: pinned client → 200; wrong pin or rogue-CA agent cert → handshake failure.
- Re-POST a result → 409 and one finding row; non-claimant → 403; wrong-key/expired/nonce-reused bundle → refused and journalled; valid bundle executes; `tests/test_agent.py` green.
- 32 idle TLS sockets → threads capped; bursts → 429 + `Retry-After`; `stat -c %a` = 600/700.

## Citations

1. RFC 9421, 2024-02-14 — https://www.rfc-editor.org/info/rfc9421/
2. SPIFFE X509-SVID (Stable) — https://spiffe.io/docs/latest/spiffe-specs/x509-svid/
3. AWS, backoff with jitter, 2019-12 (dated) — https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/
4. TUF spec v1.0.36, 2026-08-05 — https://theupdateframework.github.io/specification/latest/
5. PEP 740 / PyPI, 2024-11-14 — https://blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations/
6. RFC 9849 + RFC 9848 (ECH), 2026-03 — https://www.rfc-editor.org/info/rfc9849/
7. OpenSSL ECH, 2026-03-11 — https://openssl-library.org/post/2026-03-11-ech/
8. Zscaler ThreatLabz, 2022-03-22 (dated) — https://www.zscaler.com/blogs/security-research/analysis-domain-fronting-technique-abuse-and-hiding-cdns
