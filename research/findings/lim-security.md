# JOCKY management-plane threat model (`lim-security`)

## Scope
Files: `agent/{server,client}.py`, `runner.py`, `poly/encoder.py`, `rt/builtins.py`, `rt/raw.py`,
`exec/memfd.py`, `cli.py`, `DESIGN.md`. Adversaries: on-path attacker, token holder, local user
on an agent host. *verified* = reproduced in-process this session.

## Findings
1. **TLS verification off by default → fleet RCE.** `client.py:309,135-139`
   (`check_hostname=False`, `CERT_NONE`); `cli.py:160` passes neither flag, so nothing enables
   verification, contradicting `DESIGN.md:175-177`. On-path attacker reads `X-JKY-Token`
   (`client.py:150`), forges a poll response → code execution on every host.
2. **Jobs unsigned/unvalidated.** `server.py:658-671` accepts any `kind` + base64;
   `client.py:267` → `runner.py:83-87` runs `JKY1` artifacts or compiles raw source. No
   signature, submitter identity or allowlist; nothing proves who authored what ran.
3. **Forged/replayed findings, chosen provenance.** *Verified*: `POST /v1/jobs/result` for
   `job_deadbeef`/`agt_ghost` → `200 {"stored":false,"findings":1}`; replaying it left two rows.
   `server.py:654-655` ignores `stored`; `:381-404` unconditional; `:199-231` lacks
   ownership/uniqueness/idempotency.
4. **One static token; self-asserted identity.** `server.py:550-557`: process-wide token, no
   rotation/expiry/per-agent key; `enroll` keys on `(host,name)` (`:260-272`), so a holder
   re-enrols as a victim hostname and takes its jobs. Token is argv (`cli.py:230`);
   `/proc/<pid>/cmdline` is `0444` (*verified*; proc_pid_cmdline(5)) → any local user or `fs.read`.
5. **No capabilities; two escapes.** `fs.read` opens any readable path (`builtins.py:206,260`).
   *Verified*: `mem.syscall(62,pid,9)` killed a live process (`:305`); `mem.memfd_run` keeps a
   caller shebang (`memfd.py:71-77`), so `#!/bin/sh` ran a shell as that user (`:307`); `:305`
   takes 7 args while `raw.py:147` caps 5.
6. **Store world-readable, unsigned, re-writable.** *Verified*: `store.db` is `0644` holding
   every `evidence_json`; no chain, audit table or `submitted_by` (`server.py:199-231`);
   `:355-370` re-settles jobs, so "who told which host to run what" (`:23-27`) is unreconstructable.
7. **Artifact HMAC decorative.** Key ships inside (`encoder.py:53-62,552,631-635`), 16-byte tag:
   *verified* tamper + recomputed footer → `decode()` accepts.
8. **No replay protection, rate limit or job TTL.** `MAX_BODY` (`server.py:58`) caps one body; the
   queue is unbounded; `/v1/health` leaks the version (`:617`).
9. **Journal plaintext `0644`, written post-execution** (`client.py:401`; perms *verified*): a
   crash loses the "started" record; local users read it.
10. **Cert lifecycle ad-hoc** (`server.py:105-137`): RSA-2048/365 d, unencrypted key, no
    CA/revocation/rotation/pinning.

## Concrete improvements
1. **Pin the server cert** (finding 1). Compare a `getpeercert(binary_form=True)` hash against a
   fingerprint in `agent.json` (0600) from enrolment, refusing mismatch; `--insecure` becomes an
   explicit CLI flag. *S* — regeneration strands agents → add `--repin`.
2. **Per-agent keys, signed jobs** (findings 2/4). Enrol returns a 32-byte secret once (server
   stores `scrypt`); requests carry `HMAC(secret, method|path|sha256(body)|ts|nonce)` (RFC 9421)
   with replay checks; jobs are signed over `job_id|kind|sha256(payload)|target|expires_at`;
   unsigned, expired or repeated jobs are refused. *M* — symmetric only; non-repudiation needs
   Ed25519 via the `openssl` at `server.py:121` (no stdlib signatures).
3. **Bind results to a claimed job** (finding 3). Reject unknown `agent_id`; require `running`
   plus matching claimant; one transaction, rows keyed
   `(job_id, agent_id, ordinal, sha256(evidence))`; duplicates re-return the stored outcome.
   *S/M* — retries must stay idempotent.
4. **Hash-chained audit** (finding 6).
   `audit(seq, ts, actor, action, subject, payload_sha256, prev_hash, hash=H(prev||row))` in the
   same transaction as each enqueue/claim/result/401/429; `jocky audit verify` fails naming the
   first bad `seq`; same chain for the journal (RFC 9162). *M* — tail deletion survives → export
   the head.
5. **Harden files, gate natives** (findings 5/9). `0600` on `store.db`, journal, both state dirs;
   a `VM.ctx` policy enforced in `_fn` (allowlisted `fs.read` roots,
   `mem.syscall`/`mem.memfd_run` off); `kind` allowlist, payload cap, 429 throttling. *M* — a
   filter, not a sandbox: the payload shares the agent's uid, so only a dropped-uid child or
   seccomp bounds it.
6. **Job hygiene** (finding 8). TTL on queued jobs, revoke endpoint, findings-per-result cap,
   `/v1/health` → `{"status":"ok"}`. *S* — throttle state must persist.

## Verification approach
- TLS: a rogue cert or flipped pin makes the agent refuse; `--insecure` skips;
  `pytest tests/test_agent.py` passes.
- Forgery: the forged `result` call → 4xx, zero new rows; unsigned/expired job → agent journals
  `rejected`.
- Identity: a second identity claiming the same `(host,name)` inherits no queued jobs.
- Escapes: `mem.syscall`, `mem.memfd_run("#!/bin/sh\n…")`, out-of-root `fs.read` → policy errors;
  relaxed policy still escapes (residual risk).
- Audit: `sqlite3` row tamper, or journal truncation → `jocky audit verify` non-zero naming the
  sequence; `stat -c %a` asserts 0600.
- Artifacts: recomputing the footer with the embedded key in `tests/test_poly.py` pins that
  property.

## Citations
- RFC 9421 *HTTP Message Signatures*, 2024-02-14 — https://www.rfc-editor.org/info/rfc9421
- RFC 9162 *Certificate Transparency v2.0*, 2021-12-09 (canonical, dated) — https://www.rfc-editor.org/info/rfc9162
- `proc_pid_cmdline(5)` (canonical, dated; corroborated by local `stat` `0444`). Repo refs inline
  above.
