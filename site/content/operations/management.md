# The management server and its agents

A single host with a script is an investigation. Several hosts with one operator
is an operation, and that needs the other half of SIH26148: a central management
interface. `jocky serve` is a TLS server with token authentication, a SQLite
store and a small HTTP API; `jocky agent` is a polling client that enrols once,
asks for one job at a time, runs it with the same runtime the CLI uses, and
reports the findings back with the provenance needed to reconstruct a report
later.

The design rule is that **all policy lives on the server**: which hosts, which
checks, which payload, when. The agent is deliberately dumb — it runs exactly
what it is handed and journals what it did.

```text
operator ── POST /v1/jobs/submit ──▶ server (sqlite: agents, jobs, findings)
                                      ▲                    │
                                      │ POST /v1/jobs/result│ POST /v1/jobs/poll
                                      │                    ▼
                                    agent ──▶ run source / run fileless ──▶ findings
```

## Start the server

```bash
./venv/bin/jocky serve --port 8443 --token SECRET --state /tmp/jky-server
```

| Flag | Default | Meaning |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address. Anything but loopback exposes the API to the network |
| `--port` | `8443` | TCP port; `0` binds an ephemeral port and the banner prints the real one |
| `--token` | generated | Shared secret. Omitted, a URL-safe 32-byte token is printed **once** to stderr |
| `--cert`, `--key` | generated | PEM certificate and key; omitted, a self-signed pair is created under `--state` |
| `--state` | `.jocky-server` | State directory: `agent.crt`, `agent.key`, `store.db` |

On first start it generates the certificate by shelling out to `openssl` — the
server must not need wheels installed before it can talk TLS:

```text
jocky-server token (generated, shown once): 62gLISSHafI7nKFbJCYu96nNcCShsiLByexFRmAmntU
jocky-server: generated self-signed certificate at /tmp/jky-docs/state/agent.crt
jocky-server listening on https://127.0.0.1:19446
```

The certificate is self-signed with `CN=jocky-management`, valid for 365 days,
and carries a SAN so the same file works for loopback and a local name:

```text
subject=CN = jocky-management
issuer=CN = jocky-management
notBefore=Sep 15 17:46:00 2026 GMT
notAfter=Sep 15 17:46:00 2027 GMT
X509v3 Subject Alternative Name:
    DNS:localhost, IP Address:127.0.0.1
```

Case data is not world-readable: the state directory is `0700`, `store.db` and
`agent.key` are `0600`, and the certificate is `0644`. Point `--cert`/`--key` at
your own pair for a real deployment; when you do, no certificate is written into
the state directory at all (verified: only `store.db` appears there).

The server logs one line per request, and one line per state change, to stderr:

```text
jocky-server: enrolled agent agt_c31ffd6810dbb994 name='docs-agent' host='stormbreaker'
jocky-server: 127.0.0.1 POST /v1/jobs/poll 204 agent=agt_c31ffd6810dbb994 5.3ms
jocky-server: job job_48c047ac8c5ebb7e finished status=ok
jocky-server: 127.0.0.1 POST /v1/jobs/result 409 agent=agt_c31ffd6810dbb994 0.3ms
```

## Enrol an agent

An agent enrols on first run and stores its identity next to its journal:

```bash
./venv/bin/jocky agent --server https://127.0.0.1:8443 --token SECRET --once \
    --name docs-agent --state /tmp/jky-docs/agent-state
```

```text
jocky-agent: pinned server certificate a7a9a20e5f9a7346…
jocky-agent agt_c31ffd6810dbb994 polling https://127.0.0.1:19443 (journal /tmp/jky-docs/agent-state/journal.jsonl)
jocky-agent: job job_48c047ac8c5ebb7e (source) ok, 1 finding(s)
```

`--once` performs exactly one poll-and-execute cycle and exits `0` — that is the
mode a cron entry or a one-shot collection run uses. Without it the agent polls
every `--interval` seconds (default `5.0`) until Ctrl-C, which is also a clean
exit.

| Flag | Effect |
|---|---|
| `--server` | Required. `https://host:port`; a bare `host:port` is accepted and assumed HTTPS |
| `--token` | Shared token. Alternatively `--token-file FILE`, or the `JOCKY_TOKEN` environment variable |
| `--name` | Agent name; defaults to the hostname. Enrolment is idempotent per `(host, name)`, so a restart keeps the agent's identity and finding history |
| `--state` | Identity and journal directory (default `.jockey-agent`) |
| `--pin HEX` | Expected SHA-256 of the server certificate. Learned automatically at first enrolment, enforced afterwards |
| `--insecure` | Do not verify or pin. Prints `jocky: WARNING --insecure disables certificate pinning; the token is exposed to anyone who answers that socket` |
| `--verify-ca` | Require a certificate valid against the system trust store instead of pinning |
| `--sni NAME` | Present a different TLS SNI **and** HTTP `Host` than the address dialled (see below) |

Token handling is strict about one thing and convenient about another: a missing
token is an error before any connection is attempted
(`jocky: no token: pass --token, --token-file or set JOCKY_TOKEN`, exit `2`), and
a wrong token is fatal rather than retried, because it will never fix itself:

```text
$ ./venv/bin/jocky agent --server https://127.0.0.1:19443 --token wrong --once --name bad-agent --state /tmp/jky-docs/agent-bad
jocky-agent: enrolment failed: HTTP 401: missing or invalid X-JKY-Token
$ echo $?
1
```

Because the server's certificate is self-signed, authenticity comes from
pinning rather than from a certificate authority: the fingerprint is recorded in
`agent.json` at enrolment and later runs refuse a different certificate. What
the identity file looks like:

```json
{
  "agent_id": "agt_c31ffd6810dbb994",
  "server": "https://127.0.0.1:19443",
  "name": "docs-agent",
  "host": "stormbreaker",
  "fingerprint": "a7a9a20e5f9a73466c1a1a00a584339151fb61b53945e45c4e82ac776cf9fb93"
}
```

The fingerprint is the lowercase-hex SHA-256 of the DER certificate; `openssl
s_client -connect HOST:PORT | openssl x509 -noout -fingerprint -sha256` prints
the same value with colons and uppercase, so it can be checked by hand. Note
that `--insecure` still *records* the fingerprint it saw, but the transport
drops the pin, so nothing is enforced on that run.

## Submit a job

Two kinds of payload exist and only two: `source` is JOCKY source executed
in-process, `fileless` is the same source executed from anonymous memory on the
target. An artifact (`exec`) is *not* a job kind — the server and agent refuse
anything else:

```text
jocky-agent: job job_a53a4d2039a3cd24 (exec) error, 0 finding(s)
```

Jobs are submitted with the payload base64-encoded, because the wire is JSON:

```bash
SRC=$(base64 -w0 /tmp/jky-docs/asset.jky)
curl -sk -X POST https://127.0.0.1:8443/v1/jobs/submit \
  -H 'X-JKY-Token: SECRET' -H 'Content-Type: application/json' \
  -d "{\"kind\":\"source\",\"payload_b64\":\"$SRC\"}"
```

```json
{"job_id": "job_48c047ac8c5ebb7e"}
```

```json
{"job_id": "job_a212b4e3756aa2c5"}
```

...for the fileless kind:

```bash
FL=$(base64 -w0 /tmp/jky-docs/remember.jky)
curl -sk -X POST https://127.0.0.1:8443/v1/jobs/submit \
  -H 'X-JKY-Token: SECRET' -H 'Content-Type: application/json' \
  -d "{\"kind\":\"fileless\",\"payload_b64\":\"$FL\"}"
```

The optional `target` field names one `agent_id`; `"*"` or omitting it means "any
agent". A job is claimed atomically (`queued → running`), so two agents polling
in the same instant cannot both win. The poll response is what the agent
executes, and it carries the digest of the payload so a client can verify it
before running it:

```json
{
  "job_id": "job_ffd384a37564edef",
  "kind": "source",
  "payload_b64": "IyBNaW5pbWFsIG1hbmFnZW1lbnQtcGxhbmUgcGF5bG9hZDog…",
  "payload_sha256": "5ac3b34c0e1da814c7148c1effb1b1735c7f0c49368f20973921f0318d5a01d3"
}
```

The bundled agent does not currently re-check that digest client-side; it is
recorded in the store and echoed back on the result so you can reconcile the two
sides afterwards.

Execution limits are the runtime's own defaults: 60 000 ms wall clock and
50 000 000 VM steps per job, and a 120 s timeout around the fileless child. A
runaway payload is cut off rather than allowed to pin the host.

## Read findings

```bash
curl -sk -H 'X-JKY-Token: SECRET' 'https://127.0.0.1:8443/v1/findings?limit=5'
```

```json
{"count": 2, "findings": [
  {"id": 2, "job_id": "job_a212b4e3756aa2c5", "agent_id": "agt_c31ffd6810dbb994",
   "severity": "info", "check": "memory", "title": "fileless host probe",
   "created_at": "2026-09-15T17:46:07.162+00:00", "evidence": {"memfd_processes": 0}},
  {"id": 1, "job_id": "job_48c047ac8c5ebb7e", "agent_id": "agt_c31ffd6810dbb994",
   "severity": "info", "check": "asset", "title": "host asset inventory",
   "created_at": "2026-09-15T17:46:06.313+00:00",
   "evidence": {"listeners": 19, "processes": 50}}]}
```

Every finding keeps its job and agent, which is what makes a report
reconstructable. `GET /v1/status` is the operator's single view:

```json
{"agents": [{"agent_id": "agt_c31ffd6810dbb994", "name": "docs-agent", "host": "stormbreaker",
  "uid": 1000, "kernel": "6.6.87.2-microsoft-standard-WSL2",
  "enrolled_at": "2026-09-15T17:46:05.728+00:00", "last_seen": "2026-09-15T17:46:06.774+00:00"}],
 "jobs": {"queued": 0, "running": 0, "ok": 2, "error": 0, "total": 2},
 "findings": {"total": 2, "by_severity": {"info": 2}},
 "server_time": "2026-09-15T17:46:07.235+00:00"}
```

Only the findings a script emitted are persisted. Metrics, errors, the raw
result body and — for fileless jobs — the `exe`/memfd evidence stay in the
agent's local journal; the server keeps the findings and their provenance. If
you need the process image recorded centrally, emit it from the script.

## HTTP API

All routes answer JSON. Every route except `/v1/health` requires the header
`X-JKY-Token: <token>`, compared with `hmac.compare_digest`. Bodies must be a
JSON object, `Content-Length` is required, and unknown JSON fields are rejected
rather than ignored.

| Method | Path | Body | Success |
|---|---|---|---|
| `GET` | `/v1/health` | — | `200 {"status":"ok","version":"1.1.0"}` (no token needed) |
| `POST` | `/v1/enroll` | `name`, `host`, optional `uid`, `kernel` | `200 {"agent_id":"agt_…"}` |
| `POST` | `/v1/jobs/submit` | `kind`, `payload_b64`, optional `target` | `200 {"job_id":"job_…"}` |
| `POST` | `/v1/jobs/poll` | `agent_id` | `200 {job_id, kind, payload_b64, payload_sha256}`, or `204` when the queue is empty |
| `POST` | `/v1/jobs/result` | `job_id`, `agent_id`, `result` | `200 {"stored":true,"findings":N,"status":"ok\|error","payload_sha256":"…"}` |
| `GET` | `/v1/status` | — | `200` agents, job counts, findings by severity |
| `GET` | `/v1/findings` | — | `200 {"count":N,"findings":[…]}`; query `?limit=1..1000` (default 200) and `?severity=…` |

| Status | When |
|---|---|
| `200` | Success. A replayed result is also `200`, with `{"stored":false,"duplicate":true,"reason":"job is already ok"}` and nothing written |
| `204` | Poll with nothing queued. No `Content-Length`, `Connection: close` |
| `400` | Missing/unknown field, bad base64, bad JSON, `limit` out of range. E.g. `{"error": "unknown field(s): payload"}` |
| `401` | Missing or wrong token: `{"error": "missing or invalid X-JKY-Token"}` |
| `404` | Unknown route (`{"error": "no such endpoint: /v1/nope"}`), unknown API version (`/v2/status`), or an unenrolled `agent_id` on result submission |
| `405` | Known path, wrong method: `{"error": "GET not allowed on /v1/jobs/submit"}` |
| `409` | Reporting a job another agent claimed: `{"stored":false,"duplicate":false,"reason":"job was claimed by another agent","payload_sha256":null}` |
| `411` | `Content-Length` missing: `{"error": "Content-Length required"}` |
| `413` | Body over 8 MiB (8388608 bytes) — verified with an 8600037-byte request: `{"error": "body exceeds 8388608 bytes"}` |
| `500` | An unexpected handler error. It is logged and the listener survives it |

Result submission is the one route where a plausible-looking call can destroy
the audit trail, so it validates in three stages: the agent must be enrolled
(`404`), the job must be claimed by *that* agent (`409`), and a job that is
already finished is acknowledged as a duplicate without writing anything
(`200`, idempotent). Findings are only written when the job actually transitions
`running → finished`.

## The SQLite store

State is one SQLite file, `<state>/store.db`, so an investigation survives
restarts. The full schema:

```sql
CREATE TABLE IF NOT EXISTS agents (
    agent_id    TEXT PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    host        TEXT NOT NULL DEFAULT '',
    uid         INTEGER NOT NULL DEFAULT 0,
    kernel      TEXT NOT NULL DEFAULT '',
    enrolled_at TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS agents_identity ON agents(host, name);

CREATE TABLE IF NOT EXISTS jobs (
    job_id      TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    payload     BLOB NOT NULL,
    payload_sha256 TEXT,
    claimed_by  TEXT,
    created_at  TEXT NOT NULL,
    target      TEXT,
    status      TEXT NOT NULL DEFAULT 'queued',
    started_at  TEXT,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status, created_at);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id        TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT 'info',
    "check"       TEXT NOT NULL DEFAULT 'unknown',
    title         TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_severity ON findings(severity, id);
```

`jobs.status` is one of `queued`, `running`, `ok`, `error`. A row from a real run:

```text
{'job_id': 'job_a212b4e3756aa2c5', 'kind': 'fileless', 'status': 'ok', 'target': None,
 'claimed_by': 'agt_c31ffd6810dbb994', 'sha16': '37f7c85b61be3bea',
 'started_at': '2026-09-15T17:46:06.783+00:00', 'finished_at': '2026-09-15T17:46:07.141+00:00'}
```

`payload_sha256` and `claimed_by` were added after the first release. An older
`store.db` is migrated in place on open — `_migrate()` reads
`PRAGMA table_info(jobs)` and `ALTER TABLE`s the missing columns — so a store
taken from a 1.0 deployment keeps working. Verified by opening a 1.0-era store
whose `jobs` table lacked both columns: after `Store(path)` the column list ends
`..., payload_sha256, claimed_by` and the legacy row is still readable.

Findings are whatever the payload emitted, normalised defensively: a schema of
`{severity, check, title, evidence}` is understood, a bare string becomes
`severity=info, check=unknown`, and an exotic evidence value is serialised with
`default=str` rather than failing the request.

## What the agent journals locally

`journal.jsonl` in the agent's state directory is an append-only JSON-lines
audit record. Entries are written *before* the result is reported, so the local
record survives an unreachable server:

```text
{"event": "job", "job_id": "job_48c047ac8c5ebb7e", "kind": "source", "status": "ok", "duration_ms": 28.349, "findings": 1, "errors": 0, "ts": "2026-09-15T17:46:06.298+00:00"}
{"event": "reported", "job_id": "job_48c047ac8c5ebb7e", "stored": true, "findings": 1, "ts": "2026-09-15T17:46:06.347+00:00"}
{"event": "job", "job_id": "job_a212b4e3756aa2c5", "kind": "fileless", "status": "ok", "duration_ms": 16.984, "findings": 1, "errors": 0, "exe": "/memfd:python3 (deleted)", "ts": "2026-09-15T17:46:07.135+00:00"}
{"event": "reported", "job_id": "job_a212b4e3756aa2c5", "stored": true, "findings": 1, "ts": "2026-09-15T17:46:07.192+00:00"}
```

Three event types exist: `job` (immediately after execution, with kind, status,
duration, finding count, error count, and `exe` when the run reported one),
`reported` (the server's answer), and `report_failed` (the transport error and
what was not delivered). A broken journal prints a warning and never stops
collection.

## Frontable SNI — what it does, and what it cannot do

`--sni NAME` makes the agent connect to the address in `--server` while the TLS
ClientHello presents `NAME` and the HTTP request carries `Host: NAME`. That is
the client-side mechanic domain fronting needs, and it is a capability, not a
front. Measured end to end with the agent's own transport against a TLS listener
holding the management server's certificate: both requests were sent to
`127.0.0.1:19444` on the same socket address, and the server side saw

```text
plain    client dialled 127.0.0.1:19444, sni=None -> HTTP 204
fronted  client dialled 127.0.0.1:19444, sni='fronted.example' -> HTTP 204

server   plain    SNI in ClientHello: None
         request line: GET /v1/health HTTP/1.1
         Host: 127.0.0.1:19444
server   fronted  SNI in ClientHello: 'fronted.example'
         request line: GET /v1/health HTTP/1.1
         Host: fronted.example
```

The same flag works against the real server (the agent enrols and polls with
`--sni fronted.example` while dialling `127.0.0.1`), because authentication is
the pinned certificate fingerprint, not the hostname.

What it cannot do, stated plainly: **it hides nothing on its own.** The TCP
connection still goes to the address in `--server`, so any observer on the path
sees the real destination IP; only the name inside TLS is different. Real domain
fronting requires a CDN whose edge answers for the fronted name and forwards to
the origin — that provider must exist, must terminate TLS for the fronted name,
and must have an origin for you to reach. No CDN is involved in a local run and
none is implied. Treat `--sni` as a hook to test a deployment that already has a
front, never as a substitute for one. The reasoning is in
`research/cdn_fronting.md`, and the same statement is in the module docstring
where the code lives.

## Related pages

* `/docs/operations/cli` — every command and flag.
* `/docs/execution/fileless` — what the `fileless` job kind actually executes.
* `/docs/security/threat-model` — what the token and pin do and do not protect.
* `/docs/operations/evidence` — the harness that measures the runtime's claims.
