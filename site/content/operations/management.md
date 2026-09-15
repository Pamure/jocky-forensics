# The management server and its agents

A single host with a script is an investigation; several hosts with one operator
is an operation, and that needs the other half of SIH26148. `jocky serve` is a TLS
server with token authentication, a SQLite store and a small HTTP API; `jocky
agent` enrols once, runs one job at a time with the same runtime the CLI uses, and
reports findings with the provenance needed to reconstruct a report later.
Everything below was run against a real server on this host, and the bodies are
quoted as they came back.

All policy lives on the server — which hosts, which checks, which payload, when.
The agent is deliberately dumb: it runs exactly what it is handed, and journals
what it did before reporting it.

Version strings and command output here are what the release printed when this
page was written (1.3.0). `/docs/project/releases` is authoritative for the
version list, and `jocky --version` for the build in front of you; the request
and response bodies below are quoted from real sessions against it.

## Start the server

```bash
./venv/bin/jocky serve --port 8443 --token SECRET --state /tmp/jky-server
```

| Flag | Default | Meaning |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address. Anything but loopback exposes the API to the network |
| `--port` | `8443` | TCP port; `0` binds an ephemeral port and the banner prints the real one |
| `--token` | generated | Shared secret. Omitted, a URL-safe token is printed **once** to stderr |
| `--token-file` | — | Read the token from a file; `JOCKY_TOKEN` works too. Preferred, because argv is world-readable in `/proc/<pid>/cmdline` (mode `0444`) |
| `--cert`, `--key` | generated | PEM certificate and key; omitted, a self-signed pair is created under `--state` |
| `--state` | `.jockey-server` | State directory: `agent.crt`, `agent.key`, `store.db` |

The certificate is generated on first start by shelling out to `openssl`, so the
server needs no third-party crypto. With no token at all it generates one and
prints it exactly once: `jocky-server token (generated, shown once): 62gLISSHafI7nKFbJCYu96nNcCShsiLByexFRmAmntU`.

The generated certificate is self-signed, valid for 365 days, and carries a SAN
so the same file works for loopback and for a locally named host:

```text
subject=CN = jocky-management
issuer=CN = jocky-management
notBefore=Sep 15 17:50:08 2026 GMT
notAfter=Sep 15 17:50:08 2027 GMT
X509v3 Subject Alternative Name:
    DNS:localhost, IP Address:127.0.0.1
```

Case data is not world-readable on either side: server state directory `0700` with
key and store `0600`, agent directory `0700` with identity and journal `0600`:

```text
700 /tmp/jky-server
644 /tmp/jky-server/agent.crt
600 /tmp/jky-server/agent.key
600 /tmp/jky-server/store.db
700 /tmp/jky-docs/agent-13
600 /tmp/jky-docs/agent-13/agent.json
600 /tmp/jky-docs/agent-13/journal.jsonl
```

Point `--cert`/`--key` at your own pair for a real deployment; then no
certificate is written into the state directory at all (verified: only `store.db`
appeared there). One line is logged per request, and per state change:

```text
jocky-server: 127.0.0.1 POST /v1/enroll 200 agent=agt_a8049535d4ef35da 15.8ms
jocky-server: 127.0.0.1 POST /v1/jobs/poll 200 agent=agt_a8049535d4ef35da 40.2ms
jocky-server: job job_ef95fdb4a87fa62f finished status=ok
```

## Enrol an agent

```bash
./venv/bin/jocky agent --server https://127.0.0.1:8443 --token SECRET --once \
    --name docs-agent --state /tmp/jky-docs/agent-state
```

```text
jocky-agent: pinned server certificate a3ebf074317b95bc…
jocky-agent agt_a8049535d4ef35da polling https://127.0.0.1:8443 (journal /tmp/jky-docs/agent-state/journal.jsonl)
jocky-agent: job job_ef95fdb4a87fa62f (source) ok, 1 finding(s)
```

`--once` performs exactly one poll-and-execute cycle and exits `0` — the mode a
cron entry or a one-shot run uses. Without it the agent polls every `--interval`
seconds (default `5.0`) until Ctrl-C, which is also a clean exit.

| Flag | Effect |
|---|---|
| `--server` | Required. `https://host:port`; a bare `host:port` is accepted and assumed HTTPS |
| `--token` | Shared token. Also `--token-file FILE`, or the `JOCKY_TOKEN` environment variable |
| `--name` | Agent name; defaults to the hostname. Enrolment is idempotent per `(host, name)`, so a restart keeps the same `agent_id` and finding history |
| `--state` | Identity and journal directory (default `.jockey-agent`) |
| `--pin HEX` | Expected SHA-256 of the server certificate; learned at first enrolment, enforced afterwards |
| `--insecure` | Do not verify or pin. Prints a warning before connecting |
| `--verify-ca` | Require a certificate valid against the system trust store instead of pinning |
| `--sni NAME` | Present a different TLS SNI **and** HTTP `Host` than the address dialled (see below) |

A missing token fails before any connection is attempted, and a wrong token is
fatal rather than retried because it will never fix itself:

```text
$ ./venv/bin/jocky agent --server https://127.0.0.1:8443 --once --name none-agent --state /tmp/jky-docs/agent-none
jocky: no token: pass --token, --token-file or set JOCKY_TOKEN
$ echo $?
2
$ ./venv/bin/jocky agent --server https://127.0.0.1:8443 --token wrong --once --name bad-agent --state /tmp/jky-docs/agent-bad
jocky-agent: enrolment failed: HTTP 401: missing or invalid X-JKY-Token
$ echo $?
1
```

Because the certificate is self-signed, authenticity comes from pinning rather
than from a certificate authority: the fingerprint is recorded at enrolment and
later runs refuse a different certificate.

```json
{
  "agent_id": "agt_a8049535d4ef35da",
  "server": "https://127.0.0.1:8443",
  "name": "docs-agent",
  "host": "stormbreaker",
  "fingerprint": "a3ebf074317b95bc9386729d9ef5e2249f4714e5d460f6e55d659b749b67a546"
}
```

That is the lowercase-hex SHA-256 of the DER certificate;
`openssl s_client -connect HOST:PORT </dev/null | openssl x509 -noout -fingerprint -sha256`
prints the same value with colons and uppercase. `--insecure` still *records* the
fingerprint it saw, but the transport drops the pin, so nothing is enforced on
that run. A mismatched pin is refused before any job is accepted:

```text
$ ./venv/bin/jocky agent --server https://127.0.0.1:8443 --token SECRET --once \
      --pin 0000000000000000000000000000000000000000000000000000000000000000 \
      --name pin-agent --state /tmp/jky-docs/agent-pin
jocky-agent: enrolment failed: server certificate fingerprint mismatch: expected 0000000000000000…, got a3ebf074317b95bc…
$ echo $?
1
```

That is what makes a self-signed certificate usable: the agent does not need a CA
to trust, only the certificate it saw first. It also means rotating the server
certificate requires re-enrolling the agents (or passing the new `--pin`).

## Submit a job

Two kinds exist and only two: `source` runs JOCKY source in-process, `fileless`
runs the same source from anonymous memory on the target. Payloads are base64:

```bash
cat > /tmp/jky-docs/asset.jky <<'JKY'
# One structured asset finding, submitted to the management server.
emit {
  "severity": "info",
  "check": "asset",
  "title": "host asset inventory",
  "evidence": {"listeners": len(net.listeners()), "processes": len(proc.list(50))}
}
JKY

SRC=$(base64 -w0 /tmp/jky-docs/asset.jky)
curl -sk -X POST https://127.0.0.1:8443/v1/jobs/submit \
  -H 'X-JKY-Token: SECRET' -H 'Content-Type: application/json' \
  -d "{\"kind\":\"source\",\"payload_b64\":\"$SRC\"}"
```

```json
{"job_id": "job_ef95fdb4a87fa62f"}
```

The fileless kind is the same call with a different payload and `kind`; here
`probe.jky` is the same shape with `"check": "memory"`:

```bash
FL=$(base64 -w0 /tmp/jky-docs/probe.jky)
curl -sk -X POST https://127.0.0.1:8443/v1/jobs/submit -H 'X-JKY-Token: SECRET' \
  -H 'Content-Type: application/json' -d "{\"kind\":\"fileless\",\"payload_b64\":\"$FL\"}"
```

```json
{"job_id": "job_f0552c872f328d86"}
```

The optional `target` names one `agent_id`; `"*"` or omitting it means "any
agent". A job is claimed atomically (`queued → running`), so two agents polling
at the same instant cannot both win, and the poll response carries the payload
digest so a client can check it before executing:

```json
{
  "job_id": "job_f1be3d85fee594e7",
  "kind": "source",
  "payload_b64": "IyBPbmUgc3RydWN0dXJlZCBhc3NldCBmaW5kaW5nLCBzdWJtaXR0ZWQgdG8gdGhlIG1hbmFnZW1lbnQgc2VydmVyLgplbWl0IHsKICAic2V2ZXJpdHkiOiAiaW5mbyIsCiAgImNoZWNrIjogImFzc2V0IiwKICAidGl0bGUiOiAiaG9zdCBhc3NldCBpbnZlbnRvcnkiLAogICJldmlkZW5jZSI6IHsibGlzdGVuZXJzIjogbGVuKG5ldC5saXN0ZW5lcnMoKSksICJwcm9jZXNzZXMiOiBsZW4ocHJvYy5saXN0KDUwKSl9Cn0K",
  "payload_sha256": "0cb86b804a5ac24a34532946a2a8cee2e5d09a63d5cb7fedd95286bb867dc664"
}
```

The bundled agent does not currently re-check that digest client-side; it is stored
with the job and echoed back on the result so both sides can be reconciled. Any
other kind is accepted by the server and refused by the agent at execution time:

```text
jocky-agent: job job_8c92a06a0a49fd2e (exec) error, 0 finding(s)
```

Execution limits are the runtime's own: 60 000 ms wall clock and 50 000 000 VM
steps per job, plus a 120 s fileless timeout, so a runaway payload is cut off.

## Read findings

```bash
curl -sk -H 'X-JKY-Token: SECRET' 'https://127.0.0.1:8443/v1/findings?limit=5'
```

```json
{"count": 2, "findings": [{"id": 2, "job_id": "job_f0552c872f328d86", "agent_id": "agt_a8049535d4ef35da", "severity": "info", "check": "memory", "title": "fileless host probe", "created_at": "2026-09-15T17:50:14.657+00:00", "evidence": {"listeners": 19}}, {"id": 1, "job_id": "job_ef95fdb4a87fa62f", "agent_id": "agt_a8049535d4ef35da", "severity": "info", "check": "asset", "title": "host asset inventory", "created_at": "2026-09-15T17:50:13.864+00:00", "evidence": {"listeners": 19, "processes": 50}}]}
```

Every finding keeps its job and agent, which is what makes a report
reconstructable. `GET /v1/status` is the operator's single view:

```json
{"agents": [{"agent_id": "agt_a8049535d4ef35da", "name": "docs-agent", "host": "stormbreaker", "uid": 1000, "kernel": "6.6.87.2-microsoft-standard-WSL2", "enrolled_at": "2026-09-15T17:50:13.354+00:00", "last_seen": "2026-09-15T17:50:14.279+00:00"}, {"agent_id": "agt_b4874e9738633106", "name": "intruder", "host": "workstation", "uid": 0, "kernel": "unknown", "enrolled_at": "2026-09-15T17:50:14.875+00:00", "last_seen": "2026-09-15T17:50:15.171+00:00"}], "jobs": {"queued": 0, "running": 0, "ok": 2, "error": 1, "total": 3}, "findings": {"total": 2, "by_severity": {"info": 2}}, "server_time": "2026-09-15T17:50:16.221+00:00"}
```

Only the findings a script emitted are persisted. Metrics, errors, the raw result
body and — for fileless jobs — the process-image evidence stay in the agent's local
journal; to record the process image centrally, emit it from the script.

## HTTP API

Every route answers JSON. Every route except `/v1/health` requires the header
`X-JKY-Token: <token>`, compared with `hmac.compare_digest` so a guess cannot be
timed. Bodies must be a JSON object, `Content-Length` is required, and unknown
JSON fields are rejected instead of ignored.

| Method | Path | Body | Success |
|---|---|---|---|
| `GET` | `/v1/health` | — | `200 {"status":"ok","version":"1.3.0"}` — no token needed |
| `POST` | `/v1/enroll` | `name`, `host`, optional `uid`, `kernel` | `200 {"agent_id":"agt_…"}` |
| `POST` | `/v1/jobs/submit` | `kind`, `payload_b64`, optional `target` | `200 {"job_id":"job_…"}` |
| `POST` | `/v1/jobs/poll` | `agent_id` | `200 {job_id, kind, payload_b64, payload_sha256}`, or `204` when the queue is empty |
| `POST` | `/v1/jobs/result` | `job_id`, `agent_id`, `result` | `200 {"stored":true,"findings":N,"status":"ok\|error","payload_sha256":"…"}` |
| `GET` | `/v1/status` | — | `200` agents, job counts, findings by severity |
| `GET` | `/v1/findings` | — | `200 {"count":N,"findings":[…]}`; `?limit=1..1000` (default 200), `?severity=…` |

| Status | When |
|---|---|
| `200` | Success, including a replayed result: `{"stored":false,"duplicate":true,"reason":"job is already ok"}` writes nothing |
| `204` | Poll with nothing queued; no `Content-Length`, `Connection: close`, empty body |
| `400` | Missing/unknown field, bad base64, bad JSON, `limit` out of range: `{"error": "unknown field(s): payload"}`, `{"error": "limit must be between 1 and 1000"}` |
| `401` | Missing or wrong token: `{"error": "missing or invalid X-JKY-Token"}` |
| `404` | Unknown route (`{"error": "no such endpoint: /v1/nope"}`), unknown API version (`/v2/status`), or an unenrolled `agent_id` on result submission |
| `405` | Known path, wrong method: `{"error": "GET not allowed on /v1/jobs/submit"}` |
| `409` | Reporting a job another agent claimed: `{"stored":false,"duplicate":false,"reason":"job was claimed by another agent","payload_sha256":null}` |
| `411` | `Content-Length` missing: `{"error": "Content-Length required"}` |
| `413` | Body over 8 MiB (8 388 608 bytes). Verified with an 8 600 037-byte request: `{"error": "body exceeds 8388608 bytes"}` |
| `500` | An unexpected handler error; it is logged and the listener survives it |

Result submission is where a plausible-looking call could corrupt an audit trail,
so it validates in three stages: the agent must be enrolled (`404`), the job must
have been claimed by *that* agent (`409`), and a job that is already finished is
acknowledged as a duplicate without writing anything (`200`, idempotent).
Findings are written only when the job actually transitions `running → finished`.

## The SQLite store

State is one file, `<state>/store.db`, so an investigation survives restarts:

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

`jobs.status` is one of `queued`, `running`, `ok`, `error`. Two rows from the run
above (`sha16` is the payload digest, truncated for printing):

```text
{'job_id': 'job_ef95fdb4a87fa62f', 'kind': 'source', 'status': 'ok', 'target': None,
 'claimed_by': 'agt_a8049535d4ef35da', 'sha16': '0cb86b804a5ac24a',
 'started_at': '2026-09-15T17:50:13.798+00:00', 'finished_at': '2026-09-15T17:50:13.857+00:00'}
{'job_id': 'job_f0552c872f328d86', 'kind': 'fileless', 'status': 'ok', 'target': None,
 'claimed_by': 'agt_a8049535d4ef35da', 'sha16': '5249272014f1ecf5',
 'started_at': '2026-09-15T17:50:14.292+00:00', 'finished_at': '2026-09-15T17:50:14.635+00:00'}
```

`payload_sha256` and `claimed_by` were added after the first release, so an older
`store.db` is migrated in place when it is opened: `_migrate()` reads
`PRAGMA table_info(jobs)` and `ALTER TABLE`s whatever is missing. Verified on a
store whose `jobs` table predated both columns — afterwards the column list ended
`..., payload_sha256, claimed_by` and the legacy row was still readable. Findings
are normalised defensively, because a script may emit anything: the
`{severity, check, title, evidence}` shape is understood, a bare string becomes
`severity=info, check=unknown`, and an exotic value is serialised with `default=str`.

## What the agent journals locally

`journal.jsonl` is an append-only JSON-lines audit record, written *before* the
result is reported, so the local record survives an unreachable server. The
complete journal from the two jobs above:

```text
{"event": "job", "job_id": "job_ef95fdb4a87fa62f", "kind": "source", "status": "ok", "duration_ms": 20.255, "findings": 1, "errors": 0, "ts": "2026-09-15T17:50:13.849+00:00"}
{"event": "reported", "job_id": "job_ef95fdb4a87fa62f", "stored": true, "findings": 1, "ts": "2026-09-15T17:50:13.900+00:00"}
{"event": "job", "job_id": "job_f0552c872f328d86", "kind": "fileless", "status": "ok", "duration_ms": 8.79, "findings": 1, "errors": 0, "exe": "/memfd:python3 (deleted)", "ts": "2026-09-15T17:50:14.630+00:00"}
{"event": "reported", "job_id": "job_f0552c872f328d86", "stored": true, "findings": 1, "ts": "2026-09-15T17:50:14.679+00:00"}
```

Three event types exist: `job` (immediately after execution — kind, status,
duration, finding and error counts, plus `exe` when the run reported one),
`reported` (the server's answer) and `report_failed` (the transport error and
what was not delivered). A journal that cannot be written prints a warning and
never stops collection.

## Frontable SNI — what it does, and what it cannot do

`--sni NAME` makes the agent connect to the address in `--server` while the TLS
ClientHello presents `NAME` and the HTTP request carries `Host: NAME`. That is
the client-side mechanic domain fronting needs, and it is a capability, not a
front. Measured end to end with the agent's own transport against a TLS listener
holding the management server's certificate — both requests went to the same
socket address, `127.0.0.1:8444`, and the server side saw:

```text
plain    client dialled 127.0.0.1:8444, sni=None -> HTTP 204
fronted  client dialled 127.0.0.1:8444, sni='fronted.example' -> HTTP 204

server   plain    SNI in ClientHello: None
         request line: GET /v1/health HTTP/1.1
         Host: 127.0.0.1:8444
server   fronted  SNI in ClientHello: 'fronted.example'
         request line: GET /v1/health HTTP/1.1
         Host: fronted.example
```

The same flag works against a real server — an agent started with
`--sni fronted.example` while dialling `127.0.0.1:8443` enrols and polls
normally, because authentication is the pinned fingerprint, not the hostname:

```text
jocky-agent: pinned server certificate a3ebf074317b95bc…
jocky-agent agt_94324050ccae22cc polling https://127.0.0.1:8443 (journal /tmp/jky-docs/agent-sni/journal.jsonl)
```

What it cannot do, stated plainly: **it hides nothing by itself.** The TCP
connection still goes to the address in `--server`, so anyone on the path sees the
real destination address; only the name inside the TLS handshake differs. Real
domain fronting needs a CDN whose edge answers for the fronted name, terminates
TLS for it and forwards to the origin — a third party that must exist, be
reachable and be willing. Nothing about `--sni` creates that, no CDN is involved
in a local run, and none is claimed: treat the flag as a way to test a deployment
that already has a front, never as a substitute for one. The reasoning is in
`research/cdn_fronting.md`, and the module docstring says the same thing where
the code lives.

## Related pages

* `/docs/operations/cli` — every command and flag.
* `/docs/operations/evidence` — the harness that measures the runtime's claims.
* `/docs/execution/fileless` — what the `fileless` job kind executes, and
  `/docs/security/threat-model` — what the token and the pin do and do not protect.
