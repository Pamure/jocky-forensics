"""
Central management plane for JOCKY — the "Central Management Interface" of
SIH26148.

Why this module exists
----------------------
The runtime, the polymorphic encoder and the fileless executor all answer one
question: *what is on this host?* A real engagement needs the other half —
several hosts, one operator, and a durable record of who was told to run what,
where, and what came back. This module is that record plus the channel that
carries it.

Design notes (the *why* behind the shape)
-----------------------------------------
* **Trusted channel, honestly described.** ``ThreadingHTTPServer`` wrapped in
  ``ssl`` using a self-signed certificate generated on first start by shelling
  out to ``openssl`` (no third-party crypto dependency). Everything except
  ``/v1/health`` additionally requires a shared token compared with
  :func:`hmac.compare_digest`, so a token guess cannot be timed. TLS protects
  payloads in transit; the token protects the endpoint.
* **Frontability is a hook, not a claim.** An agent may connect to one address
  while presenting a different SNI/Host (see :mod:`jocky.agent.client`). That
  is exactly the knob a domain-fronted deployment would turn; no CDN is
  involved here and none is pretended.
* **Auditability.** SQLite in the server state directory holds agents, jobs and
  findings. A job is claimed atomically (``queued -> running``) and every
  finding is attributed to both the job and the agent that produced it, so a
  report can be reconstructed after the fact.
* **Untrusted input.** Agents are remote code callers: bodies are capped at
  8 MiB, unknown routes and unknown JSON fields are rejected, and a handler
  exception becomes a 500 instead of killing the listener.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import SplitResult, parse_qs, urlsplit

from jocky import __version__

#: Hard cap on a request body. Findings and payloads are small; anything past
#: this is either a bug or an attempt to exhaust the server.
MAX_BODY = 8 * 1024 * 1024

#: Routes answered without a token. The console shell carries no data and no
#: credential — everything it shows is fetched by the browser afterwards with
#: the operator's own token — and ``/v1/health`` is a liveness probe. Listing
#: them here (rather than an inline ``!=`` per handler) keeps the exception
#: auditable: a new route is authenticated unless it is added on purpose.
#:
#: ``/favicon.ico`` is public for a non-obvious reason: browsers request it on
#: every page load. If it fell through to the auth check it would answer 401,
#: and each 401 is counted against the per-IP failure budget — so ten console
#: reloads would lock the operator out of their own console. The page ships an
#: inline ``data:`` icon, and this route covers every client that asks anyway.
_PUBLIC_ROUTES = frozenset({"/v1/health", "/", "/dashboard", "/favicon.ico"})

#: Content-Security-Policy for the console. The page is a single self-contained
#: document, so the policy can be maximally strict: nothing may be loaded from
#: anywhere (no CDN, no font host), no frames, no forms posting off-origin.
#: Inline script/style are permitted because the alternative — external files —
#: would require the image to ship static assets and create a second source of
#: truth for the UI.
CONSOLE_CSP = (
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
    "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)

#: Rate-limit parameters for authentication failures.
MAX_AUTH_FAILURES = 10
AUTH_WINDOW_SECONDS = 60

#: Per-IP sliding-window tracker: ip -> [timestamp, …].
_AUTH_FAILURES: Dict[str, List[float]] = {}
_AUTH_FAILURES_LOCK = threading.Lock()

CERT_NAME = "agent.crt"
KEY_NAME = "agent.key"
STORE_NAME = "store.db"
DEFAULT_STATE_DIR = ".jocky-server"

_LOG_LOCK = threading.Lock()
_LAST_SERVER: Optional[ThreadingHTTPServer] = None
_LAST_BOUND_PORT: Optional[int] = None

#: Job kinds an agent knows how to execute. Validated at submit time: without
#: this, a typo reaches the agent, which reports ``unsupported job kind`` as a
#: *result* — the operator sees a job that ran and failed, rather than a request
#: that was never accepted. The set is the agent's contract (see
#: ``jocky/agent/client.py:_execute``); keeping it here makes the rejection
#: happen at the boundary where the operator can still fix it.
JOB_KINDS = ("source", "fileless")

JOB_STATUSES = ("queued", "running", "ok", "error")


# --------------------------------------------------------------------- helpers
def _now() -> str:
    """UTC timestamp, millisecond precision — audit trails need ordering."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _harden_path(path: str, mode: int) -> None:
    """Best-effort permission tightening for case data.

    Findings, evidence blobs and job payloads are case material: they should not
    be world-readable on a shared host. Failures are ignored because the target
    filesystem may not implement POSIX modes.
    """
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _log(message: str) -> None:
    """One serialised line to stderr; concurrent handlers must not interleave."""
    with _LOG_LOCK:
        print(f"jocky-server: {message}", file=sys.stderr, flush=True)


def last_bound_port() -> Optional[int]:
    """Port the most recent :func:`serve` bound to (tests pass ``port=0``)."""
    return _LAST_BOUND_PORT


def shutdown(timeout: float = 10.0) -> bool:
    """Stop the server started by the most recent :func:`serve` call.

    ``serve_forever`` only returns once somebody calls ``shutdown()``, so
    embedders (the tests, or a supervisor that restarts the server in-process)
    need a handle. Returns ``True`` when a live server was asked to stop.
    """
    server = _LAST_SERVER
    if server is None:
        return False
    server.shutdown()
    _log(f"shutdown requested (timeout={timeout:g}s)")
    return True


# ----------------------------------------------------------------- certificate
def ensure_cert(state_dir: str) -> Tuple[str, str]:
    """Return ``(cert_path, key_path)``, generating a self-signed pair once.

    ``openssl`` is shelled out rather than using a crypto library: the target
    presentation machines have openssl everywhere, and a management server that
    needs wheels installed before it can talk TLS is a management server nobody
    deploys. The SAN entry covers ``localhost`` and ``127.0.0.1`` so the same
    certificate works for loopback tests and for a locally named host.
    """
    state_dir = os.path.abspath(state_dir)
    os.makedirs(state_dir, exist_ok=True)
    cert_path = os.path.join(state_dir, CERT_NAME)
    key_path = os.path.join(state_dir, KEY_NAME)
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    openssl = shutil.which("openssl") or "/usr/bin/openssl"
    command = [
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365",
        "-subj", "/CN=jocky-management",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout", key_path, "-out", cert_path,
    ]
    try:
        subprocess.run(command, check=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or b"").decode("utf-8", "replace").strip()
        raise RuntimeError(f"openssl failed to generate a certificate: {detail}") from exc
    os.chmod(key_path, 0o600)
    _log(f"generated self-signed certificate at {cert_path}")
    return cert_path, key_path


# ------------------------------------------------------------------ data model
@dataclass(frozen=True)
class ClaimedJob:
    """A job that has been moved to ``running`` and handed to one agent."""

    job_id: str
    kind: str
    payload: bytes
    agent_id: str
    payload_sha256: str = ""

    def as_wire(self) -> Dict[str, Any]:
        """The poll response shape: bytes never travel as raw JSON."""
        return {
            "job_id": self.job_id,
            "kind": self.kind,
            "payload_b64": base64.b64encode(self.payload).decode("ascii"),
            "payload_sha256": self.payload_sha256,
        }


@dataclass(frozen=True)
class Finding:
    """One normalised finding, ready for the ``findings`` table."""

    severity: str
    check: str
    title: str
    evidence_json: str

    @classmethod
    def from_raw(cls, raw: Any) -> "Finding":
        """Normalise a finding emitted by a script.

        Findings are whatever the payload emitted: JOCKY's own detectors use
        ``{severity, check, title, evidence}`` but a script is free to emit
        anything at all — including a bare string. Every field is therefore
        defaulted instead of trusted, and the evidence blob is serialised with
        ``default=str`` plus a ``repr`` fallback so an exotic value can never
        take down the storing request.
        """
        if isinstance(raw, dict):
            severity = raw.get("severity")
            check = raw.get("check") or raw.get("kind")
            title = raw.get("title") or raw.get("kind") or raw.get("check")
            evidence: Any = raw.get("evidence", raw)
        else:
            severity = None
            check = None
            title = None
            evidence = raw
        try:
            evidence_json = json.dumps(evidence, default=str)
        except (TypeError, ValueError):
            evidence_json = json.dumps({"repr": repr(evidence)})
        return cls(
            severity=severity if isinstance(severity, str) and severity else "info",
            check=str(check) if check else "unknown",
            title=str(title) if title else "finding",
            evidence_json=evidence_json,
        )


_SCHEMA = """
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
"""


class Store:
    """SQLite-backed job and finding store.

    ``ThreadingHTTPServer`` runs one handler per connection, so the connection
    is opened with ``check_same_thread=False`` and every statement is
    serialised behind one re-entrant lock: SQLite is fast enough here that a
    connection pool would only add failure modes.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            _harden_path(directory, 0o700)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._migrate()
            self._conn.commit()
        # findings and evidence are case data: owner-only, on POSIX and best-effort elsewhere
        _harden_path(path, 0o600)

    def _migrate(self) -> None:
        """Add columns introduced after the first release (existing stores)."""
        wanted = {
            "jobs": {"payload_sha256": "TEXT", "claimed_by": "TEXT"},
        }
        for table, columns in wanted.items():
            existing = {
                row["name"]
                for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for name, ddl in columns.items():
                if name not in existing:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------- agents
    def enroll(self, name: str, host: str, uid: int = 0, kernel: str = "") -> str:
        """Register an agent, idempotently per ``(host, name)``.

        Re-enrolling is normal: an agent restarts, loses its state directory,
        and asks again. Keying on the host plus the operator-chosen name means
        the agent keeps its identity (and its finding history) across restarts.
        """
        now = _now()
        with self._lock:
            row = self._conn.execute(
                "SELECT agent_id FROM agents WHERE host = ? AND name = ?", (host, name)
            ).fetchone()
            if row is not None:
                self._conn.execute(
                    "UPDATE agents SET uid = ?, kernel = ?, last_seen = ? WHERE agent_id = ?",
                    (uid, kernel, now, row["agent_id"]),
                )
                self._conn.commit()
                return row["agent_id"]
            agent_id = "agt_" + secrets.token_hex(8)
            self._conn.execute(
                "INSERT INTO agents (agent_id, name, host, uid, kernel, enrolled_at, last_seen)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (agent_id, name, host, uid, kernel, now, now),
            )
            self._conn.commit()
        _log(f"enrolled agent {agent_id} name={name!r} host={host!r}")
        return agent_id

    def touch_agent(self, agent_id: str) -> bool:
        """Record that an agent is alive; ``False`` if we never enrolled it."""
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE agents SET last_seen = ? WHERE agent_id = ?", (_now(), agent_id)
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def agents(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM agents ORDER BY enrolled_at"
            ).fetchall()
        return [dict(row) for row in rows]

    # --------------------------------------------------------------- jobs
    def enqueue(self, kind: str, payload: bytes, target: Optional[str] = None,
                job_id: Optional[str] = None) -> str:
        """Queue a job. ``target`` is an agent id, ``"*"``/``None`` for anyone."""
        from jocky.canon import digest_bytes

        job_id = job_id or "job_" + secrets.token_hex(8)
        payload_digest = digest_bytes(bytes(payload))
        with self._lock:
            self._conn.execute(
                "INSERT INTO jobs (job_id, kind, payload, payload_sha256, created_at, target, status)"
                " VALUES (?, ?, ?, ?, ?, ?, 'queued')",
                (job_id, kind, sqlite3.Binary(payload), payload_digest, _now(), target),
            )
            self._conn.commit()
        return job_id

    def next_job(self, agent_id: str) -> Optional[ClaimedJob]:
        """Atomically claim the oldest queued job addressed to this agent.

        The ``UPDATE ... WHERE status = 'queued'`` guard is what makes the claim
        atomic: two agents polling at the same instant cannot both win, and the
        loser simply loops and looks again (or gets ``None``).
        """
        for _ in range(5):
            with self._lock:
                row = self._conn.execute(
                    "SELECT job_id, kind, payload, payload_sha256 FROM jobs"
                    " WHERE status = 'queued'"
                    "   AND (target IS NULL OR target = '*' OR target = ?)"
                    " ORDER BY created_at, rowid LIMIT 1",
                    (agent_id,),
                ).fetchone()
                if row is None:
                    return None
                cursor = self._conn.execute(
                    "UPDATE jobs SET status = 'running', started_at = ?, claimed_by = ?"
                    " WHERE job_id = ? AND status = 'queued'",
                    (_now(), agent_id, row["job_id"]),
                )
                self._conn.commit()
                if cursor.rowcount == 1:
                    return ClaimedJob(job_id=row["job_id"], kind=row["kind"],
                                      payload=bytes(row["payload"]), agent_id=agent_id,
                                      payload_sha256=row["payload_sha256"] or "")
        return None

    def finish_job(self, job_id: str, agent_id: Optional[str] = None,
                   status: Optional[str] = None,
                   result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Close out a job, verifying that the reporting agent is the claimant.

        Returns a dict instead of a bool so the handler can distinguish
        "unknown job", "not your job", "already finished" (a replay) and
        "stored". A bare boolean is how unauthenticated results were accepted:
        any caller could name any job id and the findings were written anyway.
        """
        if not status:
            errors = (result or {}).get("errors")
            status = "error" if errors else "ok"
        with self._lock:
            row = self._conn.execute(
                "SELECT status, claimed_by, payload_sha256 FROM jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                return {"stored": False, "reason": "unknown job", "status": None}
            if agent_id and row["claimed_by"] and row["claimed_by"] != agent_id:
                return {"stored": False, "reason": "job was claimed by another agent",
                        "status": row["status"]}
            if row["status"] != "running":
                return {"stored": False, "reason": f"job is already {row['status']}",
                        "status": row["status"], "duplicate": True,
                        "payload_sha256": row["payload_sha256"]}
            self._conn.execute(
                "UPDATE jobs SET status = ?, finished_at = ?"
                " WHERE job_id = ? AND status = 'running'",
                (status, _now(), job_id),
            )
            self._conn.commit()
        _log(f"job {job_id} finished status={status}")
        return {"stored": True, "reason": "ok", "status": status,
                "payload_sha256": row["payload_sha256"]}

    def job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT job_id, kind, created_at, target, status, started_at, finished_at"
                " FROM jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    # ----------------------------------------------------------- findings
    def store_findings(self, job_id: str, agent_id: str,
                       findings: Any) -> int:
        """Persist the findings a result carries; returns how many were stored."""
        if not isinstance(findings, (list, tuple)):
            return 0
        now = _now()
        rows = []
        for raw in findings:
            finding = Finding.from_raw(raw)
            rows.append((job_id, agent_id, finding.severity, finding.check,
                         finding.title, finding.evidence_json, now))
        if not rows:
            return 0
        with self._lock:
            self._conn.executemany(
                'INSERT INTO findings (job_id, agent_id, severity, "check", title,'
                " evidence_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            self._conn.commit()
        return len(rows)

    def findings(self, limit: int = 200, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        query = ("SELECT id, job_id, agent_id, severity, \"check\", title,"
                 " evidence_json, created_at FROM findings")
        params: List[Any] = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            try:
                item["evidence"] = json.loads(item.pop("evidence_json"))
            except (TypeError, ValueError):
                item["evidence"] = {"raw": item.pop("evidence_json")}
            output.append(item)
        return output

    # ------------------------------------------------------------- status
    def status(self) -> Dict[str, Any]:
        """Everything an operator needs to see at a glance, and nothing else."""
        with self._lock:
            job_rows = self._conn.execute(
                "SELECT status, COUNT(*) AS n FROM jobs GROUP BY status"
            ).fetchall()
            finding_rows = self._conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
            ).fetchall()
            finding_total = self._conn.execute(
                "SELECT COUNT(*) AS n FROM findings"
            ).fetchone()["n"]
        jobs = {name: 0 for name in JOB_STATUSES}
        for row in job_rows:
            jobs[row["status"]] = row["n"]
        jobs["total"] = sum(jobs[name] for name in JOB_STATUSES)
        return {
            "agents": self.agents(),
            "jobs": jobs,
            "findings": {"total": finding_total,
                         "by_severity": {row["severity"]: row["n"] for row in finding_rows}},
            "server_time": _now(),
        }


# ---------------------------------------------------------------- HTTP handler
class _HTTPError(Exception):
    """Raised inside a handler to produce a specific JSON error response."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def _fields(body: Dict[str, Any], required: Tuple[str, ...],
            optional: Tuple[str, ...] = ()) -> None:
    """Reject unknown fields and missing required ones.

    Strict input is deliberate: a typo like ``payload`` instead of
    ``payload_b64`` should fail loudly at submit time, not silently become an
    empty payload that executes on a dozen hosts.
    """
    unknown = sorted(set(body) - set(required) - set(optional))
    if unknown:
        raise _HTTPError(400, f"unknown field(s): {', '.join(unknown)}")
    missing = [field for field in required if field not in body]
    if missing:
        raise _HTTPError(400, f"missing field(s): {', '.join(missing)}")


def _as_str(body: Dict[str, Any], field: str, default: str = "") -> str:
    value = body.get(field, default)
    if value is None:
        return default
    if not isinstance(value, str):
        raise _HTTPError(400, f"{field} must be a string")
    return value


def _as_uid(body: Dict[str, Any], field: str = "uid") -> int:
    value = body.get(field, 0)
    if isinstance(value, bool):
        raise _HTTPError(400, f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    raise _HTTPError(400, f"{field} must be an integer")


def _as_b64(body: Dict[str, Any], field: str) -> bytes:
    value = body.get(field)
    if not isinstance(value, str):
        raise _HTTPError(400, f"{field} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _HTTPError(400, f"{field} is not valid base64") from exc


class Handler(BaseHTTPRequestHandler):
    """One request per connection thread; every route answers JSON."""

    server_version = f"jocky-management/{__version__}"
    protocol_version = "HTTP/1.1"

    #: Set by :meth:`do_HEAD`: identical headers to the GET, no body. Declared
    #: as a class attribute so ``_dispatch`` never has to clear it.
    _head_only = False

    # ----------------------------------------------------------- plumbing
    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self._dispatch("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        """Answer HEAD the way GET would, minus the body.

        Uptime probes and reverse proxies prefer HEAD; without this method
        ``BaseHTTPRequestHandler`` answers 501, which reads to a monitoring
        system as a broken service rather than a live one.
        """
        self._head_only = True
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        """Silence the stock logger — this server emits its own one-liners."""
        return

    def _dispatch(self, method: str) -> None:
        parsed = urlsplit(self.path)
        route = parsed.path.rstrip("/") or "/"
        self._status = 0
        self._agent_id = ""
        self._responded = False
        self._body_read = False
        started = time.perf_counter()
        try:
            if route not in _PUBLIC_ROUTES:
                self._require_token()
            handler = _ROUTES.get((method, route))
            if handler is None:
                if any(path == route for _, path in _ROUTES):
                    raise _HTTPError(405, f"{method} not allowed on {route}")
                raise _HTTPError(404, f"no such endpoint: {route}")
            handler(self, parsed)
        except _HTTPError as exc:
            self._send_json(exc.status, {"error": str(exc)})
        except Exception as exc:  # never let one request kill the listener
            _log(f"handler error on {method} {route}: {type(exc).__name__}: {exc}")
            self._send_json(500, {"error": "internal server error"})
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            agent = f" agent={self._agent_id}" if self._agent_id else ""
            _log(f"{self.client_address[0]} {method} {route} {self._status}{agent}"
                 f" {elapsed_ms:.1f}ms")

    def _require_token(self) -> None:
        """Constant-time token check with per-IP rate limiting."""
        client_ip = self.client_address[0]
        now = time.monotonic()

        # --- rate-limit check (before touching the token) ---
        with _AUTH_FAILURES_LOCK:
            timestamps = _AUTH_FAILURES.get(client_ip)
            if timestamps is not None:
                # Evict entries older than the window.
                cutoff = now - AUTH_WINDOW_SECONDS
                timestamps[:] = [t for t in timestamps if t > cutoff]
                if not timestamps:
                    del _AUTH_FAILURES[client_ip]
                elif len(timestamps) >= MAX_AUTH_FAILURES:
                    raise _HTTPError(429, "too many authentication failures")

        # --- constant-time token comparison ---
        expected = getattr(self.server, "token", "") or ""
        provided = self.headers.get("X-JKY-Token") or ""
        if not expected or not hmac.compare_digest(
            provided.encode("utf-8", "replace"), expected.encode("utf-8")
        ):
            with _AUTH_FAILURES_LOCK:
                _AUTH_FAILURES.setdefault(client_ip, []).append(now)
            raise _HTTPError(401, "missing or invalid X-JKY-Token")

    def _read_json(self) -> Dict[str, Any]:
        """Read and parse a bounded JSON object body."""
        header = self.headers.get("Content-Length")
        if header is None:
            raise _HTTPError(411, "Content-Length required")
        try:
            length = int(header)
        except ValueError as exc:
            raise _HTTPError(400, "invalid Content-Length") from exc
        if length < 0:
            raise _HTTPError(400, "invalid Content-Length")
        if length > MAX_BODY:
            # Close the connection: the body is left unread on purpose, and a
            # reused socket would interpret those bytes as a new request.
            self.close_connection = True
            raise _HTTPError(413, f"body exceeds {MAX_BODY} bytes")
        raw = self.rfile.read(length) if length else b""
        self._body_read = True
        if not raw:
            return {}
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _HTTPError(400, f"invalid JSON body: {exc}") from exc
        if not isinstance(body, dict):
            raise _HTTPError(400, "body must be a JSON object")
        return body

    def _send_json(self, status: int, payload: Optional[Dict[str, Any]] = None) -> None:
        """Send one JSON response; ``payload=None`` means 204 (no body)."""
        if payload is None:
            self._send_body(status, b"", None)
            return
        self._send_body(status, json.dumps(payload, default=str).encode("utf-8"),
                        "application/json")

    def _send_body(self, status: int, body: bytes, content_type: Optional[str],
                   extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
        """Write one response; ``content_type=None`` means 204 (no body).

        This is the only place the handler writes to the socket, so the framing
        rules — Content-Length, and when the connection must close instead of
        being reused — are stated exactly once.
        """
        if self._responded:
            return
        self._responded = True
        self._status = status
        if not self._body_read:
            # We are answering before consuming the request body (401/404/413).
            # Reusing the socket would make those bytes look like a new request,
            # so this response closes the connection instead.
            declared = self.headers.get("Content-Length")
            if declared not in (None, "0"):
                self.close_connection = True
        try:
            self.send_response(status)
            if content_type is None:
                # 204 must not carry Content-Length; close so framing is unambiguous.
                self.send_header("Connection", "close")
                self.close_connection = True
            else:
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                for name, value in extra_headers or ():
                    self.send_header(name, value)
            self.end_headers()
            if body and not self._head_only:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    # ------------------------------------------------------------- routes
    def _h_dashboard(self, parsed: SplitResult) -> None:
        """The operator console: static markup, therefore no token required.

        Everything the page displays is fetched by the browser afterwards with
        the operator's own token, so serving the shell to an anonymous caller
        reveals only that a server is listening. The CSP is sent here because
        this is the one response that renders markup.
        """
        from jocky.agent.dashboard import render
        self._send_body(200, render(), "text/html; charset=utf-8",
                        extra_headers=[("Content-Security-Policy", CONSOLE_CSP),
                                       ("X-Content-Type-Options", "nosniff"),
                                       ("Referrer-Policy", "no-referrer")])

    def _h_favicon(self, parsed: SplitResult) -> None:
        """204: the console carries its icon inline, so there is nothing to send.

        Answering empty is deliberate. A browser that asks here must not consume
        an authentication failure on the operator's IP (see ``_PUBLIC_ROUTES``).
        """
        self._send_body(204, b"", None)

    def _h_health(self, parsed: SplitResult) -> None:
        """Unauthenticated liveness probe: reachable, versioned, that is all."""
        self._send_json(200, {"status": "ok", "version": __version__})

    def _h_enroll(self, parsed: SplitResult) -> None:
        body = self._read_json()
        _fields(body, ("name", "host"), ("uid", "kernel"))
        agent_id = self.server.store.enroll(
            name=_as_str(body, "name"), host=_as_str(body, "host"),
            uid=_as_uid(body), kernel=_as_str(body, "kernel", "unknown"),
        )
        self._agent_id = agent_id
        self._send_json(200, {"agent_id": agent_id})

    def _h_poll(self, parsed: SplitResult) -> None:
        body = self._read_json()
        _fields(body, ("agent_id",))
        agent_id = _as_str(body, "agent_id")
        if not agent_id:
            raise _HTTPError(400, "agent_id must not be empty")
        self._agent_id = agent_id
        self.server.store.touch_agent(agent_id)
        job = self.server.store.next_job(agent_id)
        if job is None:
            self._send_json(204, None)
            return
        self._send_json(200, job.as_wire())

    def _h_result(self, parsed: SplitResult) -> None:
        body = self._read_json()
        _fields(body, ("job_id", "agent_id", "result"))
        job_id = _as_str(body, "job_id")
        agent_id = _as_str(body, "agent_id")
        result = body.get("result")
        if not isinstance(result, dict):
            raise _HTTPError(400, "result must be an object")
        self._agent_id = agent_id
        store = self.server.store

        if not agent_id or not store.agent(agent_id):
            raise _HTTPError(404, "unknown agent_id — enrol before reporting")
        if not job_id:
            raise _HTTPError(400, "job_id must not be empty")

        outcome = store.finish_job(job_id, agent_id=agent_id, result=result)
        if not outcome["stored"]:
            # A replay of an already-finished job is acknowledged without writing
            # anything (agents retry); an unknown job or another agent's job is
            # rejected outright.
            duplicate = bool(outcome.get("duplicate"))
            self._send_json(200 if duplicate else 409, {
                "stored": False,
                "duplicate": duplicate,
                "reason": outcome["reason"],
                "payload_sha256": outcome.get("payload_sha256"),
            })
            return
        count = store.store_findings(job_id, agent_id, result.get("findings"))
        self._send_json(200, {
            "stored": True,
            "findings": count,
            "status": outcome["status"],
            "payload_sha256": outcome.get("payload_sha256"),
        })

    def _h_submit(self, parsed: SplitResult) -> None:
        body = self._read_json()
        _fields(body, ("kind", "payload_b64"), ("target",))
        kind = _as_str(body, "kind")
        if not kind:
            raise _HTTPError(400, "kind must not be empty")
        if kind not in JOB_KINDS:
            raise _HTTPError(
                400, f"unknown job kind {kind!r}; the agent executes: "
                     f"{', '.join(JOB_KINDS)}")
        payload = _as_b64(body, "payload_b64")
        target = body.get("target")
        if target is not None and not isinstance(target, str):
            raise _HTTPError(400, "target must be a string or null")
        job_id = self.server.store.enqueue(kind, payload, target=target or None)
        self._send_json(200, {"job_id": job_id})

    def _h_status(self, parsed: SplitResult) -> None:
        self._send_json(200, self.server.store.status())

    def _h_findings(self, parsed: SplitResult) -> None:
        query = parse_qs(parsed.query)
        limit = 200
        if "limit" in query:
            try:
                limit = int(query["limit"][0])
            except (IndexError, ValueError) as exc:
                raise _HTTPError(400, "limit must be an integer") from exc
            if not 1 <= limit <= 1000:
                raise _HTTPError(400, "limit must be between 1 and 1000")
        severity = query.get("severity", [None])[0]
        if severity is not None and not severity:
            raise _HTTPError(400, "severity must not be empty")
        rows = self.server.store.findings(limit=limit, severity=severity)
        self._send_json(200, {"count": len(rows), "findings": rows})


_ROUTES: Dict[Tuple[str, str], Callable[[Handler, SplitResult], None]] = {
    ("GET", "/"): Handler._h_dashboard,
    ("GET", "/dashboard"): Handler._h_dashboard,
    ("GET", "/favicon.ico"): Handler._h_favicon,
    ("GET", "/v1/health"): Handler._h_health,
    ("POST", "/v1/enroll"): Handler._h_enroll,
    ("POST", "/v1/jobs/poll"): Handler._h_poll,
    ("POST", "/v1/jobs/result"): Handler._h_result,
    ("POST", "/v1/jobs/submit"): Handler._h_submit,
    ("GET", "/v1/status"): Handler._h_status,
    ("GET", "/v1/findings"): Handler._h_findings,
}


# --------------------------------------------------------------------- serving
def serve(host: str = "127.0.0.1", port: int = 8443, token: Optional[str] = None,
          cert: Optional[str] = None, key: Optional[str] = None,
          state_dir: str = DEFAULT_STATE_DIR) -> int:
    """Run the management server until interrupted; returns a process code.

    Blocks in :meth:`ThreadingHTTPServer.serve_forever`, so callers that need
    the bound port (tests pass ``port=0``) read it from the banner on stdout or
    from :func:`last_bound_port`, and stop it with :func:`shutdown`.
    """
    global _LAST_SERVER, _LAST_BOUND_PORT

    state_dir = os.path.abspath(state_dir)
    os.makedirs(state_dir, exist_ok=True)
    if token is None:
        token = secrets.token_urlsafe(32)
        # Shown exactly once: it is a credential, and logs outlive this process.
        print(f"jocky-server token (generated, shown once): {token}", file=sys.stderr,
              flush=True)
    elif not token:
        raise ValueError("token must not be empty")

    if not cert or not key:
        cert, key = ensure_cert(state_dir)

    store = Store(os.path.join(state_dir, STORE_NAME))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.store = store  # type: ignore[attr-defined]
    httpd.token = token  # type: ignore[attr-defined]

    bound_port = httpd.server_address[1]
    with _LOG_LOCK:
        _LAST_SERVER = httpd
        _LAST_BOUND_PORT = bound_port
    # The banner carries the *actual* port so ``--port 0`` stays usable.
    print(f"jocky-server listening on https://{host}:{bound_port}", flush=True)
    print(f"jocky-server console:   https://{host}:{bound_port}/", flush=True)

    try:
        httpd.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        _log("interrupted")
    finally:
        httpd.server_close()
        store.close()
        with _LOG_LOCK:
            if _LAST_SERVER is httpd:
                _LAST_SERVER = None
        _log("stopped")
    return 0
