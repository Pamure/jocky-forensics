"""
Collection agent for the JOCKY central management plane (SIH26148).

An agent is deliberately dumb and boring: it enrols once, then asks the
management server "anything for me?", runs exactly what it is handed with the
same runtime the CLI uses, and reports the result back. All policy — which
hosts, which checks, which payload — lives on the server side where an operator
can see and audit it.

Worth stating plainly:

* **The payload is trusted input here.** A job is code to execute by design;
  the trust boundary is the management token, which is why it is checked by the
  server in constant time and never written to a log.
* **The channel is a trusted channel, not a covert one.** TLS with a
  self-signed certificate plus a shared token. ``insecure`` skips certificate
  verification because the server's certificate is self-signed, not because
  verification does not matter.
* **Frontability.** ``sni`` lets the agent connect to the address in
  ``--server`` while presenting a different TLS SNI *and* HTTP Host header.
  That is the hook a domain-fronted deployment would use; no CDN exists in a
  local run, and none is claimed. The docstring of :class:`_Transport` says the
  same thing where the code lives.
* **The journal is the point of a forensic agent.** ``journal.jsonl`` records
  every executed job before the result is reported, so what an agent did stays
  auditable even when the server was unreachable at report time.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import os
import platform
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

from jocky import runner

IDENTITY_NAME = "agent.json"
JOURNAL_NAME = "journal.jsonl"
DEFAULT_STATE_DIR = ".jocky-agent"

#: Wall clock ceiling handed to the runtime for one job. A management agent
#: must stay responsive, so a runaway payload is cut off rather than allowed to
#: pin the host forever.
JOB_WALL_MS = runner.DEFAULT_WALL_MS
JOB_MAX_STEPS = runner.DEFAULT_MAX_STEPS
FILELESS_TIMEOUT = 120.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _journal(path: str, entry: Dict[str, Any]) -> None:
    """Append one JSON line to the local audit journal.

    Called *before* the result is reported: if the network or the server is
    gone, the local record still proves what ran and what came back.
    """
    entry.setdefault("ts", _now())
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, default=str) + "\n")
    except OSError as exc:  # a broken journal must not stop collection
        print(f"jocky-agent: journal write failed: {exc}", file=sys.stderr)


# --------------------------------------------------------------------- wire
@dataclass(frozen=True)
class Response:
    """One HTTP exchange. ``status == 0`` means the request never got there."""

    status: int
    body: Dict[str, Any]
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class CertificatePinError(RuntimeError):
    """The server presented a certificate that does not match the pinned one.

    Raised from the connection handshake, so it is also listed in
    :meth:`_Transport.request`'s except clause: an embedder calling
    :func:`jocky.agent.client.run` must get a reportable failure, not a stray
    exception from deep inside ``http.client``.
    """


class _FrontedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection presenting an SNI that may differ from the connect host.

    ``sni`` is the fronting hook: TCP goes to the host in ``--server`` while
    the ClientHello (and, via the explicit Host header, the request) carries a
    different name. Nothing here produces domain fronting on its own — that
    needs a CDN whose edge answers for the fronted name — so this is a
    *capability*, documented as such.

    ``pin`` is the integrity hook. The management server uses a self-signed
    certificate, so certificate *pinning* is what actually authenticates it:
    the SHA-256 of the presented certificate must equal the fingerprint learned
    at enrolment. Without it, anyone who answers the socket can read the
    management token and hand the agent jobs of their choosing.
    """

    def __init__(self, *args: Any, sni: Optional[str] = None,
                 pin: Optional[str] = None, **kwargs: Any) -> None:
        self._jky_sni = sni
        self._jky_pin = pin
        self.peer_fingerprint: Optional[str] = None
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout,
                                        self.source_address)
        try:
            self.sock = self._context.wrap_socket(sock,
                                                  server_hostname=self._jky_sni or self.host)
        except BaseException:
            sock.close()
            raise
        raw = self.sock.getpeercert(binary_form=True)
        if raw:
            self.peer_fingerprint = hashlib.sha256(raw).hexdigest()
        if self._jky_pin:
            if not self.peer_fingerprint:
                self.sock.close()
                raise CertificatePinError("server presented no certificate to pin")
            if self.peer_fingerprint != self._jky_pin:
                self.sock.close()
                raise CertificatePinError(
                    "server certificate fingerprint mismatch: expected "
                    f"{self._jky_pin[:16]}…, got {self.peer_fingerprint[:16]}…"
                )


class _Transport:
    """Minimal JSON transport for the management API (stdlib only)."""

    def __init__(self, base: str, token: str, *, insecure: bool = False,
                 sni: Optional[str] = None, pin: Optional[str] = None,
                 verify_ca: bool = False, timeout: float = 15.0) -> None:
        candidate = base if "://" in base else "https://" + base
        parts = urlsplit(candidate)
        if parts.scheme not in ("https", "http"):
            raise ValueError(f"unsupported server scheme: {parts.scheme!r}")
        if not parts.hostname:
            raise ValueError("server URL has no host")
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.prefix = parts.path.rstrip("/")
        self.sni = sni
        self.pin = pin
        self.token = token
        self.timeout = timeout
        self.peer_fingerprint: Optional[str] = None
        self.insecure = bool(insecure)
        self.context = ssl.create_default_context()
        if verify_ca:
            # A deployment with a real certificate authority: full verification.
            pass
        else:
            # The management server ships a self-signed certificate, so the chain
            # cannot be validated against system CAs. Authenticity comes from the
            # pinned fingerprint instead: learned at enrolment, enforced after.
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE
        if insecure:
            # Explicit opt-out: no chain check *and* no pinning.
            self.pin = None
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    @property
    def base_url(self) -> str:
        """Identity string used to detect that the agent was pointed elsewhere."""
        return f"{self.scheme}://{self.host}:{self.port}{self.prefix}"

    def request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None
                ) -> Response:
        """Perform one request, converting transport failures into a Response."""
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"X-JKY-Token": self.token, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        if self.sni:
            # A fronted deployment addresses the fronted name, not the edge IP.
            headers["Host"] = self.sni
        connection: Any = None
        try:
            if self.scheme == "https":
                connection = _FrontedHTTPSConnection(
                    self.host, self.port, timeout=self.timeout,
                    context=self.context, sni=self.sni, pin=self.pin)
            else:
                connection = http.client.HTTPConnection(self.host, self.port,
                                                        timeout=self.timeout)
            connection.request(method, self.prefix + path, body=body, headers=headers)
            raw = connection.getresponse()
            self.peer_fingerprint = (
                getattr(connection, "peer_fingerprint", None) or self.peer_fingerprint
            )
            data = raw.read()
            if raw.status == 204 or not data:
                return Response(status=raw.status, body={})
            try:
                parsed = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return Response(status=raw.status, body={},
                                error="server returned a non-JSON body")
            return Response(status=raw.status,
                            body=parsed if isinstance(parsed, dict) else {"data": parsed})
        except CertificatePinError as exc:
            # A pin mismatch is a hard trust failure: report it, never retry.
            return Response(status=0, body={}, error=str(exc))
        except (OSError, http.client.HTTPException, ValueError) as exc:
            return Response(status=0, body={}, error=f"{type(exc).__name__}: {exc}")
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass


# ------------------------------------------------------------------ identity
@dataclass
class Identity:
    """What the agent knows about itself across restarts."""

    agent_id: str
    server: str
    name: str = ""
    host: str = ""
    fingerprint: str = ""      # SHA-256 of the server certificate, learned at enrolment

    @classmethod
    def load(cls, path: str, server: str) -> Optional["Identity"]:
        """Load a stored identity, but only for the server it was issued by.

        A cached ``agent_id`` is meaningless — and confusing in the audit trail
        — against a different management server, so a mismatch forces a fresh
        enrolment.
        """
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or not data.get("agent_id"):
            return None
        if data.get("server") != server:
            return None
        return cls(agent_id=str(data["agent_id"]), server=str(data.get("server", server)),
                   name=str(data.get("name", "")), host=str(data.get("host", "")),
                   fingerprint=str(data.get("fingerprint", "")))

    def save(self, path: str) -> None:
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(asdict(self), handle, indent=2)
        except OSError as exc:
            print(f"jocky-agent: could not persist identity: {exc}", file=sys.stderr)


def _enroll(transport: _Transport, name: str, host: str) -> Optional[str]:
    """Ask the server for an agent id; ``None`` when the server said no."""
    response = transport.request("POST", "/v1/enroll", {
        "name": name,
        "host": host,
        "uid": os.getuid() if hasattr(os, "getuid") else 0,
        "kernel": platform.release(),
    })
    if response.error or not response.ok:
        detail = response.error or f"HTTP {response.status}: {response.body.get('error', '')}"
        print(f"jocky-agent: enrolment failed: {detail}", file=sys.stderr)
        return None
    agent_id = response.body.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        print("jocky-agent: enrolment response had no agent_id", file=sys.stderr)
        return None
    return agent_id


# ---------------------------------------------------------------- execution
def _error_result(message: str) -> Dict[str, Any]:
    """A run-result-shaped failure, so the server never sees a missing shape."""
    return {"findings": [], "output": [], "errors": [message], "steps": 0,
            "native_calls": 0, "duration_ms": 0.0, "truncated": False}


def _execute(job: Dict[str, Any], host: str, name: str) -> Tuple[Dict[str, Any], str]:
    """Run one job locally and return ``(result_dict, status)``.

    ``status`` is the job's terminal state: ``ok``, ``error`` or ``timeout``.
    """
    job_id = str(job.get("job_id", ""))
    kind = str(job.get("kind", ""))
    started = time.perf_counter()
    try:
        payload = base64.b64decode(str(job.get("payload_b64", "")), validate=True)
    except (binascii.Error, ValueError) as exc:
        result = _error_result(f"payload is not valid base64: {exc}")
        return _with_metrics(result, host, name, job, kind, started), "error"

    if kind == "source":
        run = runner.run_bytes(payload, wall_clock_ms=JOB_WALL_MS,
                               max_steps=JOB_MAX_STEPS)
        result = run.to_dict()
    elif kind == "fileless":
        # Nothing touches the target's filesystem: interpreter, runtime and
        # payload all live in anonymous memfds (see jocky.exec.fileless).
        outcome = runner.fileless_run_bytes(payload, wall_clock_ms=JOB_WALL_MS,
                                            timeout=FILELESS_TIMEOUT,
                                            name=(name or "jky")[:24])
        result = outcome.get("result") or _error_result(
            (outcome.get("stderr") or "").strip() or "fileless run produced no result")
        result = dict(result)
        result["evidence"] = outcome.get("evidence", {})
        result["exit_code"] = outcome.get("exit_code")
    else:
        result = _error_result(f"unsupported job kind: {kind!r}")

    status = "error" if result.get("errors") else "ok"
    if kind == "fileless" and result.get("exit_code") not in (0, None):
        status = "error"
    return _with_metrics(result, host, name, job, kind, started), status


def _with_metrics(result: Dict[str, Any], host: str, name: str, job: Dict[str, Any],
                  kind: str, started: float) -> Dict[str, Any]:
    """Stamp the result with where it ran — findings without provenance are noise."""
    duration_ms = result.get("duration_ms")
    if not isinstance(duration_ms, (int, float)):
        duration_ms = (time.perf_counter() - started) * 1000.0
    result["metrics"] = {
        "host": host,
        "agent": name,
        "duration_ms": round(float(duration_ms), 3),
        "mode": kind,
        "job_id": str(job.get("job_id", "")),
    }
    return result


# --------------------------------------------------------------------- agent
def run(server: str, token: str, interval: float = 5.0, once: bool = False,
        name: Optional[str] = None, state_dir: str = DEFAULT_STATE_DIR,
        insecure: bool = False, sni: Optional[str] = None,
        pin: Optional[str] = None, verify_ca: bool = False) -> int:
    """Enrol (once) and serve jobs until interrupted.

    ``once`` performs exactly one poll-and-execute cycle, which is what the
    tests and any cron-driven deployment use; otherwise the agent sleeps
    ``interval`` seconds between polls. Ctrl-C is a clean exit (``0``).

    Certificate handling: the server is self-signed, so the agent *pins* its
    certificate instead of trusting a CA. The fingerprint is learned at first
    enrolment and stored in the state directory; later runs refuse a different
    certificate. ``insecure=True`` turns pinning off entirely and is only
    appropriate on a lab network.
    """
    state_dir = os.path.abspath(state_dir)
    os.makedirs(state_dir, exist_ok=True)
    identity_path = os.path.join(state_dir, IDENTITY_NAME)
    journal_path = os.path.join(state_dir, JOURNAL_NAME)

    host = socket.gethostname()
    agent_name = name or host
    identity = Identity.load(identity_path, f"{server}")
    # Pinning is the default trust model for a self-signed server; --insecure
    # turns it off deliberately.
    effective_pin = None if insecure else (pin or (identity.fingerprint if identity else None))
    try:
        transport = _Transport(server, token, insecure=insecure, sni=sni, pin=effective_pin,
                               verify_ca=verify_ca)
    except ValueError as exc:
        print(f"jocky-agent: bad --server: {exc}", file=sys.stderr)
        return 2

    identity = Identity.load(identity_path, transport.base_url)
    if identity is None:
        while True:
            agent_id = _enroll(transport, agent_name, host)
            if agent_id:
                identity = Identity(agent_id=agent_id, server=transport.base_url,
                                    name=agent_name, host=host,
                                    fingerprint=transport.peer_fingerprint or "")
                identity.save(identity_path)
                if identity.fingerprint:
                    print(f"jocky-agent: pinned server certificate "
                          f"{identity.fingerprint[:16]}…", file=sys.stderr)
                break
            if once:
                return 1
            try:
                time.sleep(max(0.0, interval))
            except KeyboardInterrupt:
                print("jocky-agent: interrupted during enrolment", file=sys.stderr)
                return 0

    print(f"jocky-agent {identity.agent_id} polling {transport.base_url}"
          f" (journal {journal_path})", flush=True)

    try:
        while True:
            response = transport.request("POST", "/v1/jobs/poll",
                                         {"agent_id": identity.agent_id})
            if response.status == 401:
                # A bad token will never fix itself; say so and stop.
                print("jocky-agent: unauthorized — check --token", file=sys.stderr)
                return 1
            if response.error:
                print(f"jocky-agent: poll failed: {response.error}", file=sys.stderr)
                if once:
                    return 1
            elif response.status == 204:
                if once:
                    return 0
            elif not response.ok:
                print(f"jocky-agent: poll rejected: HTTP {response.status}"
                      f" {response.body.get('error', '')}".rstrip(), file=sys.stderr)
                if once:
                    return 1
            else:
                _handle_job(transport, response.body, identity, host, agent_name,
                            journal_path)
                if once:
                    return 0
            time.sleep(max(0.0, interval))
    except KeyboardInterrupt:
        print("jocky-agent: interrupted", file=sys.stderr)
        return 0


def _handle_job(transport: _Transport, job: Dict[str, Any], identity: Identity,
                host: str, name: str, journal_path: str) -> None:
    """Execute one claimed job, journal it, then report it."""
    job_id = str(job.get("job_id", ""))
    kind = str(job.get("kind", ""))
    result, status = _execute(job, host, name)
    findings = result.get("findings")
    count = len(findings) if isinstance(findings, list) else 0
    evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
    entry: Dict[str, Any] = {
        "event": "job",
        "job_id": job_id,
        "kind": kind,
        "status": status,
        "duration_ms": result.get("metrics", {}).get("duration_ms"),
        "findings": count,
        "errors": len(result.get("errors") or []),
    }
    if evidence.get("exe"):
        # The fileless path's whole claim is where the process image lived.
        entry["exe"] = evidence["exe"]
    _journal(journal_path, entry)

    reported = transport.request("POST", "/v1/jobs/result", {
        "job_id": job_id,
        "agent_id": identity.agent_id,
        "result": result,
    })
    if reported.error or not reported.ok:
        detail = reported.error or f"HTTP {reported.status}: {reported.body.get('error', '')}"
        print(f"jocky-agent: could not report job {job_id}: {detail}", file=sys.stderr)
        _journal(journal_path, {"event": "report_failed", "job_id": job_id,
                                "error": detail})
        return
    _journal(journal_path, {"event": "reported", "job_id": job_id,
                            "stored": bool(reported.body.get("stored")),
                            "findings": reported.body.get("findings", count)})
    print(f"jocky-agent: job {job_id} ({kind}) {status}, {count} finding(s)",
          flush=True)


__all__ = ["run", "Identity", "JOB_WALL_MS", "JOB_MAX_STEPS"]
