"""
Central-management end-to-end tests.

The server is started for real on an ephemeral port with a generated
self-signed certificate, the agent is driven over TLS, and the assertions are
about what an operator would observe: job queued → work executed on the agent →
finding stored with provenance.  Nothing about the network is mocked.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.agent import client, server as server_mod  # noqa: E402

TOKEN = "test-token-do-not-reuse"

_JOBS_SCRIPT = """
emit {"kind": "agent-test", "hostname": sys.hostname(),
      "uptime_positive": sys.uptime().seconds > 0, "listeners": len(net.listeners())}
emit {"kind": "second", "severity": "low", "title": "second finding"}
"""


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


@pytest.fixture(scope="module")
def management_server():
    state_dir = tempfile.mkdtemp(prefix="jky-server-")
    thread = threading.Thread(
        target=server_mod.serve,
        kwargs={"host": "127.0.0.1", "port": 0, "token": TOKEN,
                "state_dir": state_dir},
        daemon=True,
    )
    thread.start()
    port = None
    for _ in range(200):
        port = server_mod.last_bound_port()
        if port:
            break
        time.sleep(0.05)
    assert port, "management server never reported a bound port"
    yield {"port": port, "token": TOKEN, "state": state_dir,
           "url": f"https://127.0.0.1:{port}"}
    server_mod.shutdown()
    thread.join(timeout=15)


def api(server, path, token=None, payload=None, method=None, timeout=15):
    """One JSON call against the management API (returns status, body)."""
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        server["url"] + path, data=data, method=method or ("POST" if data else "GET"))
    if token:
        request.add_header("X-JKY-Token", token)
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, context=_tls_context(), timeout=timeout) as resp:
            body = resp.read()
            return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, None


# --------------------------------------------------------------------- access
def test_health_needs_no_token(management_server):
    status, body = api(management_server, "/v1/health")
    assert status == 200 and body["status"] == "ok"


@pytest.mark.parametrize("token", [None, "wrong-token"])
def test_other_routes_require_the_token(management_server, token):
    status, _body = api(management_server, "/v1/status", token=token)
    assert status == 401


def test_unknown_route_is_404(management_server):
    status, _body = api(management_server, "/v1/nope", token=TOKEN)
    assert status == 404


def test_oversized_body_is_rejected(management_server):
    raw = socket.create_connection(("127.0.0.1", management_server["port"]), timeout=15)
    try:
        sock = _tls_context().wrap_socket(raw, server_hostname="127.0.0.1")
        headers = (f"POST /v1/jobs/submit HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                   f"X-JKY-Token: {TOKEN}\r\n"
                   f"Content-Length: {server_mod.MAX_BODY + 1}\r\n\r\n")
        sock.sendall(headers.encode())
        response = sock.recv(4096).decode("utf-8", "replace")
        assert "413" in response.splitlines()[0], response.splitlines()[:1]
    finally:
        raw.close()


# ------------------------------------------------------------------ work flow
def test_full_job_lifecycle(management_server, tmp_path):
    host = socket.gethostname()
    name = f"test-agent-{time.time_ns() % 100000}"

    status, first = api(management_server, "/v1/enroll", token=TOKEN,
                        payload={"name": name, "host": host, "uid": 1000,
                                 "kernel": "test"})
    assert status == 200 and first["agent_id"]
    _status, second = api(management_server, "/v1/enroll", token=TOKEN,
                          payload={"name": name, "host": host, "uid": 1000,
                                   "kernel": "test"})
    assert second["agent_id"] == first["agent_id"], "enrolment is not idempotent"

    status, submitted = api(management_server, "/v1/jobs/submit", token=TOKEN,
                            payload={"kind": "source",
                                     "payload_b64": _b64(_JOBS_SCRIPT),
                                     "target": first["agent_id"]})
    assert status == 200 and submitted["job_id"]

    # the agent claims and executes the job (a manual poll here would consume it)
    agent_state = tmp_path / "agent-state"
    exit_code = client.run(server=management_server["url"], token=TOKEN, once=True,
                           name=name, state_dir=str(agent_state))
    assert exit_code == 0

    # a second job proves the payload survives the wire unchanged
    status, wire_job = api(management_server, "/v1/jobs/submit", token=TOKEN,
                           payload={"kind": "source", "payload_b64": _b64(_JOBS_SCRIPT),
                                    "target": first["agent_id"]})
    assert status == 200
    status, claimed = api(management_server, "/v1/jobs/poll", token=TOKEN,
                          payload={"agent_id": first["agent_id"]})
    assert status == 200
    assert claimed["job_id"] == wire_job["job_id"]
    assert claimed["kind"] == "source"
    assert _unb64(claimed["payload_b64"]) == _JOBS_SCRIPT, "payload did not survive the wire"

    status, findings = api(management_server, "/v1/findings?limit=50", token=TOKEN)
    assert status == 200
    stored = [f for f in findings["findings"] if f["job_id"] == submitted["job_id"]]
    assert len(stored) == 2, stored
    by_check = {f["check"]: f for f in stored}
    assert "agent-test" in by_check
    assert by_check["agent-test"]["severity"] == "info"
    assert by_check["agent-test"]["evidence"]["uptime_positive"] is True
    assert by_check["second"]["severity"] == "low"

    status, report = api(management_server, "/v1/status", token=TOKEN)
    assert status == 200
    assert any(a["agent_id"] == first["agent_id"] for a in report["agents"])
    assert report["jobs"]["ok"] >= 1, report["jobs"]
    assert report["jobs"]["running"] >= 1, report["jobs"]     # the wire-check job
    assert report["findings"]["total"] >= 2

    journal = agent_state / "journal.jsonl"
    assert journal.exists(), "agent kept no local journal"
    entries = [json.loads(line) for line in journal.read_text().splitlines() if line.strip()]
    assert any(entry.get("job_id") == submitted["job_id"] for entry in entries)


def test_poll_without_work_returns_no_content(management_server):
    status, _first = api(management_server, "/v1/enroll", token=TOKEN,
                         payload={"name": "idle-agent", "host": socket.gethostname(),
                                  "uid": 1000, "kernel": "test"})
    assert status == 200
    _status, agent = api(management_server, "/v1/enroll", token=TOKEN,
                         payload={"name": "idle-agent", "host": socket.gethostname(),
                                  "uid": 1000, "kernel": "test"})
    status, body = api(management_server, "/v1/jobs/poll", token=TOKEN,
                       payload={"agent_id": agent["agent_id"]})
    assert status == 204 and body is None


def test_agent_state_is_owner_only(management_server, tmp_path):
    """The state directory holds the pinned fingerprint and the job journal."""
    import stat as stat_mod

    state = tmp_path / "hardened-state"
    code = client.run(server=management_server["url"], token=TOKEN, once=True,
                      name=f"perm-agent-{time.time_ns() % 100000}", state_dir=str(state))
    assert code == 0, "agent run failed, cannot judge permissions"

    mode = stat_mod.S_IMODE(os.stat(state).st_mode)
    assert mode == 0o700, oct(mode)

    identity = state / "agent.json"
    assert identity.exists()
    assert stat_mod.S_IMODE(os.stat(identity).st_mode) == 0o600
    payload = json.loads(identity.read_text())
    assert payload["agent_id"], payload
    assert payload.get("fingerprint"), "server certificate was not pinned at enrolment"


def test_pinned_transport_refuses_a_different_certificate(management_server):
    """A pin mismatch must be reported, not raise from inside http.client."""
    wrong = "0" * 64
    transport = client._Transport(management_server["url"], TOKEN, pin=wrong)
    response = transport.request("GET", "/v1/health")
    assert not response.ok
    assert response.status == 0
    assert "fingerprint mismatch" in (response.error or ""), response.error


def test_serving_with_a_token_file(management_server):
    """`jocky serve --token-file` must accept the same token as --token."""
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        token_path = os.path.join(directory, "token")
        with open(token_path, "w", encoding="utf-8") as handle:
            handle.write("token-from-a-file\n")
        process = subprocess.Popen(
            [sys.executable, "-m", "jocky", "serve", "--host", "127.0.0.1", "--port", "0",
             "--token-file", token_path, "--state", os.path.join(directory, "srv")],
            cwd=str(REPO), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            port = None
            deadline = time.time() + 30
            while time.time() < deadline and port is None:
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                match = re.search(r"127\.0\.0\.1:(\d+)", line)
                if match:
                    port = int(match.group(1))
            assert port, "serve never reported a bound port"
            status, body = api({"url": f"https://127.0.0.1:{port}", "port": port},
                               "/v1/status", token="token-from-a-file")
            assert status == 200, body
            status_denied, _ = api({"url": f"https://127.0.0.1:{port}", "port": port},
                                   "/v1/status", token="wrong")
            assert status_denied == 401
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()



def test_agent_rejects_tampered_payload_sha256():
    """Agent must reject execution if payload_sha256 does not match decoded bytes."""
    from jocky.agent import client
    job = {
        "job_id": "job_tampered",
        "kind": "source",
        "payload_b64": _b64('emit "MALICIOUS"'),
        "payload_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    }
    result, status = client._execute(job, "localhost", "test-agent")
    assert status == "error"
    assert result.get("errors") and "cryptographic task integrity violation" in result["errors"][0]

def _b64(text: str) -> str:
    import base64
    return base64.b64encode(text.encode()).decode()


def _unb64(data: str) -> str:
    import base64
    return base64.b64decode(data).decode()


# ------------------------------------------------------------------- console
def _raw(server, path, method="GET", token=None):
    """One raw HTTP exchange, for responses that are not JSON.

    ``api()`` parses JSON, so the console (HTML) and HEAD (no body) need their
    own probe. Returns ``(status, headers, body)``.
    """
    request = urllib.request.Request(server["url"] + path, method=method)
    if token:
        request.add_header("X-JKY-Token", token)
    try:
        with urllib.request.urlopen(request, context=_tls_context(), timeout=15) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def test_console_is_served_without_a_token(management_server):
    """The console shell carries no data and no credential, so it is public —
    the same reasoning as a login page. Its API calls still need the token,
    which ``test_other_routes_require_the_token`` covers."""
    status, headers, body = _raw(management_server, "/")
    assert status == 200, status
    assert headers["Content-Type"].startswith("text/html")
    assert b"<!DOCTYPE html>" in body
    # Self-contained by design: the server is expected to run on a range with
    # no egress, where a CDN reference renders a blank page.
    assert b"http://" not in body and b"https://" not in body
    assert "default-src 'none'" in headers["Content-Security-Policy"]


def test_console_route_alias(management_server):
    status, _headers, body = _raw(management_server, "/dashboard")
    assert status == 200 and b"<!DOCTYPE html>" in body


def test_console_never_injects_fleet_supplied_text_as_markup(management_server):
    """Agent names/hosts and finding titles are chosen by the remote side.

    A console that built its DOM from markup strings would turn a hostile agent
    name into stored XSS in the operator's browser, so the page must compose
    elements and assign ``textContent``.
    """
    from jocky.agent.dashboard import DASHBOARD_HTML
    assert "innerHTML" not in DASHBOARD_HTML
    assert "textContent" in DASHBOARD_HTML


def test_head_returns_headers_without_a_body(management_server):
    """Probes and reverse proxies use HEAD; without it the stock handler
    answers 501, which a monitor reads as a dead service rather than a live one."""
    status, headers, body = _raw(management_server, "/", method="HEAD")
    assert status == 200
    assert body == b""
    assert int(headers["Content-Length"]) > 0


@pytest.mark.parametrize("kind", ["run", "exec", "bogus"])
def test_unknown_job_kind_is_refused_at_submit(management_server, kind):
    """A typo must fail where the operator can still fix it.

    The agent's vocabulary is ``source``/``fileless``; anything else used to be
    queued and then reported as ``unsupported job kind`` as a *result*, which
    reads as a job that ran and failed rather than one that was never valid.
    """
    status, body = api(management_server, "/v1/jobs/submit", token=TOKEN,
                       payload={"kind": kind, "payload_b64": _b64('emit 1')})
    assert status == 400, body
    assert "source" in body["error"] and "fileless" in body["error"]


def test_empty_job_kind_is_refused(management_server):
    status, body = api(management_server, "/v1/jobs/submit", token=TOKEN,
                       payload={"kind": "", "payload_b64": _b64('emit 1')})
    assert status == 400, body
