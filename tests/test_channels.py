"""
Pillar-4 channel tests: the DNS TXT control channel and the relayed
websocket bulk channel, proven end to end on loopback.

What these tests pin:

* **DNS** — a poll dequeues each job exactly once and in store order, an
  unknown agent id gets the NXDOMAIN-ish empty TXT, and the on-the-wire
  bytes are measured to share no 8-byte window with the payload text (the
  gauge that the armor is honest, not plaintext-in-etc).
* **WebSocket** — two clients exchange messages in exact order; every byte
  the client puts on the wire is re-parsed from a raw capture and shown to
  be masked with a key that unmasks to the exact payload; a gigabyte of
  bulk travels as 64 KiB frames rather than stalling; close frames carry
  status 1000.
* **Deadlines** — a missed poll on either transport returns ``None`` well
  inside a 2 s budget; neither side can block a test suite forever.
"""
from __future__ import annotations

import base64
import hashlib
import pathlib
import socket
import struct
import sys
import threading
import time

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.agent.channel.dns_txt import (  # noqa: E402
    DnsJobClient,
    serve as dns_serve,
)
from jocky.agent.channel.ws_relay import RelayClient, RelayServer  # noqa: E402

TIMEOUT_BUDGET = 2.0  # seconds, per the pillar-4 brief

ROWS = [
    {"agent_id": "agent-07", "payload": "enumerate the /etc/ssh host keys and hash them"},
    {"agent_id": "agent-07", "payload": "snapshot the process table with parentage"},
    {
        "agent_id": "agent-07",
        # Long enough that its base64 armor spans several 255-byte TXT chunks,
        # so the character-string splitting is exercised for real.
        "payload": "rotate the telemetry signing key " + "0x5EED " * 60,
    },
]


# ----------------------------------------------------------------- helpers
class _SniffSock:
    """Socket proxy that records everything written, so masking can be
    audited from the raw wire bytes rather than from the module's word."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self.sent = bytearray()

    def sendall(self, data: bytes) -> None:
        self.sent += data
        self._sock.sendall(data)

    def __getattr__(self, name: str):  # recv/settimeout/close/... pass through
        return getattr(self._sock, name)


def _parse_wire_frames(data: bytes) -> list[tuple[bool, int, bool, bytes]]:
    """Independent re-implementation of the frame parser: if this and the
    module disagree about masking or payload, the module is lying."""
    frames = []
    off = 0
    while off < len(data):
        b1, b2 = data[off], data[off + 1]
        off += 2
        fin, opcode, masked = bool(b1 & 0x80), b1 & 0x0F, bool(b2 & 0x80)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack(">H", data[off : off + 2])[0]
            off += 2
        elif n == 127:
            n = struct.unpack(">Q", data[off : off + 8])[0]
            off += 8
        key = data[off : off + 4] if masked else None
        if masked:
            off += 4
        payload = bytearray(data[off : off + n])
        off += n
        if key is not None:
            for i in range(len(payload)):
                payload[i] ^= key[i & 3]
        frames.append((fin, opcode, masked, bytes(payload)))
    return frames


class _DropListener:
    """A fake DNS listener: receives datagrams, answers none.  A poll aimed
    here is a legitimate miss, not a refused connection."""

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self) -> None:
        self._stop.set()
        self._sock.close()
        self._thread.join(timeout=2.0)


# ---------------------------------------------------------------------- DNS
def test_dns_jobs_arrive_exactly_once_in_order():
    server = dns_serve(ROWS)
    try:
        assert server.ready_event.wait(timeout=2.0)
        client = DnsJobClient("agent-07", port=server.port, timeout=1.0)
        got = [client.poll() for _ in range(3)]
        assert got == ROWS  # order preserved, contents intact
        # Delivered rows are gone: two further polls both draw the empty TXT.
        assert client.poll() is None
        assert client.poll() is None
    finally:
        server.close()


def test_dns_wire_carries_no_plaintext_window():
    payload = ROWS[2]["payload"]
    assert len(payload) > 255  # spans multiple TXT character-strings
    server = dns_serve([ROWS[2]])
    try:
        client = DnsJobClient("agent-07", port=server.port, timeout=1.0)
        job = client.poll()
        assert job == ROWS[2]
        wire = client.last_wire
        assert wire  # a job was answered, not the empty sentinel
        raw = payload.encode()
        hits = [raw[i : i + 8] for i in range(len(raw) - 7) if raw[i : i + 8] in wire]
        assert hits == [], f"plaintext leaked onto the wire: {hits[:3]!r}"
    finally:
        server.close()


def test_dns_unknown_agent_gets_empty_txt():
    server = dns_serve(ROWS)
    try:
        client = DnsJobClient("agent-99", port=server.port, timeout=1.0)
        assert client.poll() is None
        # NXDOMAIN-ish: exactly one TXT character-string, of length zero.
        assert client.last_wire == b"\x00"
        # And the real agent's store was untouched by the stranger's poll.
        assert DnsJobClient("agent-07", port=server.port, timeout=1.0).poll() == ROWS[0]
    finally:
        server.close()


def test_dns_missed_poll_stays_inside_budget():
    listener = _DropListener()
    try:
        client = DnsJobClient("agent-07", port=listener.port, timeout=0.3)
        started = time.monotonic()
        assert client.poll() is None
        elapsed = time.monotonic() - started
        assert elapsed < TIMEOUT_BUDGET, f"missed poll blocked for {elapsed:.3f}s"
    finally:
        listener.close()


# --------------------------------------------------------------- websockets
def test_ws_exchange_is_ordered_and_every_client_frame_is_masked():
    server = RelayServer()
    try:
        assert server.ready_event.wait(timeout=2.0)
        sniff_a = _SniffSock(socket.create_connection(("127.0.0.1", server.port)))
        sniff_b = _SniffSock(socket.create_connection(("127.0.0.1", server.port)))
        a = RelayClient(client_id="alpha", sock=sniff_a, timeout=2.0)
        b = RelayClient(client_id="beta", sock=sniff_b, timeout=2.0)
        from_a = [f"alpha->beta job-{i} telemetry-blob" for i in range(5)]
        from_b = [f"beta->alpha result-{i} short-hash" for i in range(5)]
        for msg in from_a:
            a.send_text("beta", msg)
        for msg in from_b:
            b.send_text("alpha", msg)
        got_b = [b.recv_text(timeout=2.0) for _ in range(5)]
        got_a = [a.recv_text(timeout=2.0) for _ in range(5)]
        assert got_b == [("alpha", m) for m in from_a]
        assert got_a == [("beta", m) for m in from_b]
        a.close()
        b.close()
    finally:
        server.close()

    # Audit the captured wire bytes with an independent parser.
    frames = _parse_wire_frames(bytes(sniff_a.sent).split(b"\r\n\r\n", 1)[1])
    assert frames, "no client frames captured at all"
    assert all(masked for _, _, masked, _ in frames), "an unmasked client frame escaped"
    text_payloads = [p.decode() for _, op, _, p in frames if op == 0x1]
    assert text_payloads == [f"beta\n{m}" for m in from_a]
    assert any(op == 0x8 for _, op, _, _ in frames), "close() produced no close frame"


def test_ws_unaddressed_message_echoes_to_sender():
    server = RelayServer()
    try:
        client = RelayClient(client_id="solo", port=server.port, timeout=2.0)
        client.send_text("solo", "loop me back to my sender")
        assert client.recv_text(timeout=2.0) == ("solo", "loop me back to my sender")
        client.close()
    finally:
        server.close()


def test_ws_close_frame_carries_status_1000():
    server = RelayServer()
    try:
        client = RelayClient(client_id="gone", port=server.port, timeout=2.0)
        client.close()  # waits (bounded) for the server's close echo
        deadline = time.monotonic() + 2.0
        while not server.close_codes and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.close_codes == [1000]
    finally:
        server.close()


def _plaintext_bulk_server(port_box: list, ready: threading.Event, results: dict) -> None:
    """A plain-socket websocket endpoint: handshakes with its own SHA-1
    implementation, then streams frames, counting and hashing them without
    buffering the gigabyte."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port_box.append(listener.getsockname()[1])
    ready.set()
    conn, _ = listener.accept()
    try:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = conn.recv(4096)
            assert chunk, "client gave up mid-handshake"
            head += chunk
        key = next(
            line.split(b":", 1)[1].strip()
            for line in head.split(b"\r\n")
            if line.lower().startswith(b"sec-websocket-key:")
        )
        accept = base64.b64encode(
            hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
        )
        conn.sendall(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        )
        frames = total = 0
        largest = 0
        all_masked = True
        sha = hashlib.sha256()
        fin_seen = False
        reader = _BufferedReader(conn)
        while not fin_seen:
            b1, b2 = reader.read(2)
            fin_seen = bool(b1 & 0x80)
            all_masked = all_masked and bool(b2 & 0x80)
            n = b2 & 0x7F
            if n == 126:
                (n,) = struct.unpack(">H", reader.read(2))
            elif n == 127:
                (n,) = struct.unpack(">Q", reader.read(8))
            mask = reader.read(4)
            remaining = n
            while remaining:
                piece = reader.read(min(65536, remaining))
                remaining -= len(piece)
                pad = (mask * (len(piece) // 4 + 1))[: len(piece)]
                # int-XOR, unmasking this slice; offset alignment holds
                # because each frame's payload starts at mask phase 0.
                plain = (int.from_bytes(piece) ^ int.from_bytes(pad)).to_bytes(len(piece))
                sha.update(plain)
            frames += 1
            total += n
            largest = max(largest, n)
    finally:
        conn.close()
        listener.close()
    results.update(frames=frames, total=total, largest=largest,
                   masked=all_masked, sha=sha.hexdigest())


class _BufferedReader:
    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buf = bytearray()

    def read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._sock.recv(max(65536, n - len(self._buf)))
            if not chunk:
                raise ConnectionError("client closed early")
            self._buf += chunk
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


def test_ws_gigabyte_streams_as_64kib_frames():
    ready = threading.Event()
    port_box: list = []
    results: dict = {}
    server_thread = threading.Thread(
        target=_plaintext_bulk_server, args=(port_box, ready, results), daemon=True
    )
    server_thread.start()
    assert ready.wait(timeout=2.0)
    payload = b"jky-pillar4-blk!" * (1 << 26)  # exactly 1 GiB
    expect = hashlib.sha256()
    expect.update(b"bulk\n")
    expect.update(payload)
    expected_sha = expect.hexdigest()
    client = RelayClient(
        client_id="bulk", port=port_box[0], timeout=30.0,
        sock=socket.create_connection(("127.0.0.1", port_box[0])),
    )
    started = time.monotonic()
    sent = client.send_text("bulk", payload)
    elapsed = time.monotonic() - started
    client.close()
    server_thread.join(timeout=15.0)
    assert not server_thread.is_alive(), "bulk receiver never finished"
    assert len(payload) == 1 << 30
    wire = len(b"bulk\n") + len(payload)
    expected_frames = -(-wire // (1 << 16))
    assert sent == expected_frames == results["frames"]
    assert results["total"] == wire
    assert results["largest"] <= 1 << 16
    assert results["masked"] and results["sha"] == expected_sha
    # The durable assertions are the frame contract above (≤64 KiB frames,
    # masking, exact reassembly). The wall-clock budget is a guard against a
    # quadratic or per-byte regression — not a throughput target — and must
    # survive a contended CI host, which has measured 46 s for this send.
    assert elapsed < 120.0, f"gigabyte send took {elapsed:.1f}s — investigate, do not bump"


def test_ws_missed_recv_stays_inside_budget():
    server = RelayServer()
    try:
        client = RelayClient(client_id="quiet", port=server.port, timeout=2.0)
        started = time.monotonic()
        assert client.recv_text(timeout=0.3) is None  # nobody has mail for it
        elapsed = time.monotonic() - started
        assert elapsed < TIMEOUT_BUDGET, f"missed recv blocked for {elapsed:.3f}s"
        client.close()
    finally:
        server.close()
