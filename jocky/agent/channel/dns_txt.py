"""
TXT-record job channel: pillar 4's control transport, proven on loopback.

A resolver that *will* answer is the one primitive domain fronting lost and
DNS never did: any recursive resolver forwards TXT queries to the
authoritative zone, so a job channel riding TXT answers crosses every
network that allows DNS at all.  This module is the protocol core of that
channel, bound to loopback so the wire format can be tested end to end
without operator-owned authoritative infrastructure.

Wire format (both directions are plain RFC 1035 messages built with
``struct`` — no dnspython):

* **Poll** — a TXT (qtype 16) query for ``<poll>.jky.<zone>`` where ``<poll>``
  is the base32 (RFC 4648, lowercase, padding stripped) encoding of the
  agent id.  Case is folded by resolvers in transit, which is why the label
  is lowercase base32 rather than base64.
* **Answer** — one TXT RR per answer.  Its rdata carries the job blob as
  base64 text split into character-strings of at most 255 bytes, in RR
  order.  An unknown agent id (or a drained queue) gets a TXT holding a
  single empty string — the "NXDOMAIN-ish" not-found that blends into parked
  domain noise.
* **Armor** — the blob is ``zlib``-compressed JSON, XORed with a SHA-256
  counter keystream, then base64'd, so the on-the-wire text provably shares
  no substring with the job itself (the tests measure this).  The keystream
  is obfuscation, not encryption: authentication and confidentiality remain
  the job of the management-plane token and TLS layer, exactly as in
  :mod:`jocky.agent.server`.

The server side dequeues rows FIFO per agent; a row is {"agent_id",
"payload"} and is delivered to exactly one poll, in order.  Jobs acknowledged
by the network are gone from the store — the management plane re-queues
anything that needs retry, which keeps this channel stateless and boring.

Safety invariants: binds loopback only (``_require_loopback`` refuses
anything else), UDP only, one short-lived client socket per poll, and one
daemon serving thread that ``close()`` joins.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import socket
import struct
import threading
import zlib
from typing import Optional

QTYPE_TXT = 16
QCLASS_IN = 1
_MARKER = "jky"
_DEFAULT_ZONE = "ops.local"
_MAX_CHUNK = 255  # one DNS character-string
_RECV_CAP = 4096

# Fixed salt => deterministic, reproducible armor.  This is wire hygiene
# (no greppable plaintext), not a confidentiality boundary.
_ARMOR_SALT = b"jky-txt-armor-v1"


def _require_loopback(host: str) -> None:
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError(f"channel transports bind loopback only, not {host!r}")


def _keystream(n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(_ARMOR_SALT + struct.pack(">I", counter)).digest()
        counter += 1
    return bytes(out[:n])


def _xor(data: bytes, pad: bytes) -> bytes:
    # Big-int XOR keeps the whole transform in C; a Python loop would be
    # O(len) interpreted-byte work and dominates once jobs are sizeable.
    return (int.from_bytes(data) ^ int.from_bytes(pad)).to_bytes(len(data))


def _armor(raw: bytes) -> bytes:
    blob = zlib.compress(raw, 9)
    return base64.b64encode(_xor(blob, _keystream(len(blob))))


def _dearmor(text: bytes) -> bytes:
    blob = base64.b64decode(text, validate=True)
    return zlib.decompress(_xor(blob, _keystream(len(blob))))


def _b32_encode(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


def _b32_decode(label: str) -> Optional[bytes]:
    pad = "=" * ((8 - len(label) % 8) % 8)
    try:
        return base64.b32decode(label.upper() + pad)
    except (binascii.Error, ValueError):
        return None


def _encode_name(labels: list[str]) -> bytes:
    out = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        if not 0 < len(raw) <= 63:
            raise ValueError(f"DNS label of {len(raw)} bytes is outside 1..63")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def _txt_rdata(payload_b64: bytes) -> bytes:
    """One TXT RR's rdata: the payload split into <=255-byte strings; empty
    payload is a single empty string (the NXDOMAIN-ish sentinel)."""
    if not payload_b64:
        return b"\x00"
    chunks = [payload_b64[i : i + _MAX_CHUNK] for i in range(0, len(payload_b64), _MAX_CHUNK)]
    return b"".join(bytes([len(c)]) + c for c in chunks)


class DnsJobServer:
    """Serves a job store as TXT answers; see module docstring for the wire.

    Rows are ``{"agent_id", "payload"}`` dicts.  A matching poll dequeues the
    oldest matching row, so each job is delivered exactly once, in store
    order.  ``ready_event`` is set once the socket is bound and the serve
    loop is running; ``close()`` stops the thread and closes the socket.
    """

    def __init__(self, store_rows: list[dict], host: str = "127.0.0.1", port: int = 0,
                 zone: str = _DEFAULT_ZONE) -> None:
        _require_loopback(host)
        self.zone = zone.lower().rstrip(".")
        self._rows = [dict(row) for row in store_rows]
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.ready_event = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((host, port))
        self._sock.settimeout(0.2)  # so close() is promptly observed
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, name="jky-dns-txt", daemon=True)
        self._thread.start()

    # -- lifecycle ------------------------------------------------------
    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        finally:
            if self._thread.is_alive():
                self._thread.join(timeout=2.0)

    def __enter__(self) -> "DnsJobServer":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- serving --------------------------------------------------------
    def _dequeue(self, agent_id: str) -> Optional[dict]:
        with self._lock:
            for i, row in enumerate(self._rows):
                if row.get("agent_id") == agent_id:
                    return self._rows.pop(i)
        return None

    def _serve(self) -> None:
        self.ready_event.set()
        while not self._stop.is_set():
            try:
                msg, addr = self._sock.recvfrom(_RECV_CAP)
            except socket.timeout:
                continue
            except OSError:  # socket closed from close()
                break
            try:
                reply = self._answer(msg)
            except Exception:
                continue  # a malformed datagram is background noise, drop it
            if reply is not None:
                try:
                    self._sock.sendto(reply, addr)
                except OSError:
                    break

    def _answer(self, msg: bytes) -> Optional[bytes]:
        if len(msg) < 12:
            return None
        qid, flags, qdcount, _an, _ns, _ar = struct.unpack(">6H", msg[:12])
        if flags & 0x8000 or qdcount == 0:
            return None  # responses and empty questions get nothing
        off = 12
        labels: list[str] = []
        while True:
            if off >= len(msg):
                return None
            ln = msg[off]
            off += 1
            if ln == 0:
                break
            if ln & 0xC0 or off + ln > len(msg):
                return None  # compression in a question is bogus
            labels.append(msg[off : off + ln].decode("ascii", "replace"))
            off += ln
        if off + 4 > len(msg):
            return None
        qtype, qclass = struct.unpack(">HH", msg[off : off + 4])
        off += 4
        question = msg[12:off]

        rdata = b"\x00"
        answered = False
        if (
            qtype == QTYPE_TXT
            and qclass == QCLASS_IN
            and len(labels) >= 3
            and labels[1].lower() == _MARKER
            and ".".join(label.lower() for label in labels[2:]) == self.zone
        ):
            answered = True
            raw_id = _b32_decode(labels[0])
            agent_id = raw_id.decode("utf-8", "replace") if raw_id is not None else None
            job = self._dequeue(agent_id) if agent_id is not None else None
            if job is not None:
                rdata = _txt_rdata(_armor(json.dumps(job, separators=(",", ":")).encode()))

        flags_out = 0x8000 | 0x0400 | (flags & 0x0100)  # QR | AA | echo RD
        header = struct.pack(">6H", qid, flags_out, 1, 1 if answered else 0, 0, 0)
        if not answered:
            return header + question
        answer = b"\xC0\x0C" + struct.pack(">HHIH", QTYPE_TXT, QCLASS_IN, 0, len(rdata)) + rdata
        return header + question + answer


def serve(store_rows: list[dict], host: str = "127.0.0.1", port: int = 0) -> DnsJobServer:
    """Start a TXT job server over the given rows; see :class:`DnsJobServer`."""
    return DnsJobServer(store_rows, host=host, port=port)


class DnsJobClient:
    """Polling side of the channel.

    Every poll uses a fresh short-lived connected UDP socket (connected so a
    loopback port-unreachable surfaces as ``ConnectionRefusedError`` instead
    of an indefinite wait).  A timeout, refusal, poisoned answer, or empty
    TXT all read as "no job" (``None``) — the caller's poll cadence is the
    retry policy.  ``last_wire`` keeps the rdata of the TXT answered last so
    tests and operators can inspect exactly what crossed the wire.
    """

    def __init__(self, agent_id: str, host: str = "127.0.0.1", port: int = 0,
                 zone: str = _DEFAULT_ZONE, timeout: float = 2.0) -> None:
        _require_loopback(host)
        self.agent_id = agent_id
        self.host = host
        self.port = port
        self.zone = zone
        self.timeout = timeout
        self.last_wire: Optional[bytes] = None

    def close(self) -> None:  # sockets are per-poll; present for symmetry
        return None

    def __enter__(self) -> "DnsJobClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def poll(self) -> Optional[dict]:
        label = _b32_encode(self.agent_id.encode("utf-8"))
        try:
            name = _encode_name([label, _MARKER] + self.zone.split("."))
        except ValueError:
            return None  # agent id can never form a legal query
        qid = int.from_bytes(os.urandom(2))
        query = struct.pack(">6H", qid, 0x0100, 1, 0, 0, 0) + name + struct.pack(
            ">HH", QTYPE_TXT, QCLASS_IN
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            sock.send(query)
            data = sock.recv(_RECV_CAP)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        finally:
            sock.close()
        return self._parse(data, qid)

    def _parse(self, data: bytes, qid: int) -> Optional[dict]:
        if len(data) < 12:
            return None
        rid, flags, _qd, ancount, _ns, _ar = struct.unpack(">6H", data[:12])
        if rid != qid or not flags & 0x8000 or flags & 0x000F or ancount == 0:
            return None  # wrong id, not a response, or an error rcode
        off = 12
        # Skip the question.
        while off < len(data) and data[off] != 0:
            off += 1 + data[off]
        off += 5  # root byte + qtype + qclass
        armored = b""
        for _ in range(ancount):
            if off + 2 > len(data):
                return None
            if data[off] & 0xC0:  # compressed name pointer
                off += 2
            else:  # uncompressed name
                while off < len(data) and data[off] != 0:
                    off += 1 + data[off]
                off += 1
            if off + 10 > len(data):
                return None
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off : off + 10])
            off += 10
            if off + rdlen > len(data):
                return None
            rdata = data[off : off + rdlen]
            off += rdlen
            if rtype != QTYPE_TXT:
                continue
            self.last_wire = rdata
            # Concatenate this RR's character-strings in wire order.
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                i += 1
                armored += rdata[i : i + ln]
                i += ln
        if not armored:
            return None  # empty TXT sentinel, or no TXT RR at all
        try:
            job = json.loads(_dearmor(armored))
        except (ValueError, zlib.error, binascii.Error):
            return None  # poisoned answer reads as "no job", like a loss
        return job if isinstance(job, dict) else None
