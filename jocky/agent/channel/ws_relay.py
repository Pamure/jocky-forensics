"""
Relayed websocket channel: pillar 4's bulk transport, proven on loopback.

Domain fronting is gone, so bulk traffic rides a websocket through a relay
(a serverless worker, a friend-or-neutral host) instead of a borrowed SNI.
This module is the protocol core of that relay: a minimal, dependency-free
RFC 6455 text-frame websocket server and client, bound to loopback so the
handshake, masking rules, and framing can be tested byte for byte.

What is implemented, and why each piece matters:

* **Handshake** (RFC 6455 §1.3): GET with ``Upgrade: websocket`` and a
  ``Sec-WebSocket-Key`` nonce; the accept proof is
  ``base64(sha1(key + GUID))``.  Implemented by hand — the point of the
  pillar is that the protocol survives on infrastructure whose libraries
  we don't control, so there is no library here.
* **Masking**: every client→server frame carries a fresh 4-byte mask
  (§5.3 mandates it to protect intermediaries that parse frames naively);
  the server refuses unmasked client frames, and the client refuses masked
  server frames.  The tests re-parse raw captured bytes and verify the mask
  bit and the unmasking independently.
* **Framing**: 7/16/64-bit lengths, fragmentation of large payloads into
  64 KiB frames (so a gigabyte message streams instead of stalling), ping
  answered with pong, close (0x8) answered with an echo carrying 1000.
* **Routing**: a client registers under the id in its handshake path;
  a text frame's first line is the recipient id, the rest the body.  Mail
  for an unregistered id is queued and flushed on registration; mail to
  oneself echoes — the two properties pillar 4 needs from a relay pair.

Safety invariants: loopback-only binds, no socket survives ``close()``
(or ``__exit__``), and the accept/serve threads are daemons that
``close()`` joins, so a test run leaves nothing listening.
"""
from __future__ import annotations

import base64
import hashlib
import os
import socket
import struct
import threading
from typing import Optional

_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_OP_CONT, _OP_TEXT, _OP_CLOSE, _OP_PING, _OP_PONG = 0x0, 0x1, 0x8, 0x9, 0xA
_CLOSE_NORMAL = 1000
_CLOSE_PROTOCOL = 1002
_MAX_HEADER = 16384
FRAME_SIZE = 1 << 16  # 64 KiB chunks: bulk payloads stream, never stall


def _require_loopback(host: str) -> None:
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError(f"channel transports bind loopback only, not {host!r}")


def _accept_key(key_b64: str) -> str:
    digest = hashlib.sha1(key_b64.encode("ascii") + _GUID).digest()
    return base64.b64encode(digest).decode("ascii")


def _xor_mask(data: bytes, key: bytes) -> bytes:
    if not data:
        return data
    pad = (key * (len(data) // 4 + 1))[: len(data)]
    # Big-int XOR: the RFC mask is a 4-byte repeating key, and turning it
    # into one C-level XOR per frame is what makes gigabyte frames cheap.
    return (int.from_bytes(data) ^ int.from_bytes(pad)).to_bytes(len(data))


def _build_frame(opcode: int, payload: bytes, fin: bool = True,
                 mask_key: Optional[bytes] = None) -> bytes:
    out = bytearray([(0x80 if fin else 0) | opcode])
    n = len(payload)
    mask_bit = 0x80 if mask_key is not None else 0
    if n < 126:
        out.append(mask_bit | n)
    elif n <= 0xFFFF:
        out.append(mask_bit | 126)
        out += struct.pack(">H", n)
    else:
        out.append(mask_bit | 127)
        out += struct.pack(">Q", n)
    if mask_key is not None:
        out += mask_key
        payload = _xor_mask(payload, mask_key)
    return bytes(out) + payload


class _Buffer:
    """A socket plus its not-yet-consumed bytes, so coalesced TCP frames
    are never lost between reads.  A timeout mid-read leaves the partial
    bytes in place, so the stream stays consistent for a retry."""

    __slots__ = ("sock", "buf")

    def __init__(self, sock: socket.socket, seed: bytes = b"") -> None:
        self.sock = sock
        self.buf = bytearray(seed)

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(max(65536, n - len(self.buf)))
            if not chunk:
                raise ConnectionError("peer closed the connection")
            self.buf += chunk
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out


def _read_frame(buf: _Buffer) -> tuple[bool, int, bool, bytes]:
    """One frame: (fin, opcode, masked, payload), payload already unmasked."""
    b1, b2 = buf.read(2)
    fin = bool(b1 & 0x80)
    opcode = b1 & 0x0F
    masked = bool(b2 & 0x80)
    n = b2 & 0x7F
    if n == 126:
        n = struct.unpack(">H", buf.read(2))[0]
    elif n == 127:
        n = struct.unpack(">Q", buf.read(8))[0]
    key = buf.read(4) if masked else None
    payload = buf.read(n)
    if key is not None:
        payload = _xor_mask(payload, key)
    return fin, opcode, masked, payload


def _read_http_head(sock: socket.socket) -> tuple[bytes, bytes]:
    """Read one HTTP head; returns (head, leftover-after-``\\r\\n\\r\\n``)."""
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("peer closed during the handshake")
        data += chunk
        if len(data) > _MAX_HEADER:
            raise ConnectionError("websocket handshake header too large")
    head, _, leftover = bytes(data).partition(b"\r\n\r\n")
    return head, leftover


def _parse_headers(head: bytes) -> tuple[list[str], dict[str, str]]:
    lines = head.decode("latin-1").split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return lines[0].split(), headers


class RelayServer:
    """Accepts websocket clients and relays their text by recipient id.

    ``ready_event`` fires once the listener is bound; ``port`` is the bound
    port; ``close_codes`` records the status code of every close frame
    received; ``close()`` stops accepting, closes every client socket, and
    joins all threads the server started.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        _require_loopback(host)
        self.ready_event = threading.Event()
        self.close_codes: list[int] = []
        self._conns: dict[str, tuple[socket.socket, threading.Lock]] = {}
        self._pending: dict[str, list[tuple[str, str]]] = {}
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="jky-ws-relay", daemon=True
        )
        self._accept_thread.start()

    # -- lifecycle ------------------------------------------------------
    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        finally:
            with self._lock:
                conns = [entry[0] for entry in self._conns.values()]
            for conn in conns:
                try:
                    conn.close()
                except OSError:
                    pass
            for thread in [self._accept_thread, *self._threads]:
                if thread.is_alive():
                    thread.join(timeout=2.0)

    def __enter__(self) -> "RelayServer":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- accepting --------------------------------------------------------
    def _accept_loop(self) -> None:
        self.ready_event.set()
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break  # listener closed by close()
            thread = threading.Thread(
                target=self._serve_conn, args=(conn,), daemon=True
            )
            with self._lock:
                self._threads.append(thread)
            thread.start()

    # -- per-connection ---------------------------------------------------
    def _serve_conn(self, conn: socket.socket) -> None:
        client_id: Optional[str] = None
        try:
            conn.settimeout(0.5)  # lets close() interrupt a quiet connection
            head, leftover = _read_http_head(conn)
            parts, headers = _parse_headers(head)
            key = headers.get("sec-websocket-key", "")
            if (
                len(parts) != 3
                or parts[0] != "GET"
                or "websocket" not in headers.get("upgrade", "").lower()
                or "upgrade" not in headers.get("connection", "").lower()
                or headers.get("sec-websocket-version") != "13"
                or not _valid_key(key)
            ):
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return
            client_id = parts[1].lstrip("/") or "anon"
            response = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {_accept_key(key)}\r\n\r\n"
            )
            conn.sendall(response.encode("latin-1"))
            self._register(client_id, conn)
            self._read_loop(client_id, conn, _Buffer(conn, seed=leftover))
        except (ConnectionError, OSError, ValueError):
            pass  # a misbehaving or vanished client is just a dropped relay leg
        finally:
            if client_id is not None:
                with self._lock:
                    entry = self._conns.get(client_id)
                    if entry is not None and entry[0] is conn:
                        del self._conns[client_id]
            try:
                conn.close()
            except OSError:
                pass

    def _read_loop(self, client_id: str, conn: socket.socket, buf: _Buffer) -> None:
        opcode0: Optional[int] = None
        parts: list[bytes] = []
        while not self._stop.is_set():
            try:
                fin, opcode, masked, payload = _read_frame(buf)
            except socket.timeout:
                continue
            if not masked:
                # §5.3: an unmasked client frame is a protocol error (1002).
                try:
                    conn.sendall(_build_frame(_OP_CLOSE, struct.pack(">H", _CLOSE_PROTOCOL)))
                finally:
                    return
            if opcode == _OP_CLOSE:
                code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 1005
                self.close_codes.append(code)
                try:
                    conn.sendall(
                        _build_frame(_OP_CLOSE, struct.pack(">H", _CLOSE_NORMAL))
                    )
                finally:
                    return
            if opcode == _OP_PING:
                conn.sendall(_build_frame(_OP_PONG, payload))
                continue
            if opcode in (_OP_PONG,):
                continue
            if opcode0 is None:
                if opcode == _OP_CONT:
                    raise ConnectionError("stray continuation frame")
                opcode0 = opcode
            parts.append(payload)
            if fin:
                if opcode0 == _OP_TEXT:
                    self._route(client_id, b"".join(parts).decode("utf-8", "replace"))
                opcode0, parts = None, []

    # -- routing ----------------------------------------------------------
    def _register(self, client_id: str, conn: socket.socket) -> None:
        wlock = threading.Lock()
        with self._lock:
            self._conns[client_id] = (conn, wlock)
            queued = self._pending.pop(client_id, [])
        for frm, body in queued:
            self._deliver(client_id, frm, body)

    def _route(self, frm: str, text: str) -> None:
        if "\n" in text:
            to, body = text.split("\n", 1)
        else:
            to, body = frm, text  # unaddressed mail echoes to its sender
        with self._lock:
            known = to in self._conns
            if not known:
                self._pending.setdefault(to, []).append((frm, body))
        if known:
            self._deliver(to, frm, body)

    def _deliver(self, to: str, frm: str, body: str) -> None:
        with self._lock:
            entry = self._conns.get(to)
        if entry is None:
            return  # recipient vanished between check and delivery; next poll re-queues
        conn, wlock = entry
        with wlock:
            conn.sendall(_build_frame(_OP_TEXT, f"{frm}\n{body}".encode("utf-8")))


def _valid_key(key: str) -> bool:
    try:
        return len(base64.b64decode(key, validate=True)) == 16
    except Exception:
        return False


class RelayClient:
    """Client side of the relay; handshakes, masks every frame it sends,
    and refuses masked frames from the server (see module docstring).

    ``sock`` may supply an already-connected loopback socket (tests use it
    to capture raw wire bytes).  ``recv_text`` returns ``(sender, body)``,
    or ``None`` on timeout/peer-close — a missed pull never blocks longer
    than the timeout.  ``close()`` sends a close frame with status 1000.
    """

    def __init__(self, host: str = "127.0.0.1", port: Optional[int] = None,
                 client_id: str = "anon", timeout: float = 10.0,
                 sock: Optional[socket.socket] = None) -> None:
        _require_loopback(host)
        self.id = client_id
        self.timeout = timeout
        self.closed_code: Optional[int] = None
        self._closed = False
        self._own = sock is None
        self._sock = sock if sock is not None else socket.create_connection(
            (host, port), timeout=timeout
        )
        self._sock.settimeout(timeout)
        self._buf = _Buffer(self._sock)
        try:
            self._handshake(host, port)
        except Exception:
            self._sock.close()
            self._closed = True
            raise

    # -- handshake --------------------------------------------------------
    def _handshake(self, host: str, port: Optional[int]) -> None:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        authority = f"{host}:{port}" if port is not None else host
        request = (
            f"GET /{self.id} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-Websocket-Version: 13\r\n\r\n"
        )
        self._sock.sendall(request.encode("latin-1"))
        head, leftover = _read_http_head(self._sock)
        self._buf.buf += leftover
        parts, headers = _parse_headers(head)
        if len(parts) < 2 or parts[1] != "101":
            raise ConnectionError(f"relay refused the upgrade: {parts!r}")
        if headers.get("sec-websocket-accept") != _accept_key(key):
            raise ConnectionError("relay's accept proof does not match the nonce")

    # -- sending ------------------------------------------------------------
    def send_text(self, to: str, body: "str | bytes") -> int:
        """Queue ``body`` for ``to``; returns the number of frames sent.

        Payloads above 64 KiB are fragmented into FRAME_SIZE chunks so a
        relay leg never blocks on one giant frame.
        """
        raw = body if isinstance(body, bytes) else body.encode("utf-8")
        return self._send_frames(to.encode("utf-8") + b"\n" + raw)

    def _send_frames(self, data: bytes) -> int:
        if self._closed:
            raise ConnectionError("relay client is closed")
        if not data:
            spans = [(0, 0)]
        else:
            spans = [
                (off, min(off + FRAME_SIZE, len(data)))
                for off in range(0, len(data), FRAME_SIZE)
            ]
        sent = 0
        for i, (start, end) in enumerate(spans):
            fin = i == len(spans) - 1
            opcode = _OP_TEXT if i == 0 else _OP_CONT
            frame = _build_frame(
                opcode, data[start:end], fin=fin, mask_key=os.urandom(4)
            )
            self._sock.sendall(frame)
            sent += 1
        return sent

    # -- receiving ----------------------------------------------------------
    def recv_text(self, timeout: Optional[float] = None) -> Optional[tuple[str, str]]:
        previous = self._sock.gettimeout()
        if timeout is not None:
            self._sock.settimeout(timeout)
        try:
            if self._closed:
                return None
            opcode, payload = self._read_message()
            if opcode == _OP_CLOSE:
                return None
            frm, _, body = payload.decode("utf-8", "replace").partition("\n")
            return frm, body
        except socket.timeout:
            return None
        finally:
            self._sock.settimeout(previous)

    def _read_message(self) -> tuple[int, bytes]:
        opcode0: Optional[int] = None
        parts: list[bytes] = []
        while True:
            fin, opcode, masked, payload = _read_frame(self._buf)
            if masked:
                raise ConnectionError("server frame arrived masked (§5.1 forbids it)")
            if opcode == _OP_PING:
                self._sock.sendall(
                    _build_frame(_OP_PONG, payload, mask_key=os.urandom(4))
                )
                continue
            if opcode == _OP_PONG:
                continue
            if opcode == _OP_CLOSE:
                code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 1005
                self.closed_code = code
                self._closed = True
                try:
                    self._sock.sendall(
                        _build_frame(_OP_CLOSE, payload[:2], mask_key=os.urandom(4))
                    )
                except OSError:
                    pass
                return _OP_CLOSE, b""
            if opcode0 is None:
                if opcode == _OP_CONT:
                    raise ConnectionError("stray continuation frame")
                opcode0 = opcode
            parts.append(payload)
            if fin:
                if opcode0 != _OP_TEXT:
                    raise ConnectionError(f"relay leg sent non-text message {opcode0}")
                return opcode0, b"".join(parts)

    # -- lifecycle ----------------------------------------------------------
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._sock.sendall(
                _build_frame(
                    _OP_CLOSE, struct.pack(">H", _CLOSE_NORMAL), mask_key=os.urandom(4)
                )
            )
            # Give the peer a short moment to echo its close; never block the
            # caller on a wedged relay, so the wait shares the strict budget.
            self._sock.settimeout(1.0)
            try:
                _read_frame(self._buf)
            except (OSError, socket.timeout, ConnectionError):
                pass
        except OSError:
            pass
        finally:
            self._sock.close()

    def __enter__(self) -> "RelayClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
