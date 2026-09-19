"""Proof for the pcap.py audit fixes.

Each test here failed against the code as the audit found it. They are written
against the *observable* behaviour (what a packet decodes to), not against the
implementation, so they keep working if the parser is restructured.
"""
from __future__ import annotations

import pathlib
import socket
import struct
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.rt import pcap  # noqa: E402


def _eth(payload: bytes, ethertype: bytes = b"\x86\xdd") -> bytes:
    return b"\xaa" * 6 + b"\xbb" * 6 + ethertype + payload


def _ipv6(next_header: int, body: bytes, src: bytes, dst: bytes) -> bytes:
    return (struct.pack("!IHBB", 6 << 28, len(body), next_header, 64)
            + src + dst + body)


def _frag_header(next_header: int, offset_units: int, more: bool, ident: int) -> bytes:
    field = ((offset_units & 0x1FFF) << 3) | (1 if more else 0)
    return struct.pack("!BBHI", next_header, 0, field, ident)


SRC = bytes(range(16))
DST = bytes(range(16, 32))


def test_ipv6_fragment_offset_comes_from_the_offset_field_not_the_id():
    """The audit's A3: the identification word was read as the offset.

    With a nonzero identification, `fragment_offset` decoded to a value derived
    from the ID (11206656 for ID 0x00AB0001) instead of the real 800.
    """
    body = _frag_header(6, 100, True, 0x00AB0001) + b"\x00" * 8
    packet = pcap.decode_packet(_eth(_ipv6(44, body, SRC, DST)))
    assert packet["fragment_offset"] == 800, (
        f"offset decoded as {packet['fragment_offset']}, expected 800 bytes "
        f"(100 units); a value near the identification means the fields are "
        f"being read in the wrong order"
    )
    assert packet["more_fragments"] is True
    assert packet["identification"] == 0x00AB0001


def test_a_non_first_fragment_never_fabricates_transport_ports():
    """The consequence of A3: bogus ports appeared on continuation fragments.

    A non-first fragment carries no transport header. With the identification
    misread, an ID whose low bits landed on zero looked like a first fragment
    and ports 443->1337 were decoded out of raw fragment bytes.
    """
    # Identification chosen so its low bits would have read as M=0, offset=0.
    body = _frag_header(6, 200, True, 2) + b"\x01\xbb\x05\x39" + b"\x00" * 8
    packet = pcap.decode_packet(_eth(_ipv6(44, body, SRC, DST)))
    assert packet["fragment_offset"] == 1600, packet["fragment_offset"]
    assert packet.get("src_port") in (None, 0), (
        f"a continuation fragment produced src_port={packet.get('src_port')} "
        "out of fragment payload bytes"
    )
    assert packet.get("dst_port") in (None, 0), (
        f"a continuation fragment produced dst_port={packet.get('dst_port')}"
    )


def test_a_first_fragment_still_decodes_its_transport_header():
    """The fix must not break the legitimate case: offset 0 with M=0 is an
    unfragmented datagram and its ports must come through."""
    udp = struct.pack("!HHHH", 5353, 53, 12, 0) + b"\x00" * 4
    body = _frag_header(17, 0, False, 1234) + udp
    packet = pcap.decode_packet(_eth(_ipv6(44, body, SRC, DST)))
    assert packet["fragment_offset"] == 0
    assert packet["more_fragments"] is False
    assert packet["src_port"] == 5353
    assert packet["dst_port"] == 53


# ------------------------------------------------------------- pcapng
def _shb(endian: str = "<", length: int = 28) -> bytes:
    body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    return struct.pack(endian + "II", 0x0A0D0D0A, length) + body + struct.pack(endian + "I", length)


def _idb(endian: str = "<", linktype: int = 1, snaplen: int = 65535) -> bytes:
    body = struct.pack(endian + "HHI", linktype, 0, snaplen)
    length = 8 + len(body) + 4
    return struct.pack(endian + "II", 0x00000001, length) + body + struct.pack(endian + "I", length)


def _epb(endian: str = "<", iface: int = 0, data: bytes = b"") -> bytes:
    body = struct.pack(endian + "IIIII", iface, 0, 0, len(data), len(data)) + data
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    length = 8 + len(body) + 4
    return struct.pack(endian + "II", 0x00000006, length) + body + struct.pack(endian + "I", length)


def _write(tmp_path, name: str, blob: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(blob)
    return str(path)


def test_pcapng_survives_a_section_block_declaring_a_short_length(tmp_path):
    """The audit's A2: SHB with length 12-15 raised struct.error.

    The reader's contract is that malformed blocks are counted and reported,
    never raised — one corrupt SHB mid-file used to kill the whole read.
    """
    for bad_length in (12, 13, 14, 15, 16, 20, 27):
        blob = _shb() + _idb() + _shb(length=bad_length)
        result = pcap.read_pcapng(_write(tmp_path, f"shb{bad_length}.pcapng", blob))
        assert result["stop_reason"] == "malformed", (
            f"SHB length {bad_length} produced stop_reason="
            f"{result['stop_reason']!r} instead of a reported malformed block"
        )
        assert result["error"] is None, result["error"]
        assert result["malformed_records"] >= 1


def test_pcapng_sections_do_not_share_their_interface_tables(tmp_path):
    """The audit's A1: section 2 resolved against section 1's interfaces.

    A merged capture is routine; interface IDs restart at each SHB, so a
    LINKTYPE_RAW packet in section 2 must not be decoded as Ethernet.
    """
    raw_ipv4 = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 28, 1, 0, 64, 17, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    udp = struct.pack("!HHHH", 40000, 53, 8, 0)
    blob = (_shb() + _idb(linktype=1) + _epb(data=b"")
            + _shb() + _idb(linktype=101) + _epb(data=raw_ipv4 + udp))
    result = pcap.read_pcapng(_write(tmp_path, "two-sections.pcapng", blob))
    assert result["sections"] == 2, result["sections"]
    packets = result["packets"]
    second = packets[-1]
    assert second.get("malformed") != "unsupported ethertype 0x0000", (
        "the section-2 packet was decoded with section 1's Ethernet linktype; "
        "interface tables are not being scoped per section"
    )
    assert second.get("src_ip") == "10.0.0.1", second


def test_spb_is_not_emptied_when_the_interface_declares_snaplen_zero(tmp_path):
    """The audit's A4: snaplen 0 means *no limit*, not *capture nothing*."""
    frame = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + b"\x00" * 20
    body = struct.pack("<I", len(frame)) + frame
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    length = 8 + len(body) + 4
    spb = struct.pack("<II", 0x00000003, length) + body + struct.pack("<I", length)
    blob = _shb() + _idb(snaplen=0) + spb
    result = pcap.read_pcapng(_write(tmp_path, "spb-snaplen0.pcapng", blob))
    assert result["packets"], "the SPB was dropped entirely"
    packet = result["packets"][0]
    assert packet["incl_len"] == len(frame), (
        f"incl_len {packet['incl_len']} — a snaplen of 0 was treated as "
        f"'capture nothing' instead of 'no limit'"
    )
    assert packet.get("malformed") != "empty frame", packet


def test_a_first_section_block_whose_trailer_disagrees_is_reported(tmp_path):
    """The audit's A2, second half: the opening SHB's trailer was never checked.

    Every later block has its trailing length compared against its header
    value; the block that *defines* the file's byte order and its whole read
    bound was exempt, so a self-contradicting file parsed as valid.
    """
    good = _shb()
    blob = good[:24] + struct.pack("<I", 0xDEADBEEF) + good[28:] + _idb()
    result = pcap.read_pcapng(_write(tmp_path, "bad-trailer.pcapng", blob))
    assert result["stop_reason"] == "malformed", result["stop_reason"]
    assert result["error"] and "trailer" in result["error"], result["error"]
    assert result["packets"] == []


# ------------------------------------------------------------ live capture
class _FakeSock:
    """A stand-in for the AF_PACKET socket, so the live loop runs unprivileged."""

    def __init__(self, frames, bind_error=None):
        self.frames = list(frames)
        self.bind_error = bind_error
        self.recv_sizes = []
        self.closed = False

    def bind(self, address):
        if self.bind_error is not None:
            raise self.bind_error

    def settimeout(self, value):
        pass

    def recv(self, size):
        self.recv_sizes.append(size)
        if self.frames:
            return self.frames.pop(0)
        raise socket.timeout()

    def close(self):
        self.closed = True


def _udp_frame() -> bytes:
    """A 42-byte Ethernet II / IPv4 / UDP frame."""
    udp = struct.pack("!HHHH", 40000, 53, 12, 0) + b"\x00" * 4
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + udp
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip


def _install_fake_socket(monkeypatch, fake):
    import socket as _socket
    monkeypatch.setattr(_socket, "socket", lambda *args, **kwargs: fake)


def test_live_capture_reports_a_bind_failure_instead_of_raising(monkeypatch):
    """The audit's A5(a): binding a missing interface raised ENODEV out of a
    module whose docstring promises failures are reported, never raised."""
    fake = _FakeSock([_udp_frame()], bind_error=OSError(19, "No such device"))
    _install_fake_socket(monkeypatch, fake)
    result = pcap.live_capture(count=1, timeout_s=0.5, interface="definitely0")
    assert result["stop_reason"] == "error", result
    assert "cannot bind" in (result["error"] or ""), result["error"]
    assert result["packets"] == []
    assert fake.closed, "the socket must be closed on the error path too"


@pytest.mark.parametrize("bad", [0, -1, -65536])
def test_live_capture_normalises_a_nonpositive_snaplen(monkeypatch, bad):
    """The audit's A5(b,c): `recv(0)` returns ``b""`` instantly, so the loop
    spun on the CPU until the deadline, and a negative value raised ValueError
    out of `recv` — a type the loop's `except OSError` never caught."""
    fake = _FakeSock([_udp_frame()])
    _install_fake_socket(monkeypatch, fake)
    result = pcap.live_capture(count=1, timeout_s=1.0, snaplen=bad)
    assert result["snaplen"] == 65535, result["snaplen"]
    assert result["snaplen_adjusted_from"] == bad
    assert fake.recv_sizes and all(size > 0 for size in fake.recv_sizes), (
        f"recv buffer sizes were {fake.recv_sizes}; a non-positive size returns "
        f"immediately and makes the capture loop a busy spin"
    )
    assert result["packets"], "the frame was not captured"


def test_live_packets_carry_their_wire_length(monkeypatch):
    """The audit's A8: only file packets carried `incl_len`, so `flows()` billed
    live traffic by payload bytes — the same flow read 42 bytes from a file and
    0 from a capture of it."""
    frame = _udp_frame()
    fake = _FakeSock([frame])
    _install_fake_socket(monkeypatch, fake)
    result = pcap.live_capture(count=1, timeout_s=1.0)
    assert result["packets"], "the frame was not captured"
    packet = result["packets"][0]
    assert packet["incl_len"] == len(frame), packet
    assert packet["orig_len"] == len(frame), packet
    aggregate = pcap.flows(result)
    assert aggregate, "the captured frame produced no flow"
    assert aggregate[0]["bytes"] == len(frame), (
        f"the flow billed {aggregate[0]['bytes']} bytes for a {len(frame)}-byte "
        f"wire frame"
    )


# ------------------------------------------------------------------- JA3
def _client_hello(ciphers, extensions, curves, point_formats,
                  version: int = 771) -> bytes:
    body = struct.pack("!H", version) + b"\x11" * 32 + b"\x00"
    body += struct.pack("!H", len(ciphers) * 2)
    body += b"".join(struct.pack("!H", value) for value in ciphers)
    body += b"\x01\x00"
    extension_bytes = b""
    for etype in extensions:
        if etype == 0x0000:
            inner = b"\x00" + struct.pack("!H", 11) + b"example.com"
        elif etype == 0x000A:
            inner = struct.pack("!H", len(curves) * 2)
            inner += b"".join(struct.pack("!H", value) for value in curves)
        elif etype == 0x000B:
            inner = bytes([len(point_formats)]) + bytes(point_formats)
        else:
            inner = b""
        extension_bytes += struct.pack("!HH", etype, len(inner)) + inner
    body += struct.pack("!H", len(extension_bytes)) + extension_bytes
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _tcp(seq: int, payload: bytes, src_port: int = 40000,
         dst_port: int = 80, index: int = 0) -> dict:
    return {"protocol": 6, "payload": payload.decode("latin-1"),
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": src_port, "dst_port": dst_port,
            "tcp_seq": seq, "ts": 1.0, "index": index}


def test_ja3_strips_grease_values():
    """The audit's A6: GREASE is randomised per connection, so leaving it in
    makes the hash match nothing in any threat-intel feed — the field's stated
    purpose. 2570 = 0x0A0A and 6682 = 0x1A1A are both GREASE."""
    record = _client_hello(
        ciphers=[0x0A0A, 0x1301, 0x1302, 0x1A1A],
        extensions=[0x1A1A, 0x0000, 0x000A, 0x000B, 0x0A0A],
        curves=[0x0A0A, 0x001D, 0x0017, 0x1A1A],
        point_formats=[0])
    rows = pcap.tls_client_hellos([_tcp(1, record)])
    assert rows, "the ClientHello was not parsed"
    ja3 = rows[0]["ja3"]
    assert "2570" not in ja3 and "6682" not in ja3, (
        f"JA3 still carries GREASE values: {ja3}"
    )
    assert ja3 == "771,4865-4866,0-10-11,29-23,0", ja3


def test_a_grease_free_hello_fingerprints_identically_to_a_grease_bearing_one():
    """The point of the strip: one client, two connections, one hash."""
    stripped = _client_hello([0x1301, 0x1302], [0x0000, 0x000A, 0x000B],
                             [0x001D, 0x0017], [0])
    greased = _client_hello([0x0A0A, 0x1301, 0x1302, 0x2A2A],
                            [0x2A2A, 0x0000, 0x000A, 0x000B, 0x0A0A],
                            [0x0A0A, 0x001D, 0x0017, 0x3A3A], [0])
    first = pcap.tls_client_hellos([_tcp(1, stripped)])[0]
    second = pcap.tls_client_hellos([_tcp(1, greased)])[0]
    assert first["ja3_hash"] == second["ja3_hash"], (
        f"{first['ja3']} != {second['ja3']}"
    )


def test_a_request_with_oversized_headers_is_reported_not_dropped():
    """The audit's A9: the request line matched, the `\\r\\n\\r\\n` search hit
    its 64 KiB cap, and the whole request vanished with no marker."""
    padding = b"X-Pad: " + b"a" * (70 * 1024) + b"\r\n"
    requests = pcap.http_requests([_tcp(1, b"GET /deep HTTP/1.1\r\n" + padding)])
    assert requests, "the request was dropped entirely"
    assert len(requests) == 1, requests
    row = requests[0]
    assert row["method"] == "GET"
    assert row["headers_truncated"] is True, row
    assert len(row["headers"]) <= pcap.MAX_HTTP_HEADER_BYTES


def test_a_message_before_an_oversized_one_is_still_recovered():
    """The cap must not cost the requests that came before it."""
    padding = b"X-Pad: " + b"a" * (70 * 1024) + b"\r\n"
    packets = [
        _tcp(1, b"GET /first HTTP/1.1\r\nHost: a\r\n\r\n", index=0),
        _tcp(1 + 512, b"POST /big HTTP/1.1\r\n" + padding, index=1),
    ]
    # One stream per (5-tuple, direction): give the two requests different
    # source ports so they reassemble independently, as two connections would.
    packets[1]["src_port"] = 40001
    rows = pcap.http_requests(packets)
    paths = sorted(row["path"] for row in rows)
    assert paths == ["/big", "/first"], rows
    assert [row["headers_truncated"] for row in rows if row["path"] == "/first"] == [False]
    assert [row["headers_truncated"] for row in rows if row["path"] == "/big"] == [True]


def test_obsolete_packet_block_reports_the_bytes_it_actually_holds(tmp_path):
    """The audit's A7: the PB path echoed the claimed length, not the truth.

    A Block's 4-byte alignment padding sits between the packet data and the
    trailer, so the decoder cannot know exactly how many of the trailing bytes
    are payload — but it *can* refuse to claim a length the block does not
    contain, and it can mark the truncation. Those two things are the contract;
    the old code reported the claimed 60 while decoding 10.
    """
    claimed = 60
    present = b"\xaa" * 10
    body = struct.pack("<HHIIII", 0, 0, 0, 0, claimed, claimed) + present
    body += b"\x00" * ((4 - len(body) % 4) % 4)
    length = 8 + len(body) + 4
    pb = struct.pack("<II", 0x00000002, length) + body + struct.pack("<I", length)
    blob = _shb() + _idb() + pb
    result = pcap.read_pcapng(_write(tmp_path, "short-pb.pcapng", blob))
    assert result["packets"], "the PB was dropped"
    packet = result["packets"][0]
    assert packet["incl_len"] < claimed, (
        f"incl_len {packet['incl_len']} echoes the block's claim of {claimed} "
        f"although the block holds {len(present)} bytes plus padding"
    )
    assert packet["incl_len"] <= len(present) + 4, (
        f"incl_len {packet['incl_len']} exceeds what the block could hold"
    )
    assert "truncated" in (packet.get("malformed") or ""), (
        "a block holding less than it claims must be marked, as the EPB path "
        f"already marks its own; malformed={packet.get('malformed')!r}"
    )
