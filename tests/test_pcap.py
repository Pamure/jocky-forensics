"""
Offline capture parsing: classic libpcap, block-based pcapng, and the
protocol decoders a network-forensics triage needs.

Every test writes a real capture to a temp file and then requires the parser to
recover exactly what was written. The failures these guard against are the
classic ones and each has a test that fails without the fix:

* byte-swapped files and the nanosecond magic,
* a fixed 20-byte IPv4 or TCP header, which shifts every payload when the
  capture carries options (routers set them; so does every real SYN),
* a DNS compression pointer that loops or points nowhere,
* a file cut off mid-record, which must not cost the analyst the packets that
  did survive,
* random bytes handed to every entry point, which must not raise: a forensic
  parser that aborts on packet 12 destroys the evidence in packets 13..n.
"""
from __future__ import annotations

import hashlib
import socket
import pathlib
import random
import struct
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.errors import JockyRuntimeError  # noqa: E402
from jocky.rt import pcap  # noqa: E402
from jocky.rt.pcap import (  # noqa: E402
    decode_packet, dns_queries, flows, http_requests, read_pcap, read_pcapng,
    tls_client_hellos,
)

HTTP_REQUEST = (
    b"GET /admin/login.php?u=root HTTP/1.1\r\n"
    b"Host: evil.example.net\r\n"
    b"User-Agent: curl/8.4.0\r\n"
    b"Accept: */*\r\n"
    b"\r\n"
)

# ---------------------------------------------------------------- builders


def _mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def _ipv4_addr(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def _eth(payload: bytes, ethertype: int = 0x0800,
         dst: str = "00:11:22:33:44:55", src: str = "66:77:88:99:aa:bb") -> bytes:
    return _mac(dst) + _mac(src) + struct.pack("!H", ethertype) + payload


def _ipv4(payload: bytes, src: str = "10.0.0.1", dst: str = "10.0.0.2",
          proto: int = 6, ttl: int = 64, options: bytes = b"", ident: int = 0,
          flags_frag: int = 0x4000, total_length: int = None) -> bytes:
    assert len(options) % 4 == 0
    ihl = 5 + len(options) // 4
    total = ihl * 4 + len(payload) if total_length is None else total_length
    header = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, total, ident,
                         flags_frag, ttl, proto, 0,
                         _ipv4_addr(src), _ipv4_addr(dst))
    return header + options + payload


def _ipv6(payload: bytes, next_header: int = 6,
          src: bytes = b"\x20\x01\x0d\xb8" + b"\x00" * 10 + b"\x00\x01",
          dst: bytes = b"\x20\x01\x0d\xb8" + b"\x00" * 10 + b"\x00\x02") -> bytes:
    # version/class/flow (4), payload length (2), next header (1), hop limit (1)
    return struct.pack("!IHBB", 6 << 28, len(payload), next_header, 64) \
        + src + dst + payload


def _tcp(payload: bytes, sport: int = 50123, dport: int = 80, seq: int = 1,
         ack: int = 1, flags: int = 0x18, options: bytes = b"") -> bytes:
    assert len(options) % 4 == 0
    doff = 5 + len(options) // 4
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, doff << 4,
                         flags, 0xFFFF, 0, 0)
    return header + options + payload


def _udp(payload: bytes, sport: int = 40000, dport: int = 53) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _pcap_bytes(records, magic: bytes = b"\xd4\xc3\xb2\xa1", linktype: int = 1,
                snaplen: int = 65535, version=(2, 4)) -> bytes:
    """Classic libpcap file. ``records`` are ``(ts_sec, ts_frac, data[, orig])``."""
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    out = bytearray(magic + struct.pack(endian + "HHiIII", version[0],
                                        version[1], 0, 0, snaplen, linktype))
    for record in records:
        ts_sec, ts_frac, data = record[0], record[1], record[2]
        orig = record[3] if len(record) > 3 else len(data)
        out += struct.pack(endian + "IIII", ts_sec, ts_frac, len(data), orig)
        out += data
    return bytes(out)


def _pcapng_block(block_type: int, body: bytes, endian: str = "<") -> bytes:
    padding = b"\x00" * ((4 - len(body) % 4) % 4)
    total = 12 + len(body) + len(padding)
    return (struct.pack(endian + "II", block_type, total) + body + padding
            + struct.pack(endian + "I", total))


def _pcapng_bytes(records, endian: str = "<", linktype: int = 1,
                  snaplen: int = 65535, tsresol: int = None) -> bytes:
    """SHB + IDB + one EPB (type 6) per record ``(ts_units, data[, orig])``."""
    bom = b"\x1a\x2b\x3c\x4d" if endian == ">" else b"\x4d\x3c\x2b\x1a"
    section = _pcapng_block(0x0A0D0D0A,
                            bom + struct.pack(endian + "HHq", 1, 0, -1), endian)
    interface = struct.pack(endian + "HHI", linktype, 0, snaplen)
    if tsresol is not None:
        interface += struct.pack(endian + "HH", 9, 1) + bytes([tsresol]) \
            + b"\x00\x00\x00"
    out = bytearray(section + _pcapng_block(1, interface, endian))
    for record in records:
        units, data = record[0], record[1]
        orig = record[2] if len(record) > 2 else len(data)
        body = struct.pack(endian + "IIIII", 0, units >> 32, units & 0xFFFFFFFF,
                           len(data), orig) + data
        out += _pcapng_block(6, body, endian)
    return bytes(out)


def _write(tmp_path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


# DNS wire helpers ---------------------------------------------------------


def _dns_wire_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _dns_query(name: str, qtype: int = 1, ident: int = 0x1234,
               flags: int = 0x0100) -> bytes:
    return (struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 0)
            + _dns_wire_name(name) + struct.pack("!HH", qtype, 1))


def _dns_response(name: str, answers, ident: int = 0x1234) -> bytes:
    """``answers`` is a list of ``(rtype, rdata)``; each name is a pointer to
    offset 12 (the question name), which is the compression case that matters."""
    body = struct.pack("!HHHHHH", ident, 0x8180, 1, len(answers), 0, 0)
    body += _dns_wire_name(name) + struct.pack("!HH", 1, 1)
    for rtype, rdata in answers:
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata
    return body


# TLS builder --------------------------------------------------------------


def _tls_client_hello(server_name: str = "c2.example.org",
                      ciphers=(0x1301, 0xC02F, 0x009C),
                      curves=(0x001D, 0x0017)) -> bytes:
    def extension(etype: int, data: bytes) -> bytes:
        return struct.pack("!HH", etype, len(data)) + data

    name = server_name.encode("ascii")
    sni = struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
    groups = b"".join(struct.pack("!H", c) for c in curves)
    extensions = (
        extension(0, sni)
        + extension(10, struct.pack("!H", len(groups)) + groups)
        + extension(11, b"\x01\x00")
        + extension(43, b"\x02\x03\x04")
    )
    body = struct.pack("!H", 0x0303) + bytes(range(32))
    body += b"\x00"                                   # empty session id
    body += struct.pack("!H", len(ciphers) * 2) + b"".join(
        struct.pack("!H", c) for c in ciphers)
    body += b"\x01\x00"                               # one null compression
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


# ============================================================ file formats
def test_both_byte_orders_and_both_timestamp_resolutions(tmp_path):
    frame = _eth(_ipv4(_udp(_dns_query("a.example"), 40000, 53), proto=17))
    for magic, fraction, expected in (
        (b"\xd4\xc3\xb2\xa1", 123_456, 1700000000.123456),   # little, micro
        (b"\xa1\xb2\xc3\xd4", 123_456, 1700000000.123456),   # big, micro
        (b"\x4d\x3c\xb2\xa1", 123_456_789, 1700000000.123456789),  # little, nano
        (b"\xa1\xb2\x3c\x4d", 123_456_789, 1700000000.123456789),  # big, nano
    ):
        path = _write(tmp_path, magic.hex() + ".pcap",
                      _pcap_bytes([(1700000000, fraction, frame)], magic=magic))
        result = read_pcap(path)
        assert result["error"] is None, magic
        assert result["truncated"] is False
        assert len(result["packets"]) == 1
        packet = result["packets"][0]
        assert packet["ts"] == pytest.approx(expected, abs=1e-9), magic
        assert packet["src_ip"] == "10.0.0.1"
        assert packet["malformed"] is None


def test_swapped_magic_is_not_read_as_a_different_file(tmp_path):
    """A byte-swapped header must decode to the same packet, and the file
    header facts must say which order was seen."""
    frame = _eth(_ipv4(_udp(_dns_query("b.example"), 40000, 53), proto=17))
    little = read_pcap(_write(tmp_path, "l.pcap",
                              _pcap_bytes([(1, 0, frame)], magic=b"\xd4\xc3\xb2\xa1")))
    big = read_pcap(_write(tmp_path, "b.pcap",
                           _pcap_bytes([(1, 0, frame)], magic=b"\xa1\xb2\xc3\xd4")))
    assert little["byte_order"] == "little" and big["byte_order"] == "big"
    assert little["packets"][0]["dst_port"] == big["packets"][0]["dst_port"] == 53
    assert little["packets"][0]["src_ip"] == big["packets"][0]["src_ip"]


def test_non_pcap_file_reports_the_error_without_raising(tmp_path):
    result = read_pcap(_write(tmp_path, "junk.bin", b"this is not a capture at all"))
    assert result["packets"] == []
    assert result["truncated"] is True
    assert "not a pcap file" in result["error"]
    assert result["stop_reason"] == "not-pcap"


def test_missing_path_raises_the_analyst_error():
    with pytest.raises(JockyRuntimeError):
        read_pcap("/nonexistent/definitely/not/here.pcap")


def _pcap_record_offsets(data: bytes) -> set:
    """Byte offsets at which a little-endian pcap ends a complete record."""
    offsets, position = {24}, 24
    while position + 16 <= len(data):
        incl_len = struct.unpack_from("<I", data, position + 8)[0]
        position += 16 + incl_len
        offsets.add(position)
    return offsets


def _pcapng_block_offsets(data: bytes) -> set:
    offsets, position = set(), 0
    while position + 8 <= len(data):
        total = struct.unpack_from("<I", data, position + 4)[0]
        if total < 12:
            break
        position += total
        offsets.add(position)
    return offsets


def test_truncated_capture_keeps_the_packets_it_read(tmp_path):
    frames = [
        _eth(_ipv4(_tcp(HTTP_REQUEST), proto=6)),
        _eth(_ipv4(_udp(_dns_query("trunc.example"), 40000, 53), proto=17)),
        _eth(_ipv4(_tcp(b"HTTP/1.1 200 OK\r\n\r\n", sport=80, dport=50123), proto=6)),
    ]
    whole = _pcap_bytes([(10, 1, f) for f in frames])
    path = _write(tmp_path, "cut.pcap", whole)
    complete = read_pcap(path)
    assert complete["truncated"] is False and len(complete["packets"]) == 3
    boundaries = _pcap_record_offsets(whole)

    # Every cut point must be survivable: the packets fully contained in the
    # prefix come back, the partial one does not, and nothing raises. A cut
    # that lands exactly on a record boundary is a *short but valid* file, so
    # only cuts inside a record set the flag.
    for cut in range(len(whole)):
        cut_path = _write(tmp_path, "cut%05d.pcap" % cut, whole[:cut])
        result = read_pcap(cut_path)
        assert result["truncated"] is (cut not in boundaries), cut
        assert len(result["packets"]) <= 3, cut
        for decoded, expected in zip(result["packets"],
                                     complete["packets"][:len(result["packets"])]):
            assert decoded["incl_len"] == expected["incl_len"], cut
            assert decoded["payload"] == expected["payload"], cut
    # Cutting inside the global header is an unreadable file, not a crash.
    head = read_pcap(_write(tmp_path, "head.pcap", whole[:12]))
    assert head["packets"] == [] and head["error"] and head["truncated"] is True


def test_limits_bound_packets_and_input_bytes(tmp_path):
    frames = [_eth(_ipv4(_tcp(HTTP_REQUEST), proto=6)) for _ in range(4)]
    path = _write(tmp_path, "many.pcap", _pcap_bytes([(1, 0, f) for f in frames]))
    limited = read_pcap(path, limit=2)
    assert len(limited["packets"]) == 2
    assert limited["stop_reason"] == "limit" and limited["truncated"] is True
    assert read_pcap(path, limit=0)["packets"] == []
    bounded = read_pcap(path, max_bytes=40)          # header + first record header
    assert bounded["stop_reason"] == "max_bytes"
    assert len(bounded["packets"]) == 0 and bounded["truncated"] is True


def test_pcapng_epb_parses_in_both_byte_orders(tmp_path):
    frame = _eth(_ipv4(_tcp(HTTP_REQUEST), proto=6))
    for endian in ("<", ">"):
        for tsresol, units, expected in ((None, 1_700_000_000_123_456,
                                          1700000000.123456),
                                         (9, 1_700_000_000_123_456_789,
                                          1700000000.123456789)):
            name = f"ng{endian}{tsresol}.pcapng"
            path = _write(tmp_path, name, _pcapng_bytes(
                [(units, frame)], endian=endian, tsresol=tsresol))
            result = read_pcapng(path)
            assert result["error"] is None, name
            assert result["truncated"] is False, name
            assert result["byte_order"] == ("little" if endian == "<" else "big")
            assert result["linktype"] == 1 and result["snaplen"] == 65535
            assert len(result["packets"]) == 1, name
            packet = result["packets"][0]
            assert packet["ts"] == pytest.approx(expected, abs=1e-6), name
            assert packet["dst_port"] == 80 and packet["src_ip"] == "10.0.0.1"


def test_pcapng_sections_may_switch_byte_order(tmp_path):
    frame = _eth(_ipv4(_tcp(HTTP_REQUEST), proto=6))
    first = _pcapng_bytes([(1_000_000, frame)], endian="<")
    second = _pcapng_bytes([(2_000_000, frame)], endian=">")
    path = _write(tmp_path, "merged.pcapng", first + second)
    result = read_pcapng(path)
    assert result["truncated"] is False
    assert result["sections"] == 2
    assert len(result["packets"]) == 2
    assert result["packets"][0]["ts"] == pytest.approx(1.0)
    assert result["packets"][1]["ts"] == pytest.approx(2.0)


def test_pcapng_truncated_block_and_spb(tmp_path):
    frame = _eth(_ipv4(_udp(_dns_query("ng.example"), 40000, 53), proto=17))
    whole = _pcapng_bytes([(5_000_000, frame)])
    boundaries = _pcapng_block_offsets(whole)
    for cut in (12, 28, len(whole) - 6, len(whole) - 1):
        result = read_pcapng(_write(tmp_path, "cut%d.pcapng" % cut, whole[:cut]))
        assert result["truncated"] is (cut not in boundaries), cut
        assert len(result["packets"]) <= 1, cut

    # Simple Packet Block: no timestamp, data length comes from the interface.
    endian = "<"
    bom = b"\x4d\x3c\x2b\x1a"
    section = _pcapng_block(0x0A0D0D0A, bom + struct.pack(endian + "HHq", 1, 0, -1))
    interface = _pcapng_block(1, struct.pack(endian + "HHI", 1, 0, 65535))
    spb = _pcapng_block(3, struct.pack(endian + "I", len(frame)) + frame)
    result = read_pcapng(_write(tmp_path, "spb.pcapng", section + interface + spb))
    assert len(result["packets"]) == 1
    assert result["packets"][0]["dst_port"] == 53
    assert result["packets"][0]["ts"] is None


# =========================================================== header lengths
@pytest.mark.parametrize("ip_options,tcp_options", [
    (b"", b""),
    (b"\x01\x01\x01\x01", b"\x02\x04\x05\xb4"),          # NOPs, MSS
    (b"\x01" * 12, b"\x01" * 12),                        # 28-byte / 32-byte
])
def test_ipv4_ihl_and_tcp_doff_are_multiplied_by_four(tmp_path, ip_options,
                                                      tcp_options):
    """Options shift the payload. A parser that assumes 20 bytes for either
    header hands back the option bytes as payload and loses the request."""
    segment = _tcp(HTTP_REQUEST, options=tcp_options)
    datagram = _ipv4(segment, options=ip_options)
    path = _write(tmp_path, "opt.pcap", _pcap_bytes([(7, 8, _eth(datagram))]))
    packet = read_pcap(path)["packets"][0]
    assert packet["malformed"] is None
    assert packet["payload"] == HTTP_REQUEST.decode("latin-1")
    assert packet["src_port"] == 50123 and packet["dst_port"] == 80
    assert http_requests([packet])[0]["path"] == "/admin/login.php?u=root"


def test_ipv4_total_length_does_not_truncate_below_ihl():
    """A lying total_length must not make the payload disappear or go negative."""
    datagram = _ipv4(_tcp(HTTP_REQUEST), total_length=4)
    packet = decode_packet(_eth(datagram))
    assert packet["malformed"] is None
    assert packet["payload"] == HTTP_REQUEST.decode("latin-1")


def test_tcp_payload_boundaries_and_flags():
    packet = decode_packet(_eth(_ipv4(_tcp(b"x" * 10, flags=0x02, options=b"\x01\x01\x01\x01"))))
    assert packet["payload"] == "x" * 10
    assert packet["tcp_syn"] is True and packet["tcp_ack"] is False
    assert packet["payload_len"] == 10


def test_udp_length_field_bounds_the_payload():
    packet = decode_packet(_eth(_ipv4(_udp(b"abcdef", 40000, 53), proto=17)))
    assert packet["payload"] == "abcdef"
    # A length field smaller than the frame must not leak the trailing bytes.
    lying = _eth(_ipv4(struct.pack("!HHHH", 40000, 53, 10, 0) + b"abcdefgh",
                       proto=17))
    assert decode_packet(lying)["payload"] == "ab"


def test_ipv6_and_extension_headers_are_walked():
    packet = decode_packet(
        _eth(_ipv6(_udp(_dns_query("v6.example"), 40000, 53), next_header=17),
             ethertype=0x86DD))
    assert packet["ip_version"] == 6
    assert packet["src_ip"] == "2001:db8::1" and packet["dst_ip"] == "2001:db8::2"
    assert packet["dst_port"] == 53
    assert dns_queries([packet])[0]["questions"][0]["name"] == "v6.example"

    # One 8-byte hop-by-hop header before the UDP header.
    extension = struct.pack("!BB", 17, 0) + b"\x00" * 6
    packet = decode_packet(
        _eth(_ipv6(extension + _udp(b"payload", 40000, 53), next_header=0),
             ethertype=0x86DD))
    assert packet["protocol"] == 17 and packet["payload"] == "payload"
    assert packet["dst_port"] == 53


def test_non_first_fragment_has_no_transport_header():
    # A non-first fragment carries continuation bytes, not a transport header,
    # so there are no ports to read even though the protocol field says TCP.
    datagram = _ipv4(b"rest", proto=6, flags_frag=23)
    packet = decode_packet(_eth(datagram))
    assert packet["fragment_offset"] == 184
    assert packet["src_port"] is None and packet["dst_port"] is None
    assert packet["payload"] == "rest"


def test_raw_and_cooked_linktypes():
    raw = _ipv4(_udp(_dns_query("raw.example"), 40000, 53), proto=17)
    packet = decode_packet(raw, pcap.LINKTYPE_RAW)
    assert packet["dst_port"] == 53 and packet["src_mac"] is None

    cooked = struct.pack("!HHH8sH", 0, 1, 6, _mac("66:77:88:99:aa:bb"), 0x0800) \
        + _ipv4(_udp(_dns_query("sll.example"), 40000, 53), proto=17)
    packet = decode_packet(cooked, pcap.LINKTYPE_LINUX_SLL)
    assert packet["dst_port"] == 53
    assert dns_queries([packet])[0]["questions"][0]["name"] == "sll.example"

    cooked2 = struct.pack("!HHIHBB8s", 0x0800, 0, 3, 1, 0, 6,
                          _mac("66:77:88:99:aa:bb")) \
        + _ipv4(_udp(_dns_query("sll2.example"), 40000, 53), proto=17)
    packet = decode_packet(cooked2, pcap.LINKTYPE_LINUX_SLL2)
    assert dns_queries([packet])[0]["questions"][0]["name"] == "sll2.example"


def test_vlan_tag_is_recorded_and_stripped():
    inner = _ipv4(_udp(_dns_query("vlan.example"), 40000, 53), proto=17)
    frame = (_mac("00:11:22:33:44:55") + _mac("66:77:88:99:aa:bb")
             + struct.pack("!HHH", 0x8100, 42, 0x0800) + inner)
    packet = decode_packet(frame)
    assert packet["vlan"] == 42 and packet["dst_port"] == 53
    assert dns_queries([packet])[0]["questions"][0]["name"] == "vlan.example"


# ==================================================================== flows
def test_flows_group_both_directions_with_per_direction_counters(tmp_path):
    request = _eth(_ipv4(_tcp(HTTP_REQUEST, sport=50123, dport=80, seq=1), proto=6))
    response = _eth(_ipv4(_tcp(b"HTTP/1.1 200 OK\r\n\r\n", sport=80,
                               dport=50123, seq=1),
                          src="10.0.0.2", dst="10.0.0.1", proto=6))
    path = _write(tmp_path, "flow.pcap",
                  _pcap_bytes([(100, 0, request), (100, 250000, response)]))
    result = read_pcap(path)
    rows = flows(result)
    assert len(rows) == 1
    flow = rows[0]
    assert flow["proto"] == "tcp"
    assert flow["endpoints"] == [{"ip": "10.0.0.1", "port": 50123},
                                 {"ip": "10.0.0.2", "port": 80}]
    assert flow["packets"] == 2
    assert flow["bytes"] == (len(request) + len(response))
    assert flow["packets_a_to_b"] == 1 and flow["packets_b_to_a"] == 1
    assert flow["bytes_a_to_b"] == len(request)
    assert flow["bytes_b_to_a"] == len(response)
    assert flow["first_ts"] == 100.0 and flow["last_ts"] == 100.25
    assert flow["duration"] == pytest.approx(0.25)
    assert flow["indices"] == [0, 1]
    # Passing the packet list directly gives the same grouping.
    assert flows(result["packets"]) == rows


def test_flows_separate_conversations_and_skip_packets_without_ip():
    dns = decode_packet(_eth(_ipv4(_udp(_dns_query("a.example"), 40000, 53),
                                   proto=17)))
    other = decode_packet(_eth(_ipv4(_udp(_dns_query("b.example"), 40001, 53),
                                     proto=17, dst="10.9.9.9")))
    empty = decode_packet(b"", 1)
    rows = flows([dns, other, empty])
    assert len(rows) == 2, "two 5-tuples, and the empty frame has none"
    assert all(row["packets"] == 1 for row in rows)


# ====================================================================== DNS
def test_dns_query_and_compressed_answer_name(tmp_path):
    query = _dns_query("tunnel.data.example.com", qtype=16)
    request = _eth(_ipv4(_udp(query, 40000, 53), proto=17))
    response = _eth(_ipv4(_udp(
        _dns_response("tunnel.data.example.com",
                      [(1, bytes([93, 184, 216, 34]))]), 53, 40000), proto=17))
    path = _write(tmp_path, "dns.pcap",
                  _pcap_bytes([(1, 0, request), (1, 500000, response)]))
    rows = dns_queries(read_pcap(path))
    assert len(rows) == 2
    ask, answer = rows[0], rows[1]
    assert ask["is_response"] is False and ask["questions"][0]["name"] == \
        "tunnel.data.example.com"
    assert ask["questions"][0]["type_name"] == "TXT"
    assert ask["src_port"] == 40000 and ask["dst_port"] == 53
    assert answer["is_response"] is True and answer["rcode_name"] == "NOERROR"
    assert answer["questions"][0]["name"] == "tunnel.data.example.com"
    # The answer name is a compression pointer to offset 12; decoding it is
    # the whole point.
    assert answer["answers"][0]["name"] == "tunnel.data.example.com"
    assert answer["answers"][0]["value"] == "93.184.216.34"
    assert answer["answers"][0]["ttl"] == 300


def test_dns_compression_pointer_loop_terminates(tmp_path):
    """A self-referential (or mutually-referential) name must not spin."""
    looped = {}
    looped["self"] = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" \
        + struct.pack("!HH", 1, 1)
    looped["pair"] = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0e" \
        + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    path = _write(tmp_path, "loop.pcap", _pcap_bytes([
        (1, 0, _eth(_ipv4(_udp(body, 40000, 53), proto=17)))
        for body in looped.values()]))
    started = time.monotonic()
    rows = dns_queries(read_pcap(path))
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, f"compression pointer loop spun for {elapsed:.3f}s"
    assert len(rows) == 2
    assert all("pointer loop" in (row["malformed"] or "") for row in rows)

    # The name decoder itself reports the loop rather than returning a name.
    name, end, error = pcap._dns_name(looped["self"], 12)
    assert error and "loop" in error and end == 14
    # A forward pointer is not a loop and must be followed.
    forward = b"\x00" * 12 + b"\xc0\x0e" + b"\x03www\x00"
    name, end, error = pcap._dns_name(forward, 12)
    assert name == "www" and error is None and end == 14


def test_dns_txt_and_soa_rdata_are_rendered():
    txt = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) \
        + _dns_wire_name("t.example") + struct.pack("!HH", 16, 1) \
        + b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, 6) + b"\x05hello\x00"
    packet = decode_packet(_eth(_ipv4(_udp(txt, 53, 40000), proto=17)))
    row = dns_queries([packet])[0]
    assert row["answers"][0]["value"] == "hello"

    soa_rdata = _dns_wire_name("ns.example") + _dns_wire_name("hostmaster.example") \
        + struct.pack("!IIIII", 1, 2, 3, 4, 5)
    soa = _dns_response("soa.example", [(6, soa_rdata)])
    packet = decode_packet(_eth(_ipv4(_udp(soa, 53, 40000), proto=17)))
    row = dns_queries([packet])[0]
    assert row["answers"][0]["value"]["serial"] == 1
    assert row["answers"][0]["value"]["mname"] == "ns.example"


def test_dns_over_tcp_and_unrelated_udp_are_handled():
    message = _dns_query("tcp.example")
    framed = struct.pack("!H", len(message)) + message
    packet = decode_packet(_eth(_ipv4(_tcp(framed, 40000, 53), proto=6)))
    rows = dns_queries([packet])
    assert rows and rows[0]["questions"][0]["name"] == "tcp.example"

    noise = decode_packet(_eth(_ipv4(_udp(b"\x00" * 40, 40000, 123), proto=17)))
    assert dns_queries([noise]) == []


def test_dns_name_run_past_the_message_is_reported():
    truncated = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\x09onlyfour"
    packet = decode_packet(_eth(_ipv4(_udp(truncated, 40000, 53), proto=17)))
    row = dns_queries([packet])[0]
    assert row["malformed"] and "runs past" in row["malformed"]


# ====================================================================== TLS
def test_tls_client_hello_sni_ciphers_and_ja3(tmp_path):
    record = _tls_client_hello()
    segment = _tcp(record, 50000, 443, flags=0x18)
    path = _write(tmp_path, "tls.pcap", _pcap_bytes([(1, 0, _eth(_ipv4(segment), 0x0800))]))
    rows = tls_client_hellos(read_pcap(path))
    assert len(rows) == 1
    hello = rows[0]
    assert hello["server_name"] == "c2.example.org"
    assert hello["cipher_suites"] == [0x1301, 0xC02F, 0x009C]
    assert hello["extensions"] == [0, 10, 11, 43]
    assert hello["elliptic_curves"] == [0x001D, 0x0017]
    assert hello["ec_point_formats"] == [0]
    assert hello["version"] == 0x0303
    expected = "771,4865-49199-156,0-10-11-43,29-23,0"
    assert hello["ja3"] == expected
    assert hello["ja3_hash"] == hashlib.md5(expected.encode()).hexdigest()
    assert hello["src_port"] == 50000 and hello["dst_port"] == 443


def test_tls_client_hello_split_across_segments_is_reassembled(tmp_path):
    record = _tls_client_hello()
    first, second = record[:40], record[40:]
    packets = [
        _eth(_ipv4(_tcp(first, 50000, 443, seq=1000), proto=6)),
        # Arrive out of order, which a capture routinely does.
        _eth(_ipv4(_tcp(second, 50000, 443, seq=1000 + len(first)), proto=6)),
    ]
    path = _write(tmp_path, "tlssplit.pcap",
                  _pcap_bytes([(1, 0, packets[1]), (1, 1000, packets[0])]))
    rows = tls_client_hellos(read_pcap(path))
    assert len(rows) == 1
    assert rows[0]["server_name"] == "c2.example.org"


def test_non_tls_traffic_yields_no_client_hello(tmp_path):
    path = _write(tmp_path, "httpnotls.pcap",
                  _pcap_bytes([(1, 0, _eth(_ipv4(_tcp(HTTP_REQUEST, 50000, 443), proto=6)))]))
    assert tls_client_hellos(read_pcap(path)) == []


# ===================================================================== HTTP
def test_http_request_fields_from_a_cleartext_stream(tmp_path):
    path = _write(tmp_path, "http.pcap",
                  _pcap_bytes([(1, 0, _eth(_ipv4(_tcp(HTTP_REQUEST, 50123, 80), proto=6)))]))
    rows = http_requests(read_pcap(path))
    assert len(rows) == 1
    request = rows[0]
    assert request["method"] == "GET"
    assert request["path"] == "/admin/login.php?u=root"
    assert request["host"] == "evil.example.net"
    assert request["user_agent"] == "curl/8.4.0"
    assert request["version"] == "1.1"
    assert request["headers"]["Accept"] == "*/*"
    assert request["src"] == "10.0.0.1" and request["dst_port"] == 80


def test_http_pipelined_requests_and_absolute_form_target(tmp_path):
    stream = (b"POST http://proxy.example/upload HTTP/1.1\r\n"
              b"Host: ignored.example\r\nContent-Length: 3\r\n\r\nabc"
              b"GET /next HTTP/1.0\r\nHost: second.example\r\n\r\n")
    path = _write(tmp_path, "pipe.pcap",
                  _pcap_bytes([(1, 0, _eth(_ipv4(_tcp(stream, 50123, 3128), proto=6)))]))
    rows = http_requests(read_pcap(path))
    assert [row["method"] for row in rows] == ["POST", "GET"]
    assert rows[0]["host"] == "proxy.example"
    assert rows[0]["path"] == "/upload"
    assert rows[0]["content_length"] == "3"
    assert rows[1]["path"] == "/next" and rows[1]["version"] == "1.0"


def test_http_chunked_body_does_not_hide_the_next_request(tmp_path):
    stream = (b"POST /cgi-bin/dropper HTTP/1.1\r\nHost: c2.example\r\n"
              b"Transfer-Encoding: chunked\r\n\r\n"
              b"6\r\nAAAAAA\r\n0\r\n\r\n"
              b"GET /beacon?id=1 HTTP/1.1\r\nHost: c2.example\r\n\r\n")
    path = _write(tmp_path, "chunked.pcap",
                  _pcap_bytes([(1, 0, _eth(_ipv4(_tcp(stream, 50123, 80), proto=6)))]))
    rows = http_requests(read_pcap(path))
    assert [row["path"] for row in rows] == ["/cgi-bin/dropper", "/beacon?id=1"]


def test_http_scan_is_not_fooled_by_binary_traffic(tmp_path):
    blob = bytes(random.Random(7).randrange(256) for _ in range(400))
    path = _write(tmp_path, "bin.pcap",
                  _pcap_bytes([(1, 0, _eth(_ipv4(_tcp(blob, 50123, 443), proto=6)))]))
    assert http_requests(read_pcap(path)) == []


# ======================================================== hostile input
def test_random_input_never_raises(tmp_path):
    """Feed every entry point random bytes.

    Method: a seeded :class:`random.Random` produces 150 blobs. Each blob is
    tried bare, appended to a valid pcap header, appended to a valid pcapng
    section and appended to a bare libpcap magic — so the file readers reach
    their record loops rather than only rejecting the magic. The same blobs
    become frames for :func:`decode_packet` under every supported link type and
    are then wrapped in Ethernet/IPv4/UDP-53 and TCP-443 packets so the DNS,
    TLS and HTTP decoders actually receive them. Nothing may raise and every
    return value must still have its documented shape.
    """
    rng = random.Random(0x5EED)
    header = _pcap_bytes([])
    section = _pcapng_bytes([])
    files = {"bare.pcap": None, "head.pcap": header, "sec.pcapng": section,
             "magic.bin": b"\xd4\xc3\xb2\xa1"}
    for iteration in range(150):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
        for name, prefix in files.items():
            path = _write(tmp_path, name, (prefix or b"") + blob)
            for reader in (read_pcap, read_pcapng):
                result = reader(path)
                assert isinstance(result, dict), (name, reader)
                assert isinstance(result["packets"], list)
                assert isinstance(result["truncated"], bool)
                for packet in result["packets"]:
                    assert isinstance(packet, dict)
                    assert isinstance(packet["payload"], str)

        frame = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 80)))
        for linktype in (0, 1, 101, 113, 228, 229, 276, 999):
            packet = decode_packet(frame, linktype)
            assert isinstance(packet["payload"], str)
            for decoder in (flows, dns_queries, tls_client_hellos, http_requests):
                assert isinstance(decoder([packet]), list)

        dns_packet = decode_packet(_eth(_ipv4(_udp(frame, 40000, 53), proto=17)))
        tls_packet = decode_packet(_eth(_ipv4(_tcp(frame, 50000, 443), proto=6)))
        for decoder in (dns_queries, tls_client_hellos, http_requests):
            rows = decoder([dns_packet, tls_packet])
            assert isinstance(rows, list)
            for row in rows:
                assert isinstance(row, dict)


def test_degenerate_headers_are_reported_not_raised():
    short = decode_packet(b"\x45", 1)
    assert short["malformed"] and short["src_ip"] is None
    assert flows([short]) == []

    bad_linktype = decode_packet(_eth(b""), 4242)
    assert "unsupported linktype" in bad_linktype["malformed"]

    bad_ethertype = decode_packet(_eth(b"\x00" * 20, ethertype=0x1234))
    assert "unsupported ethertype" in bad_ethertype["malformed"]

    assert decode_packet(b"", 1)["malformed"] == "empty frame"
    # A frame whose IP header claims a header longer than the frame.
    lying = _eth(b"\x4f" + b"\x00" * 30)
    assert decode_packet(lying)["malformed"] == "ipv4: header length exceeds frame"
    # A TCP data offset below the minimum.
    assert "below minimum" in (decode_packet(
        _eth(_ipv4(b"\x00\x50\x00\x50" + b"\x00" * 16)))["malformed"] or "")


def test_flows_and_decoders_bound_their_work():
    packets = [decode_packet(_eth(_ipv4(
        _tcp(HTTP_REQUEST, 50123, 80, seq=1 + index * 4096), proto=6)))
        for index in range(5)]
    assert len(http_requests(packets, limit=2)) == 2
    assert len(dns_queries([], limit=1)) == 0
    assert pcap.MAX_DNS_JUMPS < 1000 and pcap.MAX_STREAM_BYTES <= 64 * 1024 * 1024
    # A stream longer than the cap stays bounded.
    rows = pcap._tcp_streams(packets, max_bytes=100)
    assert all(row["bytes"] <= 100 for row in rows)


def test_dns_is_found_off_port_53_and_flagged():
    """DNS away from port 53 must be decoded, not skipped.

    Regression from a real capture: running this module against Wireshark's own
    `dns_port.pcap` — which exists precisely to exercise DNS on non-standard
    ports — returned **zero** queries, because the decoder filtered on port 53.
    A tool that only watches 53 reports "no DNS" on a capture that is entirely
    DNS, and DNS on an unusual port is a documented tunnelling technique.
    """
    query = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07example\x03com\x00\x00\x01\x00\x01")
    frame = decode_packet(_eth(_ipv4(_udp(query, 65282, 65333), proto=17)))
    rows = dns_queries([frame])
    assert len(rows) == 1, "DNS off port 53 was not decoded"
    assert rows[0]["questions"][0]["name"] == "example.com"
    assert rows[0]["non_standard_port"] is True

    # On port 53 the same message decodes and is not flagged.
    on_port = decode_packet(_eth(_ipv4(_udp(query, 40001, 53), proto=17)))
    standard = dns_queries([on_port])
    assert len(standard) == 1
    assert standard[0]["non_standard_port"] is False


def test_arbitrary_udp_off_port_53_is_not_mistaken_for_dns():
    """The content test must be strict enough to reject non-DNS payloads.

    Broadening the filter is only safe if a random UDP payload cannot pass it,
    so this pins the two conditions: the message parses cleanly *and* carries at
    least one question.
    """
    # Too short to hold a DNS header.
    tiny = decode_packet(_eth(_ipv4(_udp(b"\x00\x01", 1000, 2000), proto=17)))
    assert dns_queries([tiny]) == []
    # A valid header claiming a question that is not there.
    truncated_question = decode_packet(_eth(_ipv4(_udp(
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07exa", 1000, 2000), proto=17)))
    assert dns_queries([truncated_question]) == []
    # Random bytes with a plausible-looking header. Note the label content: a
    # leading 0x00 is a *valid* zero-length root label, so the bytes must include
    # a length that runs past the end (0x3f = 63 bytes demanded, few supplied) to
    # be genuinely unparseable rather than accidentally-valid DNS.
    noise = decode_packet(_eth(_ipv4(_udp(
        b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x3f" + b"A" * 8,
        1000, 2000), proto=17)))
    assert dns_queries([noise]) == []
    # The DHCP capture's payload shape: DNS has no claim here.
    dhcp = decode_packet(_eth(_ipv4(_udp(
        b"\x01\x01\x06\x00" + b"\x00" * 32, 68, 67), proto=17)))
    assert dns_queries([dhcp]) == []


# ---------------------------------------------------------------- live capture
def test_live_capture_reports_a_missing_capability_instead_of_raising():
    """Without CAP_NET_RAW the attempt is reported, not raised.

    This is the one path this development host can exercise for real: its
    CapEff is 0, so `AF_PACKET` is denied. A forensic tool that dies on a
    privilege it lacks tells the analyst nothing, so the contract is a
    structured result naming the fix.
    """
    result = pcap.live_capture(count=1, timeout_s=0.2)
    assert result["format"] == "live"
    assert result["packets"] == []
    if result["stop_reason"] == "permission-denied":
        assert "CAP_NET_RAW" in result["error"]
    else:
        # A host that *does* have the capability must still return the shape,
        # and must not have been left truncated by an error.
        assert result["stop_reason"] in ("limit", "timeout", "eof", "error")


def test_live_capture_off_linux_is_unsupported_not_a_crash(monkeypatch):
    monkeypatch.setattr(pcap.sys, "platform", "win32")
    result = pcap.live_capture(count=1, timeout_s=0.1)
    assert result["stop_reason"] == "unsupported"
    assert "Linux-only" in result["error"]
    assert result["packets"] == []


class _FakePacketSocket:
    """A stand-in for an AF_PACKET raw socket, so the capture loop is testable.

    Everything except the kernel delivering frames is exercised: option setting,
    the count ceiling, the timeout, the decode call, the byte and malformed
    counters, and each stop reason.
    """

    def __init__(self, frames, exc_after=None):
        self._frames = list(frames)
        self._exc_after = exc_after
        self.bound = None
        self.timeout = None
        self.closed = False

    def bind(self, address):
        self.bound = address

    def settimeout(self, value):
        self.timeout = value

    def recv(self, _size):
        if self._exc_after is not None and len(self._frames) <= self._exc_after:
            raise socket.timeout()
        if not self._frames:
            raise socket.timeout()
        return self._frames.pop(0)

    def close(self):
        self.closed = True


def test_live_capture_loop_decodes_frames_and_counts_them(monkeypatch):
    import socket as real_socket

    frame = _eth(_ipv4(_tcp(HTTP_REQUEST, 50123, 80), proto=6))
    fake = _FakePacketSocket([frame, frame])

    def fake_socket(family, kind, proto=0):
        assert family == real_socket.AF_PACKET and kind == real_socket.SOCK_RAW
        return fake

    monkeypatch.setattr(real_socket, "socket", fake_socket)
    result = pcap.live_capture(count=5, timeout_s=1.0, interface="eth0")

    assert result["stop_reason"] == "timeout", "an exhausted socket must end on timeout"
    assert len(result["packets"]) == 2
    assert result["bytes_read"] == len(frame) * 2
    assert result["malformed_records"] == 0
    assert [p["index"] for p in result["packets"]] == [0, 1]
    assert fake.bound == ("eth0", 0), "the interface must be bound when named"
    assert fake.timeout is not None, "the socket must be given a poll timeout"
    assert fake.closed, "the socket must be closed on every exit path"
    # The frames must be the same objects the decoders accept from a file read.
    assert http_requests(result), "a captured frame must decode like a read one"


def test_live_capture_stops_at_the_count_ceiling(monkeypatch):
    import socket as real_socket

    frame = _eth(_ipv4(_tcp(HTTP_REQUEST, 50123, 80), proto=6))
    fake = _FakePacketSocket([frame] * 10)
    monkeypatch.setattr(real_socket, "socket",
                        lambda family, kind, proto=0: fake)
    result = pcap.live_capture(count=3, timeout_s=5.0)
    assert len(result["packets"]) == 3, "count is a ceiling, not a target"
    assert result["stop_reason"] == "limit"
    assert result["truncated"] is True


def test_live_capture_is_not_promiscuous_by_default():
    """Going promiscuous changes interface state; it must be opt-in.

    Most capture tools default to promiscuous. A forensic tool pointed at a
    production host should not alter that host's behaviour as a side effect, so
    the default is off and the flag is explicit.
    """
    import inspect
    signature = inspect.signature(pcap.live_capture)
    assert signature.parameters["promiscuous"].default is False
