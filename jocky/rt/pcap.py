"""
Offline network-artifact analysis: classic libpcap and block-based pcapng
capture files, plus the protocol decoders a network-forensics triage needs.

Everything here reads a file an analyst already has and decodes it with
:mod:`struct` alone — no third-party pcap library, no ``tshark`` process, and no
live capture. The runtime's socket tables answer *what is open now*; a pcap
answers *what was said*, which is where DNS tunnelling, cleartext HTTP and TLS
fingerprints actually live.

Defensive by construction, because a forensic tool that aborts on packet 12
destroys the evidence in packets 13..n: a packet that will not decode comes
back with a ``malformed`` reason instead of an exception, every loop is bounded
(``limit`` packets, ``max_bytes`` input, ``MAX_DNS_JUMPS`` pointer hops,
``MAX_STREAM_BYTES`` per reassembled stream), and a capture cut off mid-record
returns the packets that did parse together with ``truncated: True``. The only
failure that raises is an unreadable path, which is an analyst error, not a
capture property.

What a *file* has that a socket table does not is shape at the wire level, so
the decoders record header lengths where they matter: ``ihl*4`` for IPv4,
``doff*4`` for TCP — options are normal in the wild and a parser that assumes
20 bytes silently produces garbage payloads.
"""
from __future__ import annotations

import hashlib
import re
import struct
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from jocky.errors import JockyRuntimeError

__all__ = [
    "read_pcap",
    "read_pcapng",
    "decode_packet",
    "flows",
    "dns_queries",
    "tls_client_hellos",
    "http_requests",
]

# ------------------------------------------------------------------ limits
#: Most packets any reader will materialise. A hostile capture cannot make the
#: interpreter allocate without bound.
MAX_PACKETS = 200_000

#: Most input bytes a reader will consume (64 MiB). Pass ``max_bytes=None`` to
#: walk a whole capture deliberately.
MAX_BYTES = 64 * 1024 * 1024

#: Most compression-pointer hops while decoding one DNS name.
MAX_DNS_JUMPS = 64

#: Most DNS questions/answers decoded from one message.
MAX_DNS_RECORDS = 128

#: Most cleartext requests scraped from one reassembled TCP stream.
MAX_HTTP_REQUESTS = 1_000

#: Most bytes of headers considered for one HTTP request.
MAX_HTTP_HEADER_BYTES = 64 * 1024

#: Most bytes reassembled per TCP direction before the stream is abandoned.
MAX_STREAM_BYTES = 4 * 1024 * 1024

#: Largest pcapng block accepted; a corrupt length field must not size a read.
MAX_BLOCK_BYTES = 16 * 1024 * 1024

# ------------------------------------------------------------------ formats
#: Classic libpcap magic numbers *as they appear on disk*. The field is a
#: 32-bit integer written in the file's own byte order, so the same value has
#: two spellings, and the nanosecond variant is a second value again.
_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", "microsecond"),
    b"\xa1\xb2\xc3\xd4": (">", "microsecond"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanosecond"),
    b"\xa1\xb2\x3c\x4d": (">", "nanosecond"),
}

_PCAP_SWAPPED = {
    b"\xd4\xc3\xb2\xa1": b"\xa1\xb2\xc3\xd4",
    b"\xa1\xb2\xc3\xd4": b"\xd4\xc3\xb2\xa1",
    b"\x4d\x3c\xb2\xa1": b"\xa1\xb2\x3c\x4d",
    b"\xa1\xb2\x3c\x4d": b"\x4d\x3c\xb2\xa1",
}

_PCAP_RECORD = {"<": struct.Struct("<IIII"), ">": struct.Struct(">IIII")}

_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BOM_BE = b"\x1a\x2b\x3c\x4d"
_PCAPNG_BOM_LE = b"\x4d\x3c\x2b\x1a"
_PCAPNG_IDB = 0x00000001
_PCAPNG_PB = 0x00000002          # obsolete, still present in old dumps
_PCAPNG_SPB = 0x00000003
_PCAPNG_EPB = 0x00000006

# ------------------------------------------------------------------ link types
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_VLAN_ETHERTYPES = frozenset({0x8100, 0x88A8, 0x9100})

_IPPROTO_ICMP = 1
_IPPROTO_TCP = 6
_IPPROTO_UDP = 17
_IPPROTO_ICMPV6 = 58

_PROTO_NAMES = {
    _IPPROTO_ICMP: "icmp",
    _IPPROTO_TCP: "tcp",
    _IPPROTO_UDP: "udp",
    2: "igmp",
    _IPPROTO_ICMPV6: "icmpv6",
    47: "gre",
    50: "esp",
    51: "ah",
    89: "ospf",
    132: "sctp",
}

#: IPv6 extension headers, which chain before the transport header. Values map
#: to a byte length of ``(payload)`` or ``(payload + 2) * 4`` for AH.
_IPV6_EXT_FIXED8 = frozenset({0, 43, 60})   # hop-by-hop, routing, dest opts
_IPV6_EXT_FRAGMENT = 44
_IPV6_EXT_AH = 51
_IPV6_EXT_MAX = 8

_TCP_FIN, _TCP_SYN, _TCP_RST, _TCP_ACK = 0x01, 0x02, 0x04, 0x10

#: DNS RR type numbers worth naming; anything else renders as ``TYPE<n>``.
_DNS_TYPES = {
    1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB",
    8: "MG", 9: "MR", 10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO",
    14: "MINFO", 15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 24: "SIG",
    25: "KEY", 28: "AAAA", 29: "LOC", 33: "SRV", 35: "NAPTR", 36: "KX",
    37: "CERT", 39: "DNAME", 41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP",
    45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID",
    50: "NSEC3", 55: "HIP", 59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY",
    62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS", 99: "SPF",
    108: "EUI48", 109: "EUI64", 249: "TKEY", 250: "TSIG", 251: "IXFR",
    252: "AXFR", 255: "ANY", 256: "URI", 257: "CAA",
}

_DNS_CLASSES = {1: "IN", 2: "CS", 3: "CH", 4: "HS", 255: "ANY"}

_DNS_OPCODES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}

_DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET",
    9: "NOTAUTH", 10: "NOTZONE",
}

#: TLS handshake message types; only ClientHello (1) matters here.
_TLS_HANDSHAKE = 0x16
_TLS_CLIENT_HELLO = 1
_TLS_EXT_SERVER_NAME = 0
_TLS_EXT_SUPPORTED_GROUPS = 10
_TLS_EXT_EC_POINT_FORMATS = 11


# ================================================================== helpers
def _open(path: str):
    """Open a capture for reading, or raise the one error an analyst owns."""
    try:
        return open(path, "rb")
    except OSError as exc:
        raise JockyRuntimeError(f"cannot read {path}: {exc.strerror or exc}")


def _unpack(fmt: str, data: bytes, offset: int = 0):
    """``struct.unpack_from`` that answers ``None`` instead of raising.

    Every parse site below is bounds-checked by construction: a short or
    hostile packet returns ``None`` here rather than propagating
    :class:`struct.error` out of a collector.
    """
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        return None
    return struct.unpack_from(fmt, data, offset)


def _u8(data: bytes, offset: int) -> Optional[int]:
    if 0 <= offset < len(data):
        return data[offset]
    return None


def _latin(data: bytes) -> str:
    """Bytes to the project's *byte string* convention (one char per byte)."""
    return data.decode("latin-1")


def _short_read_reason(max_bytes: Optional[int], consumed: int) -> str:
    """Why a read came up short: the byte budget, or the file itself."""
    if max_bytes is not None and consumed >= max_bytes:
        return "max_bytes"
    return "truncated"


def _ipv4_str(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _ipv6_str(raw: bytes) -> str:
    """RFC 5952-ish text: lowercase hex, longest zero run compressed to ``::``."""
    groups = list(struct.unpack("!8H", raw))
    best_start = best_len = -1
    run_start = run_len = 0
    for index, value in enumerate(groups + [1]):
        if index < 8 and value == 0:
            if run_len == 0:
                run_start = index
            run_len += 1
            continue
        if run_len > best_len:
            best_start, best_len = run_start, run_len
        run_len = 0
    if best_len < 2:
        return ":".join(f"{g:x}" for g in groups)
    head = ":".join(f"{g:x}" for g in groups[:best_start])
    tail = ":".join(f"{g:x}" for g in groups[best_start + best_len:])
    return f"{head}::{tail}"


def _mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


# ============================================================== frame decode
def decode_packet(frame: bytes, linktype: int = LINKTYPE_ETHERNET) -> Dict[str, Any]:
    """Decode one captured frame into a flat packet record. Never raises.

    Handles Ethernet (with stacked VLAN tags), raw IP, BSD loopback, Linux
    cooked v1/v2, and the ``LINKTYPE_IPV4``/``LINKTYPE_IPV6`` pseudo-links.
    Fields that the frame does not carry — or that could not be trusted — stay
    ``None``; when a layer cannot be parsed at all the record carries a
    ``malformed`` reason and whatever was decoded above it.
    """
    packet: Dict[str, Any] = {
        "linktype": linktype,
        "src_mac": None,
        "dst_mac": None,
        "vlan": None,
        "ethertype": None,
        "ip_version": None,
        "src_ip": None,
        "dst_ip": None,
        "ttl": None,
        "protocol": None,
        "protocol_name": None,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
        "tcp_syn": False,
        "tcp_ack": False,
        "tcp_fin": False,
        "tcp_rst": False,
        "tcp_seq": None,
        "tcp_ack_num": None,
        "icmp_type": None,
        "icmp_code": None,
        "fragment_offset": 0,
        "more_fragments": False,
        "payload": "",
        "payload_len": 0,
        "malformed": None,
    }
    if not frame:
        packet["malformed"] = "empty frame"
        return packet

    offset = 0
    ethertype: Optional[int] = None

    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            packet["malformed"] = "ethernet header truncated"
            return packet
        packet["dst_mac"] = _mac_str(frame[0:6])
        packet["src_mac"] = _mac_str(frame[6:12])
        ethertype = (frame[12] << 8) | frame[13]
        offset = 14
        # 802.1Q/802.1ad tags stack; each is 4 bytes and repeats the ethertype.
        while ethertype in _VLAN_ETHERTYPES:
            tag = _unpack("!HH", frame, offset)
            if tag is None:
                packet["vlan"] = packet["vlan"] or None
                packet["malformed"] = "vlan tag truncated"
                return packet
            if packet["vlan"] is None:
                packet["vlan"] = tag[0] & 0x0FFF
            ethertype = tag[1]
            offset += 4
    elif linktype == LINKTYPE_RAW:
        version = frame[0] >> 4
        if version == 4:
            ethertype = _ETHERTYPE_IPV4
        elif version == 6:
            ethertype = _ETHERTYPE_IPV6
        else:
            packet["malformed"] = f"raw ip: unknown version {version}"
            return packet
    elif linktype == LINKTYPE_NULL:
        # BSD loopback: a host-order address family word. Which order is the
        # host's, so accept either spelling rather than guess wrong.
        family = _unpack("<I", frame, 0)
        if family is not None and family in (2, 24, 28, 30):
            ethertype = _ETHERTYPE_IPV4 if family == 2 else _ETHERTYPE_IPV6
        else:
            family = _unpack(">I", frame, 0)
            if family is None or family not in (2, 24, 28, 30):
                packet["malformed"] = "null linktype: unknown address family"
                return packet
            ethertype = _ETHERTYPE_IPV4 if family == 2 else _ETHERTYPE_IPV6
        offset = 4
    elif linktype == LINKTYPE_LINUX_SLL:
        # cooked v1: pkttype(2) arphrd(2) addrlen(2) addr(8) protocol(2)
        header = _unpack("!HHH8sH", frame, 0)
        if header is None:
            packet["malformed"] = "linux sll header truncated"
            return packet
        ethertype = header[4]
        offset = 16
        if ethertype in _VLAN_ETHERTYPES:
            tag = _unpack("!HH", frame, offset)
            if tag is not None:
                packet["vlan"] = tag[0] & 0x0FFF
                ethertype = tag[1]
                offset += 4
    elif linktype == LINKTYPE_LINUX_SLL2:
        # cooked v2: protocol(2) reserved(2) ifindex(4) arphrd(2) pkttype(1)
        # addrlen(1) addr(8)
        header = _unpack("!HHIHBB8s", frame, 0)
        if header is None:
            packet["malformed"] = "linux sll2 header truncated"
            return packet
        ethertype = header[0]
        offset = 20
    elif linktype == LINKTYPE_IPV4:
        ethertype = _ETHERTYPE_IPV4
    elif linktype == LINKTYPE_IPV6:
        ethertype = _ETHERTYPE_IPV6
    else:
        packet["malformed"] = f"unsupported linktype {linktype}"
        return packet

    packet["ethertype"] = ethertype
    layer3 = frame[offset:]

    if ethertype == _ETHERTYPE_IPV4:
        reason = _decode_ipv4(layer3, packet)
    elif ethertype == _ETHERTYPE_IPV6:
        reason = _decode_ipv6(layer3, packet)
    else:
        reason = f"unsupported ethertype 0x{ethertype:04x}"
    packet["malformed"] = reason
    if not reason:
        packet["protocol_name"] = _PROTO_NAMES.get(packet["protocol"],
                                                   f"proto{packet['protocol']}")
    return packet


def _decode_ipv4(data: bytes, packet: Dict[str, Any]) -> Optional[str]:
    """Fill the IPv4/transport fields; return a malformed reason or ``None``.

    The header length is ``ihl * 4``: 20 bytes is the *minimum*, and assuming
    it byte-shifts every payload that carries options (timestamp, record
    route, router alert — all routine in captures from routers).
    """
    if len(data) < 20:
        return "ipv4 header truncated"
    version_ihl = data[0]
    if version_ihl >> 4 != 4:
        return f"ipv4: bad version {version_ihl >> 4}"
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20:
        return f"ipv4: header length {ihl} below minimum"
    if ihl > len(data):
        return "ipv4: header length exceeds frame"
    total_length = (data[2] << 8) | data[3]
    flags_frag = (data[6] << 8) | data[7]
    # Both the IPv4 and IPv6 fragment fields count 8-byte units; the reported
    # offset is in bytes, which is what a reassembler or an analyst wants.
    frag_offset = (flags_frag & 0x1FFF) * 8
    packet["ip_version"] = 4
    packet["ttl"] = data[8]
    packet["protocol"] = data[9]
    packet["src_ip"] = _ipv4_str(data[12:16])
    packet["dst_ip"] = _ipv4_str(data[16:20])
    packet["fragment_offset"] = frag_offset
    packet["more_fragments"] = bool(flags_frag & 0x2000)
    # A lying total_length must not truncate the payload we already hold.
    end = total_length if ihl <= total_length <= len(data) else len(data)
    payload = data[ihl:end]
    if frag_offset:
        # Non-first fragment: no transport header, so no ports to report.
        packet["payload"] = _latin(payload)
        packet["payload_len"] = len(payload)
        return None
    return _decode_transport(payload, packet)


def _decode_ipv6(data: bytes, packet: Dict[str, Any]) -> Optional[str]:
    if len(data) < 40:
        return "ipv6 header truncated"
    if data[0] >> 4 != 6:
        return f"ipv6: bad version {data[0] >> 4}"
    payload_length = (data[4] << 8) | data[5]
    packet["ip_version"] = 6
    packet["ttl"] = data[7]                     # hop limit
    packet["src_ip"] = _ipv6_str(data[8:24])
    packet["dst_ip"] = _ipv6_str(data[24:40])
    end = 40 + payload_length if 40 + payload_length <= len(data) else len(data)
    next_header = data[6]
    offset = 40
    for _ in range(_IPV6_EXT_MAX):
        if next_header in _IPV6_EXT_FIXED8:
            header = _unpack("!BB", data, offset)
            if header is None:
                return "ipv6: extension header truncated"
            length = (header[1] + 1) * 8
            next_header = header[0]
        elif next_header == _IPV6_EXT_FRAGMENT:
            header = _unpack("!BBHI", data, offset)
            if header is None:
                return "ipv6: fragment header truncated"
            fragment_field = header[3]
            packet["fragment_offset"] = (fragment_field >> 3) * 8
            packet["more_fragments"] = bool(fragment_field & 1)
            length = 8
            next_header = header[0]
        elif next_header == _IPV6_EXT_AH:
            header = _unpack("!BBH", data, offset)
            if header is None:
                return "ipv6: ah header truncated"
            length = (header[2] + 2) * 4
            next_header = header[0]
        else:
            break
        offset += length
        if offset > end:
            return "ipv6: extension headers overrun payload"
        if packet["fragment_offset"]:
            packet["protocol"] = next_header
            packet["payload"] = _latin(data[offset:end])
            packet["payload_len"] = len(data[offset:end])
            return None
    packet["protocol"] = next_header
    return _decode_transport(data[offset:end], packet)


def _decode_transport(data: bytes, packet: Dict[str, Any]) -> Optional[str]:
    """TCP/UDP/ICMP after the IP header; sets ports and payload."""
    proto = packet["protocol"]
    if proto == _IPPROTO_TCP:
        if len(data) < 20:
            return "tcp header truncated"
        packet["src_port"] = (data[0] << 8) | data[1]
        packet["dst_port"] = (data[2] << 8) | data[3]
        packet["tcp_seq"] = int.from_bytes(data[4:8], "big")
        packet["tcp_ack_num"] = int.from_bytes(data[8:12], "big")
        # Data offset is in 32-bit words; again 5 is the minimum, not the law.
        doff = (data[12] >> 4) * 4
        if doff < 20:
            return f"tcp: data offset {doff} below minimum"
        if doff > len(data):
            return "tcp: data offset exceeds segment"
        flags = data[13]
        packet["tcp_flags"] = flags
        packet["tcp_syn"] = bool(flags & _TCP_SYN)
        packet["tcp_ack"] = bool(flags & _TCP_ACK)
        packet["tcp_fin"] = bool(flags & _TCP_FIN)
        packet["tcp_rst"] = bool(flags & _TCP_RST)
        payload = data[doff:]
    elif proto == _IPPROTO_UDP:
        if len(data) < 8:
            return "udp header truncated"
        packet["src_port"] = (data[0] << 8) | data[1]
        packet["dst_port"] = (data[2] << 8) | data[3]
        udp_length = (data[4] << 8) | data[5]
        end = udp_length if 8 <= udp_length <= len(data) else len(data)
        payload = data[8:end]
    elif proto in (_IPPROTO_ICMP, _IPPROTO_ICMPV6):
        if len(data) < 4:
            return "icmp header truncated"
        packet["icmp_type"] = data[0]
        packet["icmp_code"] = data[1]
        payload = data[4:]
    else:
        return None
    packet["payload"] = _latin(payload)
    packet["payload_len"] = len(payload)
    return None


# ================================================================ pcap file
def _empty_result(fmt: str) -> Dict[str, Any]:
    return {
        "format": fmt,
        "packets": [],
        "truncated": False,
        "stop_reason": "eof",
        "byte_order": None,
        "timestamp_resolution": None,
        "linktype": None,
        "snaplen": None,
        "version": None,
        "bytes_read": 0,
        "malformed_records": 0,
        "error": None,
    }


def read_pcap(path: str, limit: Optional[int] = None,
              max_bytes: Optional[int] = MAX_BYTES) -> Dict[str, Any]:
    """Read a classic libpcap capture.

    Both byte orders and both timestamp resolutions (microsecond
    ``0xa1b2c3d4`` and nanosecond ``0xa1b23c4d``) are accepted; ``limit`` caps
    the packets and ``max_bytes`` the input consumed (``None`` for no cap on
    bytes). The packet count is capped by :data:`MAX_PACKETS` whatever ``limit``
    says, so a hostile capture cannot grow the result without bound.

    Returns ``{"packets": [...], "truncated": bool, "stop_reason": ...}`` plus
    the file header facts. A record cut off mid-way is dropped, the packets
    already decoded are returned, and ``truncated`` is set — never an
    exception. A file whose magic is not libpcap yields ``error`` and no
    packets, which is how an analyst finds out they passed the wrong file.
    """
    result = _empty_result("pcap")
    budget = MAX_PACKETS if limit is None else min(limit, MAX_PACKETS)
    consumed = 0
    with _open(path) as handle:

        def take(count: int) -> bytes:
            nonlocal consumed
            if max_bytes is None:
                want = count
            else:
                want = min(count, max(0, max_bytes - consumed))
            chunk = handle.read(want) if want > 0 else b""
            consumed += len(chunk)
            return chunk

        head = take(24)
        result["bytes_read"] = consumed
        if len(head) < 24:
            result["error"] = "not a pcap file: header shorter than 24 bytes"
            result["truncated"] = True
            result["stop_reason"] = "truncated"
            return result
        magic = head[:4]
        if magic not in _PCAP_MAGIC:
            result["error"] = (
                f"not a pcap file: magic {magic.hex()} "
                f"(swapped spelling {_PCAP_SWAPPED.get(magic, b'').hex() or 'none'})"
            )
            result["truncated"] = True
            result["stop_reason"] = "not-pcap"
            return result

        endian, resolution = _PCAP_MAGIC[magic]
        version_major, version_minor, _tz, _sig, snaplen, network = struct.unpack(
            endian + "HHiIII", head[4:24])
        result["byte_order"] = "little" if endian == "<" else "big"
        result["timestamp_resolution"] = resolution
        result["version"] = f"{version_major}.{version_minor}"
        result["snaplen"] = snaplen
        result["linktype"] = network
        record = _PCAP_RECORD[endian]

        while True:
            if len(result["packets"]) >= budget:
                result["stop_reason"] = "limit"
                break
            if max_bytes is not None and consumed >= max_bytes:
                result["stop_reason"] = "max_bytes"
                break
            header = take(16)
            if not header:
                result["stop_reason"] = "eof"
                break
            if len(header) < 16:
                result["truncated"] = True
                result["stop_reason"] = _short_read_reason(max_bytes, consumed)
                break
            ts_sec, ts_frac, incl_len, orig_len = record.unpack(header)
            if incl_len > MAX_BLOCK_BYTES:
                # A corrupt length must not size an allocation.
                result["malformed_records"] += 1
                result["truncated"] = True
                result["stop_reason"] = "malformed"
                break
            body = take(incl_len)
            if len(body) < incl_len:
                result["truncated"] = True
                result["stop_reason"] = _short_read_reason(max_bytes, consumed)
                break
            divisor = 1_000_000_000 if resolution == "nanosecond" else 1_000_000
            packet = decode_packet(body, network)
            packet["index"] = len(result["packets"])
            packet["ts"] = ts_sec + ts_frac / divisor
            packet["ts_sec"] = ts_sec
            packet["ts_frac"] = ts_frac
            packet["incl_len"] = incl_len
            packet["orig_len"] = orig_len
            result["packets"].append(packet)
            if len(body) < orig_len:
                result["malformed_records"] += 1
                packet["snaplen_limited"] = True

        result["bytes_read"] = consumed
        if result["stop_reason"] != "eof":
            result["truncated"] = True
        return result


# ============================================================== pcapng file
def _pcapng_options(body: bytes, endian: str) -> Dict[int, bytes]:
    """Option code -> raw value from a block body (values still padded)."""
    options: Dict[int, bytes] = {}
    offset = 0
    while offset + 4 <= len(body):
        code, length = struct.unpack_from(endian + "HH", body, offset)
        offset += 4
        if code == 0:
            break
        if length > len(body) - offset:
            break
        options.setdefault(code, body[offset:offset + length])
        offset += length + ((4 - length % 4) % 4)
    return options


def _pcapng_tsresol(options: Dict[int, bytes]) -> Tuple[int, float]:
    """``(resolution, divisor)`` from the ``if_tsresol`` option (default 6)."""
    raw = options.get(9)
    if not raw:
        return 6, 1_000_000.0
    value = raw[0]
    if value & 0x80:
        resolution = value & 0x7F
        return resolution, float(1 << resolution)
    return value, float(10 ** min(value, 9))


def read_pcapng(path: str, limit: Optional[int] = None,
                max_bytes: Optional[int] = MAX_BYTES) -> Dict[str, Any]:
    """Read a block-based pcapng capture (SHB/IDB/EPB, plus SPB and old PB).

    The section header block carries the byte order, so endianness is decided
    per section — a capture concatenated from two writers (routine when an
    analyst merges dumps) parses on both sides. Interface timestamp
    resolutions are honoured from ``if_tsresol``, including the binary form.

    Same contract as :func:`read_pcap`: bounded input, malformed blocks
    recorded rather than raised, a cut-off tail reported through
    ``truncated``, and the packet count capped by :data:`MAX_PACKETS`.
    """
    result = _empty_result("pcapng")
    budget = MAX_PACKETS if limit is None else min(limit, MAX_PACKETS)
    result["interfaces"] = []
    result["sections"] = 0
    consumed = 0
    with _open(path) as handle:

        def take(count: int) -> bytes:
            nonlocal consumed
            if max_bytes is None:
                want = count
            else:
                want = min(count, max(0, max_bytes - consumed))
            chunk = handle.read(want) if want > 0 else b""
            consumed += len(chunk)
            return chunk

        head = take(12)
        if len(head) < 12:
            result["error"] = "not a pcapng file: header shorter than 12 bytes"
            result["truncated"] = True
            result["stop_reason"] = "truncated"
            result["bytes_read"] = consumed
            return result
        if head[:4] != _PCAPNG_SHB:
            result["error"] = f"not a pcapng file: block type {head[:4].hex()}"
            result["truncated"] = True
            result["stop_reason"] = "not-pcapng"
            result["bytes_read"] = consumed
            return result
        byte_order_magic = head[8:12]
        if byte_order_magic == _PCAPNG_BOM_BE:
            endian = ">"
        elif byte_order_magic == _PCAPNG_BOM_LE:
            endian = "<"
        else:
            result["error"] = (
                f"pcapng: unknown byte-order magic {byte_order_magic.hex()}")
            result["truncated"] = True
            result["stop_reason"] = "not-pcapng"
            result["bytes_read"] = consumed
            return result

        block_length = struct.unpack(endian + "I", head[4:8])[0]
        if block_length < 28 or block_length > MAX_BLOCK_BYTES:
            result["error"] = f"pcapng: implausible section length {block_length}"
            result["truncated"] = True
            result["stop_reason"] = "malformed"
            result["bytes_read"] = consumed
            return result
        rest = take(block_length - 12)
        if len(rest) < block_length - 12:
            result["truncated"] = True
            result["stop_reason"] = "truncated"
            result["bytes_read"] = consumed
            return result
        section = rest[:-4]
        if len(section) < 12:
            result["truncated"] = True
            result["stop_reason"] = "truncated"
            result["bytes_read"] = consumed
            return result
        version_major, version_minor = struct.unpack(endian + "HH", section[0:4])
        result["version"] = f"{version_major}.{version_minor}"
        result["sections"] = 1
        result["byte_order"] = "little" if endian == "<" else "big"

        while True:
            if len(result["packets"]) >= budget:
                result["stop_reason"] = "limit"
                break
            if max_bytes is not None and consumed >= max_bytes:
                result["stop_reason"] = "max_bytes"
                break
            header = take(8)
            if not header:
                result["stop_reason"] = "eof"
                break
            if len(header) < 8:
                result["truncated"] = True
                result["stop_reason"] = _short_read_reason(max_bytes, consumed)
                break
            block_type = header[:4]
            is_section = block_type == _PCAPNG_SHB
            if is_section:
                # A new section may declare the opposite byte order; the type
                # field is palindromic, so read the magic before trusting the
                # length we just decoded.
                magic = take(4)
                if len(magic) < 4:
                    result["truncated"] = True
                    result["stop_reason"] = "truncated"
                    break
                if magic == _PCAPNG_BOM_BE:
                    endian = ">"
                elif magic == _PCAPNG_BOM_LE:
                    endian = "<"
                else:
                    result["malformed_records"] += 1
                    result["truncated"] = True
                    result["stop_reason"] = "malformed"
                    break
                result["byte_order"] = "little" if endian == "<" else "big"
            block_length = struct.unpack(endian + "I", header[4:8])[0]
            if block_length < 12 or block_length > MAX_BLOCK_BYTES:
                result["malformed_records"] += 1
                result["truncated"] = True
                result["stop_reason"] = "malformed"
                break
            already = 12 if is_section else 8
            rest = take(block_length - already)
            if len(rest) < block_length - already:
                result["truncated"] = True
                result["stop_reason"] = _short_read_reason(max_bytes, consumed)
                break
            trailer = struct.unpack(endian + "I", rest[-4:])[0]
            if trailer != block_length:
                result["malformed_records"] += 1
                result["truncated"] = True
                result["stop_reason"] = "malformed"
                break
            body = (magic + rest[:-4]) if is_section else rest[:-4]

            if is_section:
                result["sections"] += 1
                if len(body) >= 8:
                    version_major, version_minor = struct.unpack(
                        endian + "HH", body[4:8])
                    result["version"] = f"{version_major}.{version_minor}"
                continue
            number = struct.unpack(endian + "I", block_type)[0]
            if number == _PCAPNG_IDB:
                interface = _parse_idb(body, endian)
                result["interfaces"].append(interface)
                if result["linktype"] is None:
                    result["linktype"] = interface["linktype"]
                    result["snaplen"] = interface["snaplen"]
                continue
            if number == _PCAPNG_EPB:
                packet = _parse_epb(body, endian, result["interfaces"])
            elif number == _PCAPNG_SPB:
                packet = _parse_spb(body, endian, result["interfaces"])
            elif number == _PCAPNG_PB:
                packet = _parse_pb(body, endian, result["interfaces"])
            else:
                continue
            if packet is None:
                result["malformed_records"] += 1
                continue
            packet["index"] = len(result["packets"])
            result["packets"].append(packet)

        result["bytes_read"] = consumed
        if result["stop_reason"] != "eof":
            result["truncated"] = True
        return result


def _parse_idb(body: bytes, endian: str) -> Dict[str, Any]:
    header = _unpack(endian + "HHI", body, 0) or (LINKTYPE_ETHERNET, 0, 65535)
    linktype, _reserved, snaplen = header
    options = _pcapng_options(body[8:], endian)
    resolution, divisor = _pcapng_tsresol(options)
    name = options.get(2)
    return {
        "linktype": linktype,
        "snaplen": snaplen,
        "tsresol": resolution,
        "tsdivisor": divisor,
        "name": name.split(b"\x00", 1)[0].decode("utf-8", "replace") if name else None,
    }


def _interface(result_interfaces: List[Dict[str, Any]],
               interface_id: int) -> Optional[Dict[str, Any]]:
    if 0 <= interface_id < len(result_interfaces):
        return result_interfaces[interface_id]
    return None


def _stamp(packet: Dict[str, Any], ts_high: int, ts_low: int,
           interface: Dict[str, Any]) -> None:
    units = (ts_high << 32) | ts_low
    packet["ts"] = units / interface["tsdivisor"]
    packet["ts_units"] = units


def _parse_epb(body: bytes, endian: str,
               interfaces: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    fields = _unpack(endian + "IIIII", body, 0)
    if fields is None:
        return None
    interface_id, ts_high, ts_low, caplen, orig_len = fields
    interface = _interface(interfaces, interface_id)
    data = body[20:20 + caplen]
    if interface is None:
        packet = decode_packet(b"", 0)
        packet["malformed"] = f"pcapng: unknown interface {interface_id}"
        packet["ts"] = 0.0
        packet["incl_len"] = len(data)
        packet["orig_len"] = orig_len
        return packet
    packet = decode_packet(data, interface["linktype"])
    _stamp(packet, ts_high, ts_low, interface)
    packet["interface"] = interface_id
    packet["incl_len"] = len(data)
    packet["orig_len"] = orig_len
    if len(data) < caplen:
        packet["malformed"] = packet["malformed"] or "pcapng: epb data truncated"
    return packet


def _parse_spb(body: bytes, endian: str,
               interfaces: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    fields = _unpack(endian + "I", body, 0)
    if fields is None:
        return None
    orig_len = fields[0]
    interface = interfaces[0] if interfaces else None
    if interface is None:
        return None
    caplen = min(orig_len, interface["snaplen"], len(body) - 4)
    packet = decode_packet(body[4:4 + caplen], interface["linktype"])
    packet["ts"] = None
    packet["interface"] = 0
    packet["incl_len"] = caplen
    packet["orig_len"] = orig_len
    return packet


def _parse_pb(body: bytes, endian: str,
              interfaces: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    fields = _unpack(endian + "HHIIII", body, 0)
    if fields is None:
        return None
    interface_id, _drops, ts_high, ts_low, caplen, orig_len = fields
    interface = _interface(interfaces, interface_id)
    if interface is None:
        return None
    packet = decode_packet(body[20:20 + caplen], interface["linktype"])
    _stamp(packet, ts_high, ts_low, interface)
    packet["interface"] = interface_id
    packet["incl_len"] = caplen
    packet["orig_len"] = orig_len
    return packet


# ==================================================================== flows
def _packet_list(source: Union[Dict[str, Any], Iterable[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Accept either a reader result or a bare packet list."""
    if isinstance(source, dict):
        packets = source.get("packets")
        return list(packets) if packets else []
    return list(source)


def flows(packets: Union[Dict[str, Any], Iterable[Dict[str, Any]]],
          limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Group packets into bidirectional flows keyed on the 5-tuple.

    Both directions of a conversation land in one flow: endpoints are
    canonicalised (the lower ``(ip, port)`` pair is ``a``), so a request and
    its response are one row with per-direction counters — which is what makes
    a beacon or an exfiltration visible. Packets with no IP layer are skipped
    (they have no 5-tuple) and are not counted.

    Rows carry ``bytes``/``packets``/``first_ts``/``last_ts``/``duration`` plus
    the per-direction split and the capture indices.
    """
    grouped: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    ordered: List[Dict[str, Any]] = []
    for position, packet in enumerate(_packet_list(packets)):
        src_ip, dst_ip = packet.get("src_ip"), packet.get("dst_ip")
        if not src_ip or not dst_ip:
            continue
        proto = packet.get("protocol")
        src_port, dst_port = packet.get("src_port"), packet.get("dst_port")
        left = (src_ip, src_port if src_port is not None else -1)
        right = (dst_ip, dst_port if dst_port is not None else -1)
        swapped = right < left
        a, b = (right, left) if swapped else (left, right)
        key = (proto, a[0], a[1], b[0], b[1])
        flow = grouped.get(key)
        if flow is None:
            flow = {
                "proto": _PROTO_NAMES.get(
                    proto, f"proto{proto}" if proto is not None else "unknown"),
                "proto_number": proto,
                "a": f"{a[0]}:{a[1]}" if a[1] >= 0 else a[0],
                "b": f"{b[0]}:{b[1]}" if b[1] >= 0 else b[0],
                "endpoints": [{"ip": a[0], "port": a[1] if a[1] >= 0 else None},
                              {"ip": b[0], "port": b[1] if b[1] >= 0 else None}],
                "packets": 0,
                "bytes": 0,
                "orig_bytes": 0,
                "payload_bytes": 0,
                "packets_a_to_b": 0,
                "packets_b_to_a": 0,
                "bytes_a_to_b": 0,
                "bytes_b_to_a": 0,
                "first_ts": None,
                "last_ts": None,
                "duration": 0.0,
                "indices": [],
                "tcp_flags": 0,
            }
            grouped[key] = flow
            ordered.append(flow)
        length = packet.get("incl_len")
        if length is None:
            length = packet.get("payload_len", 0) or 0
        timestamp = packet.get("ts")
        flow["packets"] += 1
        flow["bytes"] += length
        flow["orig_bytes"] += packet.get("orig_len") or length
        flow["payload_bytes"] += packet.get("payload_len", 0) or 0
        flow["indices"].append(packet.get("index", position))
        flow["tcp_flags"] |= packet.get("tcp_flags") or 0
        if swapped:
            flow["packets_b_to_a"] += 1
            flow["bytes_b_to_a"] += length
        else:
            flow["packets_a_to_b"] += 1
            flow["bytes_a_to_b"] += length
        if isinstance(timestamp, (int, float)):
            if flow["first_ts"] is None or timestamp < flow["first_ts"]:
                flow["first_ts"] = timestamp
            if flow["last_ts"] is None or timestamp > flow["last_ts"]:
                flow["last_ts"] = timestamp
        if limit is not None and len(ordered) >= limit:
            break
    for flow in ordered:
        if flow["first_ts"] is not None and flow["last_ts"] is not None:
            flow["duration"] = flow["last_ts"] - flow["first_ts"]
    ordered.sort(key=lambda f: (f["first_ts"] if f["first_ts"] is not None
                                else float("inf"), f["a"], f["b"]))
    return ordered


# ====================================================================== DNS
def _dns_label(raw: bytes) -> str:
    """Render a label, escaping anything that is not printable ASCII.

    Labels are not text: a DNS tunnelling name carries arbitrary bytes, and
    passing them through unchanged produces output that cannot be logged.
    """
    out = []
    for byte in raw:
        if byte == 0x5C or byte == 0x2E:
            out.append("\\" + chr(byte))
        elif 0x21 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append(f"\\{byte:03d}")
    return "".join(out)


def _dns_name(data: bytes, offset: int) -> Tuple[str, Optional[int], Optional[str]]:
    """Decode a possibly compressed DNS name.

    Returns ``(name, end_offset, error)``. Compression pointers are followed
    with two independent bounds: a hop counter and a visited-offset set, so a
    pointer that points at itself (or at a pair of offsets that point at each
    other — the classic malformed-name infinite loop) terminates with an error
    instead of hanging the run. ``end_offset`` is the first byte *after* the
    name in the original stream, which is where the pointer chain started, not
    where it ended.
    """
    labels: List[str] = []
    position = offset
    end: Optional[int] = None
    hops = 0
    visited: set = set()
    total = 0
    while True:
        if position >= len(data):
            return (".".join(labels), end, "name runs past the message")
        length = data[position]
        if length == 0:
            position += 1
            if end is None:
                end = position
            break
        if length & 0xC0 == 0xC0:
            if position + 1 >= len(data):
                return (".".join(labels), end, "truncated compression pointer")
            target = ((length & 0x3F) << 8) | data[position + 1]
            if end is None:
                end = position + 2
            hops += 1
            if hops > MAX_DNS_JUMPS:
                return (".".join(labels), end, "compression pointer hop limit")
            if target in visited:
                return (".".join(labels), end, "compression pointer loop")
            visited.add(target)
            visited.add(position)
            position = target
            continue
        if length & 0xC0:
            return (".".join(labels), end, f"reserved label type 0x{length:02x}")
        if position + 1 + length > len(data):
            return (".".join(labels), end, "label runs past the message")
        labels.append(_dns_label(data[position + 1:position + 1 + length]))
        total += length + 1
        if total > 255:
            return (".".join(labels), end, "name exceeds 255 octets")
        position += 1 + length
    if not labels:
        return (".", end, None)
    return (".".join(labels), end, None)


def _dns_type(number: int) -> str:
    return _DNS_TYPES.get(number, f"TYPE{number}")


def _dns_rdata(data: bytes, offset: int, length: int, rtype: int
               ) -> Tuple[Any, Optional[str]]:
    """Render RDATA for the types worth naming; hex for the rest."""
    if length < 0 or offset + length > len(data):
        return None, "rdata runs past the message"
    raw = data[offset:offset + length]
    if rtype == 1 and length == 4:
        return _ipv4_str(raw), None
    if rtype == 28 and length == 16:
        return _ipv6_str(raw), None
    if rtype in (2, 5, 12):
        name, _end, error = _dns_name(data, offset)
        return name, error
    if rtype == 15 and length >= 3:
        preference = (raw[0] << 8) | raw[1]
        name, _end, error = _dns_name(data, offset + 2)
        return {"preference": preference, "exchange": name}, error
    if rtype == 16:
        strings = []
        cursor = 0
        while cursor < len(raw):
            size = raw[cursor]
            strings.append(raw[cursor + 1:cursor + 1 + size].decode("latin-1"))
            cursor += 1 + size
        return " ".join(strings), None
    if rtype == 33 and length >= 7:
        priority, weight, port = struct.unpack("!HHH", raw[0:6])
        name, _end, error = _dns_name(data, offset + 6)
        return {"priority": priority, "weight": weight, "port": port,
                "target": name}, error
    if rtype == 6 and length >= 2:
        # SOA: mname, rname, then five 32-bit counters.
        mname, end, error = _dns_name(data, offset)
        if error or end is None:
            return None, error or "soa name undecodable"
        rname, end2, error2 = _dns_name(data, end)
        if error2 or end2 is None:
            return None, error2 or "soa name undecodable"
        if end2 + 20 <= len(data):
            counters = struct.unpack_from("!IIIII", data, end2)
            return {"mname": mname, "rname": rname,
                    "serial": counters[0], "refresh": counters[1],
                    "retry": counters[2], "expire": counters[3],
                    "minimum": counters[4]}, None
        return {"mname": mname, "rname": rname}, None
    return raw.hex(), None


def _parse_dns_message(data: bytes) -> Optional[Dict[str, Any]]:
    """Decode one DNS message (header + questions + answers)."""
    fields = _unpack("!HHHHHH", data, 0)
    if fields is None:
        return None
    ident, flags, qdcount, ancount, nscount, arcount = fields
    message: Dict[str, Any] = {
        "id": ident,
        "flags": flags,
        "is_response": bool(flags & 0x8000),
        "opcode": (flags >> 11) & 0x0F,
        "opcode_name": _DNS_OPCODES.get((flags >> 11) & 0x0F, "?"),
        "rcode": flags & 0x0F,
        "rcode_name": _DNS_RCODES.get(flags & 0x0F, "?"),
        "truncated_flag": bool(flags & 0x0200),
        "recursion_desired": bool(flags & 0x0100),
        "counts": {"questions": qdcount, "answers": ancount,
                   "authorities": nscount, "additional": arcount},
        "questions": [],
        "answers": [],
        "malformed": None,
    }
    offset = 12
    for _ in range(min(qdcount, MAX_DNS_RECORDS)):
        name, end, error = _dns_name(data, offset)
        if error or end is None:
            message["malformed"] = f"question name: {error}"
            return message
        qtype_class = _unpack("!HH", data, end)
        if qtype_class is None:
            message["malformed"] = "question runs past the message"
            return message
        message["questions"].append({
            "name": name,
            "type": qtype_class[0],
            "type_name": _dns_type(qtype_class[0]),
            "class": qtype_class[1],
            "class_name": _DNS_CLASSES.get(qtype_class[1], f"CLASS{qtype_class[1]}"),
        })
        offset = end + 4
    for _ in range(min(ancount, MAX_DNS_RECORDS)):
        name, end, error = _dns_name(data, offset)
        if error or end is None:
            message["malformed"] = f"answer name: {error}"
            return message
        fixed = _unpack("!HHIH", data, end)
        if fixed is None:
            message["malformed"] = "answer runs past the message"
            return message
        rtype, rclass, ttl, rdlength = fixed
        value, rerror = _dns_rdata(data, end + 10, rdlength, rtype)
        message["answers"].append({
            "name": name,
            "type": rtype,
            "type_name": _dns_type(rtype),
            "class": rclass,
            "ttl": ttl,
            "value": value,
            "malformed": rerror,
        })
        if rerror:
            message["malformed"] = f"answer rdata: {rerror}"
            return message
        offset = end + 10 + rdlength
    return message


def dns_queries(packets: Union[Dict[str, Any], Iterable[Dict[str, Any]]],
                limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Extract DNS messages from a capture (UDP and TCP, any port).

    Names are decoded through compression pointers with bounded hops, so a
    hostile capture cannot spin the parser. Each row carries the 5-tuple, the
    header flags decoded, every question and every answer — with A/AAAA/CNAME/
    NS/PTR/MX/TXT/SRV/SOA rendered and the rest as hex, which is enough to see
    a tunnelling name or an NXDOMAIN flood without reimplementing Wireshark.

    **DNS is identified by content, not only by port.** Filtering on port 53 was
    a real coverage gap found by running this against Wireshark's own
    ``dns_port.pcap``: the capture is entirely DNS on ports 65282/65333, and the
    port filter returned zero queries — on the one capture that exists to prove
    the case. Off port 53 the message must parse cleanly and carry at least one
    question, which is what keeps the check from matching arbitrary UDP; rows
    carry ``non_standard_port`` so a caller can weight them, because DNS away
    from port 53 is itself the signal.
    """
    results: List[Dict[str, Any]] = []
    for packet in _packet_list(packets):
        src_port, dst_port = packet.get("src_port"), packet.get("dst_port")
        if packet.get("protocol") not in (_IPPROTO_UDP, _IPPROTO_TCP):
            continue
        payload = packet.get("payload") or ""
        if not payload:
            continue
        data = payload.encode("latin-1")
        if packet["protocol"] == _IPPROTO_TCP:
            # TCP DNS frames each message with a 16-bit length prefix.
            prefix = _unpack("!H", data, 0)
            if prefix is None or prefix[0] > len(data) - 2:
                continue
            data = data[2:2 + prefix[0]]
        on_port_53 = 53 in (src_port, dst_port)
        message = _parse_dns_message(data)
        if message is None:
            continue
        if not on_port_53:
            # DNS away from port 53 is a documented tunnelling and evasion
            # technique — it is why a capture like Wireshark's `dns_port.pcap`
            # exists at all — so identifying it by *content* rather than by port
            # is the point rather than a nicety. A tool that only watches port 53
            # reports no DNS on a capture that is entirely DNS.
            #
            # The structural test is what keeps this from matching arbitrary UDP:
            # the message must parse **cleanly** and carry at least one question.
            # On port 53 a malformed message is still reported (a broken DNS
            # packet is itself interesting); off port 53 it is not, because the
            # cost of a false positive is higher than the cost of missing one.
            if message.get("malformed") is not None or not message.get("questions"):
                continue
        message.update({
            "ts": packet.get("ts"),
            "src": packet.get("src_ip"),
            "dst": packet.get("dst_ip"),
            "src_port": src_port,
            "dst_port": dst_port,
            "transport": _PROTO_NAMES.get(packet.get("protocol")),
            "index": packet.get("index"),
            "non_standard_port": not on_port_53,
        })
        results.append(message)
        if limit is not None and len(results) >= limit:
            break
    return results


# ============================================================ live capture
#: Default ceiling on a live capture, so an unbounded read cannot fill memory.
_CAF_DEFAULT_COUNT = 200


def live_capture(count: int = _CAF_DEFAULT_COUNT, timeout_s: float = 5.0,
                 interface: Optional[str] = None, snaplen: int = 65535,
                 promiscuous: bool = False
                 ) -> Dict[str, Any]:
    """Capture frames from a live interface, in the shape :func:`read_pcap` returns.

    So the decoders accept the result unchanged: ``flows()``, ``dns_queries()``,
    ``tls_client_hellos()`` and ``http_requests()`` take either.

    **Requires ``CAP_NET_RAW``** — root, or ``setcap cap_net_raw+ep`` on the
    interpreter. Absence is *reported*, never raised: a capture attempt that
    cannot run returns ``stop_reason="permission-denied"`` with an actionable
    ``error``, because a forensic tool that dies on a privilege it lacks tells
    the analyst nothing. Off Linux, or with a kernel that refuses ``AF_PACKET``,
    the same applies under ``stop_reason="unsupported"``.

    ``promiscuous`` defaults to **False**, unlike most capture tools. Promiscuous
    mode changes the interface's state and makes the host process frames that are
    not addressed to it; on a production host that is an operational change, and
    a forensic tool should not make one as a side effect of being pointed at a
    network. Pass it explicitly when the authority to do so exists.

    The result is bounded by ``count`` and by ``timeout_s`` so a live socket
    cannot pin the run, and every frame is decoded with :func:`decode_packet`
    using ``LINKTYPE_ETHERNET`` — the link type ``AF_PACKET`` delivers on the
    interfaces this targets. A frame that does not decode is kept with its
    ``malformed`` reason rather than dropped.
    """
    result = _empty_result("live")
    result.update({"interface": interface, "snaplen": snaplen,
                   "linktype": LINKTYPE_ETHERNET, "promiscuous": promiscuous,
                   "requested_count": count})
    if not sys.platform.startswith("linux"):
        result["stop_reason"] = "unsupported"
        result["error"] = (f"live capture uses AF_PACKET, which is Linux-only "
                           f"(platform is {sys.platform!r})")
        return result

    try:
        import socket as _socket
    except ImportError as exc:  # pragma: no cover - socket is stdlib
        result["stop_reason"] = "unsupported"
        result["error"] = f"no socket module: {exc}"
        return result

    try:
        sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW,
                              _socket.htons(0x0003))
    except PermissionError:
        result["stop_reason"] = "permission-denied"
        result["error"] = (
            "opening an AF_PACKET raw socket needs CAP_NET_RAW: run as root, or "
            "grant it with `setcap cap_net_raw+ep $(readlink -f $(which python3))`")
        return result
    except OSError as exc:
        result["stop_reason"] = "unsupported"
        result["error"] = f"cannot open AF_PACKET socket: {exc}"
        return result

    deadline = time.monotonic() + max(0.0, timeout_s)
    try:
        if interface:
            sock.bind((interface, 0))
        sock.settimeout(0.25)
        while len(result["packets"]) < max(0, count):
            if time.monotonic() > deadline:
                result["stop_reason"] = "timeout"
                result["truncated"] = True
                break
            try:
                frame = sock.recv(min(snaplen, 65535))
            except _socket.timeout:
                continue
            except OSError as exc:
                result["stop_reason"] = "error"
                result["error"] = f"recv failed: {exc}"
                break
            if not frame:
                continue
            decoded = decode_packet(frame, LINKTYPE_ETHERNET)
            decoded["index"] = len(result["packets"])
            decoded["ts"] = time.time()
            result["packets"].append(decoded)
            result["bytes_read"] += len(frame)
            if decoded.get("malformed"):
                result["malformed_records"] += 1
        else:
            result["stop_reason"] = "limit"
            result["truncated"] = True
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return result


# ============================================================ TCP streams
def _tcp_streams(packets: Union[Dict[str, Any], Iterable[Dict[str, Any]]],
                 max_bytes: int = MAX_STREAM_BYTES) -> List[Dict[str, Any]]:
    """Reassemble TCP payloads into one byte stream per direction.

    Payloads are ordered by sequence number (duplicates collapse to the
    longest copy). Sequence wraps and gaps are not resolved — this is enough
    to recover a request line or a ClientHello from a capture that was not
    intentionally fragmented, and the alternative is a full TCP stack. The
    stream is capped at ``max_bytes`` so an endless flow cannot grow.
    """
    streams: Dict[Tuple[Any, ...], Dict[int, bytes]] = {}
    meta: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for packet in _packet_list(packets):
        if packet.get("protocol") != _IPPROTO_TCP:
            continue
        payload = packet.get("payload") or ""
        if not payload:
            continue
        src, dst = packet.get("src_ip"), packet.get("dst_ip")
        if not src or not dst:
            continue
        key = (src, dst, packet.get("src_port"), packet.get("dst_port"))
        seq = packet.get("tcp_seq")
        if seq is None:
            continue
        segments = streams.setdefault(key, {})
        existing = segments.get(seq)
        if existing is None or len(payload) > len(existing):
            segments[seq] = payload.encode("latin-1")
        if key not in meta:
            meta[key] = {
                "src": src, "dst": dst,
                "src_port": packet.get("src_port"),
                "dst_port": packet.get("dst_port"),
                "ts": packet.get("ts"),
                "index": packet.get("index"),
            }
    out: List[Dict[str, Any]] = []
    for key, segments in streams.items():
        chunks: List[bytes] = []
        total = 0
        for seq in sorted(segments):
            chunk = segments[seq]
            if total + len(chunk) > max_bytes:
                chunk = chunk[:max_bytes - total]
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        data = b"".join(chunks)
        row = dict(meta[key])
        row["data"] = data
        row["bytes"] = len(data)
        out.append(row)
    out.sort(key=lambda s: (s["ts"] if isinstance(s["ts"], (int, float))
                            else float("inf"), s["src"], s["src_port"] or 0))
    return out


# ====================================================================== TLS
def _tls_client_hello(body: bytes) -> Optional[Dict[str, Any]]:
    """Parse a ClientHello body; ``None`` when it is not structurally sound."""
    fields = _unpack("!H", body, 0)
    if fields is None:
        return None
    legacy_version = fields[0]
    offset = 2 + 32                        # Random
    session_length = _u8(body, offset)
    if session_length is None:
        return None
    offset += 1 + session_length
    cipher_field = _unpack("!H", body, offset)
    if cipher_field is None:
        return None
    cipher_bytes = cipher_field[0]
    offset += 2
    if cipher_bytes % 2 or offset + cipher_bytes > len(body):
        return None
    ciphers = list(struct.unpack(f"!{cipher_bytes // 2}H", body[offset:offset + cipher_bytes]))
    offset += cipher_bytes
    compression_length = _u8(body, offset)
    if compression_length is None:
        return None
    offset += 1 + compression_length
    hello: Dict[str, Any] = {
        "version": legacy_version,
        "cipher_suites": ciphers,
        "extensions": [],
        "server_name": None,
        "elliptic_curves": [],
        "ec_point_formats": [],
        "supported_versions": [],
    }
    extension_field = _unpack("!H", body, offset)
    if extension_field is None:
        return hello                        # a legal, pre-extension ClientHello
    offset += 2
    extension_end = min(len(body), offset + extension_field[0])
    while offset + 4 <= extension_end:
        header = struct.unpack_from("!HH", body, offset)
        etype, elength = header
        start = offset + 4
        if start + elength > extension_end:
            break
        data = body[start:start + elength]
        hello["extensions"].append(etype)
        if etype == _TLS_EXT_SERVER_NAME:
            hello["server_name"] = _tls_sni(data) or hello["server_name"]
        elif etype == _TLS_EXT_SUPPORTED_GROUPS:
            if len(data) >= 2:
                size = (data[0] << 8) | data[1]
                usable = min(size, len(data) - 2)
                hello["elliptic_curves"] = list(
                    struct.unpack(f"!{usable // 2}H", data[2:2 + (usable // 2) * 2]))
        elif etype == _TLS_EXT_EC_POINT_FORMATS:
            if data:
                size = min(data[0], len(data) - 1)
                hello["ec_point_formats"] = list(data[1:1 + size])
        offset = start + elength
    return hello


def _tls_sni(data: bytes) -> Optional[str]:
    """Server Name extension: a list is required even for one name."""
    if len(data) < 5:
        return None
    list_length = (data[0] << 8) | data[1]
    end = min(len(data), 2 + list_length)
    offset = 2
    while offset + 3 <= end:
        name_type = data[offset]
        name_length = (data[offset + 1] << 8) | data[offset + 2]
        offset += 3
        if offset + name_length > end:
            return None
        if name_type == 0:
            return data[offset:offset + name_length].decode("utf-8", "replace")
        offset += name_length
    return None


def _ja3(hello: Dict[str, Any]) -> str:
    """The JA3 string: version, ciphers, extensions, curves, point formats.

    Hyphens between values inside a field, commas between fields, decimal
    integers, order as sent — the fingerprint is the *order*, which is why the
    parser preserves it rather than sorting.
    """
    def joined(values: Iterable[Any]) -> str:
        return "-".join(str(v) for v in values)

    return ",".join((
        str(hello["version"]),
        joined(hello["cipher_suites"]),
        joined(hello["extensions"]),
        joined(hello["elliptic_curves"]),
        joined(hello["ec_point_formats"]),
    ))


def tls_client_hellos(packets: Union[Dict[str, Any], Iterable[Dict[str, Any]]],
                      limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Extract TLS ClientHellos (SNI, cipher suites, extensions) and their JA3.

    Handshakes are located in reassembled TCP streams, so a ClientHello split
    across segments is still parsed. Records are walked with their real
    lengths and resynchronised one byte at a time when a length field is
    inconsistent, so a scanner or a hostile peer cannot desynchronise the walk
    into a hang. Each row carries the raw JA3 string and its MD5, which is what
    threat-intel feeds key off.
    """
    results: List[Dict[str, Any]] = []
    for stream in _tcp_streams(packets):
        data = stream["data"]
        offset = 0
        while offset + 5 <= len(data):
            if data[offset] != _TLS_HANDSHAKE:
                # Resynchronise on the next handshake byte instead of walking
                # non-TLS payload one byte at a time: an HTTP stream in the
                # same capture is megabytes of bytes that are not 0x16.
                offset = data.find(b"\x16", offset + 1)
                if offset < 0:
                    break
                continue
            record_version = (data[offset + 1] << 8) | data[offset + 2]
            record_length = (data[offset + 3] << 8) | data[offset + 4]
            if record_version >> 8 != 3 or offset + 5 + record_length > len(data):
                offset += 1
                continue
            record = data[offset + 5:offset + 5 + record_length]
            position = 0
            while position + 4 <= len(record):
                handshake_type = record[position]
                handshake_length = int.from_bytes(record[position + 1:position + 4], "big")
                if handshake_length > len(record) - position - 4:
                    break
                if handshake_type == _TLS_CLIENT_HELLO:
                    hello = _tls_client_hello(record[position + 4:
                                                      position + 4 + handshake_length])
                    if hello is not None:
                        ja3 = _ja3(hello)
                        hello.update({
                            "ts": stream["ts"],
                            "src": stream["src"],
                            "dst": stream["dst"],
                            "src_port": stream["src_port"],
                            "dst_port": stream["dst_port"],
                            "record_version": record_version,
                            "ja3": ja3,
                            "ja3_hash": hashlib.md5(ja3.encode()).hexdigest(),
                        })
                        results.append(hello)
                        if limit is not None and len(results) >= limit:
                            return results
                position += 4 + handshake_length
            offset += 5 + record_length
    return results


# ===================================================================== HTTP
#: Matched *at* a stream offset, not anchored to a line start: a pipelined
#: request begins immediately after the previous body, with no newline between.
_HTTP_REQUEST_LINE = re.compile(rb"([A-Z]{3,10}) (\S+) HTTP/(1\.[01])\r\n")


def _http_headers(block: bytes) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in block.split(b"\r\n"):
        if not line or line[:1] in (b" ", b"\t"):
            continue                        # obs-fold: join into the previous
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        headers[name.decode("latin-1").strip()] = value.decode("latin-1").strip()
    return headers


def _header(headers: Dict[str, str], name: str) -> Optional[str]:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _http_body_length(headers: Dict[str, str], data: bytes, start: int) -> int:
    """Bytes to skip after the headers: Content-Length, or a chunked body.

    Pipelined and keep-alive requests follow their body immediately, so the
    scanner has to know where the body ends to find the next request line —
    otherwise a request that follows a body is invisible (there is no newline
    before it to anchor on).
    """
    encoding = _header(headers, "Transfer-Encoding")
    if encoding and "chunked" in encoding.lower():
        position = start
        while position + 5 <= len(data):
            if data[position:position + 2] == b"\r\n":
                position += 2
            line_end = data.find(b"\r\n", position, position + 32)
            if line_end < 0:
                return len(data) - start
            try:
                size = int(data[position:line_end].split(b";")[0], 16)
            except ValueError:
                return len(data) - start
            position = line_end + 2 + size + 2
            if size == 0:
                return min(position, len(data)) - start
        return len(data) - start
    length = _header(headers, "Content-Length")
    if length is None:
        return 0
    try:
        return max(0, int(length.split(",")[0].strip()))
    except ValueError:
        return 0


def http_requests(packets: Union[Dict[str, Any], Iterable[Dict[str, Any]]],
                  limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Recover cleartext HTTP requests from reassembled TCP streams.

    The stream is walked request by request: a request line, its headers,
    then its body (``Content-Length`` or chunked), then the next request — so
    pipelined and keep-alive connections yield every request, including the
    ones that follow a body with no newline in front of them. When a request
    line cannot be parsed at the current offset the scan resynchronises on the
    next one, so a lost segment does not hide the rest of the stream.

    Streams are scanned rather than port-filtered: HTTP on 8080, 8888 or a
    covert 4444 is exactly the traffic that matters, and the request-line
    grammar is the discriminator. An absolute-form target
    (``GET http://host/path``, sent to proxies) is split into host and path.
    """
    results: List[Dict[str, Any]] = []
    for stream in _tcp_streams(packets):
        data = stream["data"]
        position = 0
        while position < len(data):
            match = _HTTP_REQUEST_LINE.match(data, position)
            if match is None:
                next_match = _HTTP_REQUEST_LINE.search(data, position + 1)
                if next_match is None:
                    break
                position = next_match.start()
                continue
            header_end = data.find(b"\r\n\r\n", match.end(),
                                   match.end() + MAX_HTTP_HEADER_BYTES)
            if header_end < 0:
                break
            headers = _http_headers(data[match.end():header_end])
            body_start = header_end + 4
            method = match.group(1).decode("latin-1")
            target = match.group(2).decode("latin-1")
            host = _header(headers, "Host")
            path = target
            for scheme in ("http://", "https://"):
                if target.lower().startswith(scheme):
                    # RFC 7230: with an absolute-form target the authority is
                    # the real host; a Host header sent alongside is ignored
                    # (it is still in ``headers`` for the analyst to see).
                    authority, _, rest = target[len(scheme):].partition("/")
                    host = authority or host
                    path = "/" + rest
                    break
            results.append({
                "ts": stream["ts"],
                "src": stream["src"],
                "dst": stream["dst"],
                "src_port": stream["src_port"],
                "dst_port": stream["dst_port"],
                "method": method,
                "path": path,
                "version": match.group(3).decode("latin-1"),
                "host": host,
                "user_agent": _header(headers, "User-Agent"),
                "referer": _header(headers, "Referer"),
                "content_length": _header(headers, "Content-Length"),
                "headers": headers,
                "index": stream["index"],
            })
            if limit is not None and len(results) >= limit:
                return results
            if len(results) >= MAX_HTTP_REQUESTS:
                return results
            position = body_start + _http_body_length(headers, data, body_start)
    return results
