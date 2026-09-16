"""Generate a realistic synthetic capture to exercise the network playbook.

Nothing here is from a live network — it is constructed so the playbook has
each kind of signal to find, and so a reader can check the output against a
capture whose contents they know exactly.
"""
import struct

CAPTURE = "/tmp/jky-capture.pcap"


def eth_ipv4(payload: bytes, proto: int, src: str, dst: str) -> bytes:
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    ip = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234, 0, 64, proto, 0,
        bytes(int(x) for x in src.split(".")), bytes(int(x) for x in dst.split("."))
    )
    return eth + ip + payload


def udp(payload: bytes, sport: int, dport: int) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(payload: bytes, sport: int, dport: int, flags: int = 0x18) -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 8192, 0, 0) + payload


def dns_query(qid: int, name: str, qtype: int) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return (struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels
            + struct.pack(">HH", qtype, 1))


def client_hello(sni: str | None) -> bytes:
    """A minimal TLS 1.2 ClientHello, optionally carrying SNI."""
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00"          # version, random, no session id
    body += struct.pack(">H", 2) + b"\xc0\x2f"           # one cipher suite
    body += b"\x01\x00"                                   # no compression
    ext = b""
    if sni:
        name = sni.encode()
        entry = b"\x00" + struct.pack(">H", len(name)) + name
        ext += b"\x00\x00" + struct.pack(">H", len(entry) + 2) + struct.pack(">H", len(entry)) + entry
    ext += b"\x00\x0b\x00\x02\x01\x00"                    # ec_point_formats
    body += struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def http_get(host: str, path: str, ua: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\n\r\n").encode()


frames = []
t = 1700000000.0

# 1. ordinary browsing: DNS then a TLS connection that names itself
frames.append(eth_ipv4(udp(dns_query(1, "www.example.com", 1), 40001, 53), 17, "10.0.0.5", "8.8.8.8"))
frames.append(eth_ipv4(tcp(client_hello("www.example.com"), 40002, 443), 6, "10.0.0.5", "93.184.216.34"))

# 2. DNS tunnelling shape: a very long, high-entropy label under one parent
frames.append(eth_ipv4(udp(dns_query(
    2, "aGVsbG8td29ybGQtdGhpcy1pcy1hLXR1bm5lbC1jaHVuaw.exfil.example.net", 1),
    40003, 53), 17, "10.0.0.5", "8.8.8.8"))
frames.append(eth_ipv4(udp(dns_query(3, "ZXhpdGx0cmF0aW9uLXNlY29uZC1jaHVuaw.exfil.example.net", 16),
                          40004, 53), 17, "10.0.0.5", "8.8.8.8"))

# 3. TLS with no SNI: addressed by IP, which is what a check-in looks like
frames.append(eth_ipv4(tcp(client_hello(None), 40005, 443), 6, "10.0.0.5", "203.0.113.9"))

# 4. cleartext executable download
frames.append(eth_ipv4(tcp(http_get("cdn.invalid", "/payload.exe", "Mozilla/5.0"), 40006, 80),
                       6, "10.0.0.7", "198.51.100.20"))
# and a tool-shaped user agent asking for a script
frames.append(eth_ipv4(tcp(http_get("paste.invalid", "/run.sh", "curl/8.5.0"), 40007, 80),
                       6, "10.0.0.7", "198.51.100.21"))

# 5. a large outbound flow (exfiltration shape)
for i in range(40):
    frames.append(eth_ipv4(tcp(b"\x00" * 1400, 40010 + i, 8443), 6, "10.0.0.9", "203.0.113.50"))

with open(CAPTURE, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames):
        ts = t + index * 0.25
        fh.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1_000_000), len(frame), len(frame)))
        fh.write(frame)

print(f"wrote {CAPTURE}: {len(frames)} frames")
