"""
Network forensic collection from ``/proc/net``.

Sockets are enumerated from the kernel's own tables and then correlated with
the owning process through ``/proc/<pid>/fd`` symlinks (``socket:[inode]``) —
the same correlation ``ss -p`` performs, but without executing it.
"""
from __future__ import annotations

import socket
from typing import Any, Dict, List, Optional, Tuple

from jocky.rt import procfs

TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN", "0B": "CLOSING",
}

# Ports that are routinely listening on servers; anything else is surfaced
# for the analyst to look at (the script decides, this is just a baseline).
COMMON_LISTEN_PORTS = {
    22, 53, 80, 123, 443, 631, 853, 3000, 3306, 5432, 6379, 8000,
    8080, 8443, 9090, 27017,
}


def _decode_v4(hex_addr: str) -> str:
    """``0100007F`` (little endian) -> ``127.0.0.1``."""
    try:
        raw = bytes.fromhex(hex_addr)
        return socket.inet_ntoa(raw[::-1])
    except (ValueError, OSError):
        return "?"


def _decode_v6(hex_addr: str) -> str:
    """32 hex chars, four little-endian 32-bit words (as the kernel prints)."""
    try:
        words = [hex_addr[i:i + 8] for i in range(0, 32, 8)]
        raw = b"".join(bytes.fromhex(w)[::-1] for w in words)
        return socket.inet_ntop(socket.AF_INET6, raw)
    except (ValueError, OSError):
        return "?"


def _split_addr(field: str, v6: bool) -> Tuple[str, int]:
    addr, _, port = field.partition(":")
    try:
        port_no = int(port, 16)
    except ValueError:
        port_no = 0
    return (_decode_v6(addr) if v6 else _decode_v4(addr), port_no)


def _read_table(path: str, proto: str, v6: bool) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        with open(path) as fh:
            lines = fh.read().splitlines()
    except OSError:
        return rows
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            local, local_port = _split_addr(parts[1], v6)
            remote, remote_port = _split_addr(parts[2], v6)
            rows.append({
                "proto": proto,
                "local_addr": local,
                "local_port": local_port,
                "remote_addr": remote,
                "remote_port": remote_port,
                "state": TCP_STATES.get(parts[3], parts[3]) if proto.startswith("tcp") else "-",
                "uid": int(parts[7]) if parts[7].isdigit() else None,
                "inode": int(parts[9]) if parts[9].isdigit() else 0,
                "listening": proto.startswith("tcp") and parts[3] == "0A",
            })
        except (ValueError, IndexError):
            continue
    return rows


def _read_unix(path: str = "/proc/net/unix") -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        with open(path) as fh:
            lines = fh.read().splitlines()
    except OSError:
        return rows
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            rows.append({
                "proto": "unix",
                "type": parts[4],
                "state": parts[5],
                "inode": int(parts[6]) if parts[6].isdigit() else 0,
                "path": parts[7] if len(parts) > 7 else "",
                "listening": parts[4] == "0001" and parts[5] == "01",
            })
        except (ValueError, IndexError):
            # Malformed line; skip without aborting the entire table
            continue
    return rows


def connections(include_unix: bool = False, with_process: bool = True,
                proto_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Every socket in the kernel tables, optionally attributed to a process."""
    rows: List[Dict[str, Any]] = []
    for path, proto, v6 in (
        ("/proc/net/tcp", "tcp", False),
        ("/proc/net/tcp6", "tcp6", True),
        ("/proc/net/udp", "udp", False),
        ("/proc/net/udp6", "udp6", True),
        ("/proc/net/raw", "raw", False),
    ):
        if proto_filter and proto not in proto_filter:
            continue
        rows.extend(_read_table(path, proto, v6))
    if include_unix:
        rows.extend(_read_unix())
    if with_process:
        owners = procfs.socket_inode_map()
        for row in rows:
            owner = owners.get(row.get("inode", 0))
            row["pid"] = owner["pid"] if owner else None
            row["process"] = owner["name"] if owner else None
    return rows


def listeners(with_process: bool = True) -> List[Dict[str, Any]]:
    """TCP LISTEN sockets (the attack surface of the host)."""
    return [c for c in connections(with_process=with_process) if c.get("listening")]


def unusual_listeners(allow: Optional[set] = None) -> List[Dict[str, Any]]:
    """Listening TCP ports outside the baseline set (analyst review queue)."""
    allowed = COMMON_LISTEN_PORTS if allow is None else allow
    return [c for c in listeners() if c["local_port"] not in allowed]


def established(with_process: bool = True) -> List[Dict[str, Any]]:
    return [c for c in connections(with_process=with_process)
            if c.get("state") == "ESTABLISHED"]


def connections_by_process() -> Dict[int, List[Dict[str, Any]]]:
    grouped: Dict[int, List[Dict[str, Any]]] = {}
    for row in connections():
        pid = row.get("pid")
        if pid is not None:
            grouped.setdefault(pid, []).append(row)
    return grouped


def interfaces() -> List[Dict[str, Any]]:
    """Per-interface addresses, MAC and traffic counters."""
    out: List[Dict[str, Any]] = []
    counters: Dict[str, Dict[str, int]] = {}
    try:
        with open("/proc/net/dev") as fh:
            for line in fh.readlines()[2:]:
                name, _, rest = line.partition(":")
                fields = rest.split()
                if len(fields) >= 9:
                    counters[name.strip()] = {
                        "rx_bytes": int(fields[0]),
                        "rx_packets": int(fields[1]),
                        "tx_bytes": int(fields[8]),
                        "tx_packets": int(fields[9]) if len(fields) > 9 else 0,
                    }
    except (OSError, ValueError):
        pass
    try:
        names = sorted(__import__("os").listdir("/sys/class/net"))
    except OSError:
        names = sorted(counters)
    for name in names:
        base = f"/sys/class/net/{name}"
        entry: Dict[str, Any] = {"name": name, **counters.get(name, {})}
        for attr, key in (("address", "mac"), ("mtu", "mtu"),
                          ("operstate", "state"), ("type", "type")):
            try:
                with open(f"{base}/{attr}") as fh:
                    entry[key] = fh.read().strip()
            except OSError:
                entry[key] = None
        out.append(entry)
    return out


def routes() -> List[Dict[str, Any]]:
    """IPv4 routing table with decoded destinations and gateways."""
    out: List[Dict[str, Any]] = []
    try:
        with open("/proc/net/route") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) < 8:
                    continue
                try:
                    dest = _decode_v4(parts[1])
                    gw = _decode_v4(parts[2])
                    mask = _decode_v4(parts[7])
                except (ValueError, IndexError):
                    continue
                flags = int(parts[3], 16)
                out.append({
                    "iface": parts[0],
                    "destination": dest,
                    "gateway": gw,
                    "mask": mask,
                    "metric": int(parts[6]),
                    "default": dest == "0.0.0.0" and mask == "0.0.0.0",
                    "up": bool(flags & 0x1),
                })
    except (OSError, ValueError):
        return out
    return out
