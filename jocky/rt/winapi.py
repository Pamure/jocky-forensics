"""Windows host collection through pure ``ctypes`` — the Linux shapes, again.

The delivery target is *Windows and Linux*: a runtime that can only observe one
of them cannot be used during an incident on the other, and Windows is where
kernel-driver abuse and signed-binary proxying actually happen.  This module is
the Windows side of :mod:`jocky.rt.procfs` and :mod:`jocky.rt.netfs`, and it
deliberately emits the **same key names** so a script written against the Linux
collectors runs unchanged:

    proc.list()      -> list_processes()          (pid, ppid, name, exe, uid, threads, argv, ...)
    proc.cmdline(p)  -> read_cmdline(p)           (a list of argv strings)
    net.connections()-> connections()             (proto, local_addr, local_port, ..., pid, listening)
    net.interfaces() -> interfaces()              (name, mac, mtu, state, type, counters)
    net.routes()     -> routes()                  (iface, destination, gateway, mask, metric)
    sys.modules()    -> modules()                 (loaded *kernel drivers*, the BYOVD input)

Three rules shape everything below.

**No child processes.**  The Linux collectors never spawn ``ps``/``ss``/``lsof``,
because a triage that shells out leaves artefacts in the evidence and can be
hooked.  The same rule applies here: no ``tasklist``, ``netstat``, ``wmic``,
``driverquery`` or PowerShell.  Every fact comes from ``ctypes`` calls into
``kernel32``/``ntdll``/``advapi32``/``iphlpapi``/``psapi``.

**Import safety.**  ``ctypes.windll`` does not exist off Windows, and much of the
runtime imports the collectors package on Linux.  So the DLLs are resolved
lazily: :func:`available` is ``False`` on any non-Windows host and every
collector returns its empty value (``[]`` / ``{}``) without raising and without
touching a Windows API.  The pure helpers (address/port/SID/struct decoding) are
module-level functions over plain ``int``/``bytes``, so the logic that is easy
to get wrong — byte order, struct offsets, SID layout — is unit-testable on
Linux with synthetic buffers.

**Read-only.**  Nothing here loads, unloads, starts or stops anything, and no
process handle is opened with a right above ``PROCESS_QUERY_LIMITED_INFORMATION``.

Where a Windows fact genuinely does not exist, the key is still present with an
honest empty value rather than an invented one, and the reason is recorded in
the collector's docstring (``size``/``refcount`` of a driver, ``gid``, ``cwd``,
container fields).  Permission denials are never raised and never silently
dropped: they are reported through :func:`access_errors` (and the affected
process row is flagged ``access_denied``), so an analyst can tell "there is
nothing here" from "this account was not allowed to look".
"""
from __future__ import annotations

import ctypes
import os
import socket
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "TCP_STATES",
    "access_errors",
    "available",
    "boot_time",
    "clear_access_errors",
    "connections",
    "connections_by_process",
    "established",
    "interfaces",
    "list_pids",
    "list_processes",
    "listeners",
    "modules",
    "read_cmdline",
    "read_exe",
    "read_handles",
    "read_modules",
    "read_sid",
    "routes",
    "uptime_seconds",
]

# ------------------------------------------------------------------ constants
_IS_WINDOWS = sys.platform == "win32"
_POINTER_SIZE = ctypes.sizeof(ctypes.c_void_p)

#: Windows socket address families.  ``socket.AF_INET6`` is 10 on Linux but 23
#: on Windows, so the on-the-wire family of a ``SOCKADDR`` buffer is decoded
#: with these constants and never with the local ``socket`` module's.
_AF_UNSPEC = 0
_AF_INET = 2
_AF_INET6_WIN = 23

#: MIB_TCP_STATE_* -> name.  ``SYN_RECV`` matches what ``/proc/net/tcp`` prints
#: for the Linux collector, so both sides emit identical state text.
TCP_STATES = {
    1: "CLOSED",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RECV",
    5: "ESTABLISHED",
    6: "FIN_WAIT1",
    7: "FIN_WAIT2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}

_MIB_TCP_STATE_LISTEN = 2
_MIB_IPROUTE_TYPE_INVALID = 2

_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_PROCESS_COMMAND_LINE_INFORMATION = 60
_SYSTEM_EXTENDED_HANDLE_INFORMATION = 64

_TCP_TABLE_OWNER_PID_ALL = 5
_UDP_TABLE_OWNER_PID = 1

_LIST_MODULES_ALL = 0x0003

#: GAA_FLAG_SKIP_ANYCAST | SKIP_MULTICAST | SKIP_DNS_SERVER | INCLUDE_PREFIX.
#: Skipping the anycast/multicast/DNS linked lists keeps the walk bounded; the
#: prefix list is kept because it carries the on-link prefix lengths.
_GAA_FLAGS = 0x0002 | 0x0004 | 0x0008 | 0x0010

_NO_ERROR = 0
_ERROR_BUFFER_OVERFLOW = 111
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_NO_DATA = 232
_STATUS_SUCCESS = 0
_STATUS_BUFFER_TOO_SMALL = 0xC0000023
_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

_MAX_PATH = 260
_TABLE_ROWS_OFFSET = 4

#: Directory prefixes that a legitimate image path almost never starts with.
_SUSPICIOUS_DIRS = (
    "\\users\\public\\",
    "\\windows\\temp\\",
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\programdata\\",
    "\\recycler\\",
    "$recycle.bin",
)

# ------------------------------------------------------------------- win types
# Fixed-width aliases: ``ctypes.wintypes.DWORD`` is ``c_ulong``, which is 64-bit
# off Windows, so wintypes are *not* used for structure layout.  Defining every
# field with an explicit width keeps a struct's size and offsets identical here
# and on Windows, which is what makes the decoders testable on Linux.
_DWORD = ctypes.c_uint32
_LONG = ctypes.c_int32
_BYTE = ctypes.c_uint8
_BOOL = ctypes.c_int32
_ULONGLONG = ctypes.c_uint64
_SIZE_T = ctypes.c_size_t
_HANDLE = ctypes.c_void_p
_CHAR16 = ctypes.c_uint16  # WCHAR as a *width*, never as c_wchar (4 bytes on Linux)

_INVALID_HANDLE = (1 << (8 * _POINTER_SIZE)) - 1


class _PROCESSENTRY32W(ctypes.Structure):
    """``PROCESSENTRY32W`` from ``tlhelp32.h`` (568 bytes on x64)."""

    _fields_ = [
        ("dwSize", _DWORD),
        ("cntUsage", _DWORD),
        ("th32ProcessID", _DWORD),
        ("th32DefaultHeapID", _SIZE_T),
        ("th32ModuleID", _DWORD),
        ("cntThreads", _DWORD),
        ("th32ParentProcessID", _DWORD),
        ("pcPriClassBase", _LONG),
        ("dwFlags", _DWORD),
        ("szExeFile", _CHAR16 * _MAX_PATH),
    ]


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", _DWORD), ("dwHighDateTime", _DWORD)]


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    """``PROCESS_MEMORY_COUNTERS`` (the EX variant is a strict prefix)."""

    _fields_ = [
        ("cb", _DWORD),
        ("PageFaultCount", _DWORD),
        ("PeakWorkingSetSize", _SIZE_T),
        ("WorkingSetSize", _SIZE_T),
        ("QuotaPeakPagedPoolUsage", _SIZE_T),
        ("QuotaPagedPoolUsage", _SIZE_T),
        ("QuotaPeakNonPagedPoolUsage", _SIZE_T),
        ("QuotaNonPagedPoolUsage", _SIZE_T),
        ("PagefileUsage", _SIZE_T),
        ("PeakPagefileUsage", _SIZE_T),
    ]


class _TOKEN_USER(ctypes.Structure):
    """``TOKEN_USER``: one ``SID_AND_ATTRIBUTES``; the SID bytes follow it."""

    _fields_ = [("Sid", _HANDLE), ("Attributes", _DWORD)]


class _MIB_IFROW(ctypes.Structure):
    """``MIB_IFROW`` from ``ipmib.h`` (860 bytes on x64).

    Only the counters and status fields are read; the name buffers are kept so
    the layout matches the ABI exactly.
    """

    _fields_ = [
        ("wszName", _CHAR16 * 256),
        ("dwIndex", _DWORD),
        ("dwType", _DWORD),
        ("dwMtu", _DWORD),
        ("dwSpeed", _DWORD),
        ("dwPhysAddrLen", _DWORD),
        ("bPhysAddr", _BYTE * 8),
        ("dwAdminStatus", _DWORD),
        ("dwOperStatus", _DWORD),
        ("dwLastChange", _DWORD),
        ("dwInOctets", _DWORD),
        ("dwInUcastPkts", _DWORD),
        ("dwInNUcastPkts", _DWORD),
        ("dwInDiscards", _DWORD),
        ("dwInErrors", _DWORD),
        ("dwInUnknownProtos", _DWORD),
        ("dwOutOctets", _DWORD),
        ("dwOutUcastPkts", _DWORD),
        ("dwOutNUcastPkts", _DWORD),
        ("dwOutDiscards", _DWORD),
        ("dwOutErrors", _DWORD),
        ("dwOutQLen", _DWORD),
        ("dwDescrLen", _DWORD),
        ("bDescr", _BYTE * 256),
    ]


class _IP_ADAPTER_ADDRESSES(ctypes.Structure):
    """``IP_ADAPTER_ADDRESSES_LH`` with the linked lists as opaque pointers.

    The ``Length``/``IfIndex`` union is flattened to two DWORDs (identical
    layout) and the flag bitfield union to a plain DWORD, because only whole
    values are ever read.
    """

    pass


_IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", _DWORD),
    ("IfIndex", _DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
    ("AdapterName", _HANDLE),
    ("FirstUnicastAddress", _HANDLE),
    ("FirstAnycastAddress", _HANDLE),
    ("FirstMulticastAddress", _HANDLE),
    ("FirstDnsServerAddress", _HANDLE),
    ("DnsSuffix", _HANDLE),
    ("Description", _HANDLE),
    ("FriendlyName", _HANDLE),
    ("PhysicalAddress", _BYTE * 8),
    ("PhysicalAddressLength", _DWORD),
    ("Flags", _DWORD),
    ("Mtu", _DWORD),
    ("IfType", _DWORD),
    ("OperStatus", _DWORD),
    ("Ipv6IfIndex", _DWORD),
    ("ZoneIndices", _DWORD * 16),
    ("FirstPrefix", _HANDLE),
]


class _SOCKET_ADDRESS(ctypes.Structure):
    """``SOCKET_ADDRESS``: pointer plus length, with the ABI's trailing padding."""

    _fields_ = [("lpSockaddr", _HANDLE), ("iSockaddrLength", _LONG)]


class _IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    """``IP_ADAPTER_UNICAST_ADDRESS_LH`` (flattened union, as above).

    ``Address`` is the real nested ``SOCKET_ADDRESS`` rather than two loose
    fields: its trailing padding is part of the layout, and flattening it would
    shift ``OnLinkPrefixLength`` four bytes early on x64.
    """

    _fields_ = [
        ("Length", _DWORD),
        ("Flags", _DWORD),
        ("Next", _HANDLE),
        ("Address", _SOCKET_ADDRESS),
        ("PrefixOrigin", _DWORD),
        ("SuffixOrigin", _DWORD),
        ("DadState", _DWORD),
        ("ValidLifetime", _DWORD),
        ("PreferredLifetime", _DWORD),
        ("LeaseLifetime", _DWORD),
        ("OnLinkPrefixLength", _BYTE),
    ]


# --------------------------------------------------------------- fixed layouts
# Row layouts are parsed from raw bytes with ``struct`` rather than through
# ctypes arrays: a table row is *4-byte* aligned (see ``_TABLE_ROWS_OFFSET``),
# so slicing bytes is both the simplest and the only layout-independent way.
_TCP4_ROW = struct.Struct("<6I")             # state, local addr/port, remote addr/port, pid
_TCP6_ROW = struct.Struct("<16sII16sIIII")   # local addr, local scope, local port, remote addr, remote scope, remote port, state, pid
_UDP4_ROW = struct.Struct("<3I")             # local addr, local port, pid
_UDP6_ROW = struct.Struct("<16sIII")         # local addr, scope, port, pid
_FORWARD_ROW = struct.Struct("<14I")        # MIB_IPFORWARDROW
_HANDLE_ROW_64 = struct.Struct("<QQQIHHII")  # SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, 40 bytes
_HANDLE_ROW_32 = struct.Struct("<IIIIHHII")  # the same entry in a 32-bit caller, 28 bytes

#: filetime ticks between 1601-01-01 and 1970-01-01, times 10^7.
_FILETIME_EPOCH_DELTA = 116444736000000000

# ------------------------------------------------------------ access reporting
_ACCESS_ERRORS: List[Dict[str, Any]] = []
_MAX_ACCESS_ERRORS = 512


def access_errors() -> List[Dict[str, Any]]:
    """Denied/failed API calls recorded since the last :func:`clear_access_errors`.

    A collector never raises on a denial and never silently drops one: this is
    the audit trail of what the current account was *not* allowed to read, which
    is a fact about the investigation, not noise.  Bounded at 512 entries so a
    long sweep cannot grow memory without limit.
    """
    return list(_ACCESS_ERRORS)


def clear_access_errors() -> None:
    """Forget the recorded denials (call before a collection run)."""
    _ACCESS_ERRORS.clear()


def _report(scope: str, message: str = "", code: int = 0,
            errors: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Record one denied or failed call; never raises.

    The entry always lands in the module-level :func:`access_errors` log — the
    audit trail of "what this account was not allowed to read" — and, when a
    caller passes its own ``errors`` list, in that one as well, so a collector can
    correlate a denial with the row it belongs to.  Returns the entry.
    """
    entry: Dict[str, Any] = {"scope": scope, "error": message or "unavailable",
                             "code": int(code)}
    if len(_ACCESS_ERRORS) < _MAX_ACCESS_ERRORS:
        _ACCESS_ERRORS.append(entry)
    if errors is not None and errors is not _ACCESS_ERRORS:
        if len(errors) < _MAX_ACCESS_ERRORS:
            errors.append(entry)
    return entry


def _last_error() -> Tuple[int, str]:
    """``(winerror, text)`` for the last failed Win32 call.

    ``(0, "")`` off Windows or when ``use_last_error`` is unavailable — the
    reporting path must itself never raise.
    """
    try:
        code = int(ctypes.get_last_error())
    except (AttributeError, TypeError, ValueError):
        return (0, "")
    formatter = getattr(ctypes, "FormatError", None)
    if code and formatter is not None:
        try:
            return (code, formatter(code).strip())
        except (ValueError, OSError, TypeError):
            pass
    return (code, "")


def _fail(scope: str, errors: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Record a failed call together with the Windows error text."""
    code, text = _last_error()
    return _report(scope, text or f"call failed (code {code})", code, errors)


# ------------------------------------------------------------- pure decoders
def _format_ipv4(value: int) -> str:
    """Dotted quad for a MIB address DWORD.

    The MIB tables store IPv4 addresses in *network* order, so once ctypes has
    read the DWORD little-endian the first octet sits in the **low** byte:
    ``0x0100007F`` is ``127.0.0.1``.  Formatting it with
    ``socket.inet_ntoa(struct.pack(">I", value))`` — the other reading, and by
    far the most common bug against this API — silently reverses every address,
    which is why the byte order is pinned here and covered by tests.
    """
    value &= 0xFFFFFFFF
    return "%d.%d.%d.%d" % (value & 0xFF, (value >> 8) & 0xFF,
                            (value >> 16) & 0xFF, (value >> 24) & 0xFF)


def _format_ipv6(raw: bytes) -> str:
    """Text form of a 16-byte ``in6_addr`` (already network order)."""
    try:
        return socket.inet_ntop(socket.AF_INET6, bytes(raw)[:16])
    except (ValueError, OSError):
        return "?"


def _format_port(value: int) -> int:
    """Host-order port for a MIB port DWORD.

    ``dwLocalPort``/``dwRemotePort`` are DWORDs whose low 16 bits hold the port
    in network order, so the value ctypes reads is byte-swapped: the port 8080
    (``0x1F90``) arrives as ``0x901F``.  Mask *and* swap, because the upper
    half is documented as zero but is not trustworthy.
    """
    value &= 0xFFFF
    return ((value & 0xFF) << 8) | ((value >> 8) & 0xFF)


def _format_mac(raw: bytes, length: Optional[int] = None) -> str:
    """``aa:bb:cc:dd:ee:ff`` for an adapter physical address."""
    data = bytes(raw)
    if length is not None:
        data = data[:max(0, min(int(length), len(data)))]
    return ":".join("%02x" % byte for byte in data)


def _format_sid(raw: bytes) -> str:
    """``S-1-5-18`` text for raw SID bytes.

    A SID is revision, sub-authority count, a 48-bit big-endian identifier
    authority and then that many little-endian 4-byte sub-authorities; the mixed
    endianness is why this is not ``hexlify``.  Truncated input yields the
    partial SID rather than an exception — a half-read SID is still evidence.
    """
    data = bytes(raw)
    if len(data) < 8:
        return ""
    revision = data[0]
    count = data[1]
    authority = int.from_bytes(data[2:8], "big")
    head = "0x%X" % authority if authority > 0xFFFFFFFF else str(authority)
    parts = []
    for index in range(count):
        offset = 8 + 4 * index
        if offset + 4 > len(data):
            break
        parts.append("%d" % struct.unpack_from("<I", data, offset)[0])
    return "S-%d-%s%s" % (revision, head, "".join("-%s" % part for part in parts))


def _sid_byte_length(header: bytes) -> int:
    """Total SID length from its two-byte header (revision, sub-authority count)."""
    data = bytes(header)
    if len(data) < 2:
        return 0
    return 8 + 4 * data[1]


def _decode_wchar(raw: bytes) -> str:
    """NUL-terminated UTF-16LE text from an inline wide-char buffer."""
    try:
        text = bytes(raw).decode("utf-16-le", "replace")
    except (UnicodeDecodeError, ValueError):
        return ""
    return text.split("\x00", 1)[0]


def _unicode_string_fields(raw: bytes, pointer_size: int = _POINTER_SIZE) -> Tuple[int, int]:
    """``(length_in_bytes, buffer_pointer)`` of a ``UNICODE_STRING`` at ``raw[0]``.

    Layout is ``USHORT Length; USHORT MaximumLength; PWSTR Buffer;`` padded so
    the pointer is naturally aligned — 8 bytes in on x64, 4 in on x86.  The
    buffer case matters: ``ProcessCommandLineInformation`` returns this header
    with the text behind ``Buffer`` inside the same allocation.
    """
    data = bytes(raw)
    if len(data) < pointer_size + 4:
        return (0, 0)
    length = struct.unpack_from("<H", data, 0)[0]
    offset = 8 if pointer_size == 8 else 4
    if len(data) < offset + pointer_size:
        return (0, 0)
    fmt = "<Q" if pointer_size == 8 else "<I"
    return (length, struct.unpack_from(fmt, data, offset)[0])


def _filetime_to_epoch(value: int) -> float:
    """Epoch seconds for a ``FILETIME`` (100 ns ticks since 1601-01-01)."""
    if value <= 0:
        return 0.0
    return (value - _FILETIME_EPOCH_DELTA) / 1e7


def _tcp_state_name(state: int) -> str:
    """Name for a MIB TCP state code (unknown codes keep their number)."""
    return TCP_STATES.get(int(state), "UNKNOWN(%d)" % int(state))


def _oper_status_name(code: int) -> str:
    """``IF_OPER_STATUS`` as the ``/sys/class/net/*/operstate`` text.

    Linux spells the not-present state ``not-present``; the strings are copied
    from there so a script matching operstate text behaves the same on both.
    """
    return {
        1: "up",
        2: "down",
        3: "testing",
        4: "unknown",
        5: "dormant",
        6: "not-present",
        7: "lowerlayerdown",
    }.get(int(code), "unknown")


def _sockaddr_to_text(raw: bytes) -> Tuple[str, int]:
    """``(address, port)`` for a ``SOCKADDR`` buffer.

    The port sits in the first four bytes in **network** order, which is the same
    class of trap as the MIB port DWORDs, so it is decoded here once instead of
    at each call site.  An unknown family yields ``("", 0)``.
    """
    data = bytes(raw)
    if len(data) < 2:
        return ("", 0)
    family = struct.unpack_from("<H", data, 0)[0]
    if family == _AF_INET and len(data) >= 8:
        return (socket.inet_ntoa(data[4:8]), struct.unpack_from(">H", data, 2)[0])
    if family in (_AF_INET6_WIN, socket.AF_INET6) and len(data) >= 24:
        return (socket.inet_ntop(socket.AF_INET6, data[8:24]),
                struct.unpack_from(">H", data, 2)[0])
    return ("", 0)


def _decode_tcp_rows(raw: bytes, v6: bool = False) -> List[Dict[str, Any]]:
    """Decode a ``MIB_TCPTABLE_OWNER_PID`` / ``MIB_TCP6TABLE_OWNER_PID`` buffer.

    The buffer starts with a DWORD row count and the rows follow immediately at
    offset 4: the tables are 4-byte aligned, *not* pointer aligned, so starting
    the rows at ``sizeof(void*)`` is the second classic bug in this API.  Emits
    the Linux ``/proc/net/tcp`` key set; ``uid``/``inode`` have no Windows
    equivalent and stay ``None``/``0`` so a reader's ``.get`` calls behave.
    """
    rows: List[Dict[str, Any]] = []
    if len(raw) < _TABLE_ROWS_OFFSET:
        return rows
    layout = _TCP6_ROW if v6 else _TCP4_ROW
    count = struct.unpack_from("<I", raw, 0)[0]
    offset = _TABLE_ROWS_OFFSET
    for _ in range(count):
        if offset + layout.size > len(raw):
            break
        fields = layout.unpack_from(raw, offset)
        offset += layout.size
        if v6:
            local_addr, local_port = _format_ipv6(fields[0]), fields[2]
            remote_addr, remote_port = _format_ipv6(fields[3]), fields[5]
            state, pid = fields[6], fields[7]
        else:
            state, local_addr, local_port = fields[0], _format_ipv4(fields[1]), fields[2]
            remote_addr, remote_port, pid = _format_ipv4(fields[3]), fields[4], fields[5]
        rows.append({
            "proto": "tcp6" if v6 else "tcp",
            "local_addr": local_addr,
            "local_port": _format_port(local_port),
            "remote_addr": remote_addr,
            "remote_port": _format_port(remote_port),
            "state": _tcp_state_name(state),
            "pid": int(pid),
            "uid": None,
            "inode": 0,
            "listening": int(state) == _MIB_TCP_STATE_LISTEN,
        })
    return rows


def _decode_udp_rows(raw: bytes, v6: bool = False) -> List[Dict[str, Any]]:
    """Decode a ``MIB_UDPTABLE_OWNER_PID`` / ``MIB_UDP6TABLE_OWNER_PID`` buffer.

    UDP rows carry no state and no peer, so ``state`` is ``"-"`` and
    ``listening`` is ``False`` — exactly what the Linux table parser emits for
    UDP, which keeps ``net.listeners()`` meaning the same thing on both hosts.
    """
    rows: List[Dict[str, Any]] = []
    if len(raw) < _TABLE_ROWS_OFFSET:
        return rows
    layout = _UDP6_ROW if v6 else _UDP4_ROW
    count = struct.unpack_from("<I", raw, 0)[0]
    offset = _TABLE_ROWS_OFFSET
    for _ in range(count):
        if offset + layout.size > len(raw):
            break
        fields = layout.unpack_from(raw, offset)
        offset += layout.size
        if v6:
            local_addr, local_port, pid = _format_ipv6(fields[0]), fields[2], fields[3]
            wildcard = "::"
        else:
            local_addr, local_port, pid = _format_ipv4(fields[0]), fields[1], fields[2]
            wildcard = "0.0.0.0"
        rows.append({
            "proto": "udp6" if v6 else "udp",
            "local_addr": local_addr,
            "local_port": _format_port(local_port),
            "remote_addr": wildcard,
            "remote_port": 0,
            "state": "-",
            "pid": int(pid),
            "uid": None,
            "inode": 0,
            "listening": False,
        })
    return rows


def _decode_forward_rows(raw: bytes) -> List[Dict[str, Any]]:
    """Decode a ``MIB_IPFORWARDTABLE`` buffer into the Linux ``/proc/net/route`` shape.

    ``iface`` holds the interface *index* as text until :func:`routes` resolves
    it against the adapter list, because the number is what the table actually
    carries.  ``up`` is derived from ``dwForwardType``: Windows has no per-route
    RTF_UP flag, but a route of type ``MIB_IPROUTE_TYPE_INVALID`` is explicitly
    "present and not used", which is the same signal.
    """
    rows: List[Dict[str, Any]] = []
    if len(raw) < _TABLE_ROWS_OFFSET:
        return rows
    count = struct.unpack_from("<I", raw, 0)[0]
    offset = _TABLE_ROWS_OFFSET
    for _ in range(count):
        if offset + _FORWARD_ROW.size > len(raw):
            break
        fields = _FORWARD_ROW.unpack_from(raw, offset)
        offset += _FORWARD_ROW.size
        destination = _format_ipv4(fields[0])
        mask = _format_ipv4(fields[1])
        rows.append({
            "iface": str(fields[4]),
            "destination": destination,
            "gateway": _format_ipv4(fields[3]),
            "mask": mask,
            "metric": int(fields[9]),
            "default": destination == "0.0.0.0" and mask == "0.0.0.0",
            "up": int(fields[5]) != _MIB_IPROUTE_TYPE_INVALID,
            "if_index": int(fields[4]),
            "type": int(fields[5]),
            "proto": int(fields[6]),
        })
    return rows


def _decode_handle_table(raw: bytes, pid: int,
                         pointer_size: int = _POINTER_SIZE) -> List[Dict[str, Any]]:
    """Decode ``SystemExtendedHandleInformation`` and keep one process's handles.

    The header is two ``ULONG_PTR`` fields (count, reserved) and the entries are
    fixed-size: object, owner pid, handle value, granted access, backtrace index,
    object type index, attributes, reserved.  Only ``pid``'s rows are returned;
    a scanner sweeping every process decodes the buffer once per pid, so callers
    that need all of them should decode once with ``pid=-1`` and group.
    """
    layout = _HANDLE_ROW_64 if pointer_size == 8 else _HANDLE_ROW_32
    header = 2 * pointer_size
    if len(raw) < header:
        return []
    count = int.from_bytes(raw[:pointer_size], "little")
    rows: List[Dict[str, Any]] = []
    offset = header
    for _ in range(count):
        if offset + layout.size > len(raw):
            break
        obj, owner, handle, access, backtrace, type_index, attributes, _res = \
            layout.unpack_from(raw, offset)
        offset += layout.size
        if pid >= 0 and owner != pid:
            continue
        rows.append({
            "pid": int(owner),
            "handle": int(handle),
            "type_index": int(type_index),
            "granted_access": int(access),
            "attributes": int(attributes),
            "object": int(obj),
            "backtrace_index": int(backtrace),
        })
    return rows


def _normalise_driver_path(path: Optional[str],
                          system_root: Optional[str] = None) -> Optional[str]:
    """Turn an NT driver path into a DOS path when that is possible.

    ``EnumDeviceDrivers`` names come back in two shapes —
    ``\\??\\C:\\Windows\\system32\\drivers\\x.sys`` and
    ``\\SystemRoot\\system32\\drivers\\x.sys`` — and neither can be handed to
    ``os.path.exists``.  Device paths (``\\Device\\HarddiskVolume3\\...``) have
    no user-mode name at all; those return ``None`` rather than a wrong path.
    """
    if not path:
        return None
    text = path
    if text.startswith("\\\\?\\"):
        text = text[4:]
    elif text.startswith("\\??\\"):
        text = text[4:]
    elif text.startswith("\\Device\\"):
        return None
    if text.lower().startswith("\\systemroot\\"):
        root = system_root or os.environ.get("SystemRoot") or os.environ.get("windir")
        if not root:
            return None
        text = root.rstrip("\\") + text[len("\\systemroot"):]
    if text.lower().startswith("\\windows\\"):
        root = system_root or os.environ.get("SystemRoot") or os.environ.get("windir")
        if not root:
            return None
        text = root.rstrip("\\") + text
    return text or None


def _local_path_exists(path: Optional[str]) -> Optional[bool]:
    """``True``/``False`` when the path can safely be stat'ed, else ``None``.

    Only drive-letter paths are stat'ed.  A UNC path would put an SMB round trip
    inside a forensic sweep (a multi-second stall on a dead share, and a network
    connection attributable to the analyst), and ``None`` means "not
    determined", which is different from "missing".
    """
    if not path or len(path) < 3 or path[1] != ":" or path[0] == "\\":
        return None
    try:
        return os.path.exists(path)
    except OSError:
        return None


# --------------------------------------------------------------- DLL plumbing
_DLL_NAMES = ("kernel32", "ntdll", "advapi32", "iphlpapi", "psapi")
_LIBS: Optional[Dict[str, Any]] = None
_LIB_FAILURE = False


def _proto(func: Any, restype: Any, *argtypes: Any) -> Any:
    """Declare a function prototype.

    Without this the default ``c_int`` return would truncate every HANDLE and
    kernel address on x64 — handles are pointers, and a truncated handle is a
    silent wrong answer, not an error.
    """
    func.restype = restype
    func.argtypes = list(argtypes)
    return func


def _bind(libs: Dict[str, Any]) -> None:
    """Declare every prototype this module uses.  Called once, on Windows."""
    k32 = libs["kernel32"]
    _proto(k32.CreateToolhelp32Snapshot, _HANDLE, _DWORD, _DWORD)
    _proto(k32.Process32FirstW, _BOOL, _HANDLE, ctypes.c_void_p)
    _proto(k32.Process32NextW, _BOOL, _HANDLE, ctypes.c_void_p)
    _proto(k32.CloseHandle, _BOOL, _HANDLE)
    _proto(k32.OpenProcess, _HANDLE, _DWORD, _BOOL, _DWORD)
    _proto(k32.QueryFullProcessImageNameW, _BOOL, _HANDLE, _DWORD, ctypes.c_void_p,
           ctypes.c_void_p)
    _proto(k32.GetProcessTimes, _BOOL, _HANDLE, ctypes.c_void_p, ctypes.c_void_p,
           ctypes.c_void_p, ctypes.c_void_p)
    _proto(k32.GetProcessHandleCount, _BOOL, _HANDLE, ctypes.c_void_p)
    _proto(k32.GetTickCount64, _ULONGLONG)
    memory_info = getattr(k32, "K32GetProcessMemoryInfo", None)
    if memory_info is None:  # pre-Vista layout, kept as a fallback
        memory_info = libs["psapi"].GetProcessMemoryInfo
    _proto(memory_info, _BOOL, _HANDLE, ctypes.c_void_p, _DWORD)

    adv = libs["advapi32"]
    _proto(adv.OpenProcessToken, _BOOL, _HANDLE, _DWORD, ctypes.c_void_p)
    _proto(adv.GetTokenInformation, _BOOL, _HANDLE, _DWORD, ctypes.c_void_p, _DWORD,
           ctypes.c_void_p)

    ntdll = libs["ntdll"]
    _proto(ntdll.NtQueryInformationProcess, _DWORD, _HANDLE, _DWORD, ctypes.c_void_p,
           _DWORD, ctypes.c_void_p)
    _proto(ntdll.NtQuerySystemInformation, _DWORD, _DWORD, ctypes.c_void_p, _DWORD,
           ctypes.c_void_p)

    iph = libs["iphlpapi"]
    _proto(iph.GetExtendedTcpTable, _DWORD, ctypes.c_void_p, ctypes.c_void_p, _BOOL,
           _DWORD, _DWORD, _DWORD)
    _proto(iph.GetExtendedUdpTable, _DWORD, ctypes.c_void_p, ctypes.c_void_p, _BOOL,
           _DWORD, _DWORD, _DWORD)
    _proto(iph.GetAdaptersAddresses, _DWORD, _DWORD, _DWORD, ctypes.c_void_p,
           ctypes.c_void_p, ctypes.c_void_p)
    _proto(iph.GetIpForwardTable, _DWORD, ctypes.c_void_p, ctypes.c_void_p, _BOOL)
    _proto(iph.GetIfEntry, _DWORD, ctypes.c_void_p)

    psapi = libs["psapi"]
    _proto(psapi.EnumDeviceDrivers, _BOOL, ctypes.c_void_p, _DWORD, ctypes.c_void_p)
    _proto(psapi.GetDeviceDriverBaseNameW, _DWORD, ctypes.c_void_p, ctypes.c_void_p, _DWORD)
    _proto(psapi.GetDeviceDriverFileNameW, _DWORD, ctypes.c_void_p, ctypes.c_void_p, _DWORD)
    _proto(psapi.EnumProcessModulesEx, _BOOL, _HANDLE, ctypes.c_void_p, _DWORD,
           ctypes.c_void_p, _DWORD)
    _proto(psapi.GetModuleBaseNameW, _DWORD, _HANDLE, _HANDLE, ctypes.c_void_p, _DWORD)
    _proto(psapi.GetModuleFileNameExW, _DWORD, _HANDLE, _HANDLE, ctypes.c_void_p, _DWORD)


def _dlls() -> Optional[Dict[str, Any]]:
    """The Windows DLLs this module calls, or ``None`` when unusable.

    Loading is deferred to the first real call and cached (including failure), so
    importing this module on Linux — or on a Windows host where the DLLs are
    missing — costs nothing and touches no Windows-only attribute of ``ctypes``.
    """
    global _LIBS, _LIB_FAILURE
    if not _IS_WINDOWS or _LIB_FAILURE:
        return None
    if _LIBS is not None:
        return _LIBS
    win_dll = getattr(ctypes, "WinDLL", None)
    if win_dll is None:
        _LIB_FAILURE = True
        return None
    loaded: Dict[str, Any] = {}
    for name in _DLL_NAMES:
        try:
            loaded[name] = win_dll(name, use_last_error=True)
        except OSError as exc:
            _report("WinDLL(%s)" % name, str(exc))
            _LIB_FAILURE = True
            return None
    _bind(loaded)
    _LIBS = loaded
    return _LIBS


def available() -> bool:
    """True only on Windows, and only when every DLL this module needs loads."""
    return _dlls() is not None


def _wide(pointer: Any) -> str:
    """Text of a NUL-terminated UTF-16 string behind a native pointer.

    Used only against pointers the OS handed us inside a buffer we control
    (adapter names, driver paths); the read stops at the NUL terminator the API
    guarantees.
    """
    if not pointer:
        return ""
    try:
        return ctypes.wstring_at(pointer)
    except (ValueError, OSError, TypeError):
        return ""


def _filetime_value(low: int, high: int) -> int:
    """Combine the two ``FILETIME`` DWORDs into one 64-bit tick count."""
    return ((int(high) & 0xFFFFFFFF) << 32) | (int(low) & 0xFFFFFFFF)


def _ticks_ms() -> int:
    """Milliseconds since boot, or 0 when the call is unavailable."""
    libs = _dlls()
    if libs is None:
        return 0
    try:
        return int(libs["kernel32"].GetTickCount64())
    except (OSError, ValueError):
        return 0


def uptime_seconds() -> float:
    """Seconds since boot on Windows (0.0 elsewhere)."""
    return _ticks_ms() / 1000.0


def boot_time() -> float:
    """Approximate epoch seconds of the last boot (``GetTickCount64``).

    Approximate by construction: it subtracts an uptime from the current clock,
    so a clock set (or a sleep/hibernate gap) after startup shifts it.  Process
    start times come from ``GetProcessTimes`` and are exact, so timelines should
    anchor on those; this value is only for "how long has this host been up".
    """
    if not _IS_WINDOWS:
        return 0.0
    return time.time() - uptime_seconds()


# ------------------------------------------------------------ process handles
def _open_process(pid: int, errors: Optional[List[Dict[str, Any]]] = None) -> Optional[int]:
    """Open ``pid`` with query-only rights, or ``None`` (denial reported).

    ``PROCESS_QUERY_LIMITED_INFORMATION`` is the weakest right that still allows
    the image path, token and command line; ``PROCESS_QUERY_INFORMATION`` is
    tried only as a fallback for pre-Vista hosts.  Anything stronger would make
    the collector look like an attacker to the very EDR it is meant to feed.
    """
    libs = _dlls()
    if libs is None:
        return None
    k32 = libs["kernel32"]
    for access in (_PROCESS_QUERY_LIMITED_INFORMATION, _PROCESS_QUERY_INFORMATION):
        handle = k32.OpenProcess(access, False, int(pid))
        if handle:
            return int(handle)
    code, text = _last_error()
    _report("OpenProcess(pid=%d)" % pid, text or "access denied", code, errors)
    return None


def _close(handle: Optional[int]) -> None:
    """Close a handle if one was opened; never raises."""
    if not handle:
        return
    libs = _LIBS
    if libs is None:
        return
    try:
        libs["kernel32"].CloseHandle(_HANDLE(handle))
    except (OSError, ValueError):
        pass


def _snapshot_processes() -> List[Dict[str, Any]]:
    """Toolhelp process snapshot: ``pid``/``ppid``/``name``/``threads``.

    The snapshot is the one call that sees every process without opening any of
    them, including protected ones, which is why ``name`` and ``threads`` survive
    even when the richer per-process enrichment below is denied.
    """
    libs = _dlls()
    if libs is None:
        return []
    k32 = libs["kernel32"]
    snapshot = k32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot or int(snapshot) == _INVALID_HANDLE:
        _fail("CreateToolhelp32Snapshot")
        return []
    entry = _PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
    rows: List[Dict[str, Any]] = []
    try:
        ok = k32.Process32FirstW(_HANDLE(snapshot), ctypes.byref(entry))
        while ok:
            rows.append({
                "pid": int(entry.th32ProcessID),
                "ppid": int(entry.th32ParentProcessID),
                "threads": int(entry.cntThreads),
                "name": _wide(ctypes.addressof(entry) + _PROCESSENTRY32W.szExeFile.offset),
            })
            ok = k32.Process32NextW(_HANDLE(snapshot), ctypes.byref(entry))
    finally:
        _close(int(snapshot))
    return rows


def _process_names() -> Dict[int, str]:
    """``pid -> image name`` from one snapshot (used to name socket owners)."""
    return {row["pid"]: row["name"] for row in _snapshot_processes()}


def list_pids() -> List[int]:
    """All process IDs visible to this account, ascending."""
    return sorted(row["pid"] for row in _snapshot_processes())


def _query_image_path(handle: int, errors: Optional[List[Dict[str, Any]]] = None) -> Optional[str]:
    """Full DOS image path of an open process, or ``None``.

    ``QueryFullProcessImageNameW`` returns an NT path (``\\Device\\...``) unless
    ``dwFlags`` is 0, which is what asks for the Win32 path an analyst can act on.
    """
    libs = _LIBS
    if libs is None:
        return None
    buffer = ctypes.create_unicode_buffer(_MAX_PATH * 2)
    size = _DWORD(len(buffer))
    try:
        ok = libs["kernel32"].QueryFullProcessImageNameW(
            _HANDLE(handle), 0, buffer, ctypes.byref(size))
    except (OSError, ValueError):
        ok = False
    if not ok:
        code, text = _last_error()
        _report("QueryFullProcessImageNameW", text or "image path unavailable", code,
                errors)
        return None
    return buffer.value or None


def _query_sid(handle: int, errors: Optional[List[Dict[str, Any]]] = None) -> Optional[str]:
    """SID string of the process token (the Windows stand-in for ``uid``).

    ``TOKEN_USER``'s ``Sid`` member is a *pointer* into the same buffer, so the
    SID length is read from its own header and the bytes are fetched through that
    pointer — reading the structure as a fixed-size blob would silently truncate
    on a long domain SID.
    """
    libs = _LIBS
    if libs is None:
        return None
    adv = libs["advapi32"]
    token = _HANDLE()
    if not adv.OpenProcessToken(_HANDLE(handle), _TOKEN_QUERY, ctypes.byref(token)):
        code, text = _last_error()
        _report("OpenProcessToken", text or "access denied", code, errors)
        return None
    try:
        needed = _DWORD(0)
        adv.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(needed))
        if not needed.value:
            _fail("GetTokenInformation(size)", errors)
            return None
        buffer = ctypes.create_string_buffer(needed.value)
        if not adv.GetTokenInformation(token, _TOKEN_USER, buffer, needed.value,
                                       ctypes.byref(needed)):
            _fail("GetTokenInformation", errors)
            return None
        sid_pointer = ctypes.c_void_p.from_buffer(buffer).value
        if not sid_pointer:
            _report("GetTokenInformation", "token has no user SID", 0, errors)
            return None
        length = _sid_byte_length(ctypes.string_at(sid_pointer, 2))
        return _format_sid(ctypes.string_at(sid_pointer, length))
    finally:
        _close(int(token.value) if token.value else None)


def read_sid(pid: int) -> Optional[str]:
    """SID text of ``pid``'s token, or ``None`` when it cannot be read.

    A bare ``None`` is the contract (matching ``procfs.read_exe``); the reason a
    SID is missing — protected process, another session, insufficient rights —
    is in :func:`access_errors`.
    """
    handle = _open_process(pid)
    if handle is None:
        return None
    try:
        return _query_sid(handle)
    finally:
        _close(handle)


def read_exe(pid: int) -> Optional[str]:
    """Image path of ``pid``, or ``None`` when the account may not read it."""
    handle = _open_process(pid)
    if handle is None:
        return None
    try:
        return _query_image_path(handle)
    finally:
        _close(handle)


def read_cmdline(pid: int) -> List[str]:
    """Argv-like list for ``pid`` from ``ProcessCommandLineInformation`` (class 60).

    Windows keeps **one** command-line string (in the PEB), not an argv vector —
    the process itself does the splitting — so whitespace splitting is the best
    reconstruction available and quoted arguments containing spaces collapse.
    The shape is still a list, because that is what ``proc.cmdline()`` returns on
    Linux and a script must not branch on the host.

    ``NtQueryInformationProcess`` needs ``PROCESS_QUERY_LIMITED_INFORMATION``;
    a 32-bit interpreter reading a 64-bit target, a protected process, or a
    pid that exited between reads yields ``[]`` with the reason recorded in
    :func:`access_errors`.
    """
    libs = _dlls()
    if libs is None:
        return []
    handle = _open_process(pid)
    if handle is None:
        return []
    try:
        return _read_cmdline_handle(handle)
    finally:
        _close(handle)


def _query_times(handle: int, errors: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Creation time and CPU time of an open process.

    ``GetProcessTimes`` reports 100 ns FILETIME ticks, so the two "ticks" fields
    the Linux collector exposes are reported here as seconds under their own
    names: the unit is part of the value and pretending they are ``CLK_TCK``
    ticks would silently mis-scale every CPU figure a script computes.
    """
    libs = _LIBS
    if libs is None:
        return {}
    creation, exit_time = _FILETIME(), _FILETIME()
    kernel_time, user_time = _FILETIME(), _FILETIME()
    ok = libs["kernel32"].GetProcessTimes(
        _HANDLE(handle), ctypes.byref(creation), ctypes.byref(exit_time),
        ctypes.byref(kernel_time), ctypes.byref(user_time))
    if not ok:
        _fail("GetProcessTimes", errors)
        return {}
    return {
        "start_epoch": round(_filetime_to_epoch(_filetime_value(
            creation.dwLowDateTime, creation.dwHighDateTime)), 3),
        "utime_seconds": _filetime_value(user_time.dwLowDateTime,
                                        user_time.dwHighDateTime) / 1e7,
        "stime_seconds": _filetime_value(kernel_time.dwLowDateTime,
                                        kernel_time.dwHighDateTime) / 1e7,
    }


def _query_memory(handle: int, errors: Optional[List[Dict[str, Any]]] = None) -> Dict[str, int]:
    """Working set and commit size in KB (empty when the query is denied)."""
    libs = _LIBS
    if libs is None:
        return {}
    counters = _PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS)
    function = getattr(libs["kernel32"], "K32GetProcessMemoryInfo", None) or \
        libs["psapi"].GetProcessMemoryInfo
    if not function(_HANDLE(handle), ctypes.byref(counters), counters.cb):
        _fail("GetProcessMemoryInfo", errors)
        return {}
    return {
        "vmrss_kb": int(counters.WorkingSetSize) // 1024,
        "vmsize_kb": int(counters.PagefileUsage) // 1024,
    }


def read_handles(pid: int, errors: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Open handles of ``pid`` from ``SystemExtendedHandleInformation``.

    Handles are the Windows counterpart of ``/proc/<pid>/fd``: a handle to a file
    that is gone from disk, or to a rarely-abused object type, is the kind of
    thing a triage is looking for.  ``type_index`` is the per-boot object-type
    index — resolving it to a *name* means a ``NtQueryObject`` per handle, which
    deadlocks on synchronous named pipes and is a well-known way to hang a
    forensic tool; the index is therefore reported raw.

    ``Object`` is whatever the kernel returned (it is randomised for
    unprivileged callers), kept because a stable value still correlates two rows.
    """
    libs = _dlls()
    if libs is None:
        return []
    ntdll = libs["ntdll"]
    size = _DWORD(0)
    status = ntdll.NtQuerySystemInformation(
        _SYSTEM_EXTENDED_HANDLE_INFORMATION, None, 0, ctypes.byref(size))
    if status not in (_STATUS_INFO_LENGTH_MISMATCH, _STATUS_BUFFER_TOO_SMALL) or not size.value:
        _report("NtQuerySystemInformation(Handles)",
                "size probe failed (status 0x%08X)" % status, 0, errors)
        return []
    buffer = ctypes.create_string_buffer(size.value * 2)
    status = ntdll.NtQuerySystemInformation(
        _SYSTEM_EXTENDED_HANDLE_INFORMATION, buffer, len(buffer), ctypes.byref(size))
    if status != _STATUS_SUCCESS:
        _report("NtQuerySystemInformation(Handles)",
                "status 0x%08X" % status, 0, errors)
        return []
    return _decode_handle_table(buffer.raw, int(pid), _POINTER_SIZE)


def read_modules(pid: int, errors: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Loaded images of ``pid`` (the Windows counterpart of ``/proc/<pid>/maps``).

    ``LIST_MODULES_ALL`` includes both the 32-bit and 64-bit module lists, so a
    WOW64 process does not look half-empty.  Enumeration of a process of the
    other bitness can be refused by Windows; that refusal is reported, not raised.
    """
    libs = _dlls()
    if libs is None:
        return []
    handle = _open_process(pid, errors)
    if handle is None:
        return []
    psapi = libs["psapi"]
    try:
        needed = _DWORD(0)
        if not psapi.EnumProcessModulesEx(_HANDLE(handle), None, 0,
                                          ctypes.byref(needed), _LIST_MODULES_ALL) \
                and not needed.value:
            _fail("EnumProcessModulesEx(size)", errors)
            return []
        count = needed.value // _POINTER_SIZE
        bases = (_HANDLE * count)()
        if not psapi.EnumProcessModulesEx(_HANDLE(handle), bases, needed.value,
                                          ctypes.byref(needed), _LIST_MODULES_ALL):
            _fail("EnumProcessModulesEx", errors)
            return []
        rows: List[Dict[str, Any]] = []
        name_buffer = ctypes.create_unicode_buffer(_MAX_PATH)
        for base in bases:
            base_handle = _HANDLE(base)
            psapi.GetModuleBaseNameW(_HANDLE(handle), base_handle, name_buffer,
                                     len(name_buffer))
            path_buffer = ctypes.create_unicode_buffer(_MAX_PATH * 2)
            psapi.GetModuleFileNameExW(_HANDLE(handle), base_handle, path_buffer,
                                       len(path_buffer))
            rows.append({
                "name": name_buffer.value,
                "path": path_buffer.value,
                "base": int(base or 0),
            })
        return rows
    finally:
        _close(handle)


def _process_entry(base: Dict[str, Any], with_fds: bool, with_maps: bool,
                   errors: List[Dict[str, Any]]) -> Dict[str, Any]:
    """One process row: the Toolhelp facts plus every allowed enrichment.

    The row carries the same keys as ``procfs.info``.  Where Windows has no
    equivalent the key is still present so a script's ``row["gid"]`` does not
    raise: ``gid``, ``cwd`` (needs undocumented PEB traversal), ``state`` (the
    snapshot has no scheduler state), the container/cgroup fields and
    ``memfd_exe`` are empty, and ``is_container`` is ``False`` meaning "not
    determined here", not "verified absent".
    """
    pid = int(base["pid"])
    denied = False
    entry: Dict[str, Any] = {
        "pid": pid,
        "ppid": int(base["ppid"]),
        "name": base["name"],
        "exe": None,
        "cwd": None,
        "cmdline": "",
        "argv": [],
        "uid": None,
        "gid": None,
        "threads": int(base["threads"]),
        "session": None,
        "state": None,
        "start_epoch": None,
        "utime_seconds": None,
        "stime_seconds": None,
        "vmrss_kb": None,
        "vmsize_kb": None,
        "handle_count": None,
        "memfd_exe": False,
        "nspid": [],
        "cgroup": "",
        "capeff": "",
        "is_container": False,
        "deleted_exe": False,
        "suspicious_path": False,
        "file_exists": None,
    }
    handle = _open_process(pid, errors)
    if handle is None:
        denied = True
    else:
        try:
            exe = _query_image_path(handle, errors)
            entry["exe"] = exe
            if exe is None:
                denied = True
            entry["uid"] = _query_sid(handle, errors)
            if entry["uid"] is None:
                denied = True
            argv = _read_cmdline_handle(handle, errors)
            entry["argv"] = argv
            entry["cmdline"] = " ".join(argv)
            entry.update(_query_times(handle, errors))
            entry.update(_query_memory(handle, errors))
            count = _DWORD(0)
            if _LIBS is not None and _LIBS["kernel32"].GetProcessHandleCount(
                    _HANDLE(handle), ctypes.byref(count)):
                entry["handle_count"] = int(count.value)
            else:
                denied = True
        finally:
            _close(handle)
        exe = entry["exe"] or ""
        exists = _local_path_exists(exe) if exe else None
        entry["file_exists"] = exists
        entry["deleted_exe"] = exists is False
        entry["suspicious_path"] = any(marker in exe.lower() for marker in _SUSPICIOUS_DIRS)
        if with_fds:
            entry["handles"] = read_handles(pid, errors)
        if with_maps:
            entry["modules"] = read_modules(pid, errors)
    entry["access_denied"] = denied
    return entry


def _read_cmdline_handle(handle: int,
                         errors: Optional[List[Dict[str, Any]]] = None) -> List[str]:
    """Command line of an already-open process handle (see :func:`read_cmdline`)."""
    libs = _LIBS
    if libs is None:
        return []
    ntdll = libs["ntdll"]
    size = _DWORD(0)
    status = ntdll.NtQueryInformationProcess(
        _HANDLE(handle), _PROCESS_COMMAND_LINE_INFORMATION, None, 0, ctypes.byref(size))
    if status not in (_STATUS_INFO_LENGTH_MISMATCH, _STATUS_BUFFER_TOO_SMALL,
                      _STATUS_SUCCESS) or not size.value:
        _report("NtQueryInformationProcess(CommandLine)",
                "no command line (status 0x%08X)" % status, 0, errors)
        return []
    buffer = ctypes.create_string_buffer(size.value * 2)
    status = ntdll.NtQueryInformationProcess(
        _HANDLE(handle), _PROCESS_COMMAND_LINE_INFORMATION, buffer, len(buffer),
        ctypes.byref(size))
    if status != _STATUS_SUCCESS:
        _report("NtQueryInformationProcess(CommandLine)",
                "status 0x%08X" % status, 0, errors)
        return []
    length, pointer = _unicode_string_fields(buffer.raw, _POINTER_SIZE)
    if not pointer or length <= 0:
        return []
    return ctypes.string_at(pointer, length).decode("utf-16-le", "replace").split()


def list_processes(limit: Optional[int] = None, with_fds: bool = False,
                   with_maps: bool = False, **kw: Any) -> List[Dict[str, Any]]:
    """Aggregate every visible process; the Windows ``proc.list()``.

    ``detail_limit`` (Linux name) is honoured: it bounds ``with_fds``/``with_maps``
    to the first N processes so deep reads stay cheap on a host with thousands of
    processes.  Keyword arguments the Linux collector accepts but Windows has no
    equivalent for (``with_environ``, ``with_io``) are accepted and ignored so a
    cross-platform script does not have to branch.

    Denied enrichment never raises and never disappears: the row is flagged
    ``access_denied`` and the reason is in :func:`access_errors`.
    """
    detail_limit = kw.pop("detail_limit", None)
    errors: List[Dict[str, Any]] = []
    out: List[Dict[str, Any]] = []
    for index, base in enumerate(_snapshot_processes()):
        detailed = detail_limit is None or index < detail_limit
        out.append(_process_entry(base, with_fds and detailed,
                                  with_maps and detailed, errors))
        if limit is not None and len(out) >= limit:
            break
    return out


# ------------------------------------------------------------------- network
def _table_buffer(getter: Any, table_class: int, family: int,
                  errors: Optional[List[Dict[str, Any]]] = None,
                  scope: str = "GetExtendedTable") -> Optional[bytes]:
    """Two-call size probe + fetch of an iphlpapi MIB table.

    The first call is *expected* to fail with ``ERROR_INSUFFICIENT_BUFFER``; a
    different error code is a real failure (denied rights, or an unbound
    AF_INET6 stack) and is reported instead of being mistaken for an empty table.
    """
    size = _DWORD(0)
    code = getter(None, ctypes.byref(size), True, family, table_class, 0)
    if code == _NO_ERROR and size.value == 0:
        return b""  # genuinely empty table (no sockets of that family)
    if code != _ERROR_INSUFFICIENT_BUFFER or not size.value:
        _report(scope, "table size query failed (code %d)" % code, int(code), errors)
        return None
    buffer = ctypes.create_string_buffer(size.value)
    code = getter(buffer, ctypes.byref(size), True, family, table_class, 0)
    if code != _NO_ERROR:
        _report(scope, "table read failed (code %d)" % code, int(code), errors)
        return None
    return buffer.raw[:size.value]


def connections(include_unix: bool = False, with_process: bool = True,
                proto_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Every TCP/UDP socket in the kernel tables, optionally owned by a process.

    Same rows as ``/proc/net/tcp{,6}``/``udp{,6}``: ``proto``, ``local_addr``,
    ``local_port``, ``remote_addr``, ``remote_port``, ``state``, ``pid``,
    ``listening`` (plus ``uid``/``inode`` as ``None``/``0``, which Windows does
    not expose per socket).  ``GetExtendedTcpTable`` with
    ``TCP_TABLE_OWNER_PID_ALL`` attributes the owner in the kernel, so unlike the
    Linux side there is no inode sweep, and the pid is always present.

    ``include_unix`` is accepted for contract compatibility and contributes
    nothing: iphlpapi has no table for AF_UNIX sockets (Windows has them since
    10/1803, they simply are not enumerable here).  It is ignored rather than
    approximated, so an empty result means "not observable", never "none exist".
    """
    libs = _dlls()
    if libs is None:
        return []
    iph = libs["iphlpapi"]
    sources = (
        ("tcp", False, iph.GetExtendedTcpTable, _TCP_TABLE_OWNER_PID_ALL),
        ("tcp6", True, iph.GetExtendedTcpTable, _TCP_TABLE_OWNER_PID_ALL),
        ("udp", False, iph.GetExtendedUdpTable, _UDP_TABLE_OWNER_PID),
        ("udp6", True, iph.GetExtendedUdpTable, _UDP_TABLE_OWNER_PID),
    )
    rows: List[Dict[str, Any]] = []
    for proto, v6, getter, table_class in sources:
        if proto_filter and proto not in proto_filter:
            continue
        raw = _table_buffer(getter, table_class, _AF_INET6_WIN if v6 else _AF_INET,
                            scope="GetExtended%sTable(%s)" % (
                                "Udp" if proto.startswith("udp") else "Tcp", proto))
        if raw is None:
            continue
        if proto.startswith("udp"):
            rows.extend(_decode_udp_rows(raw, v6))
        else:
            rows.extend(_decode_tcp_rows(raw, v6))
    if with_process:
        names = _process_names()
        for row in rows:
            row["process"] = names.get(row.get("pid"))
    return rows


def listeners(with_process: bool = True) -> List[Dict[str, Any]]:
    """TCP LISTEN sockets (the attack surface of the host)."""
    return [c for c in connections(with_process=with_process) if c.get("listening")]


def established(with_process: bool = True) -> List[Dict[str, Any]]:
    """TCP sockets in the ESTABLISHED state."""
    return [c for c in connections(with_process=with_process)
            if c.get("state") == "ESTABLISHED"]


def connections_by_process() -> Dict[int, List[Dict[str, Any]]]:
    """Sockets grouped by owning pid (ownerless rows are dropped, as on Linux)."""
    grouped: Dict[int, List[Dict[str, Any]]] = {}
    for row in connections():
        pid = row.get("pid")
        if pid is not None:
            grouped.setdefault(pid, []).append(row)
    return grouped


def _enumerate_adapters(errors: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Walk ``GetAdaptersAddresses`` into adapter dicts (no traffic counters).

    Kept separate from :func:`interfaces` so :func:`routes` can resolve interface
    indices without paying for a ``GetIfEntry`` per adapter it does not need.
    """
    libs = _dlls()
    if libs is None:
        return []
    iph = libs["iphlpapi"]
    size = _DWORD(0)
    code = iph.GetAdaptersAddresses(_AF_UNSPEC, _GAA_FLAGS, None, None,
                                    ctypes.byref(size))
    if code == _ERROR_NO_DATA:
        return []
    if code != _ERROR_BUFFER_OVERFLOW or not size.value:
        _report("GetAdaptersAddresses", "size query failed (code %d)" % code,
                int(code), errors)
        return []
    buffer = ctypes.create_string_buffer(size.value)
    code = iph.GetAdaptersAddresses(_AF_UNSPEC, _GAA_FLAGS, None, buffer,
                                    ctypes.byref(size))
    if code == _ERROR_NO_DATA:
        return []
    if code != _NO_ERROR:
        _report("GetAdaptersAddresses", "read failed (code %d)" % code, int(code),
                errors)
        return []
    out: List[Dict[str, Any]] = []
    node = ctypes.cast(buffer, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
    while node:
        raw = node.contents
        out.append({
            "name": _wide(raw.FriendlyName),
            "description": _wide(raw.Description),
            "guid": _wide(raw.AdapterName),
            "index": int(raw.IfIndex),
            "mac": _format_mac(bytes(raw.PhysicalAddress), int(raw.PhysicalAddressLength)),
            "mtu": int(raw.Mtu),
            "state": _oper_status_name(raw.OperStatus),
            "type": str(int(raw.IfType)),
            "addresses": _unicast_addresses(raw.FirstUnicastAddress),
        })
        node = raw.Next
    return out


def _unicast_addresses(head: Any) -> List[Dict[str, Any]]:
    """Addresses from an ``IP_ADAPTER_UNICAST_ADDRESS`` chain."""
    out: List[Dict[str, Any]] = []
    node = ctypes.cast(head, ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)) if head else None
    while node:
        item = node.contents
        if item.Address.lpSockaddr and item.Address.iSockaddrLength > 0:
            address, _port = _sockaddr_to_text(ctypes.string_at(
                item.Address.lpSockaddr, int(item.Address.iSockaddrLength)))
            if address:
                out.append({"address": address,
                            "prefix_length": int(item.OnLinkPrefixLength)})
        node = ctypes.cast(item.Next, ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)) \
            if item.Next else None
    return out


def _interface_counters(index: int,
                        errors: Optional[List[Dict[str, Any]]] = None) -> Dict[str, int]:
    """Traffic counters for one interface index (``GetIfEntry``), or empty.

    ``rx_packets``/``tx_packets`` sum the unicast and non-unicast counters,
    because ``/proc/net/dev``'s packet columns count both.
    """
    libs = _LIBS
    if libs is None:
        return {}
    row = _MIB_IFROW()
    row.dwIndex = _DWORD(int(index))
    if libs["iphlpapi"].GetIfEntry(ctypes.byref(row)) != _NO_ERROR:
        _fail("GetIfEntry(ifIndex=%d)" % index, errors)
        return {}
    return {
        "rx_bytes": int(row.dwInOctets),
        "rx_packets": int(row.dwInUcastPkts) + int(row.dwInNUcastPkts),
        "tx_bytes": int(row.dwOutOctets),
        "tx_packets": int(row.dwOutUcastPkts) + int(row.dwOutNUcastPkts),
    }


def interfaces() -> List[Dict[str, Any]]:
    """Per-interface addresses, MAC and traffic counters.

    Key names match ``/proc/net/dev`` + ``/sys/class/net``: ``name``, ``mac``,
    ``mtu``, ``state``, ``type``, ``rx_bytes``, ``rx_packets``, ``tx_bytes``,
    ``tx_packets``.  Two values are host-specific by nature: ``name`` is the
    adapter's friendly name ("Ethernet") because Windows has no short interface
    name, and ``type`` is the IANA ``IfType`` here versus the kernel's ARPHRD
    value on Linux.  ``addresses`` is an extra, additive key with the IPv4/IPv6
    addresses (the Linux collector reports those separately).
    """
    errors: List[Dict[str, Any]] = []
    out = _enumerate_adapters(errors)
    for entry in out:
        entry.update(_interface_counters(entry["index"], errors))
    return out


def routes() -> List[Dict[str, Any]]:
    """IPv4 routing table with decoded destinations and gateways.

    Same rows as ``/proc/net/route``: ``iface``, ``destination``, ``gateway``,
    ``mask``, ``metric``, ``default``, ``up``.  ``iface`` is resolved from the
    interface *index* the table carries to the adapter's friendly name via
    :func:`_enumerate_adapters` (falling back to the index as text); ``up`` comes
    from ``dwForwardType`` as explained in :func:`_decode_forward_rows`.
    """
    libs = _dlls()
    if libs is None:
        return []
    iph = libs["iphlpapi"]
    size = _DWORD(0)
    code = iph.GetIpForwardTable(None, ctypes.byref(size), True)
    if code != _ERROR_INSUFFICIENT_BUFFER or not size.value:
        _report("GetIpForwardTable", "size query failed (code %d)" % code, int(code))
        return []
    buffer = ctypes.create_string_buffer(size.value)
    code = iph.GetIpForwardTable(buffer, ctypes.byref(size), True)
    if code != _NO_ERROR:
        _report("GetIpForwardTable", "read failed (code %d)" % code, int(code))
        return []
    rows = _decode_forward_rows(buffer.raw[:size.value])
    names = {adapter["index"]: adapter["name"] for adapter in _enumerate_adapters()}
    for row in rows:
        friendly = names.get(row["if_index"])
        if friendly:
            row["iface"] = friendly
    return rows


# ------------------------------------------------------------------- modules
def _driver_name(psapi: Any, base: Any, file_name: bool) -> str:
    """One ``GetDeviceDriver{Base,File}NameW`` call for a driver base address."""
    buffer = ctypes.create_unicode_buffer(_MAX_PATH * 2)
    function = psapi.GetDeviceDriverFileNameW if file_name else psapi.GetDeviceDriverBaseNameW
    try:
        function(_HANDLE(base), buffer, len(buffer))
    except (OSError, ValueError):
        return ""
    return buffer.value


def modules() -> List[Dict[str, Any]]:
    """Loaded **kernel drivers** — the Windows counterpart of ``/proc/modules``.

    ``EnumDeviceDrivers`` reports the load base of every loaded driver without
    needing any privilege beyond what a normal account has, which makes this the
    one module inventory available during a live triage; it is also what the
    BYOVD detector consumes, so the keys mirror
    :func:`jocky.rt.sysinfo.modules`: ``name``, ``size``, ``refcount``,
    ``dependencies``, ``state``, ``address``.

    ``size``, ``refcount``, ``dependencies`` and ``state`` stay ``None``/empty:
    psapi returns only bases, and inventing values would make a BYOVD heuristic
    fire on fiction.  ``address`` is the load base as the same 16-hex-digit text
    the Linux reader emits; ``path``, ``base`` and ``file_exists`` are additive —
    a mapped driver whose file is not on disk is a ghost-driver signal, and
    ``file_exists`` is ``None`` (not ``False``) when the path cannot be resolved
    or stat'ed, e.g. a ``\\Device\\...`` path or a share that must not be touched.
    """
    libs = _dlls()
    if libs is None:
        return []
    psapi = libs["psapi"]
    needed = _DWORD(0)
    if not psapi.EnumDeviceDrivers(None, 0, ctypes.byref(needed)) or not needed.value:
        _fail("EnumDeviceDrivers(size)")
        return []
    count = needed.value // _POINTER_SIZE
    bases = (_HANDLE * count)()
    if not psapi.EnumDeviceDrivers(bases, needed.value, ctypes.byref(needed)):
        _fail("EnumDeviceDrivers")
        return []
    out: List[Dict[str, Any]] = []
    for base in bases:
        path = _driver_name(psapi, base, True)
        out.append({
            "name": _driver_name(psapi, base, False),
            "size": None,
            "refcount": None,
            "dependencies": [],
            "state": None,
            "address": "%016x" % int(base or 0),
            "path": path,
            "base": int(base or 0),
            "file_exists": _local_path_exists(_normalise_driver_path(path)),
        })
    return out
