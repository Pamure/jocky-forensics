"""
Windows collection tests for ``jocky.rt.winapi``.

JOCKY must run from a Linux incident-response stick but still be able to read a
mounted Windows volume; the ``winapi`` collector therefore has to degrade to a
no-op off-platform *without raising*, while its pure byte-formatting helpers
stay exercisable on every platform.  These tests pin exactly those two things:
the platform gate, and the byte-order conversions that are the usual source of
silent, wrong-but-plausible forensic output — a swapped port or a reversed IP
still looks like a valid address, so nothing downstream would notice.
"""
from __future__ import annotations

import pathlib
import struct
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


winapi = pytest.importorskip("jocky.rt.winapi")

# The collectors the runtime contract promises; off-platform each must return
# an empty collection rather than raising.
COLLECTORS = ("list_processes", "connections", "modules", "interfaces", "routes")


def _helper(name: str):
    """Fetch a module-level pure helper, skipping if the sibling named it differently.

    Args:
        name: Contract name of the helper (e.g. ``"_format_ipv4"``).

    Returns:
        The callable, or a skip if this module does not expose that name.
    """
    fn = getattr(winapi, name, None)
    if fn is None:
        pytest.skip(f"jocky.rt.winapi.{name} not present (contract name: {name})")
    return fn


def test_module_imports_on_linux():
    """The module imports on POSIX, with no ``windll`` contact, and self-reports unavailable."""
    assert callable(winapi.available)
    assert winapi.available() is False


@pytest.mark.parametrize("name", COLLECTORS)
def test_collectors_return_empty_offplatform(name):
    """Every collector returns an empty collection on POSIX and never raises.

    A collector that raised here would abort an entire hunt script mid-run, so
    quiet-and-empty is the contract the script language relies on.
    """
    fn = getattr(winapi, name, None)
    assert fn is not None, f"jocky.rt.winapi.{name} missing (contract name: {name})"
    result = fn()
    assert isinstance(result, (list, tuple, dict, set))
    assert len(result) == 0


def test_format_ipv4():
    """Little-endian DWORDs as ctypes reads them render as dotted quads."""
    fn = _helper("_format_ipv4")
    # Windows stores 127.0.0.1 with the first octet in the low byte, so the
    # DWORD is 0x0100007F.  A helper that formats the value big-endian would
    # produce "1.0.0.127" — plausible-looking, entirely wrong.
    assert fn(0x0100007F) == "127.0.0.1"
    assert fn(0x00000000) == "0.0.0.0"
    # 192.168.1.1 -> bytes c0 a8 01 01 -> little-endian DWORD 0x0101A8C0.
    assert fn(0x0101A8C0) == "192.168.1.1"
    # 93.184.216.34 -> bytes 5d b8 d8 22 -> little-endian DWORD 0x22D8B85D.
    assert fn(0x22D8B85D) == "93.184.216.34"


def test_format_port():
    """The low 16 bits of a Windows port DWORD are network order and must be swapped."""
    fn = _helper("_format_port")
    network = struct.pack("!H", 8080)
    assert network == b"\x1f\x90"
    # A little-endian host reading those two bytes as a bare 16-bit integer
    # sees 0x901F; the helper undoes that instead of echoing the raw value.
    as_read_by_host = int.from_bytes(network, "little")
    assert as_read_by_host == 0x901F
    assert fn(as_read_by_host) == 8080
    assert fn(0) == 0
    # And the swap is an involution: feeding the decoded port back returns the
    # original DWORD, so the mapping cannot be an identity copy.
    decoded = fn(0x1F90)
    assert decoded != 0x1F90
    assert fn(decoded) == 0x1F90


# Canonical ``in6_addr`` bytes — what ``inet_ntop`` and the Windows address
# structures hand back (loopback last byte 0x01, not a word-swapped word).
IN6_LOOPBACK = b"\x00" * 15 + b"\x01"
IN6_DOC = b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01"


def test_format_ipv6():
    """A 16-byte canonical loopback renders as ``::1``, and real addresses follow."""
    fn = _helper("_format_ipv6")
    assert fn(IN6_LOOPBACK) == "::1"
    assert fn(IN6_DOC) == "2001:db8::1"
    assert fn(b"\xff" * 16) == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    assert fn(b"\x00" * 16) == "::"


def test_format_sid():
    """Raw SID bytes render as ``S-1-5-18``-style strings.

    Contract name: ``_format_sid(raw: bytes) -> str``.  A SID is a revision
    byte, a sub-authority count, a big-endian 48-bit authority id, then count
    little-endian 32-bit sub-authorities — three different byte orders in one
    short record, so the exact local-system SID is pinned.
    """
    fn = _helper("_format_sid")
    local_system = b"\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00"
    assert fn(local_system) == "S-1-5-18"
    # S-1-5-21-1-2-3: four sub-authorities, big-endian authority id 5.
    domain_sid = b"\x01\x04\x00\x00\x00\x00\x00\x05" + struct.pack("<IIII", 21, 1, 2, 3)
    assert fn(domain_sid) == "S-1-5-21-1-2-3"


def test_token_user_information_class_is_an_integer():
    """``_TOKEN_USER`` is a ``TOKEN_INFORMATION_CLASS`` value, not a struct type.

    Found on a real Windows host: a ``class _TOKEN_USER(ctypes.Structure)``
    shadowed the constant, so ``GetTokenInformation(token, _TOKEN_USER, …)``
    passed a type where a DWORD belongs and raised ``ctypes.ArgumentError``.
    Only processes the account could actually open reached that line, so a small
    ``list_processes(limit=…)`` hid it while ``list_processes()`` — the default
    call a script makes — failed outright. This asserts the name resolves to an
    int, which is what the API expects and what would have failed loudly at the
    definition instead of at the first openable process.
    """
    from jocky.rt import winapi

    assert isinstance(winapi._TOKEN_USER, int), (
        "_TOKEN_USER must be the TokenUser information class (int); a same-named "
        "struct shadows it and breaks GetTokenInformation"
    )
    assert winapi._TOKEN_USER == 1


def test_get_token_information_declares_a_dword_class_argument():
    """The binding must declare argument 2 as a DWORD, matching the API.

    Pairs with the test above: the constant being an int is necessary but not
    sufficient if the prototype asked for something else.
    """
    import ctypes
    from jocky.rt import winapi

    libs = winapi._dlls()
    if libs is None:
        import pytest
        pytest.skip("Windows DLL bindings are unavailable off Windows")

    argtypes = libs["advapi32"].GetTokenInformation.argtypes
    assert argtypes is not None and len(argtypes) == 5
    assert argtypes[1] is ctypes.c_uint32, (
        f"TokenInformationClass must be a DWORD, got {argtypes[1]!r}"
    )
