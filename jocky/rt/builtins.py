"""
JOCKY native bridge — host functions exposed to scripts.

Scripts see namespaces as maps of functions::

    for p in proc.list() { if p.memfd_exe { emit "fileless: {p.pid}" } }
    let f = fs.hash("/etc/passwd")
    let report = det.triage()

Namespacing keeps the global scope readable while every call is an explicit
``NativeFn`` (arity-checked by the VM).
"""
from __future__ import annotations

import json
import os
import platform
import sys
import time
from typing import Any, Callable, Dict, List, Optional

from jocky.errors import JockyRuntimeError
from jocky.lang.vm import JockyLimitError, NativeFn, to_str, truthy
from jocky.rt import byovd, detect, filefs, netfs, procfs, sysinfo, timeutil

#: The Windows collector backend, or ``None`` on a host that has none.
#: Resolved at most once: :func:`available` probes for the Windows DLLs, and a
#: script that loops over ``proc.list()`` must not pay for that probe per call.
_WINAPI: Any = None
_WINAPI_PROBED = False


def _windows() -> Any:
    """The Windows collectors, or ``None`` when this host is not Windows.

    ``jocky.rt.winapi`` is imported lazily and only on Windows: it is a large
    module of ``ctypes`` bindings that is dead weight on Linux, and importing it
    unconditionally would run its probe on every host that merely *has* the
    runtime installed.
    """
    global _WINAPI, _WINAPI_PROBED
    if not _WINAPI_PROBED:
        _WINAPI_PROBED = True
        if sys.platform == "win32":
            from jocky.rt import winapi
            _WINAPI = winapi if winapi.available() else None
    return _WINAPI


def _proc_backend() -> Any:
    """Collector module for process facts: ``winapi`` on Windows, ``procfs`` elsewhere.

    Both expose the same key names by contract (see ``jocky/rt/winapi.py``), so
    a script written against one runs unchanged on the other. Collectors with no
    Windows counterpart (fds, maps, cgroups, namespaces) still call ``procfs``
    directly — this exists only for the natives the two modules share.
    """
    return _windows() or procfs


def _net_backend() -> Any:
    """Collector module for socket facts: ``winapi`` on Windows, ``netfs`` elsewhere.

    Separate from :func:`_proc_backend` because the Linux side splits these
    across two modules — the socket tables live in ``netfs``, not ``procfs``,
    and asking ``procfs`` for ``listeners()`` is an ``AttributeError``.
    """
    return _windows() or netfs


def _sys_backend() -> Any:
    """Collector module for kernel-module facts: ``winapi`` on Windows, ``sysinfo`` elsewhere.

    Split out for the same reason: ``/proc/modules`` is parsed by ``sysinfo``,
    not ``procfs``. On Windows the equivalent view is the loaded driver list,
    which is what the BYOVD checks consume.
    """
    return _windows() or sysinfo


def _uptime() -> Dict[str, float]:
    """Uptime and boot time, from whichever backend this platform has.

    ``sysinfo.uptime()`` reads ``/proc/uptime``, so on Windows it answers
    ``0`` — and a script that asks how long the host has been up would be told
    "zero seconds" rather than being told the value is unavailable. ``winapi``
    reads the same two values through ``GetTickCount64`` and the boot-time
    clock, so the platform gets real numbers instead of a placeholder that
    looks like data.
    """
    backend = _windows()
    if backend is not None:
        return {"seconds": backend.uptime_seconds(), "boot_time": backend.boot_time()}
    return sysinfo.uptime()


#: Capabilities a script must be granted explicitly (`jocky run --allow …`).
#: Both of these hand a script powers that go well beyond reading the host:
#: raw syscalls can signal or kill processes, and memfd execution runs arbitrary
#: code with the caller's privileges. Research (see research/findings/lim-security.md)
#: reproduced a live `mem.syscall(62, pid, 9)` kill and a shell escape through
#: `mem.memfd_run`, so they are deny-by-default.
GUARDED_CAPABILITIES = {
    "syscall": "raw system calls can signal, trace or terminate other processes",
    "exec": "memfd execution runs arbitrary code with the caller's privileges",
}


def _policy_allows(vm: Any, capability: str) -> bool:
    policy = (getattr(vm, "ctx", None) or {}).get("policy") or {}
    return capability in (policy.get("allow") or set())


def _guarded(fn: Callable[[Any, List[Any]], Any], capability: str):
    """Wrap a native so it refuses to run without an explicit grant.

    The refusal stays *catchable* — a triage script may legitimately try an
    operation and fall back — but it is recorded in the run's ``denials`` list
    first, so a script cannot hide from the operator that it reached for a
    capability it was not granted.
    """

    def wrapper(vm: Any, args: List[Any]) -> Any:
        if _policy_allows(vm, capability):
            return fn(vm, args)
        context = getattr(vm, "ctx", None)
        if context is not None:
            context.setdefault("denials", []).append(
                {"capability": capability, "native": getattr(fn, "__name__", "native")}
            )
        raise JockyRuntimeError(
            f"'{capability}' capability is disabled: {GUARDED_CAPABILITIES[capability]}. "
            f"Re-run with --allow {capability} if this script is trusted."
        )

    return wrapper


def _fn(name: str, fn: Callable[[Any, List[Any]], Any],
        lo: int = 0, hi: Optional[int] = None) -> NativeFn:
    return NativeFn(name, fn, lo, hi)


def _int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip() or default)
        except ValueError:
            return default
    return default


def _str(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else (default if value is None else to_str(value))


def _bool(value: Any, default: bool = False) -> bool:
    return truthy(value) if value is not None else default


def _list(value: Any) -> List[Any]:
    return list(value) if isinstance(value, list) else []


# ------------------------------------------------------------------- core
def _check_sink(vm: Any) -> List[Dict[str, Any]]:
    """Where in-language assertions are recorded (per run, not global)."""
    sink = getattr(vm, "ctx", None)
    if sink is None:  # a bare VM without context: keep the call harmless
        return []
    return sink.setdefault("checks", [])


def _record(vm: Any, label: str, ok: bool, detail: str = "", skipped: bool = False) -> bool:
    entry: Dict[str, Any] = {"label": label, "ok": bool(ok), "detail": detail}
    if skipped:
        entry["skipped"] = True
    _check_sink(vm).append(entry)
    return bool(ok)


def core_builtins() -> Dict[str, Any]:
    """Value/collection helpers every script expects."""

    def _print(vm: Any, args: List[Any]) -> None:
        vm.output.append(" ".join(to_str(a) for a in args))

    def _assert(vm: Any, args: List[Any]) -> bool:
        condition = truthy(args[0])
        label = _str(args[1]) if len(args) > 1 else "assert"
        return _record(vm, label, condition,
                       "" if condition else "condition was falsy")

    def _expect(vm: Any, args: List[Any]) -> bool:
        actual, expected = args[0], args[1]
        label = _str(args[2]) if len(args) > 2 else "expect"
        ok = actual == expected
        detail = "" if ok else f"expected {to_str(expected)}, got {to_str(actual)}"
        return _record(vm, label, ok, detail)

    def _expect_throws(vm: Any, args: List[Any]) -> bool:
        """A closure must raise a *catchable* error.

        ``expect_throws(fn() { … }, label, "substring")`` additionally requires
        the error text to contain ``substring`` — "something raised" is a weak
        assertion when the interesting part is *which* error came back. Budget
        exhaustion is a failure, not a pass: exceeding a limit is not the error
        the test asked for.
        """
        fn = args[0]
        label = _str(args[1]) if len(args) > 1 else "expect_throws"
        expected = _str(args[2]) if len(args) > 2 else ""
        try:
            vm.call_value(fn, [])
        except JockyRuntimeError as exc:
            message = str(exc)
            if expected and expected not in message:
                return _record(vm, label, False,
                               f"raised {message!r}, which does not contain {expected!r}")
            return _record(vm, label, True, f"raised: {message}")
        except JockyLimitError as exc:
            return _record(vm, label, False, f"hit a limit instead of raising: {exc}")
        except Exception as exc:  # host-level surprise: report, never swallow
            return _record(vm, label, False, f"raised a host error: {type(exc).__name__}: {exc}")
        return _record(vm, label, False, "no error was raised")

    def _fail(vm: Any, args: List[Any]) -> bool:
        return _record(vm, _str(args[0]) if args else "failure", False, "explicit failure")

    def _skip(vm: Any, args: List[Any]) -> bool:
        return _record(vm, _str(args[0]) if args else "skipped", True,
                       "skipped on this host", skipped=True)

    def _range(vm: Any, args: List[Any]) -> List[int]:
        if len(args) == 1:
            return list(range(_int(args[0])))
        return list(range(_int(args[0]), _int(args[1])))

    def _transform(vm: Any, args: List[Any]) -> List[Any]:
        items, fn = _list(args[0]), args[1]
        return [vm.call_value(fn, [item]) for item in items]

    def _filter(vm: Any, args: List[Any]) -> List[Any]:
        items, fn = _list(args[0]), args[1]
        return [item for item in items if truthy(vm.call_value(fn, [item]))]

    def _sort_by(vm: Any, args: List[Any]) -> List[Any]:
        items, fn = list(_list(args[0])), args[1]
        return sorted(items, key=lambda item: _sort_key(vm.call_value(fn, [item])))

    def _count(vm: Any, args: List[Any]) -> int:
        items = _list(args[0])
        if len(args) < 2:
            return len(items)
        return sum(1 for item in items if truthy(vm.call_value(args[1], [item])))

    def _index_by(vm: Any, args: List[Any]) -> Dict[str, Any]:
        """``index_by(rows, key_fn)`` — a lookup table built in one pass.

        This is the primitive every correlation script was hand-rolling as a
        nested loop (VQL has ``memoize``, osquery has a join): process rows,
        sockets and files with one index each and the correlation costs
        O(n + m) instead of O(n x m). First row wins for a duplicate key, so
        the result is deterministic; keys are stringified because they index a
        JOCKY map.
        """
        rows, key_fn = _list(args[0]), args[1]
        table: Dict[str, Any] = {}
        for row in rows:
            key = vm.call_value(key_fn, [row])
            table.setdefault(to_str(key), row)
        return table

    def _group_by(vm: Any, args: List[Any]) -> Dict[str, Any]:
        """``group_by(rows, key_fn)`` — the same pass, keeping every row."""
        rows, key_fn = _list(args[0]), args[1]
        groups: Dict[str, Any] = {}
        for row in rows:
            key = to_str(vm.call_value(key_fn, [row]))
            groups.setdefault(key, []).append(row)
        return groups

    def _json_decode(vm: Any, args: List[Any]) -> Any:
        return json.loads(_str(args[0]))

    def _len(vm: Any, args: List[Any]) -> int:
        value = args[0]
        return len(value) if isinstance(value, (str, list, dict)) else 0

    def _ord(vm: Any, args: List[Any]) -> int:
        """Code point of a one-character string — the other half of the byte story.

        ``fs.read_bytes`` hands back a byte string (one character per byte), so
        turning a byte into the number it *is* — for arithmetic, for building
        hex, for indexing a table — needs this. Without it a script has to
        search a 256-character alphabet for the character's position, which is
        exactly the workaround this replaces.
        """
        text = args[0]
        if not isinstance(text, str) or len(text) != 1:
            _raise(f"ord() expects a one-character string, got {_type_name(text)} "
                   f"of length {_len(vm, [text])}")
        return ord(text)

    def _chr(vm: Any, args: List[Any]) -> str:
        """Character with that code point; the inverse of ``ord`` (0..1114111)."""
        code = _int(args[0])
        if not 0 <= code <= 0x10FFFF:
            _raise(f"chr() expects a code point in 0..1114111, got {code}")
        return chr(code)

    def _float(vm: Any, args: List[Any]) -> float:
        """Permissive like ``int``: unparseable text becomes 0.0, never an error."""
        value = args[0]
        if isinstance(value, bool):
            return float(value)
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip() or "0")
            except ValueError:
                return 0.0
        return 0.0

    def _contains(vm: Any, args: List[Any]) -> bool:
        """``contains(needle, haystack)`` for strings, lists and map keys."""
        needle, haystack = args[0], args[1]
        if isinstance(haystack, str):
            return to_str(needle) in haystack
        if isinstance(haystack, list):
            return any(item == needle for item in haystack)
        if isinstance(haystack, dict):
            return to_str(needle) in haystack
        return False

    return {
        "print": _fn("print", _print, 0, None),
        "assert": _fn("assert", _assert, 1, 2),
        "expect": _fn("expect", _expect, 2, 3),
        "expect_throws": _fn("expect_throws", _expect_throws, 1, 3),
        "fail": _fn("fail", _fail, 0, 1),
        "skip": _fn("skip", _skip, 0, 1),
        "len": _fn("len", _len, 1, 1),
        "ord": _fn("ord", _ord, 1, 1),
        "chr": _fn("chr", _chr, 1, 1),
        "str": _fn("str", lambda vm, a: to_str(a[0]), 1, 1),
        "int": _fn("int", lambda vm, a: _int(a[0]), 1, 1),
        "float": _fn("float", _float, 1, 1),
        "type": _fn("type", lambda vm, a: _type_name(a[0]), 1, 1),
        "range": _fn("range", _range, 1, 2),
        "transform": _fn("transform", _transform, 2, 2),
        "filter": _fn("filter", _filter, 2, 2),
        "sort": _fn("sort", lambda vm, a: sorted(_list(a[0]), key=_sort_key), 1, 1),
        "sort_by": _fn("sort_by", _sort_by, 2, 2),
        "count": _fn("count", _count, 1, 2),
        "index_by": _fn("index_by", _index_by, 2, 2),
        "group_by": _fn("group_by", _group_by, 2, 2),
        "join": _fn("join", lambda vm, a: _str(a[1] if len(a) > 1 else "").join(
            to_str(x) for x in _list(a[0])), 1, 2),
        "keys": _fn("keys", lambda vm, a: list(a[0].keys()) if isinstance(a[0], dict) else [], 1, 1),
        "values": _fn("values", lambda vm, a: list(a[0].values()) if isinstance(a[0], dict) else [], 1, 1),
        "contains": _fn("contains", _contains, 2, 2),
        "dict": _fn("dict", lambda vm, a: {}, 0, 0),
        "now": _fn("now", lambda vm, a: time.time(), 0, 0),
        "sleep": _fn("sleep", lambda vm, a: time.sleep(max(0.0, float(a[0]))), 1, 1),
        "json_encode": _fn("json_encode", lambda vm, a: json.dumps(_plain(a[0]), ensure_ascii=False), 1, 1),
        "json_decode": _fn("json_decode", _json_decode, 1, 1),
        "hex": _fn("hex", lambda vm, a: hex(_int(a[0])), 1, 1),
        "error": _fn("error", lambda vm, a: _raise(_str(a[0])), 1, 1),
    }


def _raise(message: str) -> None:
    from jocky.errors import JockyRuntimeError
    raise JockyRuntimeError(message)


def _type_name(value: Any) -> str:
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "map"
    return "fn"


def _sort_key(value: Any) -> Any:
    if isinstance(value, bool):
        return (1, int(value))
    if isinstance(value, (int, float)):
        return (0, value)
    return (2, to_str(value))


def _plain(value: Any) -> Any:
    from jocky.lang.vm import to_plain
    return to_plain(value)


# --------------------------------------------------------------- namespaces
def _sigma_namespace() -> Dict[str, Any]:
    """Sigma rule evaluation on the linear-time engine.

    The industry's detection corpus is written in Sigma, and the engines that
    normally evaluate it backtrack on adversarial input.  These natives parse
    the rule as written (a documented subset — unsupported modifiers raise
    rather than silently widening the match) and evaluate it against a record
    map or a line of text.
    """
    from jocky.rt import sigma as sigma_mod

    def _check(vm: Any, a: List[Any]) -> bool:
        return sigma_mod.load_rule(_str(a[0])).matches(a[1])

    def _summary(vm: Any, a: List[Any]) -> Dict[str, Any]:
        return sigma_mod.load_rule(_str(a[0])).summary()

    return {
        "check": _fn("sigma.check", _check, 2, 2),
        "summary": _fn("sigma.summary", _summary, 1, 1),
    }


def _yara_namespace() -> Dict[str, Any]:
    """YARA-subset rule matching on the linear-time engine.

    The industry's byte-signature corpus is written in YARA; a tool that reads
    it inherits the signatures instead of asking an analyst to retype them.  The
    subset is documented in ``jocky/rt/yararules.py`` and anything outside it
    (``xor``, ``base64``, modules, loops) raises rather than matching something
    else — a signature that silently stops matching is worse than one that
    refuses to load.
    """
    from jocky.rt import yararules

    def _check(vm: Any, a: List[Any]) -> bool:
        return yararules.load_rule(_str(a[0])).matches(_str(a[1]))

    def _summary(vm: Any, a: List[Any]) -> Dict[str, Any]:
        return yararules.load_rule(_str(a[0])).summary()

    return {
        "check": _fn("yara.check", _check, 2, 2),
        "summary": _fn("yara.summary", _summary, 1, 1),
    }


def namespaces() -> Dict[str, Any]:
    """The host-facing namespaces."""

    proc_ns = {
        "list": _fn("proc.list", lambda vm, a: _proc_backend().list_processes(
            limit=_int(a[0]) if a else None,
            with_fds=_bool(a[1]) if len(a) > 1 else False,
            with_maps=_bool(a[2]) if len(a) > 2 else False), 0, 3),
        "info": _fn("proc.info", lambda vm, a: procfs.info(
            _int(a[0]), with_fds=_bool(a[1]) if len(a) > 1 else False,
            with_maps=_bool(a[2]) if len(a) > 2 else False), 1, 3),
        "tree": _fn("proc.tree", lambda vm, a: procfs.process_tree(), 0, 0),
        "fds": _fn("proc.fds", lambda vm, a: procfs.read_fds(_int(a[0]),
                                                             deleted_only=_bool(a[1]) if len(a) > 1 else False), 1, 2),
        "maps": _fn("proc.maps", lambda vm, a: procfs.read_maps(_int(a[0])), 1, 1),
        "threads": _fn("proc.threads", lambda vm, a: procfs.read_threads(_int(a[0])), 1, 1),
        "environ": _fn("proc.environ", lambda vm, a: procfs.read_environ(_int(a[0])), 1, 1),
        "io": _fn("proc.io", lambda vm, a: procfs.read_io(_int(a[0])), 1, 1),
        "cmdline": _fn("proc.cmdline", lambda vm, a: _proc_backend().read_cmdline(_int(a[0])), 1, 1),
        "exe": _fn("proc.exe", lambda vm, a: _proc_backend().read_exe(_int(a[0])), 1, 1),
        "deleted_open": _fn("proc.deleted_open", lambda vm, a: procfs.deleted_open_files(), 0, 0),
        "socket_map": _fn("proc.socket_map", lambda vm, a: {str(k): v for k, v in procfs.socket_inode_map().items()}, 0, 0),
        "pids": _fn("proc.pids", lambda vm, a: _proc_backend().list_pids(), 0, 0),
        "cgroups": _fn("proc.cgroups", lambda vm, a: procfs.read_cgroups(_int(a[0])), 1, 1),
        "namespaces": _fn("proc.namespaces", lambda vm, a: procfs.read_namespaces(_int(a[0])), 1, 1),
        "status": _fn("proc.status", lambda vm, a: procfs.read_status(_int(a[0])), 1, 1),
    }

    net_ns = {
        "connections": _fn("net.connections", lambda vm, a: _net_backend().connections(
            include_unix=_bool(a[0]) if a else False,
            with_process=_bool(a[1]) if len(a) > 1 else True), 0, 2),
        "listeners": _fn("net.listeners", lambda vm, a: _net_backend().listeners(), 0, 0),
        "established": _fn("net.established", lambda vm, a: _net_backend().established(), 0, 0),
        "unusual_listeners": _fn("net.unusual_listeners", lambda vm, a: [
            c for c in _net_backend().listeners()
            if c.get("local_port") not in netfs.COMMON_LISTEN_PORTS], 0, 0),
        "interfaces": _fn("net.interfaces", lambda vm, a: _net_backend().interfaces(), 0, 0),
        "routes": _fn("net.routes", lambda vm, a: _net_backend().routes(), 0, 0),
        "by_process": _fn("net.by_process", lambda vm, a: {
            str(k): v for k, v in _net_backend().connections_by_process().items()}, 0, 0),
    }

    fs_ns = {
        "hash": _fn("fs.hash", lambda vm, a: filefs.hash_file(_str(a[0])), 1, 1),
        "hash_bytes": _fn("fs.hash_bytes", lambda vm, a: filefs.hash_bytes(_str(a[0]).encode()), 1, 1),
        "hash_bytes_raw": _fn("fs.hash_bytes_raw", lambda vm, a: filefs.hash_bytes_raw(
            _str(a[0]), _str(a[1], "sha256") if len(a) > 1 else "sha256"), 1, 2),
        "stat": _fn("fs.stat", lambda vm, a: filefs.stat_entry(_str(a[0])), 1, 1),
        "magic": _fn("fs.magic", lambda vm, a: filefs.magic(_str(a[0])), 1, 1),
        "scan": _fn("fs.scan", lambda vm, a: filefs.scan(
            _str(a[0], "/"),
            max_files=_int(a[1]) if len(a) > 1 else 2000,
            pattern=(_str(a[2]) or None) if len(a) > 2 else None,
            max_depth=_int(a[3]) if len(a) > 3 else 6), 0, 4),
        "timeline": _fn("fs.timeline", lambda vm, a: filefs.timeline(
            _str(a[0], "/"),
            limit=_int(a[1]) if len(a) > 1 else 200,
            max_files=_int(a[2]) if len(a) > 2 else 5000), 0, 3),
        "special_perms": _fn("fs.special_perms", lambda vm, a: filefs.special_perms(
            _str(a[0], "/"), max_files=_int(a[1]) if len(a) > 1 else 5000), 0, 2),
        "path_dirs": _fn("fs.path_dirs", lambda vm, a: filefs.path_dirs(), 0, 0),
        "ld_preload": _fn("fs.ld_preload", lambda vm, a: filefs.ld_preload(), 0, 0),
        "read": _fn("fs.read", lambda vm, a: _read_text(_str(a[0]),
                                                        _int(a[1]) if len(a) > 1 else 262144,
                                                        _int(a[2]) if len(a) > 2 else 0), 1, 3),
        "read_bytes": _fn("fs.read_bytes", lambda vm, a: filefs.read_bytes(
            _str(a[0]),
            offset=_int(a[1]) if len(a) > 1 else 0,
            limit=_int(a[2]) if len(a) > 2 else 262144), 1, 3),
        "basename": _fn("fs.basename", lambda vm, a: os.path.basename(_str(a[0])), 1, 1),
        "dirname": _fn("fs.dirname", lambda vm, a: os.path.dirname(_str(a[0])), 1, 1),
        "grep": _fn("fs.grep", lambda vm, a: filefs.grep_file(
            _str(a[0]), _str(a[1]),
            limit=_int(a[2]) if len(a) > 2 else 500,
            ignore_case=_bool(a[3]) if len(a) > 3 else False,
            max_bytes=(_int(a[4]) or None) if len(a) > 4 else 32 * 1024 * 1024,
            deadline=getattr(vm, "_deadline", None)), 2, 5),
        "grep_stats": _fn("fs.grep_stats", lambda vm, a: filefs.grep_file(
            _str(a[0]), _str(a[1]),
            limit=_int(a[2]) if len(a) > 2 else 500,
            ignore_case=_bool(a[3]) if len(a) > 3 else False,
            max_bytes=(_int(a[4]) or None) if len(a) > 4 else 32 * 1024 * 1024,
            with_stats=True, deadline=getattr(vm, "_deadline", None)), 2, 5),
        "strings": _fn("fs.strings", lambda vm, a: filefs.strings(
            _str(a[0]),
            min_len=_int(a[1]) if len(a) > 1 else 4,
            limit=_int(a[2]) if len(a) > 2 else 200,
            offset=_int(a[3]) if len(a) > 3 else 0,
            wide=_bool(a[4]) if len(a) > 4 else False,
            deadline=getattr(vm, "_deadline", None)), 1, 5),
        "entropy": _fn("fs.entropy", lambda vm, a: filefs.entropy(
            _str(a[0]),
            offset=_int(a[1]) if len(a) > 1 else 0,
            limit=_int(a[2]) if len(a) > 2 else 1 << 20), 1, 3),
        "exists": _fn("fs.exists", lambda vm, a: os.path.exists(_str(a[0])), 1, 1),
    }

    sys_ns = {
        "info": _fn("sys.info", lambda vm, a: sysinfo.info(), 0, 0),
        "pid": _fn("sys.pid", lambda vm, a: os.getpid(), 0, 0),
        "ppid": _fn("sys.ppid", lambda vm, a: os.getppid(), 0, 0),
        "kernel": _fn("sys.kernel", lambda vm, a: sysinfo.kernel(), 0, 0),
        "hostname": _fn("sys.hostname", lambda vm, a: platform.node(), 0, 0),
        "modules": _fn("sys.modules", lambda vm, a: _sys_backend().modules(), 0, 0),
        "module_integrity": _fn("sys.module_integrity",
                                lambda vm, a: byovd.loaded_modules(), 0, 0),
        "taint": _fn("sys.taint", lambda vm, a: byovd.taint_state(), 0, 0),
        "vulnerable_drivers": _fn("sys.vulnerable_drivers",
                                  lambda vm, a: [dict(entry) for entry in byovd.KNOWN_VULNERABLE], 0, 0),
        "hidden_modules": _fn("sys.hidden_modules", lambda vm, a: sysinfo.hidden_modules(), 0, 0),
        "mounts": _fn("sys.mounts", lambda vm, a: sysinfo.mounts(), 0, 0),
        "memory": _fn("sys.memory", lambda vm, a: sysinfo.memory(), 0, 0),
        "loadavg": _fn("sys.loadavg", lambda vm, a: sysinfo.loadavg(), 0, 0),
        "uptime": _fn("sys.uptime", lambda vm, a: _uptime(), 0, 0),
        "cpu": _fn("sys.cpu", lambda vm, a: sysinfo.cpu(), 0, 0),
        "users": _fn("sys.users", lambda vm, a: sysinfo.logged_in_users(), 0, 0),
        "kallsyms_visible": _fn("sys.kallsyms_visible", lambda vm, a: sysinfo.kallsyms_visible(), 0, 0),
        "distro": _fn("sys.distro", lambda vm, a: sysinfo.distro(), 0, 0),
    }

    det_ns = {
        "triage": _fn("det.triage", lambda vm, a: detect.triage(
            deep=_bool(a[0]) if a else False), 0, 1),
        "fileless": _fn("det.fileless", lambda vm, a: detect.fileless_processes(), 0, 0),
        "memfd_maps": _fn("det.memfd_maps", lambda vm, a: detect.memfd_mappings(), 0, 0),
        "deleted_exes": _fn("det.deleted_exes", lambda vm, a: detect.deleted_executables(), 0, 0),
        "temp_exes": _fn("det.temp_exes", lambda vm, a: detect.temp_executables(), 0, 0),
        "rwx": _fn("det.rwx", lambda vm, a: detect.rwx_regions(), 0, 0),
        "suspicious_cmdline": _fn("det.suspicious_cmdline", lambda vm, a: detect.suspicious_cmdline(), 0, 0),
        "unusual_listeners": _fn("det.unusual_listeners", lambda vm, a: detect.unusual_listeners(), 0, 0),
        "deleted_open": _fn("det.deleted_open", lambda vm, a: detect.deleted_open_files(), 0, 0),
        "ld_preload": _fn("det.ld_preload", lambda vm, a: detect.ld_preload_check(), 0, 0),
        "hidden_modules": _fn("det.hidden_modules", lambda vm, a: detect.hidden_modules(), 0, 0),
        "byovd": _fn("det.byovd", lambda vm, a: detect.byovd(), 0, 0),
        "world_writable_path": _fn("det.world_writable_path", lambda vm, a: detect.world_writable_path(), 0, 0),
        "persistence": _fn("det.persistence", lambda vm, a: detect.persistence(), 0, 0),
    }

    ioc_ns = {
        "match": _fn("ioc.match", lambda vm, a: detect.ioc_match(
            a[0] if isinstance(a[0], dict) else {},
            scan_root=(_str(a[1]) or None) if len(a) > 1 else None,
            max_files=_int(a[2]) if len(a) > 2 else 2000), 1, 3),
    }

    mem_ns = _memory_namespace()
    re_ns = _re_namespace()
    ns = {"proc": proc_ns, "net": net_ns, "fs": fs_ns, "sys": sys_ns,
          "det": det_ns, "ioc": ioc_ns, "mem": mem_ns, "re": re_ns,
          "sigma": _sigma_namespace(), "yara": _yara_namespace()}
    # `time`/`tl` come from the runtime module that owns them; keeping them
    # here means the documentation generator, which enumerates this mapping,
    # cannot miss a namespace that scripts can call.
    ns.update(timeutil.namespace())
    return ns


#: Characters that must be escaped to appear literally in a pattern.
_PATTERN_SPECIALS = "\\^$.[]|()?*+{}"


def _escape_pattern(text: str) -> str:
    """Quote ``text`` so the engine treats every character literally."""
    return "".join(f"\\{char}" if char in _PATTERN_SPECIALS else char for char in text)


def _re_namespace() -> Dict[str, Any]:
    """Pattern matching over JOCKY's linear-time engine (never ``re``).

    Detection scripts match attacker-controlled strings; a backtracking engine
    lets one adversarial command line (`aaaa…`) stall the whole triage run, so
    the runtime ships its own NFA matcher with an explicit step budget.
    """
    from jocky.rt.pattern import compile_pattern

    def _pattern(args: List[Any], flags_index: int) -> Any:
        return compile_pattern(_str(args[0]),
                               _bool(args[flags_index]) if len(args) > flags_index else False)

    def _find(vm: Any, a: List[Any]) -> List[Dict[str, Any]]:
        limit = _int(a[2]) if len(a) > 2 else 0
        matches = _pattern(a, 3).find_all(_str(a[1]), limit or None)
        return [{"text": m.text, "start": m.start, "end": m.end,
                 "groups": list(m.groups[1:])} for m in matches]

    return {
        "test": _fn("re.test", lambda vm, a: _pattern(a, 2).test(_str(a[1])), 2, 3),
        "full": _fn("re.full", lambda vm, a: _pattern(a, 2).fullmatch(_str(a[1])) is not None, 2, 3),
        "find": _fn("re.find", _find, 2, 4),
        "captures": _fn("re.captures", lambda vm, a: [
            [m.text, *m.groups[1:]] for m in _pattern(a, 3).find_all(
                _str(a[1]), (_int(a[2]) if len(a) > 2 and _int(a[2]) else None))], 2, 4),
        "replace": _fn("re.replace", lambda vm, a: _pattern(a, 4).sub(
            _str(a[1]), _str(a[2]), (_int(a[3]) if len(a) > 3 and _int(a[3]) else None)), 3, 5),
        "split": _fn("re.split", lambda vm, a: _pattern(a, 3).split(
            _str(a[1]), (_int(a[2]) if len(a) > 2 and _int(a[2]) else None)), 2, 4),
        "escape": _fn("re.escape", lambda vm, a: _escape_pattern(_str(a[0])), 1, 1),
    }


def _read_text(path: str, limit: int, offset: int = 0) -> str:
    """UTF-8 text read (``errors="replace"``) — lossy by design; see ``fs.read_bytes``.

    ``offset`` pages through a large file: without it a script that wanted the
    tail of a multi-gigabyte log had to read the whole head first.

    A file that cannot be read **raises**. It used to return the string
    ``<unreadable: PermissionError>``, which a detection script happily treats as
    content — `if contains(ioc, fs.read(p))` is then silently false, and a
    confined run (where /tmp and the home directory are denied) reports a clean
    sweep instead of a blind one.
    """
    from jocky.errors import JockyRuntimeError
    from jocky.rt.filefs import MAX_READ_BYTES

    count = max(0, limit)
    if count > MAX_READ_BYTES:
        raise JockyRuntimeError(
            f"read limit {count} exceeds the {MAX_READ_BYTES}-byte ceiling; "
            "read the file in windows with offset instead")
    try:
        with open(path, "rb") as fh:
            if offset > 0:
                fh.seek(offset)
            data = fh.read(count)
    except OSError as exc:
        raise JockyRuntimeError(f"cannot read {path}: {exc.strerror or exc}")
    return data.decode("utf-8", "replace")


def _memory_namespace() -> Dict[str, Any]:
    """Direct-syscall and memfd helpers (guarded: they may be unavailable)."""
    ns: Dict[str, Any] = {}

    def _probe(vm: Any, args: List[Any]) -> Dict[str, Any]:
        try:
            from jocky.rt import raw
            return raw.probe()
        except Exception as exc:
            return {"available": False, "error": f"{type(exc).__name__}: {exc}"}

    def _syscall(vm: Any, args: List[Any]) -> Any:
        from jocky.rt import raw
        if not args:
            return None
        return raw.syscall(_int(args[0]), *[_int(x) for x in args[1:]])

    def _uname(vm: Any, args: List[Any]) -> Dict[str, Any]:
        from jocky.rt import raw
        return raw.uname()

    def _memfd_run(vm: Any, args: List[Any]) -> Dict[str, Any]:
        from jocky.exec import memfd as memfd_mod
        source = _str(args[0])
        timeout = float(args[1]) if len(args) > 1 and isinstance(args[1], (int, float)) else 30.0
        return memfd_mod.run_in_memfd(source, timeout=timeout)

    def _is_memfd(vm: Any, args: List[Any]) -> bool:
        from jocky.exec import memfd as memfd_mod
        return memfd_mod.is_memfd_process(_int(args[0]))

    def _memfd_maps(vm: Any, args: List[Any]) -> List[Dict[str, Any]]:
        from jocky.exec import memfd as memfd_mod
        return memfd_mod.memfd_backed_maps(_int(args[0]))

    ns["probe"] = _fn("mem.probe", _probe, 0, 0)
    ns["syscall"] = _fn("mem.syscall", _guarded(_syscall, "syscall"), 1, 7)
    ns["uname"] = _fn("mem.uname", _uname, 0, 0)
    ns["memfd_run"] = _fn("mem.memfd_run", _guarded(_memfd_run, "exec"), 1, 2)
    ns["is_memfd"] = _fn("mem.is_memfd", _is_memfd, 1, 1)
    ns["memfd_maps"] = _fn("mem.memfd_maps", _memfd_maps, 1, 1)
    return ns


def default_natives() -> Dict[str, Any]:
    """Everything a script can call, ready for ``VM(natives=...)``."""
    natives = core_builtins()
    natives.update(namespaces())
    return natives
