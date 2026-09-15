"""
Time handling for scripts: a ``time`` namespace for conversions and a ``tl``
namespace for shaping event timelines.

The two live together because they share one hard rule: **timestamps arrive from
collected data**, never from the script author.  A procfs start time, a file
mtime and a log line are all "some text or number the host gave us", so every
reader here has to survive a missing, empty or malformed field.  Where a value
cannot be understood the natives degrade instead of raising — ``nil`` from the
``time`` helpers, "sorted last but still present" in ``tl.merge`` — because an
investigation that aborts on one bad row loses every good row with it.

Everything is UTC.  A timeline that silently mixed the host's local time into
foreign evidence would be worse than no timeline at all, so the only
non-UTC input accepted is an explicit ISO-8601 offset.
"""
from __future__ import annotations

import datetime
import math
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from jocky.errors import JockyRuntimeError
from jocky.lang.vm import NativeFn, to_str

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MONTHS_LONG = ("January", "February", "March", "April", "May", "June", "July",
                "August", "September", "October", "November", "December")
_DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_DAYS_LONG = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
              "Saturday", "Sunday")

#: Layout directives, resolved by hand instead of via ``strftime``.
#:
#: ``strftime`` is locale-sensitive (``%b``/``%A`` change with ``LC_TIME``) and
#: undefined for the out-of-range epochs that show up in corrupt metadata, so a
#: report generated on one host would not match the same report on another.
#: Unknown directives are echoed verbatim, as glibc does.
_FIELDS: Dict[str, Callable[[datetime.datetime], str]] = {
    "Y": lambda t: f"{t.year:04d}",
    "y": lambda t: f"{t.year % 100:02d}",
    "m": lambda t: f"{t.month:02d}",
    "d": lambda t: f"{t.day:02d}",
    "e": lambda t: f"{t.day:2d}",
    "H": lambda t: f"{t.hour:02d}",
    "I": lambda t: f"{t.hour % 12 or 12:02d}",
    "M": lambda t: f"{t.minute:02d}",
    "S": lambda t: f"{t.second:02d}",
    "f": lambda t: f"{t.microsecond:06d}",
    "j": lambda t: f"{t.timetuple().tm_yday:03d}",
    "a": lambda t: _DAYS[t.weekday()],
    "A": lambda t: _DAYS_LONG[t.weekday()],
    "b": lambda t: _MONTHS[t.month - 1],
    "B": lambda t: _MONTHS_LONG[t.month - 1],
    "p": lambda t: "AM" if t.hour < 12 else "PM",
    "z": lambda t: "+0000",
    "Z": lambda t: "UTC",
    "s": lambda t: str(int(t.timestamp())),
    "F": lambda t: f"{t.year:04d}-{t.month:02d}-{t.day:02d}",
    "T": lambda t: f"{t.hour:02d}:{t.minute:02d}:{t.second:02d}",
    "%": lambda t: "%",
}


def _fn(name: str, fn: Callable[[Any, List[Any]], Any],
        lo: int = 0, hi: Optional[int] = None) -> NativeFn:
    """A native with the same arity contract the VM enforces everywhere."""
    return NativeFn(name, fn, lo, hi)


# ------------------------------------------------------------------ coercion
def _epoch(value: Any) -> Optional[float]:
    """Seconds since the epoch, or ``None`` when the value is unusable.

    Accepts numbers, integer/float epoch strings and ISO-8601 — with or without
    ``Z``, with an explicit offset, with ``T`` or a space before the time, and
    with fractional seconds.  A naive ISO value is read as UTC; a bare date
    (``2024-01-02``) is midnight UTC.

    Digit strings are tried as epochs *first*: ``"20240102"`` reaches a log
    parser far more often as a timestamp than as a compact calendar date.
    ``bool`` is rejected deliberately — ``true`` is not a timestamp, and
    ``isinstance(True, int)`` would otherwise make it epoch 1.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    try:
        number = float(text)
    except ValueError:
        pass
    else:
        return number if math.isfinite(number) else None
    try:
        moment = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment.timestamp()


def _seconds(value: Any, native: str) -> float:
    """A positive span/window length; anything else is a caller bug, not data."""
    span: Optional[float] = None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        span = float(value)
    elif isinstance(value, str):
        try:
            span = float(value.strip())
        except ValueError:
            span = None
    if span is None or not math.isfinite(span) or span <= 0:
        raise JockyRuntimeError(
            f"tl.{native} needs a positive number of seconds, got {value!r}")
    return span


def _optional_key(args: List[Any], index: int) -> Optional[str]:
    """The map key a native should read, or ``None`` for bare timestamps."""
    value = args[index] if len(args) > index else None
    return value if isinstance(value, str) and value else None


def _events(value: Any, native: str) -> List[Any]:
    if not isinstance(value, list):
        raise JockyRuntimeError(
            f"tl.{native} needs a list of events, got {type(value).__name__}")
    return value


def _stamps(items: List[Any], key: Optional[str]) -> List[float]:
    """Every readable timestamp in ``items``; unreadable ones are dropped.

    With a ``key`` each item must be a map holding that key, without one each
    item is itself a timestamp.
    """
    found: List[float] = []
    for item in items:
        if key is None:
            stamp = _epoch(item)
        else:
            stamp = _epoch(item.get(key)) if isinstance(item, dict) else None
        if stamp is not None:
            found.append(stamp)
    return found


# -------------------------------------------------------------------- render
def _render(epoch: float, layout: str) -> Optional[str]:
    """Expand ``layout`` for a UTC instant; ``None`` if the epoch is impossible."""
    try:
        moment = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None
    out: List[str] = []
    index = 0
    while index < len(layout):
        char = layout[index]
        if char != "%" or index + 1 >= len(layout):
            out.append(char)
            index += 1
            continue
        code = layout[index + 1]
        index += 2
        field = _FIELDS.get(code)
        out.append(field(moment) if field is not None else "%" + code)
    return "".join(out)


# ------------------------------------------------------------ time namespace
def _now(vm: Any, args: List[Any]) -> float:
    return time.time()


def _iso(vm: Any, args: List[Any]) -> Optional[str]:
    """UTC ISO-8601 with the ``Z`` suffix (seconds precision)."""
    epoch = time.time() if not args else _epoch(args[0])
    if epoch is None:
        return None
    return _render(epoch, "%Y-%m-%dT%H:%M:%SZ")


def _parse(vm: Any, args: List[Any]) -> Optional[float]:
    return _epoch(args[0])


def _format_epoch(vm: Any, args: List[Any]) -> Optional[str]:
    layout = args[1]
    if not isinstance(layout, str):
        raise JockyRuntimeError("time.format(epoch, layout) needs a string layout")
    epoch = _epoch(args[0])
    return None if epoch is None else _render(epoch, layout)


def _filetime(vm: Any, args: List[Any]) -> Optional[Dict[str, float]]:
    """``mtime``/``ctime``/``atime`` for a path, or ``nil`` if it cannot be read.

    ``ctime`` is the inode *change* time on Linux: an investigator comparing it
    with ``mtime`` is looking for metadata tampering, not for file creation.
    ``lstat`` is used so a symlink reports its own timestamps rather than the
    target's — a symlink swapped after the fact is exactly what the timeline is
    meant to reveal.
    """
    path = args[0] if isinstance(args[0], str) else ""
    try:
        info = os.lstat(path)
    except OSError:
        return None
    return {"mtime": info.st_mtime, "ctime": info.st_ctime, "atime": info.st_atime}


def _delta(vm: Any, args: List[Any]) -> Optional[float]:
    """``b - a`` in seconds; ``nil`` when either side is unreadable."""
    first, second = _epoch(args[0]), _epoch(args[1])
    if first is None or second is None:
        return None
    return second - first


# -------------------------------------------------------------- tl namespace
def _default_time_key(items: List[Any]) -> str:
    """The field to sort on when the caller does not name one.

    ``ts`` is what findings carry (``--stamp-findings``) and what the documented
    correlation recipe feeds in; ``time`` is the older event field.  Guessing
    ``time`` for a list of stamped findings silently returned them in *input*
    order, which looks sorted until you check.
    """
    for item in items:
        if isinstance(item, dict) and "ts" in item:
            return "ts"
    return "time"


def _merge(vm: Any, args: List[Any]) -> List[Any]:
    """Order events by a time key and record where each one came from.

    The sort is stable, so events sharing a timestamp keep their input order,
    and events whose time is missing or unreadable sort last **without being
    dropped** — a timeline that quietly discarded the rows it could not parse
    would hide exactly the evidence someone was trying to bury.

    Each output map carries ``tl_index`` (position in the merged order) and
    ``tl_source`` (index in the input list), so a finding stays traceable back
    to the row it came from.  Input maps are copied, never annotated in place.
    Items that are not maps have nowhere to read a time from; they are kept as
    ``{"value": item}`` and sort last like any other unreadable row.
    """
    items = _events(args[0], "merge")
    key = _optional_key(args, 1) or _default_time_key(items)
    rows: List[Tuple[Optional[float], int, Dict[str, Any]]] = []
    for source, item in enumerate(items):
        if isinstance(item, dict):
            record = dict(item)
            stamp = _epoch(record.get(key))
        else:
            record = {"value": item}
            stamp = None
        rows.append((stamp, source, record))
    # ``None`` compares to nothing in Python, hence the explicit flag; the
    # placeholder zero keeps the comparison total.
    rows.sort(key=lambda row: (row[0] is None, row[0] if row[0] is not None else 0.0))
    for index, (_, source, record) in enumerate(rows):
        record["tl_index"] = index
        record["tl_source"] = source
    return [record for _, _, record in rows]


def _window(vm: Any, args: List[Any]) -> int:
    """Most events inside any window of ``seconds``.

    Both ends count: a 60 s window holding events 60 s apart reports both, which
    is what "how many hits in a minute" means to an analyst reading it.
    """
    items = _events(args[0], "window")
    span = _seconds(args[1], "window")
    stamps = sorted(_stamps(items, _optional_key(args, 2)))
    best = 0
    start = 0
    for end, stamp in enumerate(stamps):
        while stamp - stamps[start] > span:
            start += 1
        best = max(best, end - start + 1)
    return best


def _bucket(vm: Any, args: List[Any]) -> Dict[str, int]:
    """Event counts per ``seconds``-wide epoch bucket, keyed by bucket start.

    Buckets are aligned to the epoch (``floor(t / seconds) * seconds``) so two
    runs over overlapping data produce the same keys without a shared origin.
    Keys are strings because that is what script map lookup compares.
    """
    items = _events(args[0], "bucket")
    span = _seconds(args[1], "bucket")
    counts: Dict[str, int] = {}
    for stamp in _stamps(items, _optional_key(args, 2)):
        label = to_str(math.floor(stamp / span) * span)
        counts[label] = counts.get(label, 0) + 1
    return counts


# ------------------------------------------------------------------ namespace
def namespace() -> Dict[str, Any]:
    """The ``time`` and ``tl`` namespaces, ready for ``natives.update(...)``."""
    time_ns = {
        "now": _fn("time.now", _now, 0, 0),
        "iso": _fn("time.iso", _iso, 0, 1),
        "parse": _fn("time.parse", _parse, 1, 1),
        "format": _fn("time.format", _format_epoch, 2, 2),
        "filetime": _fn("time.filetime", _filetime, 1, 1),
        "delta": _fn("time.delta", _delta, 2, 2),
    }
    tl_ns = {
        "merge": _fn("tl.merge", _merge, 1, 2),
        "window": _fn("tl.window", _window, 2, 3),
        "bucket": _fn("tl.bucket", _bucket, 2, 3),
    }
    return {"time": time_ns, "tl": tl_ns}
