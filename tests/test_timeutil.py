"""
Time and timeline natives (``time.*`` / ``tl.*``).

These call the Python API directly and assert the observable contract: the
exact epoch an ISO string maps to, the exact UTC text it renders back, and how
a timeline behaves when its rows are *not* clean — the case the namespaces
exist for.  The last two tests wire the namespaces into a real VM the way
``builtins.namespaces()`` will, so the corpus file is exercised before the
registration lands.
"""
from __future__ import annotations

import os
import pathlib
import sys
import time as host_time

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky import runner  # noqa: E402
from jocky.rt import timeutil  # noqa: E402
from jocky.rt.builtins import default_natives  # noqa: E402

#: 2024-01-01T12:00:45Z — one fixed instant reused by every assertion below.
EPOCH = 1704110445

CORPUS_FILE = REPO / "tests" / "lang" / "13_time.jky"


def call(name, *args):
    """Invoke a native the way the VM does: ``fn(vm, args)``."""
    namespace, function = name.split(".")
    return timeutil.namespace()[namespace][function](None, list(args))


# ------------------------------------------------------------------ parsing
def test_iso_variants_all_land_on_the_same_instant():
    assert call("time.parse", "2024-01-01T12:00:45Z") == EPOCH
    assert call("time.parse", "2024-01-01T12:00:45") == EPOCH      # no Z: UTC
    assert call("time.parse", "2024-01-01 12:00:45") == EPOCH      # space separator
    assert call("time.parse", "2024-01-01T17:30:45+05:30") == EPOCH  # explicit offset
    assert call("time.parse", "2024-01-01T12:00:45.500Z") == EPOCH + 0.5


def test_epoch_strings_are_read_as_epochs():
    assert call("time.parse", "1704110445") == EPOCH
    assert call("time.parse", "1704110445.5") == EPOCH + 0.5
    assert call("time.parse", 1704110445) == EPOCH
    assert call("time.parse", 1704110445.25) == EPOCH + 0.25


def test_a_bare_date_is_midnight_utc():
    assert call("time.iso", call("time.parse", "2024-01-01")) == "2024-01-01T00:00:00Z"


@pytest.mark.parametrize("value", [
    "not a time", "", "   ", "12:00:45", "2024-13-45", "nan", "inf",
    None, True, False, 1704110445 + 0.5,  # a list would be a shape error, not a value error
])
def test_unusable_input_returns_nil_instead_of_raising(value):
    """Nothing in a host-supplied timestamp is worth aborting a timeline over."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        assert call("time.parse", value) == float(value)
        return
    assert call("time.parse", value) is None
    assert call("time.iso", value) is None
    assert call("time.delta", value, EPOCH) is None


def test_numeric_but_non_finite_floats_are_refused():
    assert call("time.parse", float("nan")) is None
    assert call("time.parse", float("inf")) is None


# ---------------------------------------------------------------- rendering
def test_iso_renders_utc_with_a_z_suffix():
    assert call("time.iso", EPOCH) == "2024-01-01T12:00:45Z"
    assert call("time.iso", EPOCH + 0.9) == "2024-01-01T12:00:45Z"  # seconds precision
    assert call("time.iso", "1704110445") == "2024-01-01T12:00:45Z"


def test_iso_without_an_argument_is_now():
    rendered = call("time.iso")
    assert rendered.endswith("Z")
    assert abs(host_time.time() - call("time.parse", rendered)) < 5


def test_format_fills_directives_without_touching_the_locale():
    assert call("time.format", EPOCH, "%Y-%m-%d %H:%M:%S") == "2024-01-01 12:00:45"
    assert call("time.format", EPOCH, "%F %T") == "2024-01-01 12:00:45"
    assert call("time.format", EPOCH, "%a %b %e %Y") == "Mon Jan  1 2024"
    assert call("time.format", EPOCH, "%j %p %Z") == "001 PM UTC"
    assert call("time.format", EPOCH, "%s") == "1704110445"
    assert call("time.format", EPOCH + 0.25, "%f") == "250000"
    assert call("time.format", EPOCH, "100%%") == "100%"
    assert call("time.format", EPOCH, "%Q") == "%Q"          # unknown: echoed, as glibc does


def test_format_refuses_a_layout_that_is_not_text():
    with pytest.raises(Exception) as caught:
        call("time.format", EPOCH, 5)
    assert "string layout" in str(caught.value)


def test_format_of_an_impossible_epoch_is_nil_not_an_error():
    assert call("time.format", 1e30, "%Y") is None


# ------------------------------------------------------------------ filetime
def test_filetime_reports_the_timestamps_we_set(tmp_path):
    target = tmp_path / "evidence.txt"
    target.write_text("x", encoding="utf-8")
    os.utime(target, (EPOCH + 100, EPOCH))

    stamps = call("time.filetime", str(target))
    assert stamps["mtime"] == pytest.approx(EPOCH, abs=1e-3)
    assert stamps["atime"] == pytest.approx(EPOCH + 100, abs=1e-3)
    assert stamps["ctime"] >= stamps["mtime"]          # the inode changed after the write


def test_filetime_of_a_missing_path_is_nil():
    assert call("time.filetime", "/definitely-not-here-9f3a") is None


# --------------------------------------------------------------------- delta
def test_delta_is_b_minus_a_and_is_signed():
    assert call("time.delta", EPOCH, EPOCH + 60) == 60
    assert call("time.delta", EPOCH + 60, EPOCH) == -60
    assert call("time.delta", EPOCH, EPOCH) == 0
    assert call("time.delta", "2024-01-01T12:00:45Z", "2024-01-01T12:01:45Z") == 60


# --------------------------------------------------------------------- merge
def test_merge_orders_readable_rows_and_keeps_unreadable_ones():
    events = [
        {"name": "late", "at": "2024-01-01T12:02:00Z"},
        {"name": "first", "at": 1704110400.0},
        {"name": "mid", "at": "2024-01-01 12:01:00"},
        {"name": "undated"},
        {"name": "bad", "at": "yesterday"},
    ]
    merged = call("tl.merge", events, "at")

    assert [row["name"] for row in merged] == ["first", "mid", "late", "undated", "bad"]
    assert [row["tl_index"] for row in merged] == [0, 1, 2, 3, 4]
    assert [row["tl_source"] for row in merged] == [1, 2, 0, 3, 4]
    assert [row["name"] for row in events] == ["late", "first", "mid", "undated", "bad"]


def test_merge_copies_instead_of_annotating_the_callers_maps():
    events = [{"at": 1}]
    merged = call("tl.merge", events, "at")
    assert merged[0] is not events[0]
    assert "tl_index" not in events[0]


def test_merge_is_stable_for_equal_timestamps_and_defaults_its_key():
    tied = call("tl.merge", [{"id": "a", "at": 5}, {"id": "b", "at": 5}], "at")
    assert [row["id"] for row in tied] == ["a", "b"]
    assert [row["time"] for row in call("tl.merge", [{"time": 20}, {"time": 10}])] == [10, 20]


def test_merge_keeps_rows_that_are_not_maps():
    """A stray scalar in the event list must not sink the whole timeline."""
    merged = call("tl.merge", [{"at": 30}, 5], "at")
    assert merged[0] == {"at": 30, "tl_index": 0, "tl_source": 0}
    assert merged[1] == {"value": 5, "tl_index": 1, "tl_source": 1}


def test_merge_of_an_empty_list_is_empty():
    assert call("tl.merge", [], "at") == []


@pytest.mark.parametrize("events", ["nope", {"at": 1}, None])
def test_merge_rejects_a_non_list(events):
    with pytest.raises(Exception) as caught:
        call("tl.merge", events, "at")
    assert "list of events" in str(caught.value)


# -------------------------------------------------------------------- window
def test_window_counts_both_ends_of_the_span():
    hits = [1000.0, 1005.0, 1010.0, 1200.0]
    assert call("tl.window", hits, 10) == 3
    assert call("tl.window", hits, 9) == 2
    assert call("tl.window", hits, 200) == 4
    assert call("tl.window", [1010, 1000, 1005], 10) == 3


def test_window_over_an_empty_or_unreadable_set():
    assert call("tl.window", [], 60) == 0
    assert call("tl.window", [1, "junk", 3], 5) == 2
    assert call("tl.window", ["2024-01-01T12:00:00Z", "2024-01-01T12:00:30Z",
                              "2024-01-01T12:05:00Z"], 60) == 2


def test_window_reads_a_map_key_when_given_one():
    events = [{"at": 100}, {"at": 130}, {"at": 500}, {}]
    assert call("tl.window", events, 60, "at") == 2
    assert call("tl.window", events, 60) == 0


@pytest.mark.parametrize("span", [0, -1, "abc", None, True])
def test_window_refuses_a_span_that_is_not_positive_seconds(span):
    with pytest.raises(Exception) as caught:
        call("tl.window", [1], span)
    assert "positive number of seconds" in str(caught.value)


# -------------------------------------------------------------------- bucket
def test_bucket_aligns_to_the_epoch_and_counts():
    buckets = call("tl.bucket", [1704110445.0, 1704110446.0, 1704110505.0], 60)
    assert buckets == {"1704110400": 2, "1704110460": 1}
    assert all(isinstance(key, str) for key in buckets)


def test_bucket_floors_toward_minus_infinity():
    assert call("tl.bucket", [-30, -10], 60) == {"-60": 2}
    assert call("tl.bucket", [0.0, 59.9], 60) == {"0": 2}


def test_bucket_reads_a_map_key_and_ignores_unreadable_rows():
    events = [{"at": 100}, {"at": 130}, {"at": 500}, {"at": "junk"}, 7]
    assert call("tl.bucket", events, 60, "at") == {"60": 1, "120": 1, "480": 1}
    assert call("tl.bucket", [], 60) == {}


@pytest.mark.parametrize("events", ["nope", 5, None])
def test_bucket_rejects_a_non_list(events):
    with pytest.raises(Exception) as caught:
        call("tl.bucket", events, 60)
    assert "list of events" in str(caught.value)


# --------------------------------------------------- wiring into a real VM
def _wired_natives():
    """The registration the maintainer performs: merge both namespaces in."""
    natives = default_natives()
    natives.update(timeutil.namespace())
    return natives


def test_namespaces_are_reachable_from_script_code():
    result = runner.run_source(
        'emit {"stamp": time.iso(1704110445), '
        '       "first": tl.merge([{"at": 2, "id": "b"}, {"at": 1, "id": "a"}], "at")[0].id, '
        '       "peak": tl.window([1, 2, 100], 5)}',
        natives=_wired_natives())
    assert result.errors == []
    assert result.findings == [{"stamp": "2024-01-01T12:00:45Z", "first": "a", "peak": 2}]


def test_arity_is_enforced_by_the_vm_not_by_the_native():
    result = runner.run_source("time.iso(1, 2)", natives=_wired_natives())
    assert any("expects at most 1 argument" in error for error in result.errors), result.errors


def test_a_bad_layout_stays_catchable_in_language():
    result = runner.run_source(
        'try { time.format(0, 1) } catch err { emit {"caught": err} }',
        natives=_wired_natives())
    assert result.errors == []
    assert "string layout" in result.findings[0]["caught"]


def test_the_corpus_file_passes_with_the_namespaces_wired_in():
    """`jocky test tests/lang --pattern '13_*.jky'` once builtins registers them."""
    result = runner.run_source(CORPUS_FILE.read_text(encoding="utf-8"),
                               natives=_wired_natives())
    failed = [f"{check['label']}: {check.get('detail', '')}"
              for check in result.checks if not check["ok"]]
    assert result.errors == [], result.errors
    assert failed == [], failed
    assert len(result.checks) >= 60, len(result.checks)
