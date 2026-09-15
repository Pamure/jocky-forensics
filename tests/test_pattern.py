"""The pattern engine: correctness against ``re``, and the DoS it exists to stop.

Two claims are load-bearing for the whole detection story:

1. For the supported subset the engine agrees with Python's ``re`` — the
   differential test below is the evidence, not spot checks.
2. Adversarial patterns finish in linear time. ``(a+)+b`` against a wall of
   ``a`` is the classic ReDoS: ``re`` backtracks exponentially and never
   returns, so the engine must be tested on inputs ``re`` cannot survive.
"""
from __future__ import annotations

import pathlib
import random
import re
import sys
import time

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from jocky.errors import JockyRuntimeError  # noqa: E402
from jocky.lang.vm import VM  # noqa: E402
from jocky.rt.builtins import default_natives  # noqa: E402
from jocky.rt.filefs import grep_file  # noqa: E402
from jocky.rt.pattern import compile_pattern  # noqa: E402
from jocky.runner import compile_source  # noqa: E402


def run(source: str):
    return VM(natives=default_natives()).run(compile_source(source), wall_clock_ms=20_000)


# --------------------------------------------------------------- differential
#: Patterns restricted to the subset the engine documents as supported: no lazy
#: quantifiers, no back-references, no look-around. Matching is leftmost-longest
#: where ``re`` is leftmost-first, so only patterns whose alternatives cannot
#: overlap ambiguously are compared for *verdicts*.
PATTERNS = [
    r"\d+", r"\w+", r"\s+", r"[a-z]+", r"[^0-9]+", r"^ab", r"bc$", r"a.c",
    r"colou?r", r"x[abc]y", r"\bword\b", r"\bnc\b", r"[A-Z][a-z]+",
    r"\d{2,4}", r"a*b+c?", r"(?:\d+\.)+\d+", r"[^|]*\|", r"\w+@\w+",
    r"^(GET|POST) ", r"\.(exe|dll|so)$", r"^\[[0-9]{4}-", r"(foo|bar)baz",
    r"\s-e\s", r"^/usr/(bin|sbin)/", r"[A-Za-z0-9+/=]{8,}", r"\b\d{1,3}(\.\d{1,3}){3}\b",
    r"\x7fELF", r"[\x00-\x1f]+", r"\x00", r"[\x20-\x7e]{4,}",
]

ALPHABET = "abcxyz019 .-|@/[]"


def _corpus(seed: int = 7, count: int = 400) -> list[str]:
    random.seed(seed)
    texts = ["".join(random.choice(ALPHABET) for _ in range(random.randint(0, 24)))
             for _ in range(count)]
    # Hand-picked shapes the random alphabet is unlikely to produce. ASCII only:
    # the differential test compares against Python's ``re``, whose ``\w`` is
    # Unicode-aware while this engine's is deliberately ASCII (tested below).
    texts += ["", "a", "abc", "word", "swordfish", "nc", "1.2.3.4", "a|b", "foo bazbaz",
              "GET /index.html", "cmd.exe", "/usr/sbin/sshd", "  socat x",
              r"\[2024-01-01", "a/b/c", "x[abc]y", "QUJDQUJDQUJD",
              "\x7fELF\x02\x01", "AB\x00\x01CD", "\x00", "printable", "\x7f\x01"]
    return texts


def test_agrees_with_python_re_on_supported_subset():
    texts = _corpus()
    checked = 0
    for source in PATTERNS:
        mine, theirs = compile_pattern(source), re.compile(source)
        for text in texts:
            checked += 1
            found = theirs.search(text)
            assert mine.test(text) == bool(found), (source, text)
            # Span equality as well as the verdict: a thread-dedup bug can keep
            # the boolean right while losing the leftmost match.
            if found is None:
                assert mine.search(text) is None, (source, text)
            else:
                match = mine.search(text)
                assert match is not None, (source, text)
                assert (match.start, match.end) == (found.start(), found.end()), (source, text)
    assert checked > 8000, f"only {checked} comparisons ran"


def test_captures_agree_with_python_re():
    cases = [
        (r"(\w+)=(\w+)", "pid=42 ppid=7"),
        (r"(\d+)\.(\d+)\.(\d+)\.(\d+)", "from 10.0.0.5"),
        (r"^(\w+)@(\w+)$", "root@host"),
        (r"(a)(b)?(c)", "ac"),
        (r"([a-z]+)-(\d+)", "svc-1234 and svc-9"),
    ]
    for source, text in cases:
        mine, theirs = compile_pattern(source), re.compile(source)
        for left, right in zip(mine.find_all(text), theirs.finditer(text)):
            assert left.groups == [right.group(0), *right.groups()], (source, text)


def test_word_boundaries_at_text_edges():
    """Regression: ``char in _WORD`` is true for ``""``, so ``\\b`` at position 0
    used to see a word character before the start and never match."""
    assert compile_pattern(r"\bnc\b").test("nc -e /bin/sh")
    assert compile_pattern(r"\bnc\b").test("nc")
    assert compile_pattern(r"^\bfoo").test("foo")
    assert compile_pattern(r"bar\b$").test("bar")
    assert not compile_pattern(r"\bnc\b").test("ncx")


CASE_PATTERNS = [
    r"[A-Z]+", r"[a-z]+", r"^[A-Z][a-z]+$", r"^logout$", r"[^A-Z]+", r"\bFAILED\b",
    r"(GET|POST) ", r"[A-Z]{2,4}", r"root@[A-Z]+", r"^[^A-Z]+$",
]


def test_ignore_case_agrees_with_python_re():
    """`ignore_case` must reach character classes and ranges, not just literals —
    `[A-Z]+` matching `abc` is the case a naive fold gets wrong. Compared
    against `re.IGNORECASE` for both verdict and span."""
    random.seed(11)
    alphabet = "abzAZ09 .-@"
    texts = ["".join(random.choice(alphabet) for _ in range(random.randint(0, 14)))
             for _ in range(400)]
    texts += ["logout", "LOGOUT", "Logout", "root@HOST", "GET /x", "get /x",
              "failed login", "FAILED login", ""]
    checked = 0
    for source in CASE_PATTERNS:
        mine, theirs = compile_pattern(source, True), re.compile(source, re.IGNORECASE)
        for text in texts:
            checked += 1
            found, match = theirs.search(text), mine.search(text)
            assert (match is None) == (found is None), (source, text)
            if found is not None:
                assert (match.start, match.end) == (found.start(), found.end()), (source, text)
    assert checked > 4000, f"only {checked} comparisons ran"


def test_hex_escapes_and_class_endpoints():
    """`\\xNN` is how byte patterns are written — `fs.read_bytes` hands back a
    latin-1 byte string, so the ELF magic is `r"\\x7fELF"`. Both ends of a class
    range must decode the same way, or `[\\x00-\\x1f]` is unparseable."""
    assert compile_pattern(r"\x7fELF").test("\x7fELF")
    assert not compile_pattern(r"\x7fELF").test("x7fELF"), \
        "an unrecognised escape must not become its letter"
    assert compile_pattern(r"[\x00-\x1f]+").test("AB\x00\x01CD")
    assert not compile_pattern(r"[\x00-\x1f]+").test("ABCD")
    assert compile_pattern(r"[^\x00-\x1f]+").test("plain")
    assert compile_pattern(r"\x41").test("A")
    assert compile_pattern(r"[\b]").test("\b"), "inside a class \\b is a backspace"
    assert compile_pattern(r"\bword\b").test("a word here"), "outside it is a boundary"
    assert compile_pattern(r"\0\a\f\v").test("\0\a\f\v")


@pytest.mark.parametrize("source, message", [
    (r"\q", "unsupported escape"),
    (r"[\q]", "unsupported escape"),
    (r"\x", "two hex digits"),
    (r"\xZZ", "two hex digits"),
    (r"[a-\d]", "unsupported escape"),
])
def test_unknown_escapes_are_rejected(source, message):
    with pytest.raises(JockyRuntimeError) as excinfo:
        compile_pattern(source)
    assert message in str(excinfo.value)
    assert "offset" in str(excinfo.value)


def test_word_class_is_ascii_only():
    """Documented semantics: ``\\w`` follows ASCII, so an accented letter is not
    a word character — which is why the differential corpus stays ASCII."""
    assert compile_pattern(r"^\w+$").test("café") is False
    assert compile_pattern(r"^\w+$").test("cafe") is True
    assert compile_pattern(r"café").test("un café noir") is True
    assert compile_pattern(r"^.$").test("é") is True


def test_alternation_takes_the_longest_match():
    """Documented semantic: leftmost-longest (POSIX), not leftmost-first."""
    assert compile_pattern("a|ab").search("ab").text == "ab"
    assert compile_pattern("(ab|a)(b?)").search("ab").text == "ab"


def test_ignore_case_applies_to_literals_classes_and_anchors():
    pattern = compile_pattern("^FAILED (\\w+)$", ignore_case=True)
    assert pattern.test("failed password")
    assert pattern.search("failed password").group(1) == "password"
    assert compile_pattern("FAILED").test("failed") is False


# ------------------------------------------------------------------- limits
def test_nested_quantifier_is_linear_where_re_is_exponential():
    """The reason this engine exists. Python's ``re`` cannot answer this input:
    every additional ``a`` doubles its backtracking work, so the test asserts on
    the engine's own wall clock instead of running ``re`` at all."""
    text = "a" * 20_000 + "b"
    start = time.perf_counter()
    assert compile_pattern("(a+)+b").test(text) is True
    elapsed = time.perf_counter() - start
    assert elapsed < 2.0, f"took {elapsed:.2f}s on {len(text)} chars"

    text = "a" * 20_000          # no trailing b: the worst case for a naive engine
    start = time.perf_counter()
    assert compile_pattern("(a+)+b").test(text) is False
    assert time.perf_counter() - start < 2.0


def test_step_budget_raises_a_catchable_error():
    """A pattern that would need more steps than allowed must raise, not run on."""
    with pytest.raises(JockyRuntimeError, match="step budget"):
        compile_pattern("a+").search("a" * 10, 0, step_budget=3)


def test_pattern_errors_are_catchable_in_language():
    """Scripts wrap detection loops in try/catch, so a bad pattern must land in
    the handler rather than aborting the run."""
    result = run('try { re.test("(a", "abc") } catch e { emit "blocked" }\nemit "after"')
    assert not result.errors, result.errors
    assert result.findings == ["blocked", "after"], result.findings


def test_huge_patterns_are_rejected_at_compile_time():
    with pytest.raises(JockyRuntimeError):
        compile_pattern("a{5000}")


@pytest.mark.parametrize("source, message", [
    ("(a", "unterminated group"),
    ("[abc", "unterminated character class"),
    ("abc\\", "trailing backslash"),
    ("a*?", "lazy"),
    ("a{3,2}", "inverted"),
    ("(?<name>a)", "unsupported group prefix"),
])
def test_malformed_patterns_report_a_position(source, message):
    with pytest.raises(JockyRuntimeError) as excinfo:
        compile_pattern(source)
    assert message in str(excinfo.value)
    assert "offset" in str(excinfo.value)


# ------------------------------------------------------------------ natives
def test_re_namespace_is_wired_into_the_language():
    result = run(r'''
    emit re.test("^root:", "root:x:0:0:root:/root:/bin/bash")
    emit re.full("\d+", "4242")
    emit re.find("\d+", "a1 b22", 5)
    emit re.captures("(\w+)=(\w+)", "pid=42")
    emit re.replace("p(\d+)", "p1 p2", "[$1]")
    emit re.split("\s*,\s*", "a , b,c")
    emit re.escape("a.b*c")
    emit re.test("failed", "FAILED", true)
    ''')
    assert not result.errors, result.errors
    assert result.findings == [
        True, True,
        [{"text": "1", "start": 1, "end": 2, "groups": []},
         {"text": "22", "start": 4, "end": 6, "groups": []}],
        [["pid=42", "pid", "42"]],
        "[1] [2]", ["a", "b", "c"], "a\\.b\\*c", True,
    ]


def test_grep_file_reports_lines_groups_and_respects_limits(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "ok login root\n"
        "Failed password for root from 10.0.0.5 port 22 ssh2\n"
        "Failed password for admin from 10.0.0.9 port 22 ssh2\n"
        "ok logout\n",
        encoding="utf-8")

    hits = grep_file(str(log), r"^Failed password for (\S+) from (\S+)")
    assert [hit["line_no"] for hit in hits] == [2, 3]
    assert hits[0]["groups"] == ["root", "10.0.0.5"]
    assert hits[1]["line"].endswith("ssh2")
    assert [hit["line_no"] for hit in grep_file(str(log), "Failed", limit=1)] == [2]
    assert grep_file(str(log), "nothing-matches") == []
    assert grep_file(str(log), "FAILED", ignore_case=True)


def test_grep_file_handles_binary_and_truncation(tmp_path):
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"\x00\x01no-newline-here \xff\xfe marker\n")
    hits = grep_file(str(blob), "marker")
    assert hits and hits[0]["line_no"] == 1
    assert "\ufffd" in hits[0]["line"]      # undecodable bytes are replaced, not fatal


def test_grep_file_rejects_a_missing_path(tmp_path):
    with pytest.raises(JockyRuntimeError, match="cannot read"):
        grep_file(str(tmp_path / "absent.log"), "x")


def test_grep_file_is_linear_on_adversarial_log_lines(tmp_path):
    """A log line crafted to ReDoS a backtracking matcher must not stall triage."""
    log = tmp_path / "adversarial.log"
    log.write_text("a" * 50_000 + "\n", encoding="utf-8")
    start = time.perf_counter()
    assert grep_file(str(log), "(a+)+b", limit=5) == []
    assert time.perf_counter() - start < 2.0
