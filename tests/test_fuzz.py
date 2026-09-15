"""
Bounded fuzz run over the language front end and the VM.

The generator, its budgets and the shrinking live in ``tests/fuzz_language.py``;
this module pins the properties the corpus has to keep:

* no exception other than a ``JockyError`` may leave ``compile_source`` /
  ``run_source`` — a raw Python exception from the lexer, parser, compiler or a
  native is a bug, and the report carries the minimised program and a traceback
  tail to act on;
* the corpus is reproducible from its seed (regression runs must be comparable)
  and every corpus starts with the recorded historical reproducers;
* malformed programs are *rejected* with ``JockySyntaxError`` rather than
  crashing the process — checked for every recipe in the defect catalogue.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.errors import JockySyntaxError  # noqa: E402
from jocky.runner import compile_source  # noqa: E402
from tests import fuzz_language  # noqa: E402
from tests.fuzz_language import (  # noqa: E402
    DEFECT_NAMES,
    HISTORICAL_REPRODUCERS,
    defect_sources,
    fuzz,
    generate,
)

# Fixed seed and size: a fuzz run has to be a comparable measurement, not a
# lottery.  ~2000 programs execute in well under a minute.
FUZZ_SEED = 20260916
FUZZ_COUNT = 2000


def test_no_host_exception_escapes_the_language():
    report = fuzz(FUZZ_COUNT, seed=FUZZ_SEED)
    assert report["generated"] == FUZZ_COUNT
    # A generator that emitted unusable text would trivially pass the check
    # below, so the corpus must also largely *run*.
    assert report["ok"] > FUZZ_COUNT * 0.5, report["jockey_errors"]
    failing = report["host_exceptions"]
    assert failing == [], "\n\n".join(
        f"{entry['error']}\nsource: {entry['source']!r}\n{entry['traceback_tail']}"
        for entry in failing[:5])


def test_corpus_is_deterministic_per_seed():
    first = generate(FUZZ_SEED, 50)
    assert first == generate(FUZZ_SEED, 50)
    assert first != generate(FUZZ_SEED + 1, 50)
    # Every corpus carries the historical reproducers, at the front.
    assert first[:len(HISTORICAL_REPRODUCERS)] == list(HISTORICAL_REPRODUCERS)


def test_historical_reproducers_still_run():
    report = fuzz(len(HISTORICAL_REPRODUCERS), seed=0)
    assert report["jockey_errors"] == [], report["jockey_errors"]
    assert report["ok"] == len(HISTORICAL_REPRODUCERS)


def test_report_flags_a_host_exception(monkeypatch):
    """The no-host-exception claim has to be falsifiable.

    A host exception is injected at the boundary the corpus crosses — the
    lexer's historical ``KeyError: ''`` stands in for any future crash — and
    the report has to name it, keep the input, and pass the traceback along.
    """
    def crash(source: str):
        if source == "emit 1":
            raise KeyError("")
        return fuzz_language.compile_source(source)

    monkeypatch.setattr(fuzz_language, "compile_source", crash)
    monkeypatch.setattr(fuzz_language, "generate", lambda seed, count: ["emit 1"])
    report = fuzz(1, seed=0)
    assert [entry["error"] for entry in report["host_exceptions"]] == ["KeyError: ''"]
    assert report["ok"] == 0
    assert "KeyError" in report["host_exceptions"][0]["traceback_tail"]


@pytest.mark.parametrize("source", defect_sources(), ids=DEFECT_NAMES)
def test_malformed_input_is_rejected_not_crashed(source: str):
    with pytest.raises(JockySyntaxError):
        compile_source(source)
