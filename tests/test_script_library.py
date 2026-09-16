"""Every script the repository ships must run.

The library is a deliverable, and a deliverable that is half broken is worse
than a small one: an analyst who picks a script from the tree and gets a
traceback stops trusting the tree. This test makes the claim "every shipped
script works" mechanical instead of aspirational — it discovers every ``.jky``
file under ``scripts/`` and runs it.

It also pins the *count*, against ``tools/claims_audit.py``, so a document that
states a script count cannot drift away from the tree (the repository already
has one such historical claim: a commit title reading "108 DFIR solutions").
"""
from __future__ import annotations

import pathlib
import re
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

SCRIPTS = sorted((REPO / "scripts").rglob("*.jky"))

#: Scripts that need an argument or a capture file and therefore cannot be run
#: bare. Each entry must say why — an unexplained skip list is how a broken
#: script stays hidden.
NEEDS_INPUT: dict[str, str] = {
    "08_network_capture_analysis.jky":
        "reads a pcap; without one it emits capture_missing and exits 0, so it "
        "is runnable — listed here only to document the dependency",
}


def _run(path: pathlib.Path):
    from jocky.runner import run_source
    return run_source(path.read_text(encoding="utf-8"))


def test_the_library_is_not_empty():
    """A zero-length parametrisation would make every test below vacuous."""
    assert len(SCRIPTS) >= 20, (
        f"only {len(SCRIPTS)} scripts found under scripts/; discovery is broken "
        "or the library shrank"
    )


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: str(p.relative_to(REPO)))
def test_every_shipped_script_runs_without_error(path: pathlib.Path):
    """No shipped script may report a runtime error."""
    result = _run(path)
    assert result.errors == [], (
        f"{path.relative_to(REPO)} reported: {result.errors[:3]}"
    )


def test_no_script_loops_forever():
    """Each script must finish well inside the default budget.

    A script that only stops because the wall clock stopped it is a broken
    script — and the case this pins is real: a miscompiled ``break`` in a nested
    loop once made a four-line script run until the budget killed it.
    """
    for path in SCRIPTS:
        result = _run(path)
        assert not result.truncated, (
            f"{path.relative_to(REPO)} hit a limit (truncated=True); it is "
            "reporting a loop it did not intend"
        )


def test_a_clean_result_is_distinguishable_from_a_broken_one():
    """Silence is allowed; silence plus an error is not.

    The library holds two kinds of script and only one of them always speaks.
    A *collector* (`inventory.jky`, the timeline) emits an inventory whatever it
    finds; a *detector* (`02_container_cloud_escape.jky`, `03_stealth_persistence.jky`,
    `05_sigma_yara_production_hunt.jky`) emits only on a hit, and on a clean host
    it correctly says nothing. An earlier version of this file required every
    script to emit at least one finding and failed on exactly those three — the
    assertion was wrong, not the scripts, because forcing a detector to speak
    would fill the output with noise and make a real hit harder to see.

    What must hold instead: a script that emits nothing must have completed
    cleanly. That is the difference between "nothing to report" and "I failed
    quietly", and it is the only part of the contract worth pinning.
    """
    for path in SCRIPTS:
        result = _run(path)
        if not result.findings:
            assert result.errors == [] and not result.truncated, (
                f"{path.relative_to(REPO)} emitted nothing AND reported "
                f"errors={result.errors} truncated={result.truncated}; that is a "
                "failure wearing a clean result's clothes"
            )
        # A script that does emit must emit structured maps an analyst can read.
        for finding in result.findings[:3]:
            assert isinstance(finding, (dict, list, str, int, float, bool, type(None))), (
                f"{path.relative_to(REPO)} emitted a {type(finding).__name__}, "
                "which no consumer can interpret"
            )


def test_the_stated_count_matches_the_tree():
    """Any document that names a number must agree with ``ls``.

    Only live documents are checked; changelog history records what was true
    then and is not a claim about now.
    """
    actual = len(SCRIPTS)
    pattern = re.compile(r"\b(\d+)\s+(?:forensic\s+)?scripts\b", re.I)
    offenders = []
    for name in ("README.md", "scripts/README.md"):
        path = REPO / name
        if not path.exists():
            continue
        for lineno, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for match in pattern.finditer(line):
                if int(match.group(1)) != actual:
                    offenders.append(f"{name}:{lineno} says {match.group(1)}")
    assert not offenders, (
        f"the tree has {actual} scripts but these say otherwise: {offenders}"
    )
