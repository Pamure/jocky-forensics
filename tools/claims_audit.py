#!/usr/bin/env python3
"""Machine-check every number this repository claims about itself.

The rule this enforces: a count that appears in prose must be reproducible by a
command. "108 DFIR solutions" appeared in a commit title while the tree held 15,
and nothing failed — because nothing was counting. This is that counter.

Run it:

    python3 tools/claims_audit.py          # audit, exit 1 on any drift
    python3 tools/claims_audit.py -v       # show every measurement

Wire it into CI next to the test suite. A claim that drifts is a bug.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


# --------------------------------------------------------------- measurements
def _jky_scripts() -> int:
    return len(list((REPO / "scripts").rglob("*.jky")))


def _test_functions() -> int:
    total = 0
    for path in (REPO / "tests").rglob("test_*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        total += len(re.findall(r"^def test_", text, re.M))
    return total


def _lang_checks() -> int:
    """Assertions inside the in-language suite, counted from their source."""
    total = 0
    for path in (REPO / "tests" / "lang").rglob("*.jky"):
        text = path.read_text(encoding="utf-8", errors="replace")
        total += len(re.findall(r"\b(expect|assert)\s*\(", text))
    return total


def _namespaces() -> int:
    from jocky.rt.builtins import namespaces
    return len(namespaces())


def _detection_checks() -> int:
    from jocky.rt.detect import CHECK_CATALOG
    return len(CHECK_CATALOG)


def _json_fields_in(field: str) -> int:  # pragma: no cover - helper for manual use
    return 0


def _version() -> str:
    from jocky import __version__
    return __version__


def _latest_tag() -> str:
    try:
        out = subprocess.run(["git", "describe", "--tags", "--abbrev=0"],
                             cwd=REPO, capture_output=True, text=True, timeout=15)
        return out.stdout.strip() or "(none)"
    except (OSError, subprocess.SubprocessError):
        return "(unavailable)"


# -------------------------------------------------------------------- checks
def _claimed_script_counts() -> list[tuple[str, int, int]]:
    """(where, claimed, actual) for every script-count claim in prose.

    Only patterns that name a specific number are matched; "the library" or
    "scripts" without a digit is not a claim this can falsify.
    """
    actual = _jky_scripts()
    violations: list[tuple[str, int, int]] = []
    patterns = [
        (re.compile(r"\b(\d+)\s+DFIR solutions\b", re.I), "DFIR solutions"),
        (re.compile(r"\b(\d+)\s+(?:forensic\s+)?scripts\b", re.I), "scripts"),
    ]
    for path in [REPO / "README.md", REPO / "CHANGELOG.md", REPO / "docs" / "INSTALL.md"]:
        if not path.exists():
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8",
                                                     errors="replace").splitlines(), 1):
            # Generated/reference tables and historical changelog entries are
            # records of what was true then, not live claims.
            for pattern, label in patterns:
                for match in pattern.finditer(line):
                    claimed = int(match.group(1))
                    if claimed != actual:
                        violations.append((f"{path.name}:{lineno} ({label})",
                                           claimed, actual))
    return violations


def _commit_title_claims() -> list[str]:
    """Commit subjects that state a count, for review against reality.

    Not a failure by itself — history is history — but the audit prints them so
    a wrong one is visible rather than buried.
    """
    try:
        out = subprocess.run(
            ["git", "log", "--format=%h %s"],
            cwd=REPO, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return []
    found = []
    for line in out.stdout.splitlines():
        if re.search(r"\b\d{2,}\s+(DFIR|scripts|solutions|checks|tests)\b", line, re.I):
            found.append(line.strip())
    return found


def _evidence_ledger_drift(measured: dict) -> list[str]:
    """Check the numbers `docs/EVIDENCE.md` states about this repository.

    The ledger is the artifact every other claim points at, so a number in it
    that has silently drifted makes the whole file untrustworthy. Its E8 entry
    states six measurements in one line; this parses them and re-derives each.

    Only repository-derived numbers are checked. External ones — a Defender
    signature version, a build rate — are records of a run and cannot be
    re-derived without re-running the thing they describe.
    """
    path = REPO / "docs" / "EVIDENCE.md"
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    # The E8 measurement line, e.g.
    #   `scripts 38 · test functions 390 · in-language checks 535 · ...`
    match = re.search(r"`scripts (\d+) · test functions (\d+) · in-language checks "
                      r"(\d+) ·\s*namespaces (\d+) · detection checks (\d+) · "
                      r"version ([\d.]+)`", text)
    if not match:
        return ["docs/EVIDENCE.md: the E8 measurement line is missing or unparseable; "
                "the ledger must state its numbers in the audited format"]
    claimed = {
        "scripts": (int(match.group(1)), measured["scripts"]),
        "test functions": (int(match.group(2)), measured["test functions"]),
        "in-language checks": (int(match.group(3)), measured["in-language checks"]),
        "namespaces": (int(match.group(4)), measured["namespaces"]),
        "detection checks": (int(match.group(5)), measured["detection checks"]),
        "version": (match.group(6), measured["version"]),
    }
    return [f"docs/EVIDENCE.md: {name} claims {got!r}, measured {actual!r}"
            for name, (got, actual) in claimed.items() if got != actual]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    measured = {
        "scripts": _jky_scripts(),
        "test functions": _test_functions(),
        "in-language checks": _lang_checks(),
        "namespaces": _namespaces(),
        "detection checks": _detection_checks(),
        "version": _version(),
        "latest tag": _latest_tag(),
    }
    if args.verbose:
        for key, value in measured.items():
            print(f"  {key:22s} {value}")

    violations = _claimed_script_counts()
    ledger = _evidence_ledger_drift(measured)
    titles = _commit_title_claims()

    print(f"\nscripts in tree: {measured['scripts']}")
    print(f"version: {measured['version']}   latest tag: {measured['latest tag']}")

    if titles:
        print("\ncommit titles that state a count (history; verify against reality):")
        for title in titles:
            print(f"  {title}")

    if violations or ledger:
        if violations:
            print("\nCLAIM DRIFT — a document states a number the tree contradicts:")
            for where, claimed, actual in violations:
                print(f"  {where}: claims {claimed}, tree has {actual}")
        if ledger:
            print("\nLEDGER DRIFT — docs/EVIDENCE.md states a number that moved:")
            for line in ledger:
                print(f"  {line}")
        print("\nFix the document or fix the tree. Do not leave both.")
        return 1

    if measured["version"] != measured["latest tag"].lstrip("v"):
        print(f"\nnote: __version__ {measured['version']} does not match the newest "
              f"tag {measured['latest tag']} (informational, not a failure)")
    print("\nno drift: stated script counts and the evidence ledger both match the tree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
