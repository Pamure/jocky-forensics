"""
Tests for `jocky init` and the bundled examples.

The scaffold is the first thing a new user runs, so the test asserts the thing
that matters: the scripts it copies actually execute on this host.
"""
from __future__ import annotations

import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky import scaffold  # noqa: E402
from jocky.runner import run_source  # noqa: E402


def test_bundled_examples_exist_and_are_described():
    examples = scaffold.example_scripts()
    assert examples, "no bundled examples found in jocky/examples"
    names = {item["name"] for item in examples}
    assert {"triage.jky", "hunt.jky"} <= names
    assert all(item["description"] for item in examples), "an example has no leading description"


#: `watch.jky` sleeps on purpose (it exists to stay alive for live-detection
#: demos), so it is compiled but not executed here.
LONG_RUNNING_EXAMPLES = {"watch.jky"}


def test_every_bundled_example_compiles_and_runs(tmp_path):
    """Every shipped example must work — the first one passing proves nothing.

    This check exists because `fs.timeline()` accepted two arguments while
    `scripts/timeline.jky` passed three, and a test that only ran the
    alphabetically first example never noticed.
    """
    from jocky.runner import compile_source, run_source

    target = tmp_path / "case"
    scaffold.init_project(str(target))
    scripts = sorted((target / "scripts").glob("*.jky"))
    assert len(scripts) >= 5, scripts

    failures = []
    for script in scripts:
        source = script.read_text(encoding="utf-8")
        try:
            compile_source(source)          # every example must at least compile
        except Exception as exc:
            failures.append(f"{script.name}: compile: {type(exc).__name__}: {exc}")
            continue
        if script.name in LONG_RUNNING_EXAMPLES:
            continue
        result = run_source(source, wall_clock_ms=60_000)
        if result.errors:
            failures.append(f"{script.name}: {result.errors[0]}")
        elif not result.findings:
            failures.append(f"{script.name}: produced no findings")
    assert not failures, failures


def test_init_is_idempotent_without_force(tmp_path):
    target = tmp_path / "case"
    scaffold.init_project(str(target))
    second = scaffold.init_project(str(target))
    assert second["created"] == []
    assert second["skipped"], "second init should have skipped existing files"
    forced = scaffold.init_project(str(target), force=True)
    assert forced["created"]
    assert not forced["skipped"]


def test_gitignore_covers_runtime_state(tmp_path):
    target = tmp_path / "case"
    scaffold.init_project(str(target))
    content = (target / ".gitignore").read_text(encoding="utf-8")
    for pattern in (".jocky-server/", ".jocky-agent/", "*.jky.build"):
        assert pattern in content
