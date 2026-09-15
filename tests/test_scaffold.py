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


def test_init_writes_runnable_case_directory(tmp_path):
    target = tmp_path / "case"
    summary = scaffold.init_project(str(target))

    assert (target / "README.md").exists()
    assert (target / ".gitignore").exists()
    assert summary["created"], summary
    assert not summary["skipped"]

    scripts = sorted((target / "scripts").glob("*.jky"))
    assert scripts, "no example scripts were copied"

    # a copied script must run with the real runtime
    result = run_source(scripts[0].read_text(encoding="utf-8"), wall_clock_ms=30_000)
    assert not result.errors, (scripts[0].name, result.errors)
    assert result.findings, f"{scripts[0].name} produced no findings"


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
