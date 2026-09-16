"""
``jocky init`` — scaffold a working case directory.

The point is that a new user gets *runnable* scripts (copied from the bundled
examples) plus the exact commands to try, instead of an empty folder and a
README that has to be interpreted.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Dict, List

EXAMPLE_DIR = Path(__file__).resolve().parent / "examples"

#: The script library, when this package is being run from a source checkout.
#: ``jocky examples`` answers "what does this project ship", and the answer that
#: matters is the library in ``scripts/`` — every topic directory included — not
#: the handful of starters that happen to be packaged as data files. An installed
#: wheel has no ``scripts/`` tree, so the packaged examples remain the fallback,
#: and each entry reports which directory it came from so the two are never
#: silently mixed.
LIBRARY_DIR = Path(__file__).resolve().parent.parent / "scripts"

GITIGNORE = """\
# jocky case directory
.jocky-server/
.jocky-agent/
*.jky.build
*.jky.artifact
evidence/
"""

README = """\
# JOCKY case directory

Scaffolded by `jocky init`. Everything here runs with the standard library and
reads the host's kernel interfaces directly.

## Bundled scripts

| Script | What it does |
|---|---|
| `scripts/triage.jky` | full host triage: in-memory execution, network exposure, kernel tampering |
| `scripts/hunt.jky` | hunt for fileless processes and correlate them with live sockets |
| `scripts/inventory.jky` | host inventory, interfaces, routes, mounts, module views |
| `scripts/timeline.jky` | recent activity in the writable drop zones, deleted-but-open files |
| `scripts/watch.jky` | long-running collection loop (stays alive for live detection demos) |

## Try it

```bash
jocky doctor                                   # verify this host
jocky run scripts/triage.jky                   # run a script
jocky triage --json                            # built-in triage, no script needed
jocky build scripts/triage.jky -o triage.build # polymorphic artifact
jocky exec triage.build --json                 # run the artifact
jocky fileless scripts/triage.jky              # nothing written to disk
jocky evidence --iterations 1000 --out evidence
```

## Writing your own

```jocky
# my-script.jky
let listeners = net.listeners()
for c in listeners {
  emit {"port": c.local_port, "process": c.process, "pid": c.pid}
}
```

Namespaces: `proc`, `net`, `fs`, `sys`, `det`, `ioc`, `mem`.
See the documentation for the full native API.
"""


def bundled_examples() -> List[Path]:
    """The starter scripts copied into a new case directory by ``init_project``."""
    if not EXAMPLE_DIR.is_dir():
        return []
    return sorted(path for path in EXAMPLE_DIR.glob("*.jky"))


def library_scripts() -> List[Path]:
    """Every script this installation can run, as ``jocky examples`` lists them.

    A source checkout has the whole library; an installed wheel has only the
    packaged starters, and returning those is the honest answer rather than an
    error.
    """
    if LIBRARY_DIR.is_dir():
        found = sorted(LIBRARY_DIR.rglob("*.jky"))
        if found:
            return found
    return bundled_examples()


def _description(path: Path) -> str:
    """The script's own one-line statement of the question it answers.

    The convention in this library is a first comment line naming the file
    (``01_thing.jky — the question``) followed by the sentence continuing onto
    the next line. A bare filename is not a description, so it is dropped and
    the wording after it is kept; the comment block is then joined and trimmed to
    its first sentence, because a listing whose descriptions repeat the file
    names tells the reader nothing.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ""
    stem = path.stem
    collected: List[str] = []
    for line in lines[:40]:
        stripped = line.strip()
        if not stripped or not stripped.startswith("#"):
            break
        text = stripped.lstrip("#").strip()
        if not text:
            break
        if not collected and text.startswith(stem):
            text = text[len(stem):]
            if text.startswith(".jky"):
                text = text[4:]
            text = text.lstrip(" -—:.").strip()
            if not text:
                # The line was only the filename: keep reading.
                continue
        collected.append(text)
        joined = " ".join(collected)
        if len(joined) > 140 or joined.endswith((".", "?", "!")):
            break
    if not collected:
        return ""
    joined = " ".join(collected).strip()
    for stop in (". ", "? ", "! "):
        head, _sep, _tail = joined.partition(stop)
        if _sep and head:
            return head + _sep.strip()
    return joined


def init_project(directory: str = ".", force: bool = False) -> Dict[str, Any]:
    """Create a case directory; returns a summary of what was written."""
    target = Path(directory).expanduser().resolve()
    created: List[str] = []
    skipped: List[str] = []

    target.mkdir(parents=True, exist_ok=True)
    (target / "scripts").mkdir(exist_ok=True)

    def write(path: Path, content: str) -> None:
        if path.exists() and not force:
            skipped.append(str(path.relative_to(target)))
            return
        path.write_text(content, encoding="utf-8")
        created.append(str(path.relative_to(target)))

    write(target / "README.md", README)
    write(target / ".gitignore", GITIGNORE)

    examples = bundled_examples()
    for example in examples:
        destination = target / "scripts" / example.name
        if destination.exists() and not force:
            skipped.append(str(destination.relative_to(target)))
            continue
        shutil.copyfile(example, destination)
        created.append(str(destination.relative_to(target)))

    if not examples:
        # the package was installed without data files: leave a runnable script
        write(
            target / "scripts" / "triage.jky",
            'emit {"kind": "summary", "host": sys.hostname(), '
            '"processes": len(proc.list())}\n',
        )

    return {
        "directory": str(target),
        "created": created,
        "skipped": skipped,
        "examples_available": len(examples),
    }


def example_scripts() -> List[Dict[str, str]]:
    """One row per shipped script, for ``jocky examples``.

    Each row carries the script's path relative to the library root (so
    ``solutions/07_byovd_kernel_integrity.jky`` keeps its topic directory in the
    name), its own description, and the group it belongs to — ``starter`` for the
    scripts ``jocky init`` copies, ``library`` for the rest.
    """
    rows: List[Dict[str, str]] = []
    # The scripts `jocky init` copies are the packaged starters; everything else
    # is library material a case directory gets on request.
    starters = {path.name for path in bundled_examples()}
    for path in library_scripts():
        try:
            name = path.relative_to(LIBRARY_DIR).as_posix()
        except ValueError:
            # The packaged fallback directory is not under LIBRARY_DIR.
            name = path.name
        rows.append({
            "name": name,
            "description": _description(path) or name,
            "group": "starter" if path.name in starters else "library",
            "path": str(path),
        })
    return rows
