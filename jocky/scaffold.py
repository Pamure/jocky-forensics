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
    if not EXAMPLE_DIR.is_dir():
        return []
    return sorted(path for path in EXAMPLE_DIR.glob("*.jky"))


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
    """Name → first-line description for `jocky examples`."""
    out: List[Dict[str, str]] = []
    for path in bundled_examples():
        first = ""
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    first = stripped.lstrip("# ").strip()
                    break
        except OSError:
            first = ""
        out.append({"name": path.name, "description": first, "path": str(path)})
    return out
