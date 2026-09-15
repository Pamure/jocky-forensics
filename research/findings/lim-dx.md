# Limitation: developer & installation experience (lim-dx)

## Scope

Root metadata, packaging, installability, environment reproducibility, CLI, error
UX, editor support, CI/release, community-health files. Baseline 2026-09-15 23:03
and re-audit 23:09, after other agents landed `pyproject.toml`, `LICENSE`,
`Dockerfile`, `jocky/diagnostics.py`, `jocky/scaffold.py` (23:07). Method:
static inspection and CLI probes; no test suite or linter.

**Addressed mid-audit, verified:** `pyproject.toml` exposes `[project.scripts]
jocky = "jocky.cli:main"` with `requires-python >=3.12`; `jocky --version` works
from `/tmp`; `LICENSE` (MIT); `jocky doctor --json` → 11 ok / 1 warn /
0 fail; `jocky init`/`examples` exist.

## Findings

1. **No published artifact** · PyPI 404 for `jocky` and `jocky-forensics` (today;
   the latter matches `pyproject.toml`), and `git init` has zero commits, no tag ·
   nothing to install by name or pin.
2. **Packaging metadata defects** · `Documentation =
   "https://jocky.vercel.app"` → HTTP 404 today, `Source =
   "https://github.com/your-org/jocky"` is a placeholder, and `license = { text =
   "MIT" }` is the form PEP 639 deprecates [6] · publishing would ship dead links.
3. **pytest config split-brain** · `pytest.ini` carries
   `[tool.pytest.ini_options]`, which that filename never reads, while
   `pyproject.toml` carries it correctly; with both present pytest reports
   `configfile: pytest.ini (WARNING: ignoring pytest config in pyproject.toml!)` ·
   neither `testpaths` nor `addopts` applies.
4. **No CI** · no `.github/` (root listing); nothing runs tests, evidence, or
   `jocky doctor` on change [1] · the measured claims can regress silently.
5. **Environment not reproducible** · `venv/` (92 MB, 2398 files) is in-tree with
   the maintainer's path in `venv/pyvenv.cfg:4`; no lock or `.python-version`;
   `README.md:26,165` assume `./venv/bin/python`; `jocky_forensics.egg-info/`
   residue · evidence is not rebuildable elsewhere.
6. **Missing project files** · `LICENSE` exists, but no `SECURITY.md` or
   disclosure route, no `CONTRIBUTING.md`, no CHANGELOG [2] · a detector-plus-TLS tool
   offers no flaw-reporting channel.
7. **No editor support** · no Pygments lexer, TextMate/tree-sitter grammar, LSP,
   or completion — only the internal lexer (`jocky/lang/lexer.py`) and an
   argparse CLI · `.jky` renders as plain text and natives are uncompletable
   [3][4][5].
8. **Unlocated runtime errors** · the bytecode has no line table (`lines` at
   `jocky/lang/compiler.py:131-142` is disassembly text), so a failing script
   prints bare `error: division by zero`, though AST positions exist
   (`jocky/lang/parser.py:109`) · no diagnostics surface.
9. **Docs are unversioned** · `README.md` + `docs/DESIGN.md` in-tree, no
   per-release snapshot, hosted URL 404s (finding 2) · claims cannot be mapped to
   a build.

## Concrete improvements

1. **Claim the distribution name on PyPI** with Trusted Publishing and digital
   attestations [7]; why: installation otherwise stops at "clone and build".
   **S**, low.
2. **Repair `pyproject.toml`** — SPDX `license = "MIT"` with `license-files`,
   real `Source`/`Documentation` URLs, pinned dev extras [6]. **S**, low.
3. **Delete `pytest.ini`**, keeping the `pyproject.toml` table; why: the duplicate
   silently disables both. **S**, low.
4. **CI** — a workflow running `pytest`, `jocky doctor --json`,
   `jocky evidence --quick`, and Scorecard on ubuntu × 3.12/3.13; why: claims
   become enforced. **M**, low [1][7].
5. **Pygments lexer, then a pygls LSP** from `jocky/rt/builtins.py`, plus an
   `argcomplete` extra; why: explorability. **S** then **L**, low [3][4][5].
6. **Compiler line table** — add `proto.lines`, prefix runtime errors with
   `file:line:col`; why: debuggability. **M**, medium — bump `ARTIFACT_VERSION`
   (`jocky/poly/encoder.py:620`), keep older artifacts decodable.
7. **Reproducibility** — drop `venv/`, add `uv.lock` and `.python-version`; why:
   rebuildable environment. **S**, low.

**Cannot be fixed:** onboarding cannot match Velociraptor's static binary [8]:
fileless mode needs a real CPython ELF in a memfd
(`jocky/exec/fileless.py:7-12`), and bundling voids the
`/proc/<pid>/exe = /memfd:python3 (deleted)` claim. CI cannot be cross-platform
either — those claims need Linux procfs.

## Verification approach

- Install: `uv build` → `uv tool install dist/*.whl`; `jocky run scripts/triage.jky`
  outside the repo.
- Metadata: both `pyproject.toml` URLs return 200; PyPI lists attestations.
- pytest: after deleting `pytest.ini`, `pytest -q` honours the pyproject table
  (today both configs are inert — reproduced).
- Errors: line-3 `1 / 0` must print `…:3:…`; today only `error: division by zero`.
- Editor and gate: `pygmentize -l jocky scripts/hunt.jky`; `jocky <TAB>`
  completes subcommands; `jocky doctor --json` exits 0 with zero warnings, and CI
  fails on `fail`.

## Citations

1. OpenSSF Scorecard checks — https://github.com/ossf/scorecard/blob/main/docs/checks.md
2. GitHub default community health files — https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/creating-a-default-community-health-file
3. VS Code syntax-highlight guide — https://code.visualstudio.com/api/language-extensions/syntax-highlight-guide
4. argcomplete 3.7.2, 2026-08-06 — https://pypi.org/project/argcomplete/
5. Pygments lexers; 2.21.0, 2026-08-17 — https://pygments.org/docs/lexerdevelopment/
6. PEP 639 licence metadata — https://setuptools.pypa.io/en/latest/userguide/license_migration.html
7. PyPI attestations, 2024-11-14 — https://blog.pypi.org/posts/2024-11-14-pypi-now-supports-digital-attestations/
8. Velociraptor single-binary deployment — https://github.com/Velocidex/velociraptor
