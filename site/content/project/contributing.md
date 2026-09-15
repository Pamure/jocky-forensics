# Contributing

How to work on JOCKY: the layout of the tree, the edit-run-test loop, the kind of test this project expects, and how to add a native, a check or a language feature.

The runtime is Python 3.12 with the standard library only — `pyproject.toml` declares
`dependencies = []`, and that is a design constraint, not an accident: a collection tool
that needs a package index is one that fails on a target host.

## Repository layout

| Path | Contents |
|---|---|
| `jocky/lang/` | the language: `lexer.py` → `parser.py` (+ `nodes.py` AST) → `compiler.py` (bytecode) → `vm.py` (stack VM and native dispatch) |
| `jocky/poly/` | polymorphic artifact encoder: `wire.py` (format, opcode indices) and `encoder.py` (per-build mutation) |
| `jocky/rt/` | collectors (`procfs.py`, `netfs.py`, `filefs.py`, `sysinfo.py`, `raw.py`), detection (`detect.py`) and the script-facing bridge (`builtins.py`) |
| `jocky/exec/`, `jocky/agent/` | memfd primitives and fileless execution; TLS management server (sqlite job/finding store) and polling agent |
| `jocky/runner.py`, `jocky/cli.py` | the execution entry point (source, artifact, fileless) and the `jocky <command>` surface |
| `jocky/evidence.py`, `jocky/diagnostics.py`, `jocky/scaffold.py`, `jocky/case.py`, `jocky/canon.py` | proof harness, `doctor`, `init`, and case-directory integrity |
| `scripts/`, `jocky/examples/` | the bundled JOCKY scripts (`jocky examples` lists them) |
| `tests/`, `evidence/` | the behavioural suite and the generated proof bundle (raw logs + `report.md`) |
| `site/`, `docs/DESIGN.md`, `research/` | the documentation site; the design notes (language spec, artifact format, telemetry matrix); the background research |

## The development loop

The checkout ships a virtual environment with the package installed, so scripts and
tests run without a build step. Start by asking the tool whether this host can do what
you are about to test:

```bash
$ ./venv/bin/python -m jocky doctor
RUNTIME
  [ok  ] python >= 3.12               3.12.3
...
FILELESS
  [ok  ] memfd_create                 available
  [ok  ] fileless end-to-end          exe=/memfd:python3 (deleted) memfd_maps=4

ready: 12 ok, 1 warning(s), 0 failure(s) in 183 ms
```

(The elided groups are `PACKAGING`, `COLLECTION`, the direct-syscall probe, `CONFINEMENT`
and `MANAGEMENT`.) A warning is not a failure: `effective uid 1000` means the collectors
will report your own processes and only what you may read, which is the normal state on a
workstation.

### Run what you changed

```bash
# a script from the repository (uptime, listener and process counts are this
# host's at the moment of the run)
$ ./venv/bin/python -m jocky run scripts/smoke.jky
{"kind": "smoke", "total": 1225, "doubled": 2450, "uptime_s": 22634.08, "listeners": 19, "processes": 93}

# the same script as a polymorphic artifact
$ ./venv/bin/python -m jocky build scripts/smoke.jky -o /tmp/smoke.jky.build
wrote /tmp/smoke.jky.build (2198 bytes, sha256 025515af1833fae9...)
$ ./venv/bin/python -m jocky exec /tmp/smoke.jky.build
{"kind": "smoke", "total": 1225, "doubled": 2450, "uptime_s": 23092.2, "listeners": 21, "processes": 115}
# 1 finding(s), 0 error(s), 467 steps, 20.1 ms
```

The artifact size and digest differ on every build — that is the encoder doing its job,
not a regression. Findings go to stdout as one JSON object per line, with a one-line
summary after them; `--json` (accepted by `exec`, `fileless` and `memfd`) prints the
whole run result instead, which is what you want when checking `errors`, `steps` or
`truncated`.

`jocky disasm <script>` shows the bytecode the compiler produced — the fastest way to
see whether a language change reached the compiler. Compile something small you can
reason about rather than a full script:

```text
$ cat /tmp/snippet.jky
let xs = [1, 2]
emit len(xs)
$ ./venv/bin/python -m jocky disasm /tmp/snippet.jky
=== constants ===
[0] 1
[1] 2
=== names ===
[0] len
=== <main> (locals=1) ===
   0  CONST      0
   1  CONST      1
   2  MK_LIST    2
   3  STOREL     0
   4  LOADG      0
   5  LOADL      0
   6  CALL       1
   7  EMIT
   8  HALT
```

### Tests

```bash
# everything (this is what the release procedure runs)
./venv/bin/python -m pytest tests/ -q

# one file while you work
$ ./venv/bin/python -m pytest tests/test_language.py
.........................................                                [100%]
41 passed in 0.14s
```

`pytest` is configured in `pyproject.toml` (`testpaths = ["tests"]`,
`addopts = "-q --tb=short"`), which is why the scoped run needs no flags; adding `-q`
on the command line is belt and braces and suppresses the pass/fail summary line.

Test files are independent and host-scoped: they read the live machine, create their
own temp files, and clean up. Nothing needs root; a test that genuinely requires a
capability the host lacks should skip with the reason (`tests/test_diagnostics.py` does
this for the end-to-end fileless probe), not fail.

The evidence harness is the other half of "did this work?": it measures behaviour over
many runs instead of one. A full run takes minutes, so during development point a small
one at a scratch directory and leave `evidence/` alone:

```bash
$ ./venv/bin/python -m jocky evidence --iterations 25 --out /tmp/docs-evidence
...
  "report": "/tmp/docs-evidence/report.md",
  "out_dir": "/tmp/docs-evidence"
```

`evidence/report.md` in the repository is generated by the release run
(`--iterations 1000 --out evidence`); treat it as build output, not as a file to edit.

### Style

There is no formatter, linter or CI configuration in the tree — no `ruff`, `black` or
`flake8` section in `pyproject.toml`, no workflow files. Match the file you are editing:

- module docstring that says *why* the module exists and which decisions matter, not
  just what it contains;
- `from __future__ import annotations`, type hints on public signatures, `_private`
  helpers for the rest;
- plain dicts and lists across module boundaries: collectors return data, callers decide
  how to present it;
- comments only where a decision needs justifying, as in the rationale blocks of
  `jocky/rt/detect.py` and `jocky/exec/fileless.py`;
- no shelling out. If a collector seems to need `ps`, `ss` or `sha256sum`, read the
  kernel interface instead — the "zero external processes" measurement in
  `evidence/report.md` is a testable claim and a stray `subprocess.run` breaks it.

## What a good test looks like here

Two files are the models. `tests/test_language.py` pins *language behaviour*: its
helpers run a script and assert on what a script can observe.

```python
def run(source: str, **kwargs):
    """Execute a script with the full runtime and return the RunResult."""
    vm = VM(natives=default_natives(), **{k: v for k, v in kwargs.items()
                                          if k in ("max_steps", "max_frames")})
    return vm.run(compile_source(source), wall_clock_ms=kwargs.get("wall_clock_ms", 20_000))


@pytest.mark.parametrize("expression,expected", [
    ("2 + 3 * 4", 14),
    ("(2 + 3) * 4", 20),
    ("20 / 4", 5.0),
])
def test_arithmetic_precedence(expression, expected):
    assert evaluate(expression) == expected
```

`tests/test_runtime.py` pins *collector behaviour* against the live host, and says so in
its docstring: "Nothing here is mocked: the tests create real files, sockets and
processes and then require the collectors to observe them." Its tests use real
artefacts — a listening socket, a temp file, a file unlinked but still open — and assert
invariants rather than machine-specific values.

What that means in practice:

- **Assert the observable contract.** `findings(source) == [[1, 3, 4]]` for a loop with
  `break`/`continue`; `result.findings` and `result.output` staying separate channels for
  `emit` and `print`. Never assert on opcode names, private helper names, or the source
  text of the implementation.
- **Cover boundaries and error paths.** `f(1)` for a two-argument function must report
  `expects 2 argument`; `xs[4]` on a one-element list must report `out of range`; `1 / 0`
  must be catchable with `try`/`catch`. A budget hit (`max_steps`, `wall_clock_ms`) is
  uncatchable and sets `truncated`.
- **Pin invariants, not snapshots.** `end > start` for every mapping, a timeline sorted by
  `mtime`, `{0, 1, 2} <= fds`, io counters that do not go backwards, kernel values equal to
  `os.uname()`.
- **Include a negative test where a false positive is the risk.** The checks were tuned
  against this host until the finding set was explainable, so the suite also asserts the
  absence of the artefact — a plain interpreter has no anonymous executable memfd
  mappings, and the two kernel module views agree.
- **Create real artefacts and clean them up.** Temp files are unlinked in `finally:`,
  sockets are closed in a fixture, temporary directories use `tempfile.TemporaryDirectory`.
- **Keep regressions once they are fixed.** The test that reproduced the bug stays, with
  the reason in the docstring: `test_io_counters_are_read_for_this_process` records that
  the path was once a literal instead of being built from the pid.

## Adding a native

A native is the only way a script touches the host. Natives live in
`jocky/rt/builtins.py`, grouped by namespace; the collector they call lives in the
matching `jocky/rt/*.py` module.

1. **Collector first.** Add a plain function to the collector module that returns
   dicts/lists and defends against races (a pid can vanish between listing and reading).
   No formatting, no printing, no exceptions for absent data — return `None`, `[]` or an
   empty dict and let the caller decide.
2. **Register it.** In `namespaces()`, add an entry to the namespace dict:

   ```python
   proc_ns = {
       ...
       "pids": _fn("proc.pids", lambda vm, a: procfs.list_pids(), 0, 0),
       "threads": _fn("proc.threads", lambda vm, a: procfs.read_threads(_int(a[0])), 1, 1),
   }
   ```

   `_fn(name, callable, min_args, max_args)` builds the `NativeFn`; the last two
   arguments are the VM's arity contract, so `1, 3` means "one to three arguments".
   Coerce script values with the helpers next to it (`_int`, `_str`, `_bool`, `_list`)
   rather than trusting the type.
3. **Guard what needs a grant.** A native that can signal processes or run code is
   deny-by-default: wrap it with `_guarded(fn, capability)` and add the capability and
   its justification to `GUARDED_CAPABILITIES`. `mem.syscall` and `mem.memfd_run` are
   the two current examples; `jocky run --allow syscall` is how a caller grants one.

The VM enforces arity before your code runs, as a catchable error:

```text
arity ok   : [98] []
arity bad  : ['proc.pid_count() expects at most 0 argument(s), got 1']
```

Nothing else is needed for the documentation: `site/tools/gen_reference.py` reads
`jocky.rt.builtins` and renders the function and its arity range, so a new native
appears in `runtime/api.md` (or `language/standard-library.md` for a core builtin) after
`cd site && npm run gen`. Verified by adding a throwaway native and regenerating the
page in memory:

```text
['| `pid_count` | 0..0 |']
```

Add a test to `tests/test_runtime.py` for the collector's behaviour — call it against the
live host and assert the shape and the invariant, exactly as the existing collector tests
do.

## Adding a detection check

Detection is the mirror image of execution: every technique the runtime can use has to
be findable by `jocky/rt/detect.py`.

1. Write the check as a module-level function returning a list of finding dicts built
   with `_finding(check, severity, title, evidence, recommendation)`. Findings must carry
   `check`, `severity`, `title` and `evidence`; `severity` is one of
   `info < low < medium < high < critical`.
2. Add the check to `CHECK_CATALOG` with `check`, `severity`, `source`, `summary` and
   `action`. The catalogue is what the documentation renders, so a check that is emitted
   without an entry is a check the reference page cannot describe; the two are expected
   to move together. In the current tree the two sets are exactly equal:

   ```text
   emitted not in catalog: []
   catalog not emitted  : []
   ```

3. Add the function to the tuple in `triage()`. Only cheap checks belong there: the
   expensive ones (`memfd_mappings`, `persistence`) run behind `deep=True`, and
   everything in the default path runs on every `det.triage()` call. `triage()` catches
   per-check exceptions and reports them as `check_error` rather than aborting, but a
   check that raises on normal hosts is still a defect.
4. Extend `tests/test_runtime.py`: one behavioural test proving the check fires on a real
   artefact you create (that is why the file already has a temp file, a socket fixture and
   a deleted-open-file test), and one proving it does not fire on the benign version of
   that artefact.
5. Regenerate the reference page (`cd site && npm run gen`) — `runtime/detection.md` is
   rendered from `CHECK_CATALOG`.
6. Tune for false positives before you commit. Checks were narrowed against the
   development host until the finding set was explainable: the hidden-module check, for
   instance, compares `/proc/modules` against the *loadable* subset of `/sys/module`,
   because built-in subsystems never appear in `/proc/modules`.

## Adding a language feature

A construct flows through five files; skipping one produces a compiler the parser cannot
reach, or a VM that cannot execute what the compiler emits.

1. **Lexer** (`jocky/lang/lexer.py`) — a keyword goes in `KEYWORDS`, an operator in
   `_ONE_CHAR_OPS` or `_TWO_CHAR_OPS`. Token kinds are `int`, `float`, `str`, `ident`,
   `kw`, `op`, `eof`, and for operators the kind *is* the operator text. Syntax problems
   raise `JockySyntaxError` with line and column.
2. **AST** (`jocky/lang/nodes.py`) — add a `@dataclass` deriving from `Node` (which
   carries `line`/`col`). The compiler walks nodes generically through
   `dataclasses.fields`, so ordinary field types are picked up by scope analysis
   automatically; anything exotic needs handling in `_walk`.
3. **Parser** (`jocky/lang/parser.py`) — recursive descent, one method per production;
   add the node to the statement or expression chain and report unexpected tokens with
   the token's position.
4. **Compiler** (`jocky/lang/compiler.py`) — emit instructions in a single pass with label
   patching for forward jumps. A new instruction goes in the `OPCODES` tuple and in the
   module docstring. Two things follow from that tuple: `jocky/poly/wire.py` indexes
   opcodes by position in it and `jocky/poly/encoder.py` permutes over it, so artifacts
   built before the change cannot be decoded by the new build — acceptable, since
   artifacts are per-build anyway. A new statement must land in `Proto.starts`, which is
   where the encoder may insert junk.
5. **VM** (`jocky/lang/vm.py`) — add the handler to the `self._ops` dispatch table and
   implement it as an `_op_*` method. Runtime errors must be catchable
   (`JockyRuntimeError`, naming what failed and with which operands); safety limits stay
   uncatchable (`JockyLimitError`). A loop construct that pushes an iterator must leave
   the stack balanced on every exit path, including `break`.

Watch the intermediate representations instead of guessing: the lexer is one command away,
and `jocky disasm` (above) shows what the compiler emitted.

```text
$ ./venv/bin/python -c "from jocky.lang.lexer import tokenize; [print(t) for t in tokenize('emit \"n={len(xs)}\"')]"
kw:'emit'@1:1
str:[('t', 'n='), ('e', 'len(xs)', 1, 10)]@1:6
eof:None@1:19
```

Tests for a language feature go in `tests/test_language.py` (semantics: precedence,
scoping, closures, error text, limits) and, if you added an instruction, in
`tests/test_poly.py`, whose round-trip test asserts that a decoded artifact produces the
same findings hash as the source.

## Working on the documentation site

The site is SvelteKit with `marked`, prerendered to static files. Content is plain
markdown under `site/content/`, served at `/docs/<slug>`:

```bash
$ cd site && npm run gen
gen_versions: current=1.2.0 tags=2 unreleased_commits=4
gen_reference: wrote site/content/language/standard-library.md (1652 bytes)
gen_reference: wrote site/content/runtime/api.md (2501 bytes)
gen_reference: wrote site/content/runtime/detection.md (6252 bytes)
gen_reference: wrote site/content/operations/cli.md (6879 bytes)
gen: 2/2 generator(s) ran
```

`npm run gen` is `node tools/gen.mjs`, which invokes the two Python generators; if
`python3` is unavailable it warns and leaves the committed output in place, so a hosted
builder without Python still deploys. `npm run dev` runs it and then starts Vite (port
5174, per `site/vite.config.js`); `npm run build` prerenders into `site/build`.

Five pages are generated and must never be edited by hand — the next `npm run gen`
overwrites them:

| Page | Generated from |
|---|---|
| `language/standard-library.md` | `jocky.rt.builtins.core_builtins()` |
| `runtime/api.md` | `jocky.rt.builtins.namespaces()` |
| `runtime/detection.md` | `jocky.rt.detect.CHECK_CATALOG` |
| `operations/cli.md` | `jocky.cli.build_parser()` |
| `project/releases.md` | `git tag`, via `site/tools/gen_versions.py` |

Everything else in `site/content/` is written by hand:

- no frontmatter: the page title is the first `#` heading, and the sidebar and search
  description come from the first paragraph, so keep that paragraph a real summary and
  on one line;
- tag fenced code blocks (`jocky`, `bash`, `python`, `json`, `text`); the highlighter in
  `site/src/lib/highlight.js` maps `jky`→`jocky`, `py`→`python` and `sh`→`bash`, and
  falls back to plain text for anything else;
- link between pages with absolute slugs: `[Fileless execution](/docs/execution/fileless)`;
- register a new page in `site/src/lib/nav.js`. A page listed there that does not exist
  fails the build (`site/src/routes/docs/[...slug]/+page.js` throws before rendering), and
  a content file that is not listed is reported as orphaned by `validate()` in
  `site/src/lib/content.js`.

Every command and output on a page should be one you actually ran on a checkout. Treat a
quoted terminal session the way you treat a test assertion — it is a claim that has to
keep being true.

## Commits and releases

The version string has one home: `jocky/__init__.py`. `pyproject.toml` reads it
dynamically, `jocky --version` prints it, and the site's version banner is generated from
it plus `git tag`.

The repository currently has no commits and no tags, so the conventions below come from
the tooling (`site/tools/gen_versions.py` documents the release procedure it expects)
rather than from a history to imitate. Keep a change reviewable on its own: one behaviour
change, its tests, and — if you touched a native, a check, a CLI flag or the version — the
regenerated documentation in the same commit. Release commits are named `release: vX.Y.Z`.

Cutting a release, in the order the tooling assumes:

1. bump `__version__` in `jocky/__init__.py`;
2. run the suite (`./venv/bin/python -m pytest tests/ -q`);
3. regenerate the evidence bundle (`./venv/bin/python -m jocky evidence --iterations 1000 --out evidence`) and re-read `evidence/report.md` — the numbers on the site are these
   numbers;
4. write the changelog entry in `site/content/project/changelog.md` (newest first,
   `Added` / `Changed` / `Fixed` / `Security`) and regenerate the site;
5. commit, then create an annotated tag `vX.Y.Z` with a one-line summary and push the
   tag; the tag is what `project/releases.md` and the version banner read.

Steps 1–4 are the part you can verify locally; 5 is the maintainer's act, and nothing in
the build depends on it until the tag exists.
