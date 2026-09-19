# Contributing

How to work on JOCKY: the layout of the tree, the edit-run-test loop, the kind of test this project expects, and how to add a native, a check or a language feature.

The runtime is Python 3.12 with the standard library only: `pyproject.toml` declares
`dependencies = []`, and a collection tool that needs a package index is one that fails on
a target host. Everything runs on Linux and reads `/proc`, `/proc/net` and `/sys` directly.

## Repository layout

| Path | Contents |
|---|---|
| `jocky/lang/` | the language: `lexer.py` → `parser.py` (+ `nodes.py` AST) → `compiler.py` (bytecode) → `vm.py` (stack VM and native dispatch) |
| `jocky/poly/` | polymorphic artifact encoder: `wire.py` (format, opcode indices) and `encoder.py` (per-build mutation) |
| `jocky/rt/` | collectors (`procfs.py`, `netfs.py`, `filefs.py`, `sysinfo.py`, `raw.py`), detection (`detect.py`) and the script-facing bridge (`builtins.py`) |
| `jocky/exec/`, `jocky/agent/` | memfd primitives and fileless execution; TLS management server (sqlite job/finding store) and polling agent |
| `jocky/runner.py`, `jocky/cli.py` | the execution entry point (source, artifact, fileless) and the `jocky <command>` surface |
| `jocky/evidence.py`, `jocky/diagnostics.py`, `jocky/scaffold.py`, `jocky/case.py`, `jocky/canon.py` | proof harness, `doctor`, `init`, and case-directory integrity |
| `scripts/`, `jocky/examples/`, `tests/`, `evidence/` | bundled JOCKY scripts; the behavioural suite; the generated proof bundle (raw logs + `report.md`) |
| `docs/` | the documentation: `language/` (the syntax manual), `runtime/`, `security/`, `operations/`, `execution/`, plus the design notes, install guide, verification tests, evidence ledger and evasion report |

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

The artifact size and digest differ on every build — that is the encoder doing its job, not
a regression. Findings go to stdout as one JSON object per line; `exec` adds a one-line
summary, `run` does not, and `--json` prints the whole run result instead, which is what you
want when checking `errors`, `steps` or `truncated`.

`jocky disasm <script>` shows the bytecode the compiler produced, which is the fastest way
to see whether a language change reached the compiler:

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
`addopts = "-q --tb=short"`), so the scoped run above needs no flags; adding `-q` again
suppresses the pass/fail summary line.

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

There is no formatter or linter configuration in the tree — no `ruff`, `black` or
`flake8` section in `pyproject.toml`. The one workflow,
`.github/workflows/polymorphism.yml`, is not a lint gate: it runs the suite and the
polymorphism/claims checks that the project actually makes claims about. Match the file
you are editing:

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
2. **Register it.** In `namespaces()`, add an entry to the namespace dict — `_fn(name,
   callable, min_args, max_args)` builds the `NativeFn`, and the last two arguments are the
   VM's arity contract, so `1, 1` means exactly one argument. Coerce script values with the
   helpers next to it (`_int`, `_str`, `_bool`, `_list`) rather than trusting the type.
3. **Guard what needs a grant.** A native that can signal processes or run code is
   deny-by-default: wrap it with `_guarded(fn, capability)` and add the capability and
   its justification to `GUARDED_CAPABILITIES`. `mem.syscall` and `mem.memfd_run` are
   the two current examples; `jocky run --allow syscall` is how a caller grants one.

An entry is one line per call, next to the existing ones:

```python
proc_ns = {
    ...
    "pids": _fn("proc.pids", lambda vm, a: procfs.list_pids(), 0, 0),
    "threads": _fn("proc.threads", lambda vm, a: procfs.read_threads(_int(a[0])), 1, 1),
}
```

The VM enforces arity before your code runs, as a catchable error:

```text
arity ok   : [98] []
arity bad  : ['proc.pid_count() expects at most 0 argument(s), got 1']
```

A new native must also appear in `docs/runtime/api.md` (or
`docs/language/standard-library.md` for a core builtin), which lists every namespace
entry with its arity range. Nothing regenerates or validates those pages — they are
maintained by hand, so updating the row is part of the change, not an afterthought.

Add a test to `tests/test_runtime.py` for the collector's behaviour: call it against the
live host and assert the shape and the invariant, as the existing collector tests do.

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
   to move together.
3. Add the function to the tuple in `triage()`. Only cheap checks belong there: the
   expensive ones (`memfd_mappings`, `persistence`) run behind `deep=True`, and
   everything in the default path runs on every `det.triage()` call. `triage()` catches
   per-check exceptions and reports them as `check_error` rather than aborting, but a
   check that raises on normal hosts is still a defect.
4. Extend `tests/test_runtime.py`: one behavioural test proving the check fires on a real
   artefact you create (that is why the file already has a temp file, a socket fixture and
   a deleted-open-file test), and one proving it does not fire on the benign version of
   that artefact.
5. Update `docs/runtime/detection.md`, which lists every entry in `CHECK_CATALOG`. The
   page is hand-maintained — nothing regenerates it — so the row is part of the change.
   (`tests/test_runtime.py` does assert that `CHECK_CATALOG` and the names actually
   emitted by `_finding()` agree in both directions, which is the half a machine can
   check.)
6. Tune for false positives before you commit. Checks were narrowed against the
   development host until the finding set was explainable: the hidden-module check, for
   instance, compares `/proc/modules` against the *loadable* subset of `/sys/module`,
   because built-in subsystems never appear in `/proc/modules`.

Step 2 is what keeps the reference page honest: every name passed to `_finding()` in
`jocky/rt/detect.py` must have a catalogue entry, and the current tree has no name on one
side missing from the other.

```text
emitted not in catalog: []
catalog not emitted  : []
```

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

## Working on the documentation

The documentation is plain markdown under `docs/`, read directly on the repository host.
There is no site build, no generator and no `npm` step — if you find yourself wanting one,
edit the markdown instead.

| Directory | Contents |
|---|---|
| `docs/language/` | the syntax manual: `reference.md` (normative grammar and semantics), `basics.md`, `functions-errors.md`, `patterns.md`, `standard-library.md`, `testing.md` |
| `docs/runtime/` | the collector reference (`collectors.md`), the native API (`api.md`), the detection-check reference (`detection.md`) |
| `docs/security/` | `limits.md` (what the runtime refuses to do) and `threat-model.md` |
| `docs/operations/` | `cli.md`, `management.md`, `evidence.md`, `rules.md`, `versioning.md` |
| `docs/execution/` | `modes.md`, `artifacts.md`, `fileless.md` |

The pages at the repository root — `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`,
`SECURITY.md`, `LICENSE` — are the front door, and `docs/DESIGN.md`, `docs/INSTALL.md`,
`docs/VERIFY.md`, `docs/ARCHITECTURE.md`, `docs/EVIDENCE.md` and `docs/EVASION.md` are the
top-level reports the problem statement asks for. `docs/PROJECT-AUDIT.md` grades every
claim in the repository against the command that proves it, and
`docs/AUDIT-2026-09-17-runtime-modules.md` is an adversarial audit of the two newest
runtime modules, with a reproduction for each finding.

Four documents state counts that also live in the tree, and `tools/claims_audit.py` is what
keeps them honest — it reads `README.md`, `CHANGELOG.md`, `docs/INSTALL.md` and the
measurement line in `docs/EVIDENCE.md`, and fails when a stated number and the tree
disagree:

| Document | Must agree with |
|---|---|
| `docs/language/standard-library.md` | `jocky.rt.builtins.core_builtins()` |
| `docs/runtime/api.md` | `jocky.rt.builtins.namespaces()` |
| `docs/runtime/detection.md` | `jocky.rt.detect.CHECK_CATALOG` |
| `docs/operations/cli.md` | `jocky.cli.build_parser()` |
| `docs/project/releases.md` | `git tag` |

When you write a page:

- no frontmatter: the page title is the first `#` heading, and the first paragraph is the
  summary a reader sees first, so make it a real one;
- tag fenced code blocks (`jocky`, `bash`, `python`, `json`, `text`) so they render;
- link between pages with **relative** paths, as in
  `[Fileless execution](docs/execution/fileless.md)` from the repository root, or
  `[Fileless execution](../execution/fileless.md)` from inside another `docs/`
  subdirectory. A leading-slash path like `/docs/execution/fileless` resolves against a
  site root that no longer exists and is a dead link on the repository host.

Every command and output on a page should be one you actually ran on a checkout: treat a
quoted terminal session the way you treat a test assertion, as a claim that has to keep
being true.

## Commits and releases

The version string has one home: `jocky/__init__.py`. `pyproject.toml` reads it
dynamically and `jocky --version` prints it. `tools/claims_audit.py` compares it against
the newest tag and reports a mismatch as a note rather than a failure.

Releases in this repository are annotated tags — `git tag -l` currently lists `v1.1.0` and
`v1.2.0`, both dated 2026-09-15, with the commit each tag dereferences to shown on the
[releases page](docs/project/releases.md). The release commit names the version it ships
(`v1.2.0: Landlock sandbox, docs site and release versioning`), and the tag annotation is a
one-line summary of the same release.

Keep a change reviewable on its own: one behaviour change, its tests, and — if you touched
a native, a check, a CLI flag or the version — the corresponding page under `docs/` in the
same commit. Prose changes go in `CHANGELOG.md` (the file of record), newest release
first, under `Added` / `Changed` / `Fixed` / `Security`.

Cutting a release, in the order the tooling and the tag history assume:

1. bump `__version__` in `jocky/__init__.py`;
2. run the suite (`./venv/bin/python -m pytest tests/ -q`);
3. regenerate the evidence bundle (`./venv/bin/python -m jocky evidence --iterations 1000 --out evidence`) and re-read `evidence/report.md` — the numbers the documents state are these
   numbers;
4. write the release section in `CHANGELOG.md` and update the counts in `README.md` and
   `docs/EVIDENCE.md` that the new version moves;
5. run `./venv/bin/python tools/claims_audit.py` and require `no drift` — it reads the
   README, this file, `docs/INSTALL.md` and the evidence ledger, so a stale number fails
   here rather than in front of a reader;
6. commit with the version in the subject, create the annotated tag `vX.Y.Z`, and push
   both.
