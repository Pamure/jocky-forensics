# Language testing: conformance, differential and in-language suites

## Scope

How production languages test themselves — conformance corpora, line-anchored diagnostics, differential runs, property fuzzing, mutation, snapshots — and what JOCKY needs: v1.4.0 (`bde84eb`) already ships the facility — `jocky test tests/lang` → 12 files, 453 checks green in ~3 s.

## How others do it

- **Diagnostics asserted in place, by substring; surplus fails** — rustc's `//~ ERROR <substr>`, `//~^`, `//~|` sit on the offending line, every ERROR/WARN must be annotated, and a missing golden means "expect no output" (rustc-dev-guide `tests/ui.html`, 2026-05-29). ⇒ JOCKY needs substring assertions and a surplus rule.
- **One corpus, several implementations, per-backend tolerance** — Go's `internal/types/testdata` runs under `go/types` and `types2` with column deltas 50/20/125/100; `/* ERROR "substr" */` and `/* ERRORx "re" */` anchor substring/regexp at the preceding token (`cmd/compile/internal/types2/README.md:53-67`, Go 1.25.7), inside a tree the toolchain refuses to build (`cmd/go/internal/search/search.go:148-153`). ⇒ JOCKY's source/artifact/fileless paths are three backends; the corpus needs a boundary pytest will not collect.
- **Interpreter-level helpers** — CPython ships `script_helper.assert_python_ok/assert_python_failure` and `check__all__` (public-surface completeness) (docs.python.org/3/library/test.html, 3.14.7; `Lib/test/support/__init__.py:1834`). ⇒ a meta-test that every `default_natives()` name appears in the corpus is the analogue.
- **Round-trip first; unparsable output must fail, not skip** — Hypothesis recommends encode/decode round trips with terminal-branch-first recursion, or shrinking degrades (hypothesis.readthedocs.io/en/latest/reference/strategies.html); the UPenn round-trip note (2023-12-07) warns that discarding unparsable printer output deletes the bug you want. ⇒ add `decode(encode(p))` to the corpus.
- **Generators: always-valid, seed-deterministic, locally mutating** — wasm-smith's advertised properties; Wasmtime's `differential` target runs one corpus through several engines (github.com/bytecodealliance/wasm-tools; `wasmtime/fuzz/README.md`); a grammar-aware mutator hit a crash in ~16k executions where blind mutation ran 4.2M (github.com/google/fuzzing). ⇒ a seeded stdlib generator, not Atheris, which needs a wheel against `dependencies = []`.
- **Mutation grades the suite; diagnostic snapshots are the brittle half** — Just et al. (FSE 2014, dated) shows mutants proxy real faults only at equal coverage; `cargo mutants --in-diff -` (mutants.rs, 2026-06-02) scopes them per change. Cruz/Rocha/Valente, *JSS* 207 (2023-07) find snapshots blind-bless-prone. ⇒ every check must be able to fail; postpone `--bless`.

## Where JOCKY stands

- **In-language assertions — yes:** `assert/expect/expect_throws/fail/skip` (`jocky/rt/builtins.py:212-216`) recorded at `:106-111` into `RunResult.checks` (`jocky/lang/vm.py:136,149,246`).
- **Corpus + CLI — yes:** `jocky/testrunner.py:62,74,110,137`, `cli.py:270,411` (exit 0/1/2, `--json/--sandbox/--allow`); no `-k`, no mode matrix, and `failed` entries are prose (`testrunner.py:52`).
- **Line-located failures — no:** `_record` and `JockyRuntimeError` carry no position (`builtins.py:106-111`, `jocky/errors.py:28`), though the compiler records statement starts (`compiler.py:110,246`).
- **Message pinning — no:** `expect_throws` takes 1–2 args (`builtins.py:214`) and asserts existence only; no native compiles source, so syntax errors are untestable.
- **Negative assertions — no:** `expect_throws` returns its recorded bool, so "must not raise" records a spurious failure (`tests/lang/07_errors.jky:48-50`).
- **Host guards — partial:** `skip()` records but does not halt (`builtins.py:150-152`).
- **Mode differential, fuzzing, mutation, golden bless — no**; equivalence lives only in the evidence harness.

## Concrete improvements

1. **Line-tagged checks** — `Proto.lines` beside `starts`, VM sets `frame.line`, `_record` adds `"line"`, `format_report` prints `path:line: label`. 462 checks failing as `expect:` are unactionable. **S**.
2. **`expect_throws(fn, substring?, label?)` + `expect_no_throw(fn, label?)`** — wording unpinned, negative controls inexpressible. **S**; `label` stays second.
3. **`jocky test --modes source,artifact`** — compile once via `runner.build_artifact`, require identical `(label, ok, skipped)` sequences. **S/M**; `--deterministic --seed-hex`, fileless stays opt-in.
4. **`tests/crashes/*.jky`** — one file per host-exception leak ("an error, never a host exception class"). Precedent: pre-1.4.0 `emit float("nope")` surfaced `ValueError`. **S**.
5. **`tests/gen_programs.py`** — stdlib grammar expander (depth cap, nonrecursive escape, fixed `--seed`) asserting no host exception; minimise failures by line deletion, commit under `tests/corpus/<sha256[:16]>`. **M**.
6. **`tests/test_testrunner.py`** — corpus green; every `default_natives()` name and `det.CHECK_CATALOG` entry appears in it. Boundary: pytest owns internals (encoder, collectors, TLS, Landlock); the corpus owns script-visible semantics, wording and refusals. **S**.

## Verification approach

- `jocky test tests/lang` green; `--json` carries `path/line/label/detail`; flipping one expectation must exit 1 with the line.
- `--modes source,artifact` agrees corpus-wide; each `tests/crashes/*.jky` fails again when its fix is reverted.
- Generator: 1 000 seeded programs, zero host exceptions, failures minimised and committed.

## Citations

1. https://rustc-dev-guide.rust-lang.org/tests/ui.html (2026-05-29); https://rustc-dev-guide.rust-lang.org/tests/compiletest.html (2026-08-15).
2. `cmd/go/internal/search/search.go:148-153`; `cmd/compile/internal/types2/README.md:53-67` (Go 1.25.7, read 2026-09-16).
3. https://docs.python.org/3/library/test.html (3.14.7); `Lib/test/support/__init__.py:1834`.
4. https://hypothesis.readthedocs.io/en/latest/reference/strategies.html; https://www.cis.upenn.edu/~plclub/blog/2023-12-07-round-trip-properties/.
5. https://github.com/bytecodealliance/wasm-tools; https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md.
6. https://homes.cs.washington.edu/~mernst/pubs/mutation-effectiveness-fse2014-abstract.html; https://mutants.rs/in-diff.html (2026-06-02).
7. https://doc.rust-lang.org/rustc/json.html; https://doi.org/10.1016/j.jss.2023.111797 (*JSS* 207, 2023-07).
