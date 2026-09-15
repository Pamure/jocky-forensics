# Language testing: conformance, differential and in-language suites

## Scope

How production languages/DSLs test their own implementation — `testdata` corpora, line-anchored diagnostics, differential runs over one corpus, property/grammar fuzzing, mutation, snapshot discipline — and what JOCKY needs. State, 2026-09-16 00:35 IST: `jocky/{lang/vm,rt/builtins,runner,sandbox,cli}.py` modified, `jocky/testrunner.py` + `tests/lang/` untracked; `jocky test tests/lang` → 12 files, 462 checks, green, 2.35 s.

## How others do it

- **Diagnostics asserted in place, by substring; surplus diagnostics fail.** rustc's `//~ ERROR <substr>`, `//~^`, `//~|` annotate the offending line, every ERROR/WARN must be annotated, a missing `.stderr` golden means "expect no output" — rustc-dev-guide `tests/ui.html` (2026-05-29). ⇒ JOCKY needs message-substring assertions and an unexpected-diagnostic failure rule.
- **One corpus, two implementations, per-backend tolerance.** Go's `src/internal/types/testdata` runs under `go/types` and `types2` with column deltas 50/20/125/100; `/* ERROR "substr" */` is substring, `/* ERRORx "re" */` regexp, anchored at the preceding token — `cmd/compile/internal/types2/README.md:53-67` (Go 1.25.7). Fixtures sit in a tree the toolchain refuses to build (`cmd/go/internal/search/search.go:148-153`), which also holds fuzz seeds replayed as regressions — https://go.dev/doc/security/fuzz. ⇒ JOCKY's source/artifact/fileless paths are three backends, and the corpus needs a boundary pytest cannot collect.
- **Interpreter-level helpers, not just assertions.** CPython ships `script_helper.assert_python_ok/assert_python_failure`, `captured_stdout`, `check__all__` (public-surface completeness), `regrtest -R` leak hunting — https://docs.python.org/3/library/test.html (3.14.7), `Lib/test/support/__init__.py:891-924,1834`. ⇒ a meta-test that every `default_natives()` name appears in the corpus is the `check__all__` analogue.
- **Round-trip is the first property; unparsable output must fail, not skip.** Hypothesis recommends encode/decode round trips and terminal-branch-first recursion, else shrinking degrades (hypothesis.readthedocs.io/en/latest/reference/strategies.html); the UPenn round-trip note (2023-12-07) warns that discarding unparsable printer output deletes the bug you want. ⇒ `decode(encode(p))` over the corpus.
- **Generators must be always-valid, seed-deterministic, locally mutating** — wasm-smith's three properties; Wasmtime's `differential` target runs one corpus through several engines (github.com/bytecodealliance/wasm-tools; `wasmtime/fuzz/README.md`). A grammar-aware mutator found a crash in ~16k executions where blind mutation ran 4.2M (github.com/google/fuzzing, `structure-aware-fuzzing.md`). ⇒ a seeded stdlib generator, not Atheris (needs a wheel; `dependencies = []`).
- **Mutation grades the suite; diagnostic snapshots are the brittle half.** Just et al. FSE 2014 (canonical-but-dated) shows mutants proxy real faults only at equal coverage; `cargo mutants --in-diff -` (v27.1.0, 2026-06-02, mutants.rs/in-diff.html) scopes them per change. rustc's JSON pins `code`+span and warns off `rendered` (doc.rust-lang.org/rustc/json.html); gopls markers match substring/regex and fail on un-eliminated diagnostics; Cruz/Rocha/Valente, *JSS* 207 (2023-07) find snapshots brittle and blind-bless-prone. ⇒ affordable slice: every check must be able to fail; postpone `--bless`.

## Where JOCKY stands

- **In-language assertions per run — yes** (working tree): `assert/expect/expect_throws/fail/skip` at `jocky/rt/builtins.py:212-216`, recorded at `:106-111`, surfaced as `RunResult.checks` (`jocky/lang/vm.py:136,149,246`). Gap: entries are `{label, ok, detail}` only.
- **Corpus + CLI — yes** (uncommitted): `jocky/testrunner.py:62,74,110,137`; `cli.py:270` `cmd_test`, exit 0/1/2, flags at `:410-419`. Gap: untracked; no `-k`, no mode matrix; `failed` entries are prose (`testrunner.py:53`).
- **Failure located to a line — no:** `_record` carries no position (`builtins.py:106-111`), `JockyRuntimeError` none (`jocky/errors.py:28`), though `JockySyntaxError.render` shows line/col (`:18-22`) and the compiler records statement starts (`compiler.py:110,246`).
- **Diagnostic-message pinning — no:** `expect_throws` takes 1–2 args (`builtins.py:214`) and asserts existence only; no native compiles source, so syntax-error wording is untestable in-language.
- **Negative assertions — no:** `expect_throws` returns the recorded bool, so a "must not raise" control records a spurious failure; `tests/lang/07_errors.jky:48-52` tests only the raising direction.
- **Host-dependent files — partial:** `skip()` records but does not halt (`builtins.py:150-152`), so guards must read `if fs.exists(…) { … } else { skip("…") }`.
- **Differential across delivery modes — no** in the suite; equivalence lives only in the evidence harness (README: 25 fresh rebuilds, 0 failures).
- **Property/grammar fuzzing, mutation, golden bless — no:** nothing in `tests/` uses `random`/`hypothesis`.

## Concrete improvements

1. **Line-tagged checks** — `Proto.lines` beside `starts` (`compiler.py:110`), VM sets `frame.line`, `_record` adds `"line"`, `format_report` prints `path:line: label`. 462 checks failing as `expect:` are unactionable. **S**.
2. **`expect_throws(fn, substring?, label?)` + `expect_no_throw(fn, label?)`** — wording unpinned and negative controls inexpressible. **S**; keep `label`'s position.
3. **`jocky test --modes source,artifact`** — compile once via `runner.build_artifact`, run both, require identical `(label, ok, skipped)` sequences. **S/M**; use `--deterministic --seed-hex`, keep fileless opt-in.
4. **`tests/crashes/*.jky`** — one file per leaked host exception ("report an error, never a host exception class"). Precedent: at 00:09 `emit float("nope")` surfaced `ValueError`, fixed by 00:35. **S**.
5. **`tests/gen_programs.py`** — stdlib grammar expander (depth cap, nonrecursive escape, fixed `--seed`, always valid) asserting no host exception; minimise failures by line deletion, commit under `tests/corpus/<sha256[:16]>`. **M**; run generated programs in both modes.
6. **`tests/test_testrunner.py`** — corpus green; every `default_natives()` name and `det.CHECK_CATALOG` entry appears in the corpus. Boundary: pytest owns internals (encoder bytes, collectors, TLS/sqlite, Landlock, `VM(max_steps=…)`); the corpus owns script-visible semantics, wording, capability refusals. **S**.

## Verification approach

- `jocky test tests/lang` green; `--json` carries `path/line/label/detail`; flip one expectation → exit 1 naming the line.
- `--modes source,artifact` agrees check-for-check corpus-wide; fileless on a subset.
- Each `tests/crashes/*.jky` fails again when its fix is reverted.
- Generator: 1 000 seeded programs, zero host exceptions; failures minimised and committed.

## Citations

1. https://rustc-dev-guide.rust-lang.org/tests/ui.html (2026-05-29); https://rustc-dev-guide.rust-lang.org/tests/compiletest.html (2026-08-15).
2. `cmd/go/internal/search/search.go:148-153`, `cmd/compile/internal/types2/README.md:53-67`, https://go.dev/doc/security/fuzz (Go 1.25.7, read 2026-09-16).
3. https://docs.python.org/3/library/test.html (3.14.7); `Lib/test/support/__init__.py:891-924,1834`.
4. https://hypothesis.readthedocs.io/en/latest/reference/strategies.html; https://www.cis.upenn.edu/~plclub/blog/2023-12-07-round-trip-properties/ (2023-12-07).
5. https://github.com/bytecodealliance/wasm-tools; https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md.
6. https://homes.cs.washington.edu/~mernst/pubs/mutation-effectiveness-fse2014-abstract.html (FSE 2014, dated); https://mutants.rs/in-diff.html (2026-06-02).
7. https://doc.rust-lang.org/rustc/json.html; `gopls/internal/test/marker/marker_test.go`; https://doi.org/10.1016/j.jss.2023.111797 (2023-07).
