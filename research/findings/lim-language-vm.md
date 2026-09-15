# `lim-language-vm` — JOCKY language & VM limitations

## Scope

Audited `jocky/lang/{lexer,parser,compiler,nodes,vm}.py` and `tests/test_language.py`; behaviour reproduced
2026-09-15 via probes run under `-X pycache_prefix=…`; facts are `file:line`.

## Findings

1. **Runtime errors carry no position.** Lines survive only in compile messages (compiler.py:266,270,307);
   `Proto.starts` records instruction indices, not lines (compiler.py:110); `JockyRuntimeError` has no fields
   (errors.py:20). `emit a / 0` gives `['division by zero']`; host faults become `KeyError: 'x'` (vm.py:281).
   Impact: no line.
2. **No bytecode verifier.** `_op_jmp` sets `ip` unchecked (vm.py:491), `consts[arg]` unchecked (vm.py:262);
   `_remap_index` clamps bad targets "since the VM tolerates them" (encoder.py:183). `Proto(code=[("JMP",999)])`
   pops its frame and survives `PolyEncoder` round-trip with `errors: []`; `CONST -1` reads backwards silently.
   Impact: empty reports look clean.
3. **Too small for forensics.** No bitwise ops (`&|^~<<>>` are lexer errors, lexer.py:31), `**`, `switch`,
   `import`/modules, `raise`, `finally` (lexer.py:22-26); collectors pass mode bits as octal strings
   (`oct(mode & 0o7777)`, filefs.py:84). Impact: helpers get re-typed per script.
4. **Valid programs crash the lexer.** lexer.py:85 tests `self._peek(1) in "xXbBoO"`, which matches `""`, so a `0`
   at end-of-input indexes `{}[""]`. `emit 0` with no trailing newline → `jocky: KeyError: ''`, exit 2; `"{0}"`
   likewise.
5. **Function-wide scoping, silent aliasing.** `declare` is monotonic and name-keyed (compiler.py:145-160): block
   locals leak, re-`let` rebinds one slot, `for`/`catch` names leak. Captures see only already-declared names
   (compiler.py:367): `fn outer(){ fn inner(){ return x } let x = 5 }` fails `undefined name 'x'`; `let`-first works.
   Impact: helper hoisting breaks.
6. **Host `RecursionError` escapes.** ~100 nested parens or a ~1,000-term `+` chain raises it out of `run_source`
   (parser.py:332-362; recursive `_walk`, compiler.py:40-56). Impact: generated predicates die with no position.
7. **`try` leaks handler entries on `continue`/`break`.** `TRY_EXIT` runs only on fall-through (compiler.py:403-418);
   `continue` jumps to the loop head (compiler.py:269-272). Measured handler depth per iteration 1,2,3,4 —
   unbounded at 20k — each holding the depth `_unwind` uses for `del frame.stack[depth:]` (vm.py:353).
   Impact: unbounded memory; operand truncation.
8. **Failures coerce into empty results.** `EQ` is Python `==` (vm.py:186), so `1 == true` and `[1] == [true]`;
   `_int("abc") → 0`, `_list(nil) → []` (builtins.py:29-51), so `transform(nil, f)` is `[]`; `fs.hash("/missing")`
   is nil (filefs.py:45); `catch` binds a string. Impact: failed collection looks like "nothing found".
9. **Budgets don't bound real work.** Steps count bytecode (`len(range(500000))` = 7); the clock is sampled every
   1,024 instructions (vm.py:262), so a native call is uninterruptible; `max_frames` 256 (vm.py:157) is never passed
   by `run_program` (runner.py:62-68), recursion dies at 254 frames uncatchably.
10. **Dispatch dominates loops.** `_str/_list/_dict_method` rebuild lambda tables and a `NativeFn` per member read
    (vm.py:669-695); 100k `s.upper()` = 1,205 ms vs `len(s)` = 512 ms. `s = s + "x"` moves O(n²) bytes (8k→77 ms,
    32k→347 ms), no builder.

## Concrete improvements

1. **Line table** — record `(ip,line)` in `stmt()` (compiler.py:242), attribute errors per frame, print `path:line`;
   mirror in `wire.py`. *Why* #1. M · low risk.
2. **`verify_program`** before non-source execution: jump/handler targets in `[0,len(code)]`, `CONST`/name/`MK_FN`
   bounded, `nlocals` ≥ max slot. *Why* #2. M · rejects hand-built protos.
3. **Fix lexer.py:85** (require a non-empty base char). *Why* #4. S · nil risk.
4. **Operator surface** — bitwise, `**`, `switch`/`match` on the existing `JMPF` ladder, `try/finally`. *Why* #3,#8.
   L · re-baselines poly tests.
5. **`TRY_EXIT` before `continue`/`break`** (compiler.py:264-272), or expire handlers with `end_ip <= ip`. *Why* #7.
   S–M · low risk.
6. **Depth caps, `--max-frames`** — map `RecursionError` to `JockyCompileError`; thread `max_frames` through
   `run_program`. *Why* #6,#9. S · low risk.
7. **Structured errors** — consistent unreadable sentinel or raised error (filefs.py:45,66), `{kind,message,path}`
   catch values, a `raise` statement. *Why* #8. M · touches `rt/` contracts.

## Verification approach

One probe each under `python3 -X pycache_prefix=$(mktemp -d)`, failing first and passing after: a line-3 error
reports `:3`; crafted `JMP 999`/`CONST -1` raise `JockyArtifactError`; `emit 0` → `[0]`; `1|2` and `switch` parse;
handler depth stays 1 over 1,000 `try{continue}` iterations; 100 parens raise no `RecursionError`;
`fs.hash("/missing")` is catchable. Then `pytest tests/ -q` once and refresh `evidence/`. The cache counts too:
mid-audit the interpreter ran an older `parser.py` than the source on disk — pin a revision, use `-B`.

## Citations

- Repo refs inline (`jocky/lang/*.py`, `jocky/poly/encoder.py`, `jocky/runner.py`, `jocky/cli.py`, `jocky/rt/`).
- Velociraptor VQL (nested scopes, `LET`, artifact `export`/`imports` — the nearest DFIR peer):
  <https://docs.velociraptor.app/docs/vql/fundamentals/>, <https://docs.velociraptor.app/docs/artifacts/export_imports/>
  (living docs, 2026-09-15).
- Python tracebacks carry file/line (contrast, finding 1): <https://docs.python.org/3/tutorial/errors.html>
  (canonical, undated).
