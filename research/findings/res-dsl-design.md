# res-dsl-design — JOCKY v2 language features

## Scope

Six features JOCKY lacks: modules, capability typing, ADTs + pattern matching,
streaming, replay, resource contracts. Repo claims cite
`file:line`, external ones a dated source (accessed 2026-09-15); effort
S ≤ 1 day, M ≈ 1 week, L > 1 week.

## Findings

1. **No modules.** No `import`/`use` keyword (`jocky/lang/lexer.py:21-26`) or
   statement (`jocky/lang/parser.py:123-126`); scripts copy-paste instead
   (`scripts/hunt.jky:6-19` vs `scripts/triage.jky:17-19`). Impact: no shareable
   detector library or testable helper. Models: Starlark's `load`+*freezing*
   [1], Sigma's cross-document rule refs [2]. Constraint: `jocky/poly/encoder.py`
   permutes per build, so modules must be inlined **before** encoding.
2. **Ambient authority.** `jocky/lang/vm.py:163` seeds globals from the full
   native map; `jocky/rt/builtins.py:152-267` wires all seven namespaces; the
   agent accepts any base64 payload unvalidated (`jocky/agent/server.py:659-668`)
   and runs it with them (`jocky/agent/client.py:266-276`). Impact:
   `mem.syscall` (`jocky/rt/builtins.py:280-284`) gives operator-submitted code
   raw syscalls, voiding the stealth claims. WASI 0.2 exposes capabilities as
   inspectable imports, no ambient authority [3]; Flix's FileSystem effect
   is sandboxable [5]; Roc gives I/O only to a platform [4]. Nuclei shows the
   anti-pattern: sandbox-escape/RCE fixes
   gated on one global `-lfa` flag [7].
3. **Untyped errors, dict-soup.** `catch` binds `str(exc)`
   (`jocky/lang/vm.py:354`); collectors return `list[dict]`
   (`jocky/rt/detect.py:78,323`), scripts fish fields out
   (`scripts/hunt.jky:16-19`); a renamed key yields silent `nil`
   (`jocky/lang/vm.py:532-534`). Impact: failure logic is string matching;
   detector renames break scripts invisibly. Models: Flix `enum`+`match` [5],
   CEL's type-check pass [8]; Kaitai does it declaratively for binary layouts
   [15].
4. **No streaming.** `_range`/`_transform`/`_filter` materialise lists
   (`jocky/rt/builtins.py:61-72`), collectors return finished lists, and
   `MK_LIST` is unbounded (`jocky/lang/vm.py:502`). Impact: memory is O(host)
   inside a payload resident in memfd. Target shape: Tenzir TQL's typed operators
   with pushdown [10]; ProGQL avoids >100 GB materialisation [11].
5. **Determinism without replay.** A findings hash proves determinism
   (`jocky/evidence.py:92-94`), yet collectors read `/proc` directly, so no past
   run is re-executable (rr is the alternative [12]). Impact: findings are not
   independently reproducible post-incident.
6. **Contracts cover time, not memory.** Budgets are steps/frames
   (`jocky/lang/vm.py:156-159`) and wall clock (`:262-263`); a native costs one
   step regardless (`:296-310`), so `fs.scan` can exhaust RAM while
   "within budget". Wasmtime fuel meters deterministically per operator [13];
   Wasm memories declare a maximum [14]; eBPF rejects recursion [6]; AARA gives
   type-based bounds [9].

## Concrete improvements

1. **`use` modules** (Finding 1) — `use "lib/triage.jky" as T`;
   `runner.compile_source` inlines bodies under a name prefix, cycle-checked,
   before encoding. **S**. *Risk:* collisions; no `use` inside `fn`.
2. **`needs` capabilities** (Finding 2) — `program needs fs:read, proc:list`; a
   native→capability table makes undeclared calls a compile error and the host
   passes only granted namespaces to `VM(natives=…)`. `run` defaults to `needs *`;
   the agent requires declared ⊆ policy and denies `syscall`. **M**.
   *Risk:* an incomplete table is a silent hole.
3. **ADTs, `match`, typed errors** (Finding 3) — `type Finding = Fileless{pid,
   exe} | Cmdline{pid, score}`; `match f { case Fileless{p, exe} => … }`; `catch
   e` binds `{"kind": "io"|"limit"}` while `str(e)` works. **L**. *Risk:*
   encoder round-trip and wire-version tests.
4. **`|>` streaming** (Finding 4) — `proc.list() |> where(fn(p){…}) |>
   window(30)` over lazy iterators reusing `ITER_INIT` (`jocky/lang/vm.py:611`) plus `*_iter` collectors. **M**. *Risk:* per-item budget accounting.
5. **`budget` blocks** (Finding 6) — `budget { mem: 256MiB, steps: 5_000_000 }`;
   charge the deep size of native returns; exceeding it raises the existing
   uncatchable limit. **M**. *Risk:* approximate accounting.
6. **`--record`/`--replay`** (Finding 5) — all collectors behind one `Sys`
   handle; record a hashed JSONL of calls+returns and replay it, re-checking the
   findings hash and extending `jocky/runner.py:38-47`. **M**. *Risk:* fixtures
   leak host data — hash them.

## Verification approach

A script calling `fs.read` under `needs proc:list` must fail to compile; the agent must reject such a job with 400. Rename a key in
`rt/detect.py` and require a compile error in matching scripts; the
1000-build/1000-hash and 25-rebuild equivalence checks (`jocky/evidence.py`) must
still pass with modules inlined. Assert peak RSS below a ceiling on a 100k-entry
`fs.scan`. Record, spawn and kill a
process, then replay: `result.to_dict()` must be byte-identical. Under
`RLIMIT_AS` an over-budget script must report `truncated=true`, not SIGKILL.

## Citations

1. Starlark spec — raw.githubusercontent.com/bazelbuild/starlark/master/spec.md
2. Sigma correlation spec v2.1.0 — github.com/SigmaHQ/sigma-specification
3. wasi.dev/security
4. roc-lang.org/platforms
5. flix.dev
6. docs.kernel.org/bpf/verifier.html
7. github.com/projectdiscovery/nuclei/blob/dev/SECURITY_CONTEXT.md (2026-09-01)
8. github.com/google/cel-spec
9. arXiv:2304.13627 (LICS'23, dated)
10. tenzir.com/docs/explanations/pipeline
11. arXiv:2510.22400 (2025-10-25)
12. rr-project.org (dated)
13. Wasmtime `consume_fuel` — crates/wasmtime/src/config.rs
14. webassembly.github.io/spec/core (Wasm 3.0, 2026-09-11)
15. kaitai.io (Kaitai Struct 0.11, 2025-09-07)
