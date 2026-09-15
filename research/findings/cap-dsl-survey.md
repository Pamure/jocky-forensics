# cap-dsl-survey — comparable languages: host access, permission, testing

## Scope

Eleven languages/rule formats used in endpoint/network forensics and policy:
kind, host access, sandbox/permission, testing, and one thing JOCKY should copy
— then the closest analogue. Repo claims cite `file:line`; external ones a URL
(accessed 2026-09-16).

## How others do it

1. **VQL** — SQL + plugins; plugins inherit client privileges (no security
   boundary) and `cpu_limit`/`iops_limit` die when a plugin shells out [1][2].
   → budgets as artifact data.
2. **osquery** — SQL over C++ virtual tables; mutation verbs are inert, so
   read-only by construction [3]; `profile.py` scores queries in CI [4].
   → CI gating on measured cost.
3. **Sigma** — YAML detection data, transpiled to a backend query language by
   `sigma convert` [5]; spec 2.1.0 adds JSON Schema plus
   `id`/`related`/`status` [6]. → rule identity, deprecation metadata.
4. **YARA/YARA-X** — byte-pattern DSL, no host API; YARA warns at compile time
   when a rule may slow scanning [7]. → compile-time cost warnings.
5. **KAPE** — no language: Targets/Modules are config, and Modules run external
   programs with full rights [8]. → separate collection from interpretation.
6. **Starlark** — hermetic, finite, deterministic; no environment access by
   default, values freeze after build [9]; tests via skylib `asserts` [10].
   → freeze collected data.
7. **CEL** — total, side-effect-free, terminating, gradually typed [11]; static
   `EstimateCost` plus a runtime cost limit reject runaway expressions [12].
   → reject expensive work before running.
8. **Rego/OPA** — Datalog-derived policy over `input`/`data`; `opa test` finds
   `test_` rules, mocks with `with`, reports coverage [13]. → test-rule
   convention with mocking.
9. **Datalog (Soufflé)** — stratified declarative relations compiled to C++,
   with provenance for derived facts [14]. → fixpoint rules for transitive
   closure.
10. **Nuclei** — YAML templates with a matcher DSL; host-executing `code`
    templates need `-code` and a signature — unsigned never run [15].
    → signature-gated executable content.
11. **Wireshark Lua** — full Lua plus a host API, no capability sandbox, only a
    guard refusing personal scripts under setuid root [16]. → refuse, never
    degrade silently.

**Closest analogue: Velociraptor VQL** — same problem shape: a query language
over host-native data, deployed as versioned artifacts from a central server,
with per-artifact budgets, detections in the same format. JOCKY's namespaces
mirror VQL plugins and `serve`/`agent` mirror hunts; JOCKY adds bytecode,
polymorphic artifacts and two gated natives.

## Where JOCKY stands

| Capability | Has it? | Evidence | Gap |
|---|---|---|---|
| Host-access language | Yes | 7 namespaces (`builtins.py:176-386`) | no `use` (`lexer.py:22`) |
| Permission model | Partial | `syscall`/`exec` denied by default, probe-verified (`builtins.py:31-50`); Landlock levels (`sandbox.py:37,228`) | ~60 natives ambient; sandbox default `off` (`cli.py:342`); agent trusts payloads (`agent/client.py:8-10`) |
| Resource limits | Yes | uncatchable `JockyLimitError` (`vm.py:159,264-267`) | no cost model: a native counts once (`vm.py:299`) |
| Detections as data | No | patterns hard-coded (`detect.py:163,438`); per-finding `evidence` (`detect.py:190`) | no Sigma/YARA ingestion, rule ids or derivation chain |
| Script testing | Yes (new) | `jocky test`, `assert`/`expect` (`builtins.py:172-176`, untracked `testrunner.py`) | no fixtures; needs a live host |

## Concrete improvements

1. **`needs` capability block** — undeclared namespace calls fail to compile;
   VM gets only granted namespaces. *M*, script churn.
2. **Static cost estimate** — `NativeFn(..., cost=)`, `jocky estimate
   --max-cost`; `fs.scan` escapes budgets. *S*, must stay conservative.
3. **Fixture replay** — `jocky test --record` captures collector output for
   later runs. *M*, fixture drift.
4. **Signed payload bundles** — agent refuses unsigned jobs (`jocky/case.py`
   already signs). *M*, key distribution.
5. **Sigma/YARA importer** — `detection` blocks become predicates over
   `proc`/`fs` rows. *L*, taxonomy drift.

## Verification approach

Comparisons come from the cited docs. JOCKY claims are line-cited; two
were probe-checked read-only: `jocky run` refused `mem.syscall`, then accepted
it under `--allow syscall`. The untracked test runner
(`?? jocky/testrunner.py`) is work landing now.

## Citations

1. VQL — docs.velociraptor.app/docs/vql/fundamentals/
2. Artifact resources — velociraptor-docs.org/docs/artifacts/resources/
3. osquery SQL — osquery.readthedocs.io/en/stable/introduction/sql/
4. osquery profiling — osquery.readthedocs.io/en/stable/deployment/performance-safety/
5. sigma-cli — github.com/SigmaHQ/sigma-cli
6. Sigma spec 2.1.0 (2025-08-02) — github.com/SigmaHQ/sigma-specification
7. YARA-X docs (2023-09-07) — virustotal.github.io/yara-x/docs/intro/yara-x-vs-yara/
8. KAPE — ericzimmerman.github.io/KapeDocs/
9. Starlark — github.com/bazelbuild/starlark/blob/master/spec.md
10. Bazel testing — bazel.build/rules/testing, bazelbuild/bazel-skylib
11. CEL — github.com/google/cel-spec/blob/master/doc/langdef.md
12. CEL cost — celbyexample.com/execution-cost/
13. OPA testing — openpolicyagent.org/docs/policy-testing
14. Soufflé — souffle-lang.github.io/simple
15. Nuclei — docs.projectdiscovery.io/templates/protocols/code
16. Wireshark Lua — wireshark.org/docs/wsdg_html_chunked/wsluarm.html
