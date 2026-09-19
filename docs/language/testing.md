# Testing scripts

JOCKY ships a test facility in the language itself. A `.jky` file can assert its
own behaviour, and `jocky test` runs a directory of those files, reports every
check and exits non-zero when one fails.

```bash
jocky test tests/lang                 # the corpus in this repository
jocky test my/scripts                 # your own
jocky test scripts/triage.jky --json  # one file, machine-readable
```

```
PASS  01_arithmetic.jky                  22 check(s)  (0 ms)
PASS  02_strings.jky                     38 check(s)  (1 ms)
...
all green: 12 file(s), 456 check(s), 0 failed, 0 error(s), 0 skipped in 2513 ms
```

## The assertions

Five natives record checks against the run; they never abort the file unless the
error is uncaught.

| Native | Checks | Fails when |
|---|---|---|
| `assert(condition, label)` | the condition is truthy | it is falsy |
| `expect(actual, expected, label)` | deep equality | the values differ |
| `expect_throws(closure, label, substring)` | the closure raises a *catchable* error (optionally containing `substring`) | nothing was raised, the wrong error came back, or a budget was hit instead |
| `fail(label)` | — | always (for a branch that must not be reached) |
| `skip(label)` | — | never; the check is recorded as skipped |

`expect` compares structurally, so lists and maps are compared by value:

```jocky
expect(2 + 3 * 4, 14, "precedence")
expect([1, 2] == [1, 2], true, "structural equality")
expect("x={7}", "x=7", "interpolation")

expect_throws(fn() { return 1 / 0 }, "division by zero is catchable", "division by zero")
expect_throws(fn() { return mem.syscall(39) }, "capabilities are denied by default",
              "capability is disabled")

if fs.exists("/etc/shadow") {
  expect(len(fs.hash("/etc/shadow")), 64, "SHA-256 of a readable file")
} else {
  skip("no /etc/shadow on this host")
}
```

A check that fails is reported with its label and the observed difference; the
file keeps running so you see every failure in one pass:

```
FAIL  03_collections.jky                 39 check(s)  (1 ms)
       ✗ sort does not mutate the original: expected [3,1,2], got [1,2,3]
```

## What a test file is

A test file is an ordinary script. There is no special syntax, no test-runner
harness to import and no fixture system: the assertions are natives, so anything
a script can do (read `/proc`, call `det.triage()`, spawn a `memfd` payload) a
test can assert.

Two consequences worth knowing:

1. **Host-dependent checks must be written as invariants.** `assert(len(proc.list(50)) > 0)`
   holds on any running Linux host; `expect(len(proc.list()), 137)` holds only on
   the machine where it was written. The corpus in `tests/lang/` is entirely
   invariant-based so it passes on any Linux host.
2. **Ordering is execution order.** Functions are globals bound when their `fn`
   statement runs, so declare a helper before the line that calls it.

## Running under confinement and with capabilities

`jocky test` accepts the same execution controls as `jocky run`, which makes it
a capability test rather than only a regression test:

```bash
jocky test tests/lang --sandbox=ro        # every file under Landlock
jocky test tests/lang --sandbox=strict    # + no sockets (seccomp)
jocky test tests/lang --allow syscall     # granted capabilities
jocky test tests/lang --wall-ms 5000      # per-file wall-clock budget
```

Measured on the development host: the corpus is green unconfined (**456 checks**)
and green under `--sandbox=strict` (**375 checks** — fewer, because
host-dependent branches legitimately take the other path when confinement hides
another process's `/proc` entries).

`11_capabilities.jky` asserts the *default* posture — raw syscalls and memfd
execution refused — so running the corpus with `--allow syscall` makes it fail on
purpose. That is the capability gate working, not a broken test.

## The corpus in this repository

| File | Covers |
|---|---|
| `01_arithmetic.jky` | precedence, division and modulo, literal forms, integer width |
| `02_strings.jky` | escapes, interpolation, methods, concatenation |
| `03_collections.jky` | lists, maps, methods, copy-vs-mutation, higher-order helpers |
| `04_control_flow.jky` | branches, loops, loop control, short-circuit evaluation, truthiness |
| `05_functions.jky` | declarations, lambdas, recursion, arity errors |
| `06_closures.jky` | shared cells, independent instances, loop binding |
| `07_errors.jky` | catchable errors, cross-frame unwinding, messages, `expect_throws` |
| `08_types.jky` | the eight value kinds, equality, conversions, `len()` |
| `09_builtins.jky` | the standard library and JSON round trips |
| `10_iteration.jky` | iteration order, UTF-8, large loops, break-on-match |
| `11_capabilities.jky` | the deny-by-default posture and the read-only probes |
| `12_collectors.jky` | collector shapes and invariants on a live host |

## Why write assertions in the language at all

Because the corpus is the artefact a reviewer reads to learn what the language
promises. `tests/lang/01_arithmetic.jky` states, in a file anyone can run, that
`/` is true division and that `7 % 3` is `1`; the Python suite next to it tests
the compiler tables and the VM internals, which is a different question.

It also earns its keep as a defect finder: the first run of this corpus found
three real defects in the language (member names could not be keywords, so the
map `set` method was unreachable; `float()` raised where `int()` was permissive;
`list.sort()` mutated its receiver while the global `sort()` copied it), all of
which are fixed and now pinned by the checks above.
