# Functions & errors

Functions are the only abstraction JOCKY has: no classes, no modules. They
come in two forms — named declarations and lambdas — and both close over the
enclosing function's variables **by reference to a shared cell**, which is what
makes counter-style state, callbacks and the higher-order helpers work.

Everything below was executed with this repository's CLI; output blocks are
verbatim.

## Declaring functions

```jocky
fn severity(score) {
  if score >= 9 { return "critical" }
  if score >= 7 { return "high" }
  return "low"
}
print(severity(9), severity(7), severity(3))

fn no_return(x) { }
print(type(no_return(0)), no_return(0))

let scale = fn(x, k) { return x * k }
print(scale(4, 5))
print(type(scale), type("".upper))
```

```text
critical high low
nil nil
20
fn fn
```

* `fn name(params) { … }` is a statement; `fn(params) { … }` is a lambda
  expression that can be assigned, passed or returned.
* Parameters are positional and fixed. There are no defaults, no varargs and no
  keyword arguments. Arity is checked at the call:
  `severity() expects 1 argument(s), got 0`.
* Falling off the end of a body (or `return` with no value) yields `nil`.
* Functions are ordinary values: `type(f)` is `fn`, they can live in lists and
  maps, and `m.handler(x)` or `m["handler"](x)` both call one stored in a map.
* A named `fn` declaration binds where a local of that name already exists (a
  parameter, or an earlier `let` in the same function); otherwise the closure
  is stored under that name in the globals. A `fn` declared inside another
  function is therefore callable from outside it unless the name was already a
  local — the compiled listing shows `STOREG` in the first case and `STOREL`
  in the second.

## `return`, and the newline trap

Statements are separated by whitespace, so a `return` written on its own line
is **not** a bare return unless the next token is `}` or end of input. In this
example `f` returns the result of the next statement:

```jocky
fn f() {
  return
  print("inside f after return")
}
print("f -> {f()}")
fn g() {
  if true { return }
  print("g fell through")
}
print("g -> {g()}")
```

```text
inside f after return
f -> nil
g -> nil
```

`f` prints because `return print(…)` parsed as one statement — and `print`
returns `nil`, so `f -> nil`. In `g` the `return` is directly before `}`, so it
is a real bare return and the line after it never runs. If a value-less return
must be followed by more code, write it as the last statement of the branch.

## Closures and shared mutable capture

```jocky
fn counter_from(start) {
  let n = start
  return fn() {
    set n = n + 1
    return n
  }
}
let a = counter_from(0)
let b = counter_from(100)
print(a(), a(), a(), b(), a())

fn pair() {
  let hits = 0
  fn bump() { set hits = hits + 1 }
  fn read() { return hits }
  return [bump, read]
}
let p = pair()
p[0]()
p[0]()
print("shared cell read through the second closure: {p[1]()}")
```

```text
1 2 3 101 4
shared cell read through the second closure: 2
```

### What the compiler actually does

When a nested `fn` refers to a variable of the enclosing function, the compiler
promotes that enclosing **local slot** to a *cell*: a one-element box. The
parent no longer copies the value into the closure; it pushes the box itself
(`PUSH_CELL`) while constructing the closure (`MK_FN`), and every read or write
of the variable inside the closure goes through the box (`LOAD_CELL`,
`STORE_CELL`). Consequences, all visible above:

* **Writes are shared.** `a()` increments one cell three times, giving
  `1 2 3`. `b` was created by a different activation of `counter_from`, so it
  has its own cell starting at `100` — closures never share state across calls
  unless the cell was created once and captured by several closures, which is
  what `pair()` does: `bump` writes the cell and `read` observes `2`.
* **Capture is by cell, not by copy**, so the two closures in `pair()` see each
  other's writes without any argument passing.
* **A loop body is one activation.** The loop variable and any `let` inside the
  body occupy a single cell reused for every iteration, so closures made in a
  loop all observe the final value:

```jocky
let fns = []
for i in [1, 2, 3] { fns.push(fn() { return i }) }
print(transform(fns, fn(f) { return f() }))

let gs = []
for i in [1, 2, 3] {
  let doubled = i * 2
  gs.push(fn() { return doubled })
}
print(transform(gs, fn(g) { return g() }))
```

```text
[3,3,3]
[6,6,6]
```

If you need per-iteration values, capture them with a factory function that
takes the value as a parameter (`counter_from` above), which creates a fresh
cell per call.

* **Capture is decided lexically, at the point of definition.** A function can
  only capture names that are already in scope where it is written:

```jocky
fn later() { return x }
let x = 5
print(later())
```

```text
error: undefined name 'x'
```

Declare the variable before the function that uses it, or pass it as a
parameter.

## Higher-order use

`transform`, `filter`, `sort_by`, `count`, `sort` and `join` are runtime
built-ins that call back into the VM (`call_value`), so a JOCKY closure can be
passed anywhere a function is expected:

```jocky
let procs = [
  {"pid": 30, "name": "sshd", "score": 2.5},
  {"pid": 12, "name": "memfd:python3", "score": 9.0},
  {"pid": 7, "name": "curl", "score": 6.25}
]
print(transform(procs, fn(p) { return p.pid }))
print(transform(filter(procs, fn(p) { return p.score > 5 }), fn(p) { return p.name }))
print(transform(sort_by(procs, fn(p) { return p.score }), fn(p) { return "{p.pid}:{p.score}" }))
print(count(procs), count(procs, fn(p) { return p.score > 5 }))

fn above(t) { return fn(p) { return p.score > t } }
print(count(procs, above(7)))
try { transform(procs, 5) } catch err { print("callback: {err}") }
try { count(procs, fn(a, b) { return true }) } catch err { print("arity: {err}") }
```

```text
[30,12,7]
["memfd:python3","curl"]
["30:2.5","7:6.25","12:9"]
3 2
1
callback: int is not callable
arity: <lambda>() expects 2 argument(s), got 1
```

`transform` maps, `filter` keeps items whose callback is truthy, `sort_by`
sorts ascending on the key returned by the callback (stable), and `count`
without a callback returns the length. Passing a non-callable, or a callback
whose parameter count does not match, raises a catchable error naming the
problem. `above(t)` shows the idiomatic way to build a predicate with
configuration bound in its cell.

## The error model

A runtime problem raises a catchable error. `try { … } catch name { … }`
binds **the message string** to `name`; there are no error objects, no
backtraces and no re-raise:

```jocky
fn probe(label, thunk) {
  try {
    print("{label}: ok -> {thunk()}")
  } catch err {
    print("{label}: {err}")
  }
}
probe("undefined name", fn() { return nope })
probe("divide by zero", fn() { return 7 / 0 })
probe("modulo by zero", fn() { return 7 % 0 })
probe("type mismatch", fn() { return 1 + nil })
probe("bad comparison", fn() { return 1 < "a" })
probe("index range", fn() { return [4, 5][9] })
probe("unknown member", fn() { return "s".no_such() })
probe("wrong arity", fn() { return len() })
probe("not callable", fn() { return (5)() })
probe("not iterable", fn() { for q in 5 { print(q) } })
```

```text
undefined name: undefined name 'nope'
divide by zero: division by zero
modulo by zero: modulo by zero
type mismatch: cannot add int and NoneType
bad comparison: cannot compare int < str
index range: index 9 out of range (length 2)
unknown member: string has no member 'no_such'
wrong arity: len() expects at least 1 argument(s), got 0
not callable: int is not callable
not iterable: cannot iterate over int
```

Note the host type names (`NoneType`, `int`, `str`) in the messages: the
runtime is Python underneath and does not translate them. Errors raised by
native functions surface the host exception with its class as a prefix — for
example `"abc".to_int()` yields a catchable
`ValueError: invalid literal for int() with base 10: 'abc'`.

`error(message)` raises your own catchable error, and an error raised inside a
callee is caught by the **caller's** handler — the unwinder discards the callee
frames until it finds a matching protected region:

```jocky
fn inner(n) {
  if n == 0 { error("inner refused at n=0") }
  return n
}
fn outer(n) { return inner(n) }

try { outer(0) } catch err { print("caller caught: {err}") }
try { "abc".to_int() } catch err { print("host error: {err}") }
print("outer(3) = {outer(3)}")
```

```text
caller caught: inner refused at n=0
host error: ValueError: invalid literal for int() with base 10: 'abc'
outer(3) = 3
```

### Uncaught errors

An error with no active handler stops the program. Everything collected before
it is kept — findings, printed output — and the message is appended to
`result.errors`, which makes `jocky run` exit `1`:

```jocky
emit {"kind": "collected", "pid": 11}
print("printed before the failure")
let x = 1 / 0
print("never reached")
```

```text
{"kind": "collected", "pid": 11}
printed before the failure
error: division by zero
```

The first two lines are stdout (the finding and the printed line); the
`error:` line is stderr. With `--json` the same run reports
`"errors": ["division by zero"]` alongside the preserved `findings` and
`output`. A script that must not leave a partial investigation behind should
wrap risky collection in `try`/`catch` and `emit` what it did get: the findings
collected before the failure are part of the result either way, and an agent
reports such a job's status as `error` rather than `ok`.

## Safety budgets

Three limits stop a hostile or broken script from wedging a collection run:
a step count, a wall-clock deadline and a call-depth ceiling. All three are
**uncatchable** — a `catch` cannot swallow them — and all three set
`truncated: true` in the result.

```jocky
emit {"kind": "started", "note": "counting"}
let total = 0
try {
  while true { set total = total + 1 }
} catch err {
  print("caught inside: {err}")
}
emit {"kind": "done", "total": total}
```

```bash
jocky run budget.jky --max-steps 50000 --json
```

```text
{
  "findings": [
    {
      "kind": "started",
      "note": "counting"
    }
  ],
  "output": [],
  "errors": [
    "step budget exceeded (50000 instructions)"
  ],
  "steps": 50001,
  "native_calls": 0,
  "duration_ms": 40.053,
  "truncated": true
}
error: step budget exceeded (50000 instructions)
```

The `catch` never ran, the `emit` before the loop survived, and the run exited
`1`. With a wall-clock limit instead:

```bash
jocky run budget.jky --wall-ms 150
```

```text
{"kind": "started", "note": "counting"}
error: wall-clock budget exceeded
```

Call depth is capped as well; an unbounded recursion stops with a limit error
that no handler can catch:

```jocky
fn depth(n) { return depth(n + 1) }
try { depth(0) } catch err { print("caught inside: {err}") }
print("never reached")
```

```text
error: call depth exceeded (256 frames)
```

| Limit | Default | Set by |
|---|---|---|
| VM steps | 50,000,000 | `jocky run --max-steps N` |
| Wall clock | 60,000 ms | `jocky run --wall-ms N`, `jocky exec --wall-ms N`, `jocky fileless --wall-ms N` |
| Call depth | 256 frames | `VM(max_frames=…)`; not exposed on the CLI |

Two details that matter when you size a budget:

* The step budget is exact: the run stops at the first instruction that takes
  the count past the limit, which is why the counter above reads `50001`.
* The wall-clock budget is sampled every 1024 VM instructions **and** when a
  native returns, because a call is one instruction: a deadline that passes
  while it runs is noticed when it comes back, not during it. That makes an
  overrun *visible* rather than silent — `sleep(0.4)` under `--wall-ms 100`
  prints `start`, then reports `error: wall-clock budget exceeded`, exits `1`,
  and `--json` shows `truncated: true` with `duration_ms` ≈ 400. The call itself
  still runs to completion (there is no way to interrupt a syscall from inside
  the VM), so the limit bounds what the *script* does next, not how long the
  native takes.

## Related pages

* [Language basics](basics.md) — values, syntax, operators,
  truthiness, `emit` vs `print`.
* [Reference](reference.md) — the instruction set the compiler
  emits for closures, calls and handlers.
* [Standard library](standard-library.md) — `transform`, `filter`,
  `sort_by`, `count` and the rest of the built-ins.
* [CLI reference](../operations/cli.md) — the flags that set the budgets.
