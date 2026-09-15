# Language basics

JOCKY is a small dynamically typed language with one job: let an analyst write
collection and correlation logic that the runtime can execute, compile into a
polymorphic artifact, or run fileless. There are no classes, no imports and no
module system — scripts call into the built-in runtime namespaces (`proc`,
`net`, `fs`, `sys`, `det`, `ioc`, `mem`) and push structured findings out with
`emit`.

Everything on this page was executed with this repository's CLI
(`jocky 1.2.0`); the output blocks are verbatim.

## Running a script

```bash
jocky run hello.jky
```

```jocky
let pid = 4242
print("triage of pid {pid}: {type(pid)}")
```

```text
triage of pid 4242: int
```

`jocky run -` reads the script from standard input instead of a file:

```bash
printf 'print("stdin mode", 2 + 2)\n' | jocky run -
```

```text
stdin mode 4
```

Findings and printed lines are collected by the VM, not written as they happen;
the CLI then prints **all findings first, then all `print` output** (see
[`emit` and `print`](#emit-and-print) below).

## Values

Seven value types exist. `type(x)` returns the name:

```jocky
print(0xff, 0b1011, 0o17, 1_000_000)
print(2.5, 5e3, .5, 2.5e-2)
print(type(255), type(2.5), type("x"), type([2, 3]), type({"a": 2}), type(nil), type(true))
print([2, 3], {"pid": 7, "name": "curl"}, nil, true, false)
```

```text
255 11 15 1000000
2.5 5000 0.5 0.025
int float str list map nil bool
[2,3] {"pid":7,"name":"curl"} nil true false
```

| Type | `type()` | Literals |
|---|---|---|
| integer | `int` | `42`, `0xff`, `0o17`, `0b1011`, `1_000_000` |
| float | `float` | `2.5`, `.5`, `5e3`, `2.5e-2` |
| string | `str` | `"text"`, `"pid={pid}"` |
| list | `list` | `[2, 3]`, `[]` |
| map | `map` | `{"pid": 7, count: 3}`, `{}` |
| boolean | `bool` | `true`, `false` |
| nothing | `nil` | `nil` |

Maps in a literal may use bare identifiers as keys (`{count: 3}` is
`{"count": 3}`) and keys may themselves be interpolated strings. Printing a
list or map renders it as compact JSON.

Lists and maps are mutable and hold references: `let a = [2]` then
`let b = a` gives two names for one list, and `set b[0] = 3` is visible
through `a`.

## Numbers

Integers are arbitrary precision; floats are IEEE doubles. `/` is always true
division, `%` follows Python's sign rule (the sign of the divisor):

```jocky
print(7 / 2, 7 % 2, -7 % 3, 2 * 3.5)
print(9223372036854775807 + 1)
```

```text
3.5 1 2 7
9223372036854775808
```

Comparison operators (`<`, `<=`, `>`, `>=`) accept two numbers or two strings
and raise `cannot compare int < str` for anything else; `==`/`!=` compare
across int and float (`3 - 2 == 3.0 - 2.0` is `true`) and compare lists and
maps structurally.

## Strings

Only double-quoted strings exist, with these escapes:
`\n \t \r \0 \\ \" \{ \} \xNN`. An unrecognised escape keeps its backslash —
`"\d+"` is the two characters `\d+`, which matters when you write detection
patterns:

```jocky
let pid = 4242
let proc = {"cmd": "/usr/bin/curl"}
print("pid={pid} cmd={proc.cmd} sum={pid / 2}")
print("braces: {{pid}} stays literal, {pid} interpolates")
print("tab[\t] newline ->\n<- backslash[\\] quote[\"] hexA[\x41]")
print("nested { "inner {pid}" } works")
print("\d+\s" == "\\d+\\s")
```

```text
pid=4242 cmd=/usr/bin/curl sum=2121
braces: {pid} stays literal, 4242 interpolates
tab[	] newline ->
<- backslash[\] quote["] hexA[A]
nested inner 4242 works
true
```

Interpolation `{expr}` embeds any expression — member access, calls and nested
strings all work. `{{` and `}}` produce literal braces (`\{` and `\}` do the
same). An empty `{}` is a syntax error, not an empty expression.

`str` and `list` both support indexing; `str` also carries methods such as
`.upper()`, `.split()`, `.substr(start, end)`. Methods must be called:
`"abc".len` is a function value, `len("abc")` or `"abc".len()` is the number.

## Lists and maps

```jocky
let m = {}
set m[7] = "seven"
set m["kind"] = "beacon"
let xs = [4, 5]
set xs[0] = 40
print(m, m["7"], m.kind, xs, xs[-1], "abc"[1])
print(m["absent"], xs.len())
try { print(m.nope) } catch err { print("member: {err}") }
```

```text
{"7":"seven","kind":"beacon"} seven beacon [40,5] 5 b
nil 2
member: map has no member 'nope'
```

Four rules worth remembering:

* **Map keys are always strings.** `set m[7] = "seven"` stores the key `"7"`,
  and both `m[7]` and `m["7"]` find it.
* A **missing key read by index** yields `nil` (`m["absent"]`); a **missing
  member read** is an error (`m.nope`), because `.name` also has to look for
  built-in methods such as `.has`, `.get`, `.keys`.
* Negative indices count from the end, on read and on assignment
  (`set xs[-1] = 9`).
* Slicing does not exist: `xs[0:2]` is a syntax error. Use `xs.slice(0, 2)`.

## Variables: `let` and `set`

`let` introduces a name; `set` assigns to something that already exists — a
name, a member or an index. Assignment never happens with a bare `=`:

```jocky
if true { let inner = 7 }
print("visible after the block? {inner}")
set fresh = 99
print("set introduced: {fresh} / {type(fresh)}")
```

```text
visible after the block? 7
set introduced: 99 / int
```

Local names are **function-scoped**: `if`, `while` and `for` bodies do not
create a scope, so a `let` inside a block is still visible after it. The one
exception is that `set` on a name that was never declared writes a global
instead of raising — useful at the top level, a source of typos inside a
function. Reading an undeclared name is an error rather than `nil` —
`print(missing_name)` fails the run with `undefined name 'missing_name'`.

## Control flow

`if`/`elif`/`else`, `while` and `for … in` all require a brace-delimited body
— there is no single-statement form. `break` and `continue` work in both loop
kinds:

```jocky
let sev = "medium"
if sev == "low" { print("info") }
elif sev == "medium" { print("correlate") }
else { print("page out") }

let n = 0
let sum = 0
while n < 10 {
  set n = n + 1
  if n % 2 == 0 { continue }
  if n > 7 { break }
  set sum = sum + n
}
print("sum={sum} n={n}")

for item in [10, 20, 30] { print("list {item}") }
for ch in "abc" { print("char {ch}") }
for pair in {"a": 3, "b": 4} { print("map {pair[0]}={pair[1]}") }
```

```text
correlate
sum=16 n=9
list 10
list 20
list 30
char a
char b
char c
map a=3
map b=4
```

`for` accepts a list, a string (per character) or a map (per `[key, value]`
two-element list); `nil` iterates zero times. There is no `range`-style loop
keyword — `for i in range(10)` uses the built-in `range`.

The iterable is handled differently per type, and it is observable:

```jocky
let xs = [4, 5]
for x in xs {
  if x == 4 { xs.push(9) }
  print("list iteration saw {x}")
}
print("list after the loop: {xs}")

let m = {"a": 3}
for pair in m {
  set m["b"] = 4
  print("map iteration saw {pair[0]}={pair[1]}")
}
print("map after the loop: {m}")

for v in nil { print("never printed: {v}") }
print("a nil iterable runs the body zero times")
```

```text
list iteration saw 4
list iteration saw 5
list iteration saw 9
list after the loop: [4,5,9]
map iteration saw a=3
map after the loop: {"a":3,"b":4}
a nil iterable runs the body zero times
```

A list is iterated **live** — appending during the loop extends the loop
(above, the pushed `9` is visited). A map is snapshotted at loop entry, so the
entry added inside the loop is not visited. The iterator holds the list itself,
while a map iterator is built from a snapshot of its items taken at loop entry.

## Operators

Precedence, tightest first: member/index/call, unary `-`, `* / %`, `+ -`,
comparisons (`== != < <= > >= in`), `not`, `and`, `or`.

```jocky
print(1 + 2 * 3, (1 + 2) * 3, 2 * 3 + 4 * 5)
print(-2 + 3, -2 * 3, - -2)
print(7 / 2, 7 % 2, -7 % 3, 2 * 3.5, 10 / 5)
print(1 + 2 < 4, not 1 == 2, not (1 == 1))
print(2 and 3, nil or "fallback", "" or "also falsy")
print(3 < 2 < 5, 1 < 2 < 3)
print("a" + "b", "ab" * 3, [2] + [3], [7] * 3)
print(2 in [1, 2, 3], "bc" in "abcd", "k" in {"k": 2}, 9 in [2, 3])
```

```text
7 9 26
1 -6 2
3.5 1 2 7 2
true true false
3 fallback also falsy
true true
ab ababab [2,3] [7,7,7]
true true true false
```

Behaviour that is easy to get wrong:

* `and`/`or` **short-circuit and return an operand**, not a coerced boolean:
  `2 and 3` is `3`, `nil or "fallback"` is `"fallback"`. `not` always yields a
  real boolean.
* Comparisons **chain left to right** instead of behaving like Python's
  chained comparisons: `3 < 2 < 5` evaluates `(3 < 2) < 5`, which is `true`
  because `false` compares as `0`. Write `3 < 2 and 2 < 5` when you mean
  conjunction.
* `+` concatenates when either side is a string and stringifies the other
  (`"pid " + 42` is `"pid 42"`); it also concatenates two lists.
* `*` repeats a string or a list only in the `value * int` order:
  `2 * "ab"` raises `cannot multiply int by str`.
* `in` tests substrings for strings, membership for lists and key presence for
  maps; it raises `'in' needs a string, list or map, got int` for anything
  else.
* Division and modulo by zero are catchable runtime errors, not `nil`.

## Truthiness

`nil`, `false`, the numbers `0`/`0.0`, `""`, `[]` and `{}` are falsy;
everything else is truthy — including `" "`, `["x"]` and `{"k": nil}`.

```jocky
let values = [nil, false, "", [], {}, " ", ["x"], {"k": nil}, -1]
for v in values {
  if v { print("truthy: {json_encode(v)}") } else { print("falsy:  {json_encode(v)}") }
}
let zero_int = 3 - 3
let zero_float = 1.5 - 1.5
if zero_int { print("0 is truthy") } else { print("0 is falsy") }
if zero_float { print("0.0 is truthy") } else { print("0.0 is falsy") }
```

```text
falsy:  null
falsy:  false
falsy:  ""
falsy:  []
falsy:  {}
truthy: " "
truthy: ["x"]
truthy: {"k": null}
truthy: -1
0 is falsy
0.0 is falsy
```

Use `x != nil` when you need to distinguish "absent" from "zero"; a bare
`if x` cannot.

## `emit` and `print`

`emit` is the forensic output channel: each call appends one value to the run
result's findings, which is what the CLI, the artifact runner, the agent and
the evidence harness consume. `print` writes human-readable text to stdout:

```jocky
print("human line first")
emit {"kind": "fileless_process", "pid": 42}
print("human line second")
emit "plain string finding"
```

```text
{"kind": "fileless_process", "pid": 42}
plain string finding
human line first
human line second
```

Findings are emitted to the result, not to the terminal, so their position in
the file does not affect where they appear. `jocky run --json` prints the whole
result object — `findings`, `output`, `errors`, `steps`, `truncated`; see
[Functions & errors](/docs/language/functions-errors) for a complete example.

`json_encode`/`json_decode` convert between script values and JSON text.
Findings are converted to plain host data first, which renders a function as a
string such as `"<fn <lambda>>"` and stringifies map keys.

## Syntax rules that surprise people

* Statements are separated by whitespace only. Newlines are insignificant and
  `;` is tokenized but rejected by the parser, so `let a = 1; let b = 2` is a
  syntax error.
* A statement starting with `{` is always a block, never a map literal.
* Trailing commas are rejected in list, map and argument lists:
  `[1, 2,]` is `expected an expression but found op ']'`.
* Single quotes are not string delimiters — `'x'` is `unexpected character`.
* `return` swallows the next expression because newlines do not terminate a
  statement: a bare `return` is only safe directly before `}` or end of input.
  See [Functions & errors](/docs/language/functions-errors) for the
  demonstration.
* There is no `**`, no bitwise/shift operators and no compound assignment.

## Related pages

* [Functions & errors](/docs/language/functions-errors) — `fn`, closures, the
  error model and the step/wall-clock budgets.
* [Reference](/docs/language/reference) — grammar, precedence table, semantics
  table and the bytecode instruction set.
* [Standard library](/docs/language/standard-library) — the built-in functions
  used above (`print`, `len`, `range`, `transform`, `json_encode`).
* [CLI reference](/docs/operations/cli) — `run`, `exec`, `build`, `disasm`.
