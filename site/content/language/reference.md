# Reference

Normative summary of JOCKY 1.2.0 as implemented in this repository: the grammar
from `jocky/lang/parser.py`, lexical rules from `jocky/lang/lexer.py`, and the
instruction set from `jocky/lang/compiler.py` (`OPCODES`) with execution
semantics in `jocky/lang/vm.py`. Anything the parser rejects is not in the
grammar below; every example shown here was executed against the built CLI.

## Lexical structure

* **Source** is UTF-8 text. `#` starts a comment that runs to the end of the
  line. Space, tab, carriage return and line feed separate tokens and are
  otherwise insignificant — statements have no terminator and newlines carry no
  meaning (see the `return` caveat in [Functions & errors](/docs/language/functions-errors)).
* **Identifiers** start with a letter or `_` and continue with letters, digits
  or `_`. The test is Python's Unicode-aware `isalpha`/`isalnum`, so `café` is a
  valid name.
* **Keywords** are only the 21 reserved words listed below; anything else that
  looks like an identifier is one.
* **Token inventory.** Two-character: `== != <= >=`. One-character:
  `+ - * / % < > = : ; , . ( ) [ ] { }`. The lexer also emits `;` but no
  production consumes it, so a semicolon in source is a syntax error.
* **Numbers and strings** follow the tables below.

### Numeric literals

| Form | Example | Value |
|---|---|---|
| decimal integer | `42`, `1_000_000` | `42`, `1000000` |
| hexadecimal | `0xff`, `0xff_ff` | `255`, `65535` |
| octal | `0o17` | `15` |
| binary | `0b1011`, `0b1_0` | `11`, `2` |
| decimal float | `2.5`, `.5` | `2.5`, `0.5` |
| exponent float | `5e3`, `5E+3`, `2.5e-2` | `5000`, `5000`, `0.025` |

`_` may appear between digits in any form. A trailing point is not part of a
number: `5.` lexes as the integer `5` followed by `.` and the parser then fails
looking for a member name.

### String literals and escapes

Strings use double quotes only; `'x'` is `unexpected character "'"`. Inside a
string, `\` introduces one of:

| Escape | Meaning |
|---|---|
| `\n` `\t` `\r` | newline, tab, carriage return |
| `\0` | NUL |
| `\\` `\"` | backslash, double quote |
| `\{` `\}` | literal braces (same as `{{` / `}}`) |
| `\xNN` | one byte from two hex digits (`\x41` → `A`) |
| any other `\X` | **kept verbatim**, backslash included |

The last rule is deliberate, not a fallback: `"\d+"` is the two characters
`\d+`, so a detection pattern keeps matching what it was written to match.

`{expr}` interpolates any expression into the string; nested braces and nested
strings inside the expression are matched by the lexer, and the fragment is
parsed as a full expression. `{{` and `}}` emit literal braces. `{}` with an
empty body is a syntax error (`empty interpolation`), and an unterminated
`{` is an error at the opening line/column.

## Grammar

Complete EBNF, transcribed from the parser (`EOF` = end of token stream):

```text
program              = { statement } , EOF ;

statement            = let | set | if | while | for | fn-decl | return
                     | break | continue | emit | try | block
                     | expression-statement ;

let                  = "let" , IDENT , "=" , expression ;
set                  = "set" , assignable , "=" , expression ;
assignable           = IDENT | member | index ;

if                   = "if" , expression , block ,
                       { "elif" , expression , block } ,
                       [ "else" , block ] ;
while                = "while" , expression , block ;
for                  = "for" , IDENT , "in" , expression , block ;
fn-decl              = "fn" , IDENT , params , block ;
return               = "return" , [ expression ] ;
break                = "break" ;
continue             = "continue" ;
emit                 = "emit" , expression ;
try                  = "try" , block , "catch" , IDENT , block ;
block                = "{" , { statement } , "}" ;
expression-statement = expression ;

expression           = or-expr ;
or-expr              = and-expr , { "or" , and-expr } ;
and-expr             = not-expr , { "and" , not-expr } ;
not-expr             = "not" , not-expr | comparison ;
comparison           = additive ,
                       { ( "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" ) , additive } ;
additive             = multiplicative , { ( "+" | "-" ) , multiplicative } ;
multiplicative       = unary , { ( "*" | "/" | "%" ) , unary } ;
unary                = "-" , unary | postfix ;

postfix              = primary , { call | index | member } ;
call                 = "(" , [ expression , { "," , expression } ] , ")" ;
index                = "[" , expression , "]" ;
member               = "." , IDENT ;

primary              = INT | FLOAT | STRING | "true" | "false" | "nil"
                     | IDENT | "(" , expression , ")"
                     | list-literal | map-literal | lambda ;
list-literal         = "[" , [ expression , { "," , expression } ] , "]" ;
map-literal          = "{" , [ pair , { "," , pair } ] , "}" ;
pair                 = ( IDENT | STRING ) , ":" , expression ;
lambda               = "fn" , params , block ;
params               = "(" , [ IDENT , { "," , IDENT } ] , ")" ;
```

Constraints that are not expressible in the grammar above:

* No trailing commas — `[1, 2,]`, `{"a": 1,}` and `f(1,)` are all syntax
  errors, because after a comma the parser always requires another element.
* A statement beginning with `{` is a block, never a map literal: the parser
  tests for `{` before trying to parse an expression statement.
* `assignable` is checked after parsing, so `set 5 = 1` fails with
  `assignment target must be a name, member or index but found kw 'set'`.
* No default parameters, no variadic parameters, no named arguments.
* `return` followed by another statement on the next line parses as
  `return <that statement's expression>`, because newlines are insignificant.
* `break`/`continue` outside a loop are compile errors (`'break' outside of a
  loop (line N)`), not syntax errors.

## Keywords

21 reserved words; all of them are rejected as identifiers:

```text
and      break    catch    continue elif     else     emit     false
fn       for      if       in       let      nil      not      or
return   set      true     try      while
```

`and`, `or`, `not` and `in` are keywords rather than punctuation, but they are
the boolean/comparison operators in the precedence table.

## Operator precedence

Highest binding first:

| Level | Operators | Associativity | Result |
|---|---|---|---|
| 1 | literals, `( )`, `[ ]`, `{ }`, `fn ( ) { }` | — | value |
| 2 | call `f(a)`, index `a[i]`, member `a.b` | left | value |
| 3 | unary `-` | right | number |
| 4 | `*` `/` `%` | left | number, string or list (see semantics) |
| 5 | `+` `-` | left | number, string or list |
| 6 | `==` `!=` `<` `<=` `>` `>=` `in` | left-folding | boolean |
| 7 | `not` | right | boolean |
| 8 | `and` | left | one operand |
| 9 | `or` | left | one operand |

Level 6 **folds left** instead of behaving like Python's chained comparisons:
`3 < 2 < 5` is `(3 < 2) < 5`, and `false` compares as `0`, so it evaluates to
`true`. Write the conjunction explicitly. `not` binds looser than comparison
(`not 1 == 2` is `not (1 == 2)` → `true`) and tighter than `and`.

## Semantics

| Area | Rule |
|---|---|
| Scoping | Locals belong to the enclosing function; `if`/`while`/`for` bodies create no scope, so a `let` in a block stays visible. |
| Name resolution | A name resolves to a local slot of the current function, otherwise to a global. Reading an undefined name raises `undefined name 'x'`; `set` on an undefined name silently creates a global. |
| `<main>` | Top-level `let`s are locals of a hidden `<main>` proto, so a function sees them only by capturing them, and only if they were declared before it. |
| Closures | Captured **by reference to a cell** (a one-element box): several closures over one variable observe each other's writes, and each function activation creates fresh cells. |
| Loop capture | The loop variable and any `let` in the loop body are one cell reused for every iteration, so closures created in a loop all observe the final value. |
| `fn` binding | A named declaration stores the closure in an existing local slot of that name, otherwise in the globals. |
| Truthiness | `nil`, `false`, `0`, `0.0`, `""`, `[]`, `{}` are falsy; everything else (including `" "`, `{"k": nil}`) is truthy. |
| `and` / `or` | Short-circuit and evaluate to an operand, not a coerced boolean; `not` always returns a boolean. |
| Equality | `==`/`!=` are structural for lists and maps and numeric across `int`/`float`. Closures compare **structurally** — proto plus captured cells — so two lambdas with identical bodies are `==` even though they are distinct objects; a named function does not equal a lambda (the proto name differs). |
| Ordering | `<`, `<=`, `>`, `>=` accept two numbers or two strings; anything else raises `cannot compare X < Y`. |
| Numbers | `int` is arbitrary precision, `float` is a double; `/` is true division; `%` takes the sign of the divisor; division or modulo by zero is a catchable error. |
| `+` / `*` | `+` concatenates when either operand is a string (the other is stringified) and concatenates two lists. `*` repeats `string`/`list` by an `int`; the reverse order (`2 * "ab"`) is an error. |
| Printing | `to_str` renders `nil`/`true`/`false` by name, floats that are integral as integers (`2.0` → `2`), and lists/maps as compact JSON. |
| Indexing | `list`/`string` accept an integer index; negative counts from the end; out of range raises. `map` stringifies the key and returns `nil` for a missing one. Slicing does not exist. |
| Members | Maps check data first, then built-in methods (`.get`, `.set`, `.keys`, `.del`, …); a missing map member raises `map has no member 'x'`. Strings, lists and numbers expose methods only, and an un-called method is a function value. `nil` accepts any member and yields `nil`. |
| Calls | Script functions check arity exactly; natives check a min/max range; a non-callable raises `X is not callable`. |
| Errors | Catchable errors carry a message string; host exceptions are prefixed with the host class (`ValueError: …`). Uncaught errors are appended to `result.errors`, keep the findings already emitted, and make `jocky run` exit `1`. |
| Limits | Step budget, wall clock and call depth raise an **uncatchable** limit error and set `truncated: true`. |

## Bytecode

The compiler emits a flat stream of `(opcode, operand)` pairs. `jocky disasm`
prints the constant pool, the name table and one listing per function proto.
There are 50 opcode names: the 42 below plus the eight `NOP` slots. The
polymorphic encoder renames and permutes opcodes per build (see
[Polymorphic artifacts](/docs/execution/artifacts)), so these canonical names
describe what the compiler and VM use, not the bytes stored in an artifact.

| Opcode | Operand | Effect |
|---|---|---|
| `CONST` | constant index | push `consts[i]` |
| `LOADL` | local slot | push frame local `s` |
| `STOREL` | local slot | pop into frame local `s` |
| `LOAD_CELL` | local slot | push the *contents* of the capture cell in slot `s` |
| `STORE_CELL` | local slot | pop into the capture cell in slot `s` (shared with closures) |
| `PUSH_CELL` | local slot | push the cell object itself, ahead of `MK_FN` |
| `LOADG` | name index | push global `names[i]`, else `undefined name` |
| `STOREG` | name index | pop into global `names[i]` |
| `POP` | — | discard top of stack (expression statements) |
| `DUP` | — | duplicate top of stack (used by `and`/`or`) |
| `ADD` `SUB` `MUL` `DIV` `MOD` | — | arithmetic, plus string/list concatenation and string/list repetition |
| `EQ` `NE` | — | equality / inequality, structural for containers |
| `LT` `LE` `GT` `GE` | — | ordering of two numbers or two strings |
| `IN` | — | membership: substring, list element or map key |
| `NEG` | — | unary minus |
| `NOT` | — | logical negation (always yields a boolean) |
| `JMP` | target | unconditional jump |
| `JMPF` | target | pop; jump when falsy |
| `JMPT` | target | pop; jump when truthy |
| `CALL` | argument count | pop `argc` arguments and the callee; call it |
| `RET` | — | pop the return value (or `nil`) and leave the frame |
| `MK_LIST` | item count | pop `n` values into a list |
| `MK_MAP` | pair count | pop `2n` values (key then value); keys are stringified |
| `GET_IDX` | — | `obj[index]`: list/string by integer, map by stringified key |
| `SET_IDX` | — | `obj[index] = value`: mutation only for lists and maps |
| `GET_MEM` | name index | `obj.name`: map data, then built-in method |
| `SET_MEM` | name index | `obj.name = value`; only maps are writable |
| `MK_FN` | proto index | pop `proto.ncaptures` cells and push the closure |
| `ITER_INIT` | — | pop the iterable, push an iterator handle |
| `ITER_NEXT` | target | push the next element, or jump to `target` when exhausted |
| `EMIT` | — | pop a value and append it to `result.findings` |
| `TRY_ENTER` | `(start, end, handler, slot)` | push a handler covering `[start, end)`, recording the current stack depth |
| `TRY_EXIT` | — | pop the innermost handler |
| `HALT` | — | stop the program (clears the frame stack) |
| `NOP0` … `NOP7` | — | no-ops; junk slots the encoder can fill at statement boundaries |

A proto also carries `name`, `params`, `captures`/`ncaptures`, `nlocals`,
`cell_slots` (locals promoted to cells), `handlers` and `starts` (instruction
indices that begin a statement, the only places the encoder may insert junk).

## Disassembly illustration

```jocky
let limit = 2
let hits = 0
for p in [1, 2, 3] {
  if p > limit { set hits = hits + 1 }
}
emit {"kind": "count", "value": hits}
print("hits={hits}")
```

```bash
jocky disasm hitcount.jky
```

```text
=== constants ===
[0] 2
[1] 0
[2] 1
[3] 3
[4] 'kind'
[5] 'count'
[6] 'value'
[7] 'hits='
=== names ===
[0] print
=== <main> (locals=3) ===
   0  CONST      0
   1  STOREL     0
   2  CONST      1
   3  STOREL     1
   4  CONST      2
   5  CONST      0
   6  CONST      3
   7  MK_LIST    3
   8  ITER_INIT  
   9  ITER_NEXT  21
  10  STOREL     2
  11  LOADL      2
  12  LOADL      0
  13  GT         
  14  JMPF       20
  15  LOADL      1
  16  CONST      2
  17  ADD        
  18  STOREL     1
  19  JMP        20
  20  JMP        9
  21  CONST      4
  22  CONST      5
  23  CONST      6
  24  LOADL      1
  25  MK_MAP     2
  26  EMIT       
  27  LOADG      0
  28  CONST      7
  29  LOADL      1
  30  ADD        
  31  CALL       1
  32  POP        
  33  HALT       
```

Reading it: slots 0 and 1 hold `limit` and `hits`, slot 2 the loop variable;
`ITER_NEXT 21` jumps past the loop when the iterator is empty and `JMP 9`
closes it; the `if` body is `LOADL/LOADL/GT` and `JMPF 20`; the `emit` map is
built by pushing keys and values then `MK_MAP 2`; `print` is global name 0, so
the last call is `LOADG 0 / CONST 7 / LOADL 1 / ADD / CALL 1 / POP`.

Closures and handlers produce the interesting opcodes — `PUSH_CELL`,
`LOAD_CELL`, `MK_FN` and the `TRY_ENTER` tuple, with the protected region
repeated in the listing's `handlers:` line:

```jocky
fn make(start) {
  let n = start
  return fn() {
    set n = n + 1
    return n
  }
}
let tick = make(0)
try {
  print(tick())
} catch err {
  print(err)
}
```

```bash
jocky disasm counters.jky
```

```text
=== constants ===
[0] 1
[1] None
[2] 0
=== names ===
[0] make
[1] print
=== <main> (locals=2) ===
   0  MK_FN      1
   1  STOREG     0
   2  LOADG      0
   3  CONST      2
   4  CALL       1
   5  STOREL     0
   6  TRY_ENTER  (7, 14, 14, 1)
   7  LOADG      1
   8  LOADL      0
   9  CALL       0
  10  CALL       1
  11  POP        
  12  TRY_EXIT   
  13  JMP        19
  14  STOREL     1
  15  LOADG      1
  16  LOADL      1
  17  CALL       1
  18  POP        
  19  HALT       
handlers: [(7, 14, 14, 1)]
=== <lambda> (locals=1) ===
   0  LOAD_CELL  0
   1  CONST      0
   2  ADD        
   3  STORE_CELL 0
   4  LOAD_CELL  0
   5  RET        
   6  CONST      1
   7  RET        
=== make (locals=2) ===
   0  LOADL      0
   1  STORE_CELL 1
   2  PUSH_CELL  1
   3  MK_FN      0
   4  RET        
   5  CONST      1
   6  RET        
```

In `make`, the parameter arrives as `LOADL 0`, but the local `n` was captured
by the lambda, so slot 1 is a cell: `STORE_CELL 1` writes it, `PUSH_CELL 1`
hands the box to `MK_FN 0`, and the lambda reads and writes the same box with
`LOAD_CELL 0` / `STORE_CELL 0`. The trailing `CONST None / RET` in every proto
is the implicit `nil` return. An error raised deeper in a call stack unwinds
frames until one has a protected region covering the failing instruction, then
jumps to that handler with the message string pushed on the frame's stack.

## Related pages

* [Language basics](/docs/language/basics) — values, syntax, operators, control
  flow and output.
* [Functions & errors](/docs/language/functions-errors) — closures, the error
  model and the safety budgets.
* [Standard library](/docs/language/standard-library) — every built-in and
  runtime namespace.
* [Polymorphic artifacts](/docs/execution/artifacts) — how the opcode names and
  constants above are rewritten per build.
