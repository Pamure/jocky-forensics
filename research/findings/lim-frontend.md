# JOCKY front-end limitations (lexer · parser · compiler)

## Scope
`jocky/lang/{lexer,parser,nodes,compiler}.py` and the front-end-forced parts of `vm.py`/`cli.py`.
Claims were reproduced through `jocky.runner` (throwaway snippets). The brief's premise "no unicode
identifiers" is false (6).

## Findings
1. **Constant pool collides literals across types** — dedup keys on the Python value
   (`compiler.py:198-211`): `emit 1.0;emit 1;emit true` → `[1.0,1.0,1.0]`, and `let w=0` after any
   `false` makes `type(w)=="bool"`. Impact: evidence JSON says `false` where the script wrote `0`.
2. **The lexer crashes and mangles literals.** A trailing `0` raises a raw `KeyError` — `lexer.py:85`
   treats `""` as a base prefix, then indexes the dict (`lexer.py:86`) — so `let x = 0` at EOF, or any `"{0}"`, prints `jocky: KeyError: ''`
   and escapes the `JockyError` contract. Unknown escapes also drop the backslash (`lexer.py:160`):
   `"\d+ \."` → `d+ .`, while `"C:\temp\x"` hard-errors (`lexer.py:152-158`). Impact: detection
   patterns lose `\d`/`\b` → false negatives.
3. **No source map** — `Proto` keeps statement-start indices, not lines (`compiler.py:110,243`);
   `emit()` drops `node.line`; the wire carries `starts` alone (`wire.py:344-348`). Runtime errors
   are bare strings (`division by zero`; `vm.py:231-234,449-450`); syntax errors alone carry
   `line:col` (`errors.py:15-27`). Impact: a failing hunt cannot be localised.
4. **Name resolution is single-pass and unchecked.** `_captures_for` (`compiler.py:367-371`) sees only
   code compiled so far: `fn a(){return s}` before `let s=5` gives `undefined name 's'`, after it `5`;
   `let sys=7` after `fn f(){return keys(sys)}` leaves `f` reading the namespace
   while callers read `7`. Namespaces (`rt/builtins.py:152-317`) are globals, so `let sys=1` masks one
   unwarned (`len(keys(sys))` → `0`). Impact: one name, two meanings; a hunt can silently return zero findings.
5. **Operator surface and chaining** — no `!`, `&`, `&&`, shifts or unary `+` (`lexer.py:28-29`), and
   `a == not b` is a syntax error though `not a == b` correctly parses as `not (a==b)`. Comparisons
   chain left-associatively (`parser.py:264-279`) with bools counted as numbers (`vm.py:375-383`):
   `emit 3 < 2 < 1` → `true`. Impact: no local mode/TCP-flag bit math; wrong predicates.
6. **Unicode accepted but ungoverned** — identifiers take any `isalpha()`/`isalnum()` codepoint with no
   normalization (`lexer.py:217,241`), numbers any `isdigit()` (`lexer.py:235-236`): Cyrillic
   `let рids` coexists with `let pids`; `emit ٣` → `3`. Impact: homoglyph logic is invisible to review (UTS #39).
7. **No module system** — `import` is not a keyword (`lexer.py:22-26`) and no import statement exists
   (`parser.py:123-138`): `import os` → `undefined name 'import'`. Impact: playbooks cannot be composed
   or namespaced.
8. **No folding, dead-code elimination, lint or formatter** — operands always both emit
   (`compiler.py:463-464`), dead code is still compiled and pooled, and no warnings channel exists
   (shadowed namespaces, `let` redeclare at `compiler.py:246,343`). Comments vanish
   (`lexer.py:230-233`), `Token` has no trivia field (`lexer.py:38-41`), there is no `fmt`/`lint`
   command (`cli.py:171-235`), and interpolation has no format spec (`parser.py:413-414`). Impact:
   artifact bloat; typos unheard.

## Concrete improvements
- **Const key** — type-tagged (`(type,value)`, bool first). S/L (1).
- **Lexer literal handling** — guard with `_peek(1).lower() in ("x","b","o")`; keep the backslash on
  unknown escapes, add `\uXXXX`, error only on malformed `\x`; fuzz the lexer. S/M (2).
- **Source map** — `Proto.lines` beside `starts`, filled from a `node.line` cursor in `emit()` and
  bisected into VM error text; bump `WIRE_VERSION` (`wire.py:41`), extend `wire.py:344-348`, remap
  lines with `starts` in the encoder (`encoder.py:237-238`). M/M (3).
- **Resolver + lint** — pre-pass binding locals, warning on shadowed namespaces, unused locals,
  unreachable code, use-before-declaration; replaces `_mark_cell` (`compiler.py:171-180`). M-L/M (4,8).
- **Operators** — `!`/`&&`/`||` aliases, int-only `& | ^ ~ << >>`, non-associative comparisons; append
  the opcodes at the end of `OPCODES` (`wire.py:56`). L/M (5).
- **Unicode policy** — apply the UTS #39 profile; reject non-ASCII digits. S/L (6).
- **Format spec** in interpolation; a CST plus `jocky fmt` to keep comments. M/M, L/M (8).

## Verification approach
Re-run each reproduction and assert the new observable (`[0,"int"]`; `JockySyntaxError`; `\d+` kept;
`(line 12)`). For the source map, build a fixed-seed artifact, decode and re-run it, asserting the
line survives remapping. For the resolver/lint, diff findings hashes of `scripts/*.jky` before and
after (as `evidence.py` does), asserting warnings only on the 4/8 repros. Fuzz 64-byte inputs: only
`JockyError` may escape.

## Citations
External: PEP 657 (2021-05-08, Final, Python 3.11)
https://peps.python.org/pep-0657/ — canonical-but-dated precedent for per-instruction line maps (3).
PEP 672 (2021-11-01, Active) https://peps.python.org/pep-0672/ — confusables and confusable digits.
Unicode® UTS #39 v17.0.0, 2025-09-04, https://www.unicode.org/reports/tr39/ — identifier security
profiles (6).
