# Tooling: what makes a small language usable, and where JOCKY stands (cap-tooling)

## Scope

Highlighting (Pygments/TextMate/tree-sitter), LSP subset, formatter, REPL, debugger — evidence,
minimum increment, acceptance test each. Packaging/CI: `lim-dx.md`.

## How others do it — findings

1. **Highlighting is three artefacts, three channels.** VS Code/Sublime/GitHub consume TextMate
   grammars ("Syntax highlighting in GitHub is performed using TextMate-compatible grammars"); Helix
   configures `[[grammar]]` and `[language-server]` separately. Ship TextMate/Pygments first;
   tree-sitter is a third parser that can drift.
2. **`.jky` will not become a first-class GitHub language.** Linguist requires "at least 2000 files
   per extension … indexed in the last year, excluding forks" and closes hobby-language PRs, but
   `docs/overrides.md` documents `*.jky linguist-language=Python` in `.gitattributes`, which "will be
   used to syntax highlight files". One line buys colouring today.
3. **Pygments lexers ship out-of-tree** via entry points (found by `pygmentize`); regex flags default
   to `re.MULTILINE`. Measured locally: a 22-rule `RegexLexer` lexes 24 `.jky` files (1082 lines,
   13,390 tokens) with **0 `Token.Error`**; `flags = 0` broke `#.*$` and errored every comment.
   Interpolation is the hard part: the repo brace-scans `{…}` and raises `unterminated interpolation`
   (`jocky/lang/lexer.py:181`), so a naive rule mis-lexes `"{not json"` (the corpus escapes it,
   `tests/lang/09_builtins.jky:40`).
4. **An LSP subset is JSON-RPC over stdio and needs no SDK.** LSP 3.18 negotiates capabilities at
   initialize; debugging is a separate protocol (DAP). `jocky lsp` is stdlib-viable (`json` +
   `Content-Length`); `pygls` is excluded.
5. **Every interactive tool is gated on metadata the compiler discards.** AST nodes carry line/col
   (`jocky/lang/nodes.py:15-17`); `Proto` has no line table (`compiler.py:100-110`), only `starts`
   (`:110`, appended `:246`), which round-trips (`jocky/poly/wire.py:346-347`). Runtime errors are
   bare strings (`vm.py:233-236`), comments dropped (`lexer.py:236-238`), local names compile-time
   only (`compiler.py:145-161`).

## Where JOCKY stands

| Capability | Evidence | Gap |
|---|---|---|
| Highlighting | docs-only: `site/src/lib/highlight.js:15,36,48,113,139`, mirrored in `site/tools/build_static.py:38,63-70`, fences `markdown.js:31` | lists duplicate `lexer.KEYWORDS`; no editor grammar, nothing consumes `.jky` |
| LSP | CLI runs `run…agent`, no `lsp` (`jocky/cli.py:335-465`) | `NativeFn` has name/arity only (`vm.py:51`) → no hover text |
| Formatter | no `fmt`; lexer drops comments/whitespace (`lexer.py:236-238`) | printer + comment attachment |
| REPL | `run_program` builds a fresh VM (`runner.py:104`) | persistent VM (globals survive `vm.py:165,220-226`), continuation (`parser.py:100`) |
| Debugger | `Frame` has locals/stack/ip (`vm.py:29-34`); `_run_one` is the step point with budgets (`vm.py:249-262`); `disasm` (`compiler.py:131`) | no ip→line map, no local names, no breakpoints |

## Concrete improvements

| What | Sketch | Effort · risk | Acceptance |
|---|---|---|---|
| Highlighting | `jocky-pygments` (entry point, ~90 lines, interpolation state stack) + `.gitattributes` `linguist-language=Python` now, `source.jocky` TextMate grammar later | S/M · `{` in strings; looks like Python | `pygmentize -l jocky` over 24 files: zero `Token.Error`; `scripts/*.jky` render coloured |
| Compiler metadata | `Proto.start_lines` + `local_names`; remap in `poly/encoder.py:211`; bump `wire.py:14` | M · hashes change, evidence regenerated | v1 artifacts still decode; new builds map ip→line |
| `jocky lsp` | diagnostics via `runner.compile_source` (`runner.py:57`), completion from `lexer.KEYWORDS` + `builtins.namespaces()`, hover, definition | L · capability/position bugs | one typo → diagnostic at the lexer's line/col; `proc.` completes every `proc` native |
| `jocky fmt [--check]` | AST printer, comments verbatim at their line anchor, refuse when unplaceable | M · comment loss | one pass then `--check` exits 0 on all 19 `.jky`; idempotent; `parse(fmt(s)) == parse(s)` |
| `jocky repl` | persistent VM, per-line compile, continuation on `end of input`/`unterminated` | S · half-parsed input | `let x = 1` then `x + 1` → `2`; budget trip prints `truncated`, no exit |
| `jocky debug` (or `dap`) | line breakpoints, step/next/continue, `bt`, locals | M/L · stale frames after unwind | break inside a closure; `bt` shows both frames with correct locals |

## Verification approach

- `pygmentize -l jocky` over `scripts/`, `jocky/examples/`, `tests/lang/`; assert zero `Error`.
- Parity: same corpus through Pygments/TextMate/tree-sitter; each non-whitespace byte gets a
  real-lexer token class.
- Formatter/LSP/REPL/debug: `--check` exit codes, idempotence and AST equality on a mangled copy;
  scripted stdin transcripts; diagnostics compared against lexer positions.

## Citations

- github-linguist/linguist `CONTRIBUTING.md`, `docs/overrides.md` (read 2026-09-16) —
  https://github.com/github-linguist/linguist/blob/main/CONTRIBUTING.md
- Helix, Adding languages (read 2026-09-16) — https://docs.helix-editor.com/guides/adding_languages.html
- Pygments plugins, lexer development (read 2026-09-16) — https://pygments.org/docs/plugins/
- LSP 3.18 (read 2026-09-16) —
  https://microsoft.github.io/language-server-protocol/specifications/lsp/3.18/specification/
- Debug Adapter Protocol (read 2026-09-16) — https://microsoft.github.io/debug-adapter-protocol/
