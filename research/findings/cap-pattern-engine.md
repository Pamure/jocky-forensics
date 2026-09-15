# cap-pattern-engine — why JOCKY ships its own matcher, and what it cost

## Scope
Build host: WSL2, i7-13620H, Python 3.12 (repo venv). Measurements are
back-to-back runs on the same machine; the `re` figures are subprocess timings
(cold interpreter included, ~30 ms), the engine figures are in-process.
Work: `jocky/rt/pattern.py` (+ `re.*` natives and `fs.grep`), `tests/test_pattern.py`,
`tests/lang/14_patterns.jky`.

## The problem this exists to avoid
Detection scripts match text the *attacker* wrote — command lines, file names,
log lines. A backtracking engine (Perl-style, which is what Python's `re` is)
is exponential on nested quantifiers, and the input length is attacker-chosen.

Measured, `re.search(r"(a+)+b", "a"*n)`, no match possible (`b` absent):

| n | Python `re` |
|---|---|
| 20 | 158 ms |
| 24 | 1.96 s |
| 28 | **31 s** |
| ≥32 | hours — the run was killed |

Roughly 4× per two input characters. A 4 KB command line is enough to burn days
of CPU. This is not hypothetical for a triage tool: `fs.grep` on an auth log
where one line is crafted, or a script matching `p.cmdline`, is the vulnerable
path — and the failure mode is a *stalled collection run*, which an adversary
controls.

## What was built
A Thompson/Pike NFA engine: parse → compile to instructions
(`Char/Any/Class/Split/Jmp/Save/Match/Anchor`) → simulate with a per-position
thread set. Cost is `O(len(text) × len(pattern))` for any pattern shape, with an
explicit step budget (4,000,000 thread-steps) that raises a catchable error
rather than hanging the host.

| Input | JOCKY engine |
|---|---|
| `(a+)+b` against 20,000 `a` | 47–59 ms (quiet host), 147 ms (host running a fuzz sweep) — no match either way |
| `(a+)+b` against 50,000 `a` | 384 ms |
| `(a+)+b` against 200,000 `a` | 1.6–2.3 s — still linear, still answers |
| same shape via `fs.grep` over a 50,000-char log line | 368 ms, 0 hits |
| `\b\w+\.exe\b` over 2,000 repetitions | 118 ms, 1,999 hits |

Linear in the input — ≈8 ms per 1,000 adversarial characters — where `re`'s cost
doubles every two characters. The in-suite pins are deliberately loose
(< 2 s at 20,000 chars in `test_pattern.py`, same bound for the 50,000-char
`fs.grep` case) so they assert the *shape* of the complexity, not a machine.

Deliberate exclusions, each a *syntax error with the offset*: lazy quantifiers
(`*?`), back-references, look-around, negated shorthands inside classes, and
unknown letter escapes (`r"\q"` reports rather than matching a literal `q`).
Silently matching something different from what was written is the failure mode
that makes a detection tool untrustworthy, so unsupported means "refuses",
never "reinterprets".

Byte patterns are first-class: `\xNN` (both endpoints of a class range are
decoded, so `r"[\x00-\x1f]+"` works), `\0`, `\a`, and `\b` as a backspace
inside a class. Paired with `fs.read_bytes` — whose latin-1 mapping makes one
character one byte — the ELF check is `re.test(r"\x7fELF", head)`, and the
verdict is the same as `re`'s for every one of those shapes (differential
corpus includes them).

## Correctness, not just speed
A bespoke engine is only useful if it agrees with what users expect. The test
suite compares it against the host `re` for every pattern shape in the supported
subset, on both **verdict and match span** — 400 random texts × 26 patterns,
plus hand-picked shapes: **8,000+ comparisons, zero disagreements**
(`tests/test_pattern.py`).

Where the semantics deliberately differ, they are documented and tested:

* **Leftmost-longest, not leftmost-first.** `a|ab` on `ab` matches `ab`. For a
  forensic verdict ("does this text contain the shape?") one predictable answer
  beats Perl's alternative-order preference.
* **ASCII classes.** `\w` = `[A-Za-z0-9_]`; `\w+` against `café` matches `caf`.
  (Python's `re` on `str` is Unicode-aware, which is why the differential corpus
  stays ASCII.)
* **Per-line matching in `fs.grep`**, per-string in `re.*`.

Bugs found by that testing during development, both silent-wrong-answer class:
a loop-back that jumped to the body instead of the split (so `\d+` could never
stop), and `char in _WORD` being true for `""` (so `\b` never matched at
position 0). Neither would have been caught by hand-written happy-path tests.

## Cost accepted
* The engine is ~600 lines to maintain and Python-level slow compared to C
  `re` (10–50× on trivial patterns). For a triage tool that is the right trade:
  the failure mode of the alternative is unbounded, the failure mode here is a
  few hundred milliseconds.
* `{m,n}` is expanded at compile time (60 copies of the body), so patterns with
  large repeat counts grow the program; `MAX_PROGRAM` caps it and the error says
  the pattern is too large.
* Captures under alternation can differ from Perl in ambiguous cases; the
  documented POSIX-like rule applies instead.

## Verification approach (pinned)
`pytest tests/test_pattern.py` — differential agreement ≥8,000 comparisons
(verdict + span), ReDoS shape under 2 s at 20,000 chars, step budget raises and
is catchable from a script, malformed patterns report an offset.
`jocky test tests/lang/14_patterns.jky` — 83 in-language checks including
`fs.grep` against `/proc/self/status`.

## Citations
* `jocky/rt/pattern.py`, `jocky/rt/filefs.py:grep_file`, `jocky/rt/builtins.py:_re_namespace`
* `tests/test_pattern.py`, `tests/lang/14_patterns.jky`
* `site/content/language/patterns.md` (user-facing rules)
* Python `re` catastrophic backtracking: <https://docs.python.org/3/library/re.html#catastrophic-backtracking>
  ("if you are not careful… can spend a long time"), Cox, *Regular Expression
  Matching: Can Be Simple And Fast* <https://swtch.com/~rsc/regexp/regexp1.html>
