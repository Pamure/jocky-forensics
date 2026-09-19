# Patterns

Detection is pattern matching, and the text being matched is written by the
attacker: command lines, file names, log lines, registry-ish strings. JOCKY
therefore ships its **own** matcher (`re.*`) instead of calling into the host
language's `re`, because a backtracking engine can be made to run for
exponentially long on a crafted input — one 40 KB command line of `a`s is
enough to wedge a triage run that used `re.search("(a+)+b", …)`.

The engine compiles a pattern to an NFA and simulates it over the input, so the
cost is `O(len(text) × len(pattern))` regardless of the pattern's shape. There
is also an explicit step budget: a match that exceeds it raises a catchable
error instead of hanging the run.

## Writing a pattern

Use a raw string. Inside a normal string the lexer decodes escapes and treats
`{…}` as interpolation, so a pattern has to be written with doubled backslashes
and escaped braces; `r"…"` takes the text verbatim.

```jky
re.test(r"^\s*(curl|wget)[^|]*\|\s*(ba)?sh", p.cmdline)
```

| Construct | Meaning |
|---|---|
| `abc` | literal characters |
| `.` | any character except newline |
| `\d` `\w` `\s` | digit, word (`A-Za-z0-9_`, ASCII), whitespace |
| `\D` `\W` `\S` | negations of the above |
| `[abc]` `[^abc]` `[a-z0-9]` | character class, negation, ranges |
| `^` `$` | start of text, end of text (or before a final newline) |
| `\b` `\B` | word boundary, non-boundary (`\b` is a backspace *inside* a class) |
| `*` `+` `?` `{m}` `{m,}` `{m,n}` | greedy repetition |
| `\|` | alternation |
| `(…)` `(?:…)` | capturing group, non-capturing group |
| `\xNN` | one character by code point — `r"\x7fELF"`, `r"[\x00-\x1f]"` |
| `\n` `\t` `\r` `\f` `\v` `\0` `\a` | newline, tab, CR, FF, VT, NUL, BEL |
| `\.` `\\` `\*` … | escaped punctuation, i.e. a literal |

An unknown *letter* escape is an error, not a literal: `r"\q"` reports
`unsupported escape \q` instead of quietly matching `q`. Punctuation needs no
quoting in practice (`-` and `_` are literal anyway), and `re.escape` quotes
whatever does.

Unsupported by design (they are what breaks linear time or needs a different
engine): lazy quantifiers (`*?`), back-references, look-around. Each is a
*syntax error* with the offset in the message — never a silently different
match.

## Semantics worth knowing

* **Leftmost-longest.** `a|ab` against `ab` matches `ab`; the rule is POSIX-like
  rather than Perl's leftmost-first, so "does this text contain the shape?"
  always answers the same way.
* **ASCII classes.** `\w` is `[A-Za-z0-9_]`, so `café` matches `caf` with `\w+`.
  Literals are unaffected: `r"café"` matches `café`.
* **Matching is per line inside `fs.grep`**, per string in `re.*`.
* **The step budget** defaults to 4,000,000 thread-steps and raises
  `pattern match exceeded its step budget (…)`, which a script can catch like
  any other error.

## Natives

| Call | Returns |
|---|---|
| `re.test(pattern, text, ignore_case?)` | `true`/`false` — does it match anywhere |
| `re.full(pattern, text, ignore_case?)` | `true`/`false` — must the *whole* text match |
| `re.find(pattern, text, limit?, ignore_case?)` | `[{text, start, end, groups}]` |
| `re.captures(pattern, text, limit?, ignore_case?)` | `[[whole, group1, …], …]` |
| `re.replace(pattern, text, replacement, limit?, ignore_case?)` | text, `$1`/`\1` expand a group |
| `re.split(pattern, text, limit?, ignore_case?)` | list of pieces |
| `re.escape(text)` | text with every special character quoted |
| `fs.grep(path, pattern, limit?, ignore_case?)` | `[{line_no, line, match, start, end, groups}]` |

`fs.grep` reads the file line by line from a binary stream (a multi-gigabyte
log costs one line of memory), caps the walk at 32 MiB and the result at
`limit`, replaces undecodable bytes instead of failing, and stops rather than
raising if the file becomes unreadable mid-read.

## Example: a hunt you can read

```jky
# Reverse shells that were started without ever touching disk.
for p in proc.list(400) {
  if re.test(r"(curl|wget)[^|]*\|\s*(ba)?sh", p.cmdline) {
    emit {"kind": "pipe_to_shell", "severity": "high", "pid": p.pid,
          "cmdline": p.cmdline}
  }
}

# Failed logins from a single source, straight out of an auth log.
let hits = fs.grep("/var/log/auth.log", r"Failed password for (\S+) from (\S+)", 200)
let by_ip = dict()
for h in hits {
  let ip = h.groups[1]
  set by_ip[ip] = (by_ip.get(ip, 0) or 0) + 1
}
for pair in by_ip {
  if pair[1] >= 10 { emit {"kind": "brute_force", "source": pair[0], "count": pair[1]} }
}
```

## Why linear time is not a micro-optimisation

Measured on this project's test host, three runs of the same shape
(`re.search(r"(a+)+b", "a"*n)` versus `re.test(r"(a+)+b", "a"*n)`):

| Input | Python `re` | JOCKY `re` |
|---|---|---|
| 20 `a` | 0.16 s | < 1 ms |
| 28 `a` | 31 s | < 1 ms |
| 20,000 `a` | does not finish | 50–150 ms |
| 50,000-char log line via `fs.grep` | does not finish | ~0.4 s |
| 200,000-char line | does not finish | 1.6–2.3 s |

The engine's column grows linearly (≈8 ms per 1,000 adversarial characters on
this host, whatever the pattern shapes it into); `re`'s column doubles every
two characters of input. And the step budget means even a *worse* case stops
with a catchable error instead of a stalled run.

Agreement is a test in the suite, not a claim: the engine's verdict *and* the
match span are compared against Python's `re` for every supported pattern
shape, so "our own engine" does not mean "subtly different semantics".
