# Industry rules: Sigma and YARA

JOCKY reads the two rule formats the industry already writes — **Sigma** for log
detection and **YARA** for byte signatures — instead of asking an analyst to
translate a rule corpus into yet another syntax. Both are evaluated on the
runtime's own [linear-time engine](../language/patterns.md), which is the part
that matters for a forensic tool: the usual engines (Python `re` in Zircolite,
.NET regex in Chainsaw and Hayabusa) backtrack, so a rule plus a crafted log line
is a denial of service. Here the cost is bounded by construction and a step
budget turns the worst case into an error.

## Sigma

```bash
jocky sigma rules/reverse_shell.yml /var/log/auth.log --json --stamp-findings
```

```jky
# The same thing from a script, over records you already collected.
let rule = fs.read("/tmp/rules/reverse_shell.yml", 65536)
for p in proc.list(400) {
  if sigma.check(rule, {"CommandLine": p.cmdline, "User": p.uid}) {
    emit {"kind": "sigma_match", "pid": p.pid, "rule": sigma.summary(rule).title}
  }
}
```

Input lines that parse as JSON are matched as **records** (field selections get
real fields); anything else is matched as **text** (keywords and field-less
selections). Supported today:

| Part | Supported |
|---|---|
| Modifiers | `contains` `startswith` `endswith` `re` `all` `cased` `base64` |
| Values | scalars, lists (any-of), lists of maps, bare keyword lists, `*`/`?` wildcards |
| Condition | `and` `or` `not`, parentheses, `N of them`, `all of them`, `1 of selection*` |

Refused **by name** (never half-applied): `|cidr`, `|lt`/`|gt`/`|fieldref`,
aggregations (`| count() > 5`), and rule *correlation* — those need state across
events, and a rule that silently degrades to "match everything" is worse than one
that refuses to load.

## YARA

```bash
jocky yara rules/apt_elf.yar /usr/bin/suspicious --json
```

```jky
let sig = fs.read("/tmp/rules/apt_elf.yar", 65536)
let head = fs.read_bytes("/usr/bin/suspicious", 0, 4096)
if yara.check(sig, head) {
  emit {"kind": "yara_match", "path": "/usr/bin/suspicious",
        "sha256": fs.hash_bytes_raw(head)}
}
```

| Part | Supported |
|---|---|
| Hex strings | `{ 4D 5A ?? [2-4] ( 50 45 \| 45 4C ) }`, nibble wildcards `?A`, exact `[4]` |
| Text strings | `nocase` `wide` `ascii` `fullword`; regex strings `/…/` |
| Conditions | `and` `or` `not`, `any/all/N of them`, `$a at 0`, `filesize` comparisons |
| Meta/tags | read and reported in the finding, never matched on |

Refused by name: `xor`, `base64`, `~` (not-byte), modules (`uint16(0)`, `pe.*`),
`for` loops, `$a in (…)` ranges.

## Why this is a safety property, not a compatibility checkbox

Measured on the development host, same rule, same input:

| Engine | `(\w+\s?)+whoami` over an 80 KB crafted command line |
|---|---|
| Python `re` (Zircolite's engine class) | still running after **20 s** (killed) |
| JOCKY | **745 ms**, no match reported |

The pattern is a shape a rule author writes by accident; the input is one the
adversary controls. Every comparison above goes through the same bounded engine,
with `\xNN` byte patterns and byte strings (`fs.read_bytes`) for the YARA side.

## Correlation: the join your rule needs

Sigma and YARA decide one record at a time. Cross-artifact questions (which
socket belongs to which process, which file appeared in which window) are built
from two passes and one index:

```jky
let by_pid = index_by(proc.list(400), fn(p) { return p.pid })
for c in net.established() {
  let owner = by_pid.get(str(c.pid), nil)
  if owner != nil { emit {"pid": c.pid, "exe": owner.exe, "remote": c.remote} }
}
```

`index_by` is one pass and a lookup (O(n + m)), `group_by` keeps every row under
its key, and `tl.window`/`tl.merge` put the results on a timeline — the shape VQL
calls `memoize` and osquery calls a `JOIN`.
