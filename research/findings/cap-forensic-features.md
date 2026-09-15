# cap-forensic-features — DFIR language features and where JOCKY stands

## Scope

Bar: regex/YARA matching over strings and bytes, binary unpacking, JSON/CSV/XML/Protobuf ingestion, time handling and timeline merging, aggregation/joins, streaming, record types, sorting/limiting/pagination, per-record error taxonomy, deterministic replay — versus VQL, PowerShell, Python, jq. Evidence: `file:line` at HEAD + read-only `./venv/bin/jocky` probes (2026-09-16).

## How others do it

| Claim | Evidence | Implication for JOCKY |
|---|---|---|
| Rules (regex/YARA) are language primitives | VQL `yara()`/`proc_yara()` over files, memory, accessors (velociraptor docs, 2026-09-16); PowerShell `Select-String` (MS Learn, 2026-05-02) | Literals only (vm.py:672-688); regexes trapped in detect.py:163 |
| Binary parsing is data-driven and lazy | `parse_binary(profile=…, struct=…)`, JSON vtypes profile (github.com/Velocidex/vtypes, 2026-09-16) | `fs.read` starts at byte 0, decodes lossily (builtins.py:323); ≈8.25 steps/byte (lim-forensic-depth F2) |
| Ingestion spans evidence formats | jq `fromjson`/`--stream`; PowerShell `ConvertFrom-Json -DateKind` (2025-01-30); Protobuf wire format (protobuf.dev) | JSON only (builtins.py:225-226) |
| Time is a type; timelines merge | VQL Event = Timestamp+Message+Data → Supertimeline (velociraptor blog, 2024-09-12); jq `strptime` | Floats only; no parse/tz native, no `ts` on findings (builtins.py:223, detect.py:190) |
| Aggregation is in-language; pipelines stream | PowerShell passes one object at a time; VQL `GROUP BY/ORDER BY/LIMIT` lazily (MS Learn, 2025-12-28; vql/fundamentals) | Every helper materialises (builtins.py:212-216); joins via O(n·m) `contains` (188-198) |
| Bad records are values, not aborts | jq `try/catch`, `?`, `--stream-errors` yield `[error, path]`; VQL notebooks re-query stored collections | First uncaught error ends the run (vm.py:284); natives return `null`, `"unreadable"`, or an error string as content (filefs.py:60, 70) |

## Where JOCKY stands

| Capability | Has it? | Evidence · gap |
|---|---|---|
| Patterns (string) | literal only | vm.py:672-688 · no regex |
| Patterns (bytes/YARA) | no | detect.py:163 · no byte type |
| Struct unpack | no | builtins.py:323 · no offset seek |
| JSON/CSV/XML/Protobuf | JSON only | builtins.py:225-226 · rest absent |
| Time + timeline merge | floats | builtins.py:205-231, filefs.py:160-166 · no `ts`, one root |
| Aggregation/joins | maps by hand | builtins.py:188-198 · O(n·m) |
| Streaming/lazy | no | builtins.py:212-216 · full lists only |
| Record types | untyped maps | vm.py:132-152 · no schema check |
| Sort/limit/page | partial | `sort_by`, `slice` · no offset |
| Error taxonomy | ad hoc | filefs.py:60, 70 · no error records |
| Deterministic replay | convention | evidence.py:148, 169 · `now()` unguarded |

## Concrete improvements

1. **Pattern native** (content rules are the core of DFIR work) — `fs.grep(path, {regex|literal-set}, max_hits)` and string `match/capture`; `re` + Aho–Corasick over 4 MiB windows, hits `{path,offset,rule,excerpt}`. **M**; risk: backtracking — cap pattern length.
2. **Bytes + profiles** — `fs.bytes(path,off,len)` and `parse_binary`-style unpack; unlocks wtmp, journals, MFT, carving (lim-forensic-depth F2/F9). New VM value type must survive `poly/` encoding. **L**; risk: encodability.
3. **Ingestion** — `csv.parse`, `jsonl.lines`, `lines`. **S–M**; risk: delimiters, encodings.
4. **Time, merge, replay** — `parse_time(s,fmt,tz)`, `fmt_time`, `ts` on every finding, `tl.merge(sources)` → `{ts,source,kind,data}`, injectable `--as-of` clock, stable collector ordering (lim-forensic-depth F3). **M**; risk: explicit tz only.
5. **Aggregation** — `group_by(rows,keyfn)`, `index(rows,keyfn)` hash join, `limit(rows,n,offset)`. **S–M**; risk: key-ordering spec.
6. **Streaming + error records** — lazy `ITER_NEXT` iteration, `fs.lines`, natives returning `{ok,value,error{kind,detail}}`, so one bad record cannot abort collection. **M–L**; risk: encoder coupling.

Priority: 1, 4, 2, 3, 5, 6. Full UDTs are **L** for little gain; `validate(record, schema)` is the cheap 80% (no schema check exists — builtins.py:205-231).

## Verification approach

Probes, not implementation assertions: grep/match must equal a Python `re` reference on known offsets; `fs.bytes` + profile must decode a generated wtmp and ELF header as `struct.unpack` does; `tl.merge` must emit monotonic `ts` across file+log+proc inputs, one malformed line becoming an error record, not an abort; `group_by` must equal `collections.Counter`; replay must reproduce evidence.py:148's findings hash under injected clocks; CI must run all `scripts/*.jky`; today only the first does (tests/test_scaffold.py:40), hence `scripts/timeline.jky:8` ships broken (`fs.timeline() expects at most 2 argument(s), got 3` — arity builtins.py:317-318).

## Citations

- https://docs.velociraptor.app/docs/vql/fundamentals/ · https://docs.velociraptor.app/docs/forensic/searching/ (fetched 2026-09-16)
- https://github.com/Velocidex/vtypes/blob/master/README.md (fetched 2026-09-16)
- https://docs.velociraptor.app/blog/2024/2024-09-12-timelines/ (2024-09-12)
- MS Learn `Select-String` (2026-05-02) · `ConvertFrom-Json` (2025-01-30) · `about_Pipelines` (2025-12-28)
- https://jqlang.org/manual/ (jq 1.8) · https://protobuf.dev/programming-guides/encoding/
- Repo: README.md:67-73 · jocky/lang/vm.py · jocky/rt/{builtins,filefs,detect}.py · scripts/timeline.jky · research/findings/lim-forensic-depth.md
