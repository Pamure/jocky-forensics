# cap-performance-envelope — how fast is a triage DSL, and where JOCKY's envelope ends

## Scope
WSL2, 16 vCPU, 117 pids (78 unreadable as uid 1000), drvfs `$PATH`. Probes ran on a clean copy of HEAD `de25f67` in `/tmp` (live tree mid-edit) via the repo venv; min-of-3, read-only.

## How others do it — findings
1. **Sub-second is the bar for one process-table query.** osquery's profiler thresholds are warn/error/critical at `duration: (0.8, 1, 3)` s and `utilization: (8, 20, 50)` %; its sample run logs a `processes ⋈ listening_ports` join at **1.02 s / 44.3 % CPU**, and its Linux `processes` table is procfs-backed (osquery docs, *Performance safety*, canonical, read 2026-09-16). ⇒ JOCKY's 12-check triage (151 ms) is inside that bar: **collection is procfs-bound, not VM-bound**; the lever is fewer passes.
2. **Budgets live outside the query engine.** osquery runs a watchdog (10 % sustained CPU, 12 s at limit, 200 MB, 60 s grace; `cli-flags`, canonical). Velociraptor uses measurable units — `ops_per_second`, `iops_limit`, `cpu_limit`, `max_rows`, batch flush at 1000 rows / 5 MB / 100 s (`velociraptor-docs.org/docs/artifacts/resources/`, read 2026-09-16). ⇒ JOCKY has the ops/second analogue (steps) but no row/byte/IO budget and no flush, and samples its wall budget only between VM steps (`jocky/lang/vm.py:262`), so natives cannot be interrupted — `ioc.match(…,"/usr/lib",3000)` runs **380 ms under `--wall-ms 20`, `truncated: false`**.

## Where JOCKY stands
| Capability | Has it? | Measurement | Gap |
|---|---|---|---|
| VM dispatch | yes | 13,000,013 steps / 10.2–12.6 s → **1.03–1.18 M steps/s (0.85–0.97 µs)**; matches `lim-scale.md` 840 ns | no JIT; accounting ≈16 % |
| Native call | yes | 15 M steps + 1 M `len()` (13.2–13.9 s) vs 13 M steps (10.2 s) → **≈1.3 µs marginal** (`vm.py:577-593`) | Python call per dispatch |
| VM share of triage | yes | `scripts/triage.jky`: 581 steps, 4 natives, 743 ms → **≈0.07 %** | — |
| Process walk | yes | `list_processes()` **14.2 ms/118 pids**, 4 calls (`detect.py:216,425,538,580`), 2 fd sweeps; 4,696–5,257 syscalls/triage | nothing shared: 151 ms whole ≈ 167 ms sum |
| maps | yes | **4.9 µs/line** (12,082 lines = 46.6 ms) | re-parsed by `rwx_regions` (50.8 ms), `memfd_mappings` (39.9 ms) |
| sockets | yes | **13 µs/table entry**; attribution = full fd sweep, 14→**68 ms at +1,000 sockets**; 5.3 µs/fd | per-call fd re-sweeps |
| files | yes | 46–47 k files/s scan; 55–80 k small hashes/s; **850–900 MB/s** streamed hash (`filefs.py:44-54`); 19.4 k files/s read+filter | 2 opens/file (`filefs.py:150-152`) |
| findings | partly | **1.34 kB RSS + 122 B JSON each**: 100 k → 148 MB/1.5 s; 300 k → **403 MB/4.5 s**, one `json.dumps` (`cli.py:29`) | no streaming, no row cap |
| fileless hand-off | yes | 301 ms in-job, 0.42–0.50 s wall vs 0.12–0.14 s source | ~0.3 s fixed |
| Budget covers natives | **no** | 380 ms under `--wall-ms 20`, `truncated:false` | envelope set by native arg caps |

**Envelope (comfortable):** ~1 k processes, ~5 k sockets, ~20 k files, ≤100 k findings (≈150 MB), triage 0.2–0.4 s. **Degrades:** drvfs/network `$PATH` (`path_dirs()` 845 ms → CLI triage 0.93–1.12 s), >400 pids (five checks `[:400]`, `detect.py:235-351`), MAPS-heavy privileged hosts, >100 k findings.

## Concrete improvements
1. **Streaming results** — 403 MB/one dump vs Velociraptor batching. `--ndjson` with flush + `--max-rows`/`--max-bytes`; agent/server accept both. **S**; risk: new contract.
2. **Merged per-run `/proc` snapshot** — checks re-derive identical facts; snapshot once, checks become filters (~2× headroom; `lim-scale.md` prototype 45.2→11.5 ms). **M**; staleness risk.
3. **Byte builtins** — `fs.read` decodes with `errors="replace"` (`builtins.py:292`): 16.7 vs 7 µs per `/etc` file, **46 MB/s vs 2.2 GB/s** on 4 MiB binary, invalid bytes irreversibly replaced. Add `fs.read_bytes`, byte `contains`/`index`, bytes-taking `hash_bytes`. **S**; risk: second string type.
4. **Deadline inside native loops** — `fs.scan`/`ioc_match`/`det.*` honour `vm._deadline`. **S**; fixes the 380 ms violation.

## Verification approach
Pinned re-run: `steps.jky` ≥1.0 M steps/s; (2) triage ≤1,200 syscalls, findings hash unchanged; (1) `--ndjson` byte-equal to `--json`, RSS <50 MB at 300 k; (4) `longnative.jky --wall-ms 20` → `truncated:true`.

## Citations
- `de25f67`: `vm.py:255-264,577-593`; `runner.py:26-27`; `detect.py:216,235-351,425,521,538,580`; `filefs.py:44-54,150-152`; `builtins.py:224,238,292`; `cli.py:29`; `evidence/report.md:29-35`.
- osquery: <https://osquery.readthedocs.io/en/stable/deployment/performance-safety/>, <https://osquery.readthedocs.io/en/stable/installation/cli-flags/>, <https://github.com/osquery/osquery/blob/master/specs/processes.table> (canonical; 3.4-era sample, dated).
- Velociraptor: <https://www.velociraptor-docs.org/docs/artifacts/resources/> (read 2026-09-16).
