# JOCKY evidence report (SIH26148)

Generated: 2026-09-16 01:41:14
Host: stormbreaker · kernel 6.6.87.2-microsoft-standard-WSL2 · python 3.12.3
Mode: full

Every number below was produced by `python -m jocky evidence`; raw logs sit next to this file (`polymorphism.csv`, `runs.json`, `artifacts.json`, `audit.json`, `detection.json`).

## 1. Polymorphic builds

- builds: **1000**, unique SHA-256: **1000** (all unique)
- artifact sizes: 3605–4124 bytes, 357 distinct sizes (per-build padding/structure differs)
- build throughput: 405.0/s
- semantic equivalence: 25 freshly built artifacts re-executed, findings hash identical to the reference run (1 finding(s), 0 failures)

## 2. Repeatability of a single build

- runs: **1000**, distinct finding-hashes: **1**, errors: 0
- latency ms — min 14.96, median 17.58, p95 20.264, max 45.372
- throughput: 52.7 runs/s

## 3. On-disk footprint

- source mode (warm interpreter): created 0, modified 0 file(s)
- source mode (cold interpreter): 85 bytecode-cache file(s) written — the interpreter caches imported modules, which fileless mode never does
- fileless mode: created 0, modified 0 file(s); exit=0 ok=True
- fileless process image: `/memfd:python3 (deleted)` with 4 memfd-backed mappings
- in-memory payload: interpreter 8020928 bytes, runtime zip 167247 bytes

## 4. Process and write telemetry (audit hook)

- child processes spawned during collection: **0**
- execve calls: 0 · write-mode opens: 0 · socket calls: 0
- read-mode opens: 586 · imports: 63
- VM steps: 885 · findings: 1 · duration 17.9 ms

## 5. Detection proves the technique

- memfd-backed processes observed while the fileless job ran: **1**
- detector findings: **1** (executable memfd mappings: 1)
- example: ['process 94599 (4) runs from memory']
- the fileless job's own report: ok=True, exe=/memfd:python3 (deleted), memfd mappings=4
