# JOCKY evidence report (SIH26148)

Generated: 2026-09-15 19:14:23
Host: stormbreaker · kernel 6.6.87.2-microsoft-standard-WSL2 · python 3.12.3
Mode: full

Every number below was produced by `python -m jocky evidence`; raw logs sit next to this file (`polymorphism.csv`, `runs.json`, `artifacts.json`, `audit.json`, `detection.json`).

## 1. Polymorphic builds

- builds: **1000**, unique SHA-256: **1000** (all unique)
- artifact sizes: 3625–4175 bytes, 367 distinct sizes (per-build padding/structure differs)
- build throughput: 296.0/s
- semantic equivalence: 25 freshly built artifacts re-executed, findings hash identical to the reference run (1 finding(s), 0 failures)

## 2. Repeatability of a single build

- runs: **1000**, distinct finding-hashes: **1**, errors: 0
- latency ms — min 12.298, median 16.121, p95 21.358, max 28.348
- throughput: 55.2 runs/s

## 3. On-disk footprint

- source mode (warm interpreter): created 0, modified 0 file(s)
- source mode (cold interpreter): 74 bytecode-cache file(s) written — the interpreter caches imported modules, which fileless mode never does
- fileless mode: created 0, modified 0 file(s); exit=0 ok=True
- fileless process image: `/memfd:python3 (deleted)` with 4 memfd-backed mappings
- in-memory payload: interpreter 8020928 bytes, runtime zip 94110 bytes

## 4. Process and write telemetry (audit hook)

- child processes spawned during collection: **0**
- execve calls: 0 · write-mode opens: 0 · socket calls: 0
- read-mode opens: 405 · imports: 62
- VM steps: 885 · findings: 1 · duration 20.3 ms

## 5. Detection proves the technique

- memfd-backed processes observed while the fileless job ran: **1**
- detector findings: **1** (executable memfd mappings: 1)
- example: ['process 30385 (4) runs from memory']
- the fileless job's own report: ok=True, exe=/memfd:python3 (deleted), memfd mappings=4
