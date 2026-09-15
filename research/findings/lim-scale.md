# lim-scale — throughput and scale limits of collection

## Scope
WSL2, kernel 6.6.87.2, 16 CPUs, uid 1000, 86–92 pids, ~540–613 fds. Throwaway wrappers counted `/proc` `open`/`readlink`/`listdir`; per-check timings; `triage --json` timed.

## Findings
1. **One triage = 3,288 `/proc` syscalls for a constant fact set.** Ten checks (detect.py:322-353) do 9 × `listdir("/proc")` (procfs.py:50-59), two full `info()` walks (detect.py:83, 227), two full fd sweeps, a counter walk. On 90 pids: 1,170 `readlink(fd)`, 572 `readlink(exe)`, 470 `stat`.
2. **`info()` reads `exe` three times** (procfs.py:270, 277): 199 readlinks per 90-process walk, not 90; `memfd_exe` derives from `entry["exe"]`.
3. **`world_writable_path()` dominates and scales with `$PATH`, not processes.** 66-entry PATH, 42 on drvfs `/mnt/c`: 646–736 ms of an 873–953 ms triage (realpath+lstat+`fstype_for` per entry, filefs.py:211-240; `_mount_table()` re-reads `/proc/mounts` per call, filefs.py:182-202, uncached). `PATH=/usr/bin:/bin`: 67–70 ms — 13×. 42 are opaque fstypes, rejectable pre-`lstat`.
4. **Two full fd sweeps per triage.** `socket_inode_map()` (procfs.py:347-358) and `deleted_open_files()` (procfs.py:326-345) each `listdir`+`readlink` every fd (590–1,170 each); `setdefault`'s inline `read_stat(pid)` (procfs.py:353-355) runs per socket fd (198 opens for 178 inodes); `deleted_only` filters after readlink (procfs.py:165-171): 443 readlinks → 7 kept. Rebuilt per call: 10 × `net.established()` = 102.5 ms vs 13.5 ms for one sweep + filters; `hunt.jky` causes 3 sweeps where 1 suffices.
5. **`max_pids=400` truncates by PID value, silently.** `list_pids()` sorts ascending (procfs.py:57-58); `[:400]` (detect.py:102-153, 246) keeps the 400 lowest PIDs, while `fileless_processes`/`ld_preload_check`/`ioc_match` (detect.py:83, 227, 364) are uncapped and `scanned.processes` reports the full count (detect.py:345). On >400-process hosts five checks skip the newest processes, unflagged. [INFERENCE; `suspicious_cmdline(max_pids=3)` spot-checked (3/90, unflagged).]
6. **Threads slow `/proc` collection; they only help the latency-bound stage.** ThreadPool(4)/(16) `list_processes`: 116/119 vs 8.1 ms sequential (GIL-bound). Drvfs PATH resolution parallelises 11× (736 → 67 ms). Parallelise stat walks, never the sweep.
7. **VM: 840 ns/instruction, 16% of it accounting.** 3.9 M steps in 3,068 ms; dropping `self.steps += 1`, the `max_steps` compare and the `& 0x3FF` deadline poll (vm.py:259-265) → 706 ns. 50 M steps (runner.py:27) ≈ 42 s here, so step and wall budgets are near-redundant. No JIT: non-`CONST` ops cost a `dict.get` + call (vm.py:269).
8. **Fileless costs ~270 ms fixed per run vs 0.9 ms for source.** Empty payload 272 ms; `smoke.jky` 279 vs 40 ms. 7.65 MiB interpreter memfd (fileless.py:47-81), fork/execve, then zipimport of a **.py-only zip** (29 members, 0 `.pyc`; fileless.py:56-70): 0.21 vs 0.09 s warm.
9. **No streaming, caps or incrementality.** `triage()` returns one dict; `_emit` prints one `json.dumps` (cli.py:26-30, 130-135); findings grow unbounded at ~1,516 B each (10k ≈ 1.8 MiB objects, 4.4 MiB copied, 3.0 MiB JSON); only `_BOOT_TIME` is cached (procfs.py:34); the harness's 1,000 iterations are serial (evidence.py:151, 197).
10. **Unprivileged reads set the denominator:** only 16/90 pids expose `exe`/`cwd`/`environ`/`maps`/`fd` — >80% of sweep syscalls are EACCES [INFERENCE].

## Concrete improvements
1. **Per-run `Snapshot` + one merged fd sweep** feeding checks as filters (fixes 1–4). Prototype: process part 45.2 → 11.5 ms (3.9×), two sweeps 11.6 → 2.8 ms (4.2×). **M**; scope per call, stamp `captured_at`.
2. **`memfd_exe` from `entry["exe"]`** (procfs.py:277). **S**; no measurable risk.
3. **Cache mount table; reject opaque fstypes pre-`lstat`; memoise `path_dirs()`.** **S**.
4. **Check-then-insert instead of eager `setdefault`; cache pid→name per sweep.** **S**.
5. **Rank-and-cap; expose per-check inspected/total and `truncated`.** **S**; real fix is namespace scoping.
6. **Opt-in `.pyc` zip and ELF-memfd reuse across agent jobs.** **M**; adds disk artefacts.
7. **Charge VM accounting per basic block.** **M**; coarser budget — stay uncatchable.
8. **`--ndjson` streaming for triage.** **S**; new output contract.

Not fixable: the kernel-imposed walk cost (~15 µs per fd readlink) — 10⁴ processes / 10⁶ fds cannot be triaged sub-second in user space. Optimising the 82% unreadable processes is pointless.

## Verification approach
Instrumented counters before/after: triage ≤ 3,288 → ≤ 1,200 `/proc` syscalls, `read_exe` 572 → 90, `read_fds` calls 180 → 90, findings hash unchanged, live detection still finds a fileless process. Drvfs PATH within ±10% of `PATH=/usr/bin:/bin`. Stub 1,000 pids: all inspected, `truncated` set. `fileless_run_source("emit 1")` ≤ 150 ms. Microbenchmark ≥ 1.15 M steps/s, budgets still uncatchable.

## Citations
- microsoft/WSL #4197 (*/mnt performance*) — open, updated 2 Jul 2026 (canonical since 2019).
- PEP 779 (*supported free-threaded Python*) — 13 Mar 2025; outside the 3.12/GIL target.
- Python docs, `zipimport` (canonical): `.py`-only zips recompile per import.
