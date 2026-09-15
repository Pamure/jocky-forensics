## Scope
`detect.py` and its collectors (`procfs`, `netfs`, `filefs`, `sysinfo`), plus `tests/test_runtime.py`. Measurements: this host, uid 1000, 90 visible pids, direct calls; no suite run. Line refs re-verified after a concurrent `detect.py` edit (516 lines). Out of scope: language/VM, encoder, agent.

## Findings
1. **PID hiding is undetectable.** `hidden_modules` diffs two kernel views (detect.py:376-395) yet `list_pids` (procfs.py:65-75) is the only PID enumeration; loadavg's live-entity count and newest PID (proc_loadavg(5)) go unread. A `readdir`/`getdents` filter (Symbiote, Intezer 9 Jun 2022; Hildegard, T1014) returns "clean" — visibility is attacker-chosen.
2. **`hidden_modules` is the only `critical` check and needs a careless rootkit.** sysinfo.py:182-191 diffs `/proc/modules` against `/sys/module`; a module unlinked from both (Drovorub, NSA/FBI Aug 2020) diffs empty. No kallsyms, taint or syscall-table check.
3. **Unprivileged coverage collapses silently.** `read_exe`/`read_environ` swallow `OSError` (procfs.py:146-151, 161-167); measured 73/90 gave `environ=[]`, 75/90 `exe=None`, so the fileless/deleted/temp checks (detect.py:190-256) and `ld_env_injection` (detect.py:328-350) inspected ~17% and reported success.
4. **No coverage accounting; `sys.users()` is broken.** Crashed checks become `check_error` at `info` (detect.py:446) and results carry no denominators (detect.py:454-462), so hunt.jky:11 cannot separate clean from broken. `logged_in_users` reads `stat["tty"]`, which `read_stat` never returns (procfs.py:78-116): `KeyError: 'tty'` (builtins.py:226).
5. **Namespace/hidepid opacity is presented as completeness.** One PID namespace; `hidepid=2`/`subset=pid` hide entries (proc(5), 8 Feb 2026). `container()` (sysinfo.py:38-49) never reaches `triage` (detect.py:457-461).
6. **Mount-level hiding is excluded by design.** `mounts()` (sysinfo.py:109-133) is never consumed; `OPAQUE_MODE_FSTYPES` exempts `fuse` (filefs.py:207-208); no `/dev/fuse`, `ns/mnt` or `bpf()` check. eBPF getdents hiding (TripleCross) and FUSE shadowing of `/etc` are invisible.
7. **Timestomping is invisible.** `persistence` is forward-only, `mtime >= now-30d` (detect.py:414); `ctime` is collected (filefs.py:95) but never compared. `touch -t 200001010000` hides artefacts (T1070.006).
8. **Log tampering is one live-cmdline regex** (detect.py:150); `/var/log`, wtmp/btmp, journal, `/etc/audit/*` are absent from `PERSISTENCE_PATHS` (detect.py:156-166) and triage (T1685.004/.006).
9. **No temporal state — every run is a cold snapshot.** `triage` is stateless and the agent store appends only (server.py:200-238): no diff, baseline or allow-list learning.
10. **Severity is uncalibrated; measured `high` precision is ~0.** `SEVERITY_ORDER` (detect.py:26) and per-check literals (detect.py:142-168) are the model. `triage(deep=True)` here returned 136 benign persistence hits (snap/dbus), 0 medium/critical, 9-14 `rwx_memory` from Node/V8 reservations. `rwx_regions` needs literal `rwx` (procfs.py:230), missing W^X `rw-`+`r-x` aliases; `memfd_mappings` (detect.py:211-225) is deep-only (detect.py:448-450) while README sells `jocky triage` as host triage.

## Concrete improvements
1. **Cross-view PID ceilings** — `procfs.view_counters()`: loadavg field 4 vs Σ`Threads`, field 5 vs max PID → `view_mismatch`. Root-free readdir detection. **S**; risk: churn → 2-sample/10% slack, cap `medium`.
2. **Module triangulation** — `/proc/modules` vs `/sys/module` vs kallsyms + taint. **M**; risk: symbol mangling → suffix whitelist.
3. **Coverage accounting** — `scanned.unreadable_processes`, per-check evaluated/total, `errors`, `check_error` at `medium`. **S**; risk: stricter thresholds surface real failures.
4. **Fix `sys.users()`** — parse `tty_nr` (field 7 → `rest[4]`, procfs.py:78-116). **S**; risk: none.
5. **Timestomp check** — `mtime > ctime+1s`, whole-second mtime, `mtime > now` over `PERSISTENCE_PATHS`. **S**; risk: rsync/untar → cap `medium`.
6. **Log integrity** — stat `/var/log/journal`, `/var/log/audit`, wtmp/btmp, `auditd.conf` drift. **M**; risk: distro variance → else `not_present`.
7. **Baseline diff** — keyed snapshot + agent `baselines` table; emit `new_finding`/`known_finding`. **M**; risk: keys must exclude cmdline.
8. **Detection-quality scoring** — per-check robustness/precision and implementation coverage, per STP (CTID 10 Sep 2026). **M**; risk: re-baselining thresholds.
9. **W^X-aware scan** — group maps by inode/offset, flag `rw-`+`r-x` aliases and `(deleted)` exec maps; hash-keyed JIT allow-list. **M**; risk: name-keying restores FPs.
10. **ptrace/LD hardening** — collect `TracerPid`, `State=='t'`, `yama/ptrace_scope`, `/etc/ld.so.conf.d`. **S**; risk: absent LSM → report `absent`.

## Verification approach
Throwaway repros. (a) LD_PRELOAD a `readdir` wrapper dropping one PID → `view_mismatch` while `list_pids` looks clean; nothing when idle. (b) Fixtures for a fabricated `/proc/modules`+`/sys/module` pair. (c) uid 1000 vs root: `unreadable_processes`→0, fileless denominator = `len(list_pids())`. (d) `os.utime(path,(2000,2000))` → one `medium`. (e) Two runs, one new benign process → exactly one `new_finding`. (f) Re-run here: `high` falls to the snap/dbus floor. `test_module_views_agree_on_loadable_modules` pins Finding 2's absence — rewrite, not extend.

## Citations
- Intezer/BlackBerry, *Symbiote Deep-Dive*, 9 Jun 2022 — intezer.com/blog/new-linux-threat-symbiote
- MITRE ATT&CK v19 (12 May 2026): T1014, T1070.006, T1574.006, T1055.008; T1685.004/.006 (14 Apr 2026).
- NSA/FBI, *Drovorub*, Aug 2020 — canonical-but-dated.
- proc(5), proc_loadavg(5), ptrace(2) — man-pages 6.19, 8 Feb 2026.
- h3xduck/TripleCross, read 2026-09-15; CTID *Summiting the Pyramid*, 16 Dec 2024; *Beyond the Heatmap*, 10 Sep 2026.
