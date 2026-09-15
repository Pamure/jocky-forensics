# Linux in-memory execution & injection, 2024–2026 — measured against JOCKY

## Scope

Newest fileless-execution/injection primitives, kernel requirements, observable artifacts and
Volatility 3 / Falco / Elastic detection. Repo/kernel results were reproduced here
(6.6.87.2-WSL2, 2026-09-15); `file:line` cites the tree then.

## Findings

1. **Script-mode memfd is invisible to JOCKY's own detectors.** `jocky memfd` execs a shebang script
   from a memfd via `/proc/self/fd/N` (`jocky/exec/memfd.py:34,53,121`). Measured:
   `exe=/usr/bin/python3.12`, `cmdline=[python3, /proc/self/fd/3]`, fd3 → `/memfd:jky (deleted)`, no
   memfd mapping. exe/maps checks miss it (`detect.py:190-208,211-225,227-240`), the fd scan skips
   memfd targets (`procfs.py:351`), `CMD_PATTERNS` has no fd-exec rule (`detect.py:142-152`).
   Reproduced: five checks plus `triage()` → **0 findings** for a live script-memfd process.
   **Impact:** hunting misses script-mode jobs; Falco's default rule shares the gap.
2. **`memfd_create(name, 0)` + `fchmod +x` breaks under hardening.** Kernel 6.3 added `MFD_EXEC`/
   `MFD_NOEXEC_SEAL` and `vm.memfd_noexec`: at `1` an unflagged memfd is NOEXEC+sealed, at `2` creation
   fails. JOCKY passes `0` (`memfd.py:53`, `fileless.py:77`) then `fchmod 0755` (`memfd.py:63`).
   Measured: `MFD_NOEXEC_SEAL` + `fchmod(0o755)` → `EPERM`. **Impact:** hardening-driven breakage.
3. **`execveat(AT_EMPTY_PATH)` drops the procfs dependency.** Measured: artifacts identical to JOCKY's
   route (`exe=/memfd:py (deleted)`, memfd mappings) with no `/proc`. Pathless exec fabricates
   `/dev/fd/N` and rejects CLOEXEC script targets (`fs/exec.c:1517-1539`, `fs/binfmt_script.c`), so
   "never `MFD_CLOEXEC`" (`memfd.py:13-15,46-49`) is load-bearing. **Impact:** portability.
4. **Shebang ≠ ELF.** Only ELF mode yields a `/memfd:` `exe`; script mode leaves a real interpreter plus a memfd fd. New 2026 variant: `O_TMPFILE` + read-only reopen + execveat →
   `exe=/tmp/#1563905 (deleted)` with no `memfd` string (Dntry 2026-09-06; Elastic rule 6fdd522d
   2026-09-07, regex `.*/#[0-9]+.*`). JOCKY catches it only via the generic `(deleted)` test and
   mislabels it "runs from memory" (`detect.py:202`) — it is a nameless inode on a real filesystem.
5. **Injection primitives are uncovered.** No `TracerPid`, `process_vm_writev`, `pidfd_getfd` or
   `anon_inode:[userfaultfd]`/`[io_uring]` check, though `read_fds` collects them
   (`procfs.py:172-186`). Measured: unprivileged `userfaultfd(UFFD_USER_MODE_ONLY)` succeeds (fd →
   `anon_inode:[userfaultfd]`), `userfaultfd(0)` → `EPERM` (`vm.unprivileged_userfaultfd=0`), and
   `io_uring_setup` succeeds (fd → `anon_inode:[io_uring]`). Elastic hunts `ptrace`/`memfd_create` via
   auditd; Falco ships `ptrace_attach_or_injection`. **Impact:** injection blind spot.
6. **io_uring is staging-only.** ARMO's "curing" (2025-04-24) hid file/network I/O from syscall-scoped
   tools; Sysdig answered with `io_uring_setup` alerting, noting it cannot hide `execve` or processes
   (2025-04-25). Docker's default seccomp blocks it. **Impact:** staging blind spot.
7. **Real-time memfd telemetry is new upstream.** Elastic collects `memfd_create` only from stack 9.3.0
   (rule 42663c0e, 2026-09-08). JOCKY's on-demand equivalent is `deep`-only and capped at 400 pids
   (`detect.py:211,448`). **Impact:** real-time gap only.
8. **Volatility 3 does not rescue 1/4.** `linux.malfind` fires on RWX, RX with NULL `vm_file`, or X+dirty pages
   (`framework/plugins/linux/malware/malfind.py::_is_suspicious`); memfd/O_TMPFILE images are
   file-backed, so recovery needs `linux.proc.Maps`/`linux.elfs` or live `/proc`. **Impact:** no
   memory-forensics rescue.

## Concrete improvements

* **I1** pass `MFD_EXEC` (0x10), retry `flags=0` on `EINVAL` (pre-6.3), report
  `vm.memfd_noexec` in the triage host block — keeps `fileless` alive under hardening
  (`memfd.py:43-68`). **S**, low risk.
* **I2** use `execveat(AT_EMPTY_PATH)` for the ELF memfd, `/proc` route as fallback: identical
  artifacts, no procfs need. **S**, low risk.
* **I3** new checks `memfd_fd_holder` (pid holds a non-executed `/memfd:` fd) and `fd_script_exec`
  (`argv[1]` matching `/proc/self/fd/*` or `/dev/fd/*`), registered in `CHECKS`. Closes Finding 1 with
  no new collection; baseline `runc`, as Falco does. **S**, low risk.
* **I4** new check `injection_primitives`: `TracerPid != 0`, `anon_inode:[userfaultfd]`,
  `anon_inode:[io_uring]`, `exe` matching `/#\d+`; low/medium, correlation-only, run in non-deep
  `triage()`. **M**, medium FP risk (browsers, databases).
* **I5** out of scope in `docs/DESIGN.md` §7: ptrace/`process_vm_writev`/`pidfd_getfd`/
  userfaultfd injectors, an io_uring staging mode, O_TMPFILE *execution*. Offensive surface without
  forensic capability; two are default-denied. **S**, no code risk.

## Verification approach

* I1: run the fileless smoke test under `vm.memfd_noexec=1`; assert a result and the flag word.
* I2: assert evidence reports `exe == "/memfd:<name> (deleted)"` and `memfd_map_count >= 1`.
* I3: reuse the reproducer here (shebang memfd on `/proc/self/fd/N`): one finding for that pid, today none.
* I4: spawn `userfaultfd(UFFD_USER_MODE_ONLY)`/`io_uring_setup` children; assert one finding each in
  non-deep `triage()`.
* I5: doc-only; `triage()` must not raise.

## Citations

* memfd flags/sysctl — docs.kernel.org/userspace-api/mfd_noexec.html.
* Pathless exec — `fs/exec.c:1517-1539`, `fs/binfmt_script.c`, git.kernel.org torvalds/linux.
* io_uring — armosec.io/blog/io_uring-rootkit-bypasses-linux-security/ (2025-04-24); sysdig.com/blog/detecting-and-mitigating-io-uring-abuse-for-malware-evasion (2025-04-25).
* O_TMPFILE fileless ELF (Dntry) — matheuzsecurity.github.io/hacking/fileless-loader-bypassing-elastic-memfd/ (2026-09-06).
* Elastic — detection-rules `rules/linux/defense_evasion_fileless_execution_via_o_tempfile.toml` (6fdd522d, 2026-09-07), `..._unusual_memfd_create.toml` (42663c0e, 2026-09-08, 9.3.0+), `hunting/linux/queries/low_volume_process_injection_syscalls_by_executable.toml`.
* Falco — falcosecurity/rules `rules/falco_rules.yaml`: `Fileless execution via memfd_create`, `ptrace_attach_or_injection`.
* Volatility 3 — `framework/plugins/linux/malware/malfind.py`; releases v2.26.0 (2025-05-16), v2.28.0 (2026-04-30).
* All pages/kernel files retrieved 2026-09-15. userfaultfd defaults — man7.org/linux/man-pages/man2/userfaultfd.2.html; docs.kernel.org/admin-guide/mm/userfaultfd.html (since 5.11).
