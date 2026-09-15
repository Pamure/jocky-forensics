# Sandboxing untrusted JOCKY scripts

## Scope

Sandboxing for untrusted scripts (`--sandbox=<level>`); measurements from this host (WSL2, kernel `6.6.87.2`) in forked children self-restricting via `jocky/rt/raw.py:100-135`.

## Findings

1. **Escapes are two natives, not the language.** No write-mode open exists in `jocky/rt/`/`jocky/exec/`; `fs` is read-only (`builtins.py:229-247`). But `mem.memfd_run` (`:279-282`) runs arbitrary Python and `mem.syscall` (`:283-286`) any syscall: a script wrote `/tmp/pwn.txt` and opened a socket. → Gate `mem`.
2. **Budgets are not resource limits.** Only steps/frames/wall (`jocky/lang/vm.py:157-159`), sampled every 1024 steps (`:262-264`); natives are uninterruptible, memory unbounded. → Add `RLIMIT_AS`/`NPROC`/`NOFILE`.
3. **Landlock here is filesystem-only (probed ABI 3).** 8-byte attr accepted; 16/24 bytes → `E2BIG`, bit 15 → `EINVAL`, matching v6.6.87's `handled_access_fs`-only UAPI. TCP rights need ABI 4 (landlock(7)). → seccomp must own egress.
4. **Landlock is precise, unprivileged, stdlib-only.** Via `raw.syscall` 444/445/446 plus `PR_SET_NO_NEW_PRIVS`: `/etc/shadow` reads and `/tmp` writes → `EACCES`, while per-file rules kept `/etc/passwd` readable. An outer launcher cannot (exec → `EACCES`). → Install the policy inside the executing process.
5. **Metadata and inherited descriptors stay open.** `stat`/`access`/`chdir` are unrestrictable (landlock(7)); `fs.stat("/etc/shadow")` returned size and mode while `fs.read` was denied. → Not confidentiality.
6. **seccomp without libseccomp works.** Hand-built `sock_filter`/`sock_fprog` via ctypes and `prctl`: `Seccomp: 2`, target syscall `EPERM`. BPF sees registers only, so no path filtering; filters are irreversible and need TSYNC for threads.
7. **The stack closes both escapes.** Landlock plus the seccomp denylist: `memfd_run` exit 127, `socket` → `EPERM`, `/etc/shadow` unreadable, no `/tmp/pwn.txt`.
8. **Fileless is the binding constraint.** With `EXECUTE` handled but ungranted, fileless dies silently (exit 127, empty stderr — swallowed at `jocky/exec/fileless.py:96-101`), its interpreter needing `EXECUTE` for `PT_INTERP`; granting it on `/usr`,`/lib`,`/lib64` restores fileless (`ok=true`, `exe=/memfd:python3 (deleted)`, 4 mappings). → Policy in-process or in `BOOTSTRAP` (`fileless.py:33-40`); `strict` excludes fileless.
9. **Namespace sandboxes silently corrupt the forensic view.** Unprivileged bubblewrap 0.9.0 (implicit user namespace) left `/proc/<pid>/maps` readable for 2 of 91 pids vs 17 of 90 outside; findings 24 → 10 (ro-bind) → 0 with `--unshare-net`; sockets 153 → 0. Nothing errored. → Payloads only.
10. **cgroup v2 is a throttle, not a guarantee; microVMs and WASI cannot host the collector.** Direct `/sys/fs/cgroup` writes fail for uid 1000, but `systemd-run --user --scope -p MemoryMax=64M` sets `memory.max`; a 200 MiB touch hit it 2078 times with `oom_kill 0`, so `RLIMIT_*` stays the deterministic floor. gVisor/Firecracker need `/dev/kvm`, root and images, and show guest state, not host `/proc`. WASI has no stdlib engine (wasmtime-py is third-party) and refuses absolute paths, so `/proc/<pid>/exe` is unreachable.

## Concrete improvements

- **`jocky/sandbox.py`, four levels.** `off` (today); `vm` = native allowlist dropping `mem.*` + `RLIMIT_AS`/`NPROC`/`NOFILE`; `ro` = `vm` + Landlock (handle every fs right; grant `READ_FILE|READ_DIR` on `/proc`,`/sys`,`/usr`,`/lib`,`/lib64`,`/home` plus per-file `/etc` allowlist) + `no_new_privs`; `strict` = `ro` + seccomp denylist (`socket`, `execve`, `memfd_create`, …). *Why:* findings 1, 3, 6. *Sketch:* `apply(level)` from `runner.run_program` before `vm.run`; ABI probed at runtime. *Effort S/M/M.* *Risk:* per-host allowlists (CVE-2025-68736 needs rights we deny).
- **Refuse, never downgrade.** A missing primitive must fail loudly (`EOPNOTSUPP`/`ENOSYS`), matching the doctor's honesty contract (`jocky/diagnostics.py:30-72`). *Effort S.* *Risk:* worse UX, correct forensics.
- **Self-reported denials.** Landlock audit needs ABI 7 (6.15) and seccomp `ERRNO` is silent, so the runtime must count its own refusals as findings. *Effort S.* *Risk:* counters are advisory.
- **Doctor group and payload-only namespaces.** Add `_check_sandbox` beside `diagnostics.py:75-236`; gate namespaced mode behind a "collection will be wrong" warning. *Effort S/L.* *Risk:* bwrap is an external binary, against the zero-dependency rule.

## Verification approach

Fixtures run the hostile script per level, asserting: `fs.read("/etc/shadow")` yields `<unreadable: …>`; `mem.memfd_run` exits non-zero; `mem.syscall(41,2,1,0)` raises; no `/tmp/pwn.txt` exists; `fileless --sandbox=ro` still reports `exe=/memfd:python3 (deleted)` with 4 mappings. Negative control: the same script under `--sandbox=off` must succeed. Unchanged findings hashes under `--sandbox=ro` prove no collection loss; `jocky doctor --json` must show the sandbox group. Below kernel 5.13 the tests must skip, not pass.

## Citations

- landlock(7), man-pages 6.19, 2026-07-18 — https://man7.org/linux/man-pages/man7/landlock.7.html
- seccomp(2), man-pages 6.19 — https://man7.org/linux/man-pages/man2/seccomp.2.html
- Landlock kernel docs (RST), Aug 2026 — https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/Documentation/userspace-api/landlock.rst
- Landlock UAPI v6.6.87 — https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain/include/uapi/linux/landlock.h?h=v6.6.87
- CVE-2025-68736, 2025-12-24 — https://nvd.nist.gov/vuln/detail/CVE-2025-68736
- WASI 0.2 filesystem `types.wit` — https://raw.githubusercontent.com/WebAssembly/WASI/wasi-0.2/proposals/filesystem/wit/types.wit
- WASI roadmap, 0.3.0 2026-06-11 — https://wasi.dev/roadmap
- gVisor install requirements — https://gvisor.dev/docs/user_guide/install/
- Firecracker specification — https://github.com/firecracker-microvm/firecracker/blob/main/SPECIFICATION.md
- bubblewrap, 0.9.0 measured locally — https://github.com/containers/bubblewrap
