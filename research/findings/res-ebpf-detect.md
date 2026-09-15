# eBPF/LSM endpoint telemetry (2024–2026) and JOCKY's observability floor

## Scope
JOCKY's exec/memory chain and self-measurement; Linux 6.6 hook
availability; default detection in Falco, Tetragon, Tracee, Elastic Defend; what
user space cannot hide. Anchors: revision read 2026-09-15; symbols are authoritative.

## Findings

**1. Every hook exists.** `/proc/kallsyms` (6.6.87.2-WSL2) lists
`security_bprm_check`, `security_bprm_creds_for_exec`,
`security_bprm_committed_creds`, `security_file_mprotect`,
`security_mmap_file/addr`, `security_file_open`, `security_task_alloc`,
`security_ptrace_access_check`, `do_mmap`, `vm_mmap`; BPF LSM attach is
documented [1,2]. ⇒ each step of `fileless.py:75-77,134,147` and `raw.py:100`
lands on a named hook.

**2. JOCKY chose the loudest fileless variant.** ShiftyLoader (ITASEC 2024)
loads `PT_LOAD`s with one `mmap` and jumps — no `exec*` — evading Tracee,
Kaspersky and ESET on 162 samples; only noisy `mmap`/`mprotect` visibility
remains [12]. ⇒ docs must say "detectable by construction".

**3. Stock Falco fires; the allow-list is runc-only.** Rule *Fileless execution
via memfd_create*: `proc.is_exe_from_memfd=true and not
known_memfd_execution_processes`, exempting runc and
`memfd:runc_cloned:/proc/self/exe` [3]. JOCKY is `/memfd:python3 (deleted)`
(README.md:122). ⇒ accept the alert or weaken a stable rule; falco#3444 (2025,
rules PR #268) shows it is contested.

**4. Memory hooks exist; defaults are uneven.** Falco defines PPME events for
memfd_create, execveat, ptrace, process_vm_writev, mmap2 but ships no
`mmap`/`mprotect`/`process_vm_writev` rule among 25 defaults [3,5]; Tracee
kprobes `security_file_mprotect`, `security_mmap_file/addr`, `do_mmap`,
`security_bprm_check` [6]; Tetragon ships `process_exec`/`process_exit` (bprm
sensors, `kprobe/wake_up_new_task`) plus LSM policies [9,10]. ⇒ verdicts are
per-policy.

**5. Elastic closed the memfd gap in 2026.** Security 9.4.0 records
`memfd_create` process events on Linux (kernel ≥5.10.16) and
`init_module`/`finit_module`, with rule *Potential Memory File Descriptor
Process Execution* [11]. ⇒ no mainstream blind spot.

**6. Self-measurement is audit-scoped.** `evidence.py:79` counts Python audit
events (`os.fork`/`os.exec`); the `raw.py` trampoline's machine-code syscalls
raise none, and `fileless` never runs under the hook. ⇒ README.md:119's "0 child
processes, 0 execve" is not an eBPF claim.

**7. Self-exclusion hides the data.** `detect.py:180` skips JOCKY's own pids in
the fileless/memfd/RWX checks (190/211/258/435), so it never reports its own
memfd mapping (`high`) or RWX trampoline (`low`). ⇒ the audit needs a
self-inclusive pass.

**8. The floor is a trust statement.** Tracee: kernel trusted at start; user-space
root cannot evade; kernel adversaries best-effort; syscall-event args are
TOCTOU-racable; prefer LSM events [7,8]. ⇒ document the boundary; report
hook presence, never "clean".

**9. This host sees none of it.** `/sys/kernel/security/` empty, no tracefs
events, `unprivileged_bpf_disabled=2` [13]. ⇒ print `unknown/not exposed`, never
a silent pass.

**10. `vm.memfd_noexec` caps the technique.** Flags `0` (`fileless.py:77`,
`memfd.py:53`); level 1 ⇒ non-exec memfds (exec fails, child exits 127,
`fileless.py:147-150`), level 2 ⇒ `memfd_create` rejected [1]. ⇒ hardened hosts
cannot run `fileless`.

## Concrete improvements
1. **`docs/OBSERVABILITY.md`** — action × hook × shipping tool × verdict matrix,
   replacing prose (README.md:110-119, DESIGN.md:113-115). **S**.
2. **`jocky observe`** (`jocky/rt/observer.py`; CLI at cli.py:232-238) —
   read-only probe of `/sys/kernel/security/lsm`, `unprivileged_bpf_disabled`,
   `vm.memfd_noexec`, `/etc/audit/audit.rules`, tracefs `available_events`
   (memfd_create, execveat, ptrace, process_vm_writev); findings via `_finding`
   (detect.py:169) at `info`/`unknown`. **M**, low risk.
3. **`jocky selfaudit --policy falco|tetragon|tracee|elastic|all`** — matrix
   (rule id, hook, predicate, URL+date) scored against the ledger, printing
   matched conditions; `--include-self` un-skips detect.py:180; unknown policy id
   fails loudly. **M**, risk: matrix rot — pin dates.
4. **Action ledger** — `JKY_LEDGER=<path>` JSONL in `fileless.py`/`raw.py`/
   `memfd.py`, feeding (2)/(3) and replacing the Python hook in `stage_audit`
   (evidence.py:276); off by default. **S–M**.
5. **Dedup/allow-list guidance** — match the correlated triple (memfd_create →
   writable exec memfd → exec of `/proc/self/fd`), never bare syscalls; ship
   literal Falco overrides flagged contested (falco#3444); prefer
   `security_bprm_check` over syscall tracepoints to close the TOCTOU race. **S**.

## Verification approach
- Stock Falco + `jocky fileless scripts/smoke.jky` ⇒ exactly one alert;
  `jocky selfaudit --policy falco` predicts the same set (audit log = ground truth).
- Tracee (`--events memfd_create,security_file_mprotect,security_bprm_check,
  execveat,mmap`) ⇒ one ledger entry each, despite three memfds.
- Unit: `selfaudit` is pure over a fixture ledger — fires on memfd+exec, silent
  without, `unknown` (not pass) for an unrecognised policy id.
- Controls: `observe` here reports securityfs/tracefs not exposed; under
  `vm.memfd_noexec=2`, `fileless` fails loudly and `observe` names the sysctl.

## Citations
Web sources accessed 2026-09-15.
1. docs.kernel.org/userspace-api/mfd_noexec.html (kernel 6.3+).
2. docs.kernel.org/bpf/prog_lsm.html.
3. github.com/falcosecurity/rules `rules/falco_rules.yaml` (commit `80880bd5`, 2026-09-04).
4. falcosecurity/falco#3444 (2025-01 → 2025-02; rules PR #268).
5. falcosecurity/libs `driver/ppm_events_public.h`.
6. aquasecurity/tracee `pkg/ebpf/c/tracee.bpf.c`.
7. aquasecurity/tracee `docs/docs/security-model.md`.
8. aquasecurity.github.io/tracee/latest/docs/events/builtin/security-events/.
9. tetragon.io/docs/concepts/tracing-policy/hooks/.
10. cilium/tetragon `bpf/process/{bpf_execve_bprm_commit_creds.c,bpf_fork.c}`.
11. Elastic Security Labs, "Linux Detection Engineering - Fileless Execution" (2026-09-01).
12. Salvatori et al., "ShiftyLoader", ITASEC 2024 — ceur-ws.org/Vol-3731/paper02.pdf.
13. Local: `/proc/kallsyms`, `/proc/sys/vm/memfd_noexec`, `/sys/kernel/security/` (6.6.87.2-WSL2).
