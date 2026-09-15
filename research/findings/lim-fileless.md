# lim-fileless — true-fileless execution: real limits

## Scope
`jocky/exec/fileless.py` (interpreter/pkg/payload memfds, `fork`+`execve` bootstrap), `jocky/exec/memfd.py`, plus runner/CLI/agent wiring; claims: "nothing on disk" (`fileless.py:14-15`), implied stealth (`docs/DESIGN.md:125`). Probed inline on Linux 6.6.87.2-WSL2 / CPython 3.12.3.

## Findings
1. **Payload readable in cleartext while live.** Same-uid probe: reading `/proc/<pid>/fd/<pay_fd>` returned the payload. Fds are `0o600` via `os.memfd_create(name,0)` (`fileless.py:77`; no `MFD_ALLOW_SEALING`) and `BOOTSTRAP` never closes them (`fileless.py:35-41`). Impact: no confidentiality, and the unsealed fd stays same-uid writable (integrity).
2. **`cmdline`/`environ` carry the loader and the fds.** `fileless.py:147` execs `["python3","-c",BOOTSTRAP]`; probe: `cmdline` = `python3\0-c\0import os, sys, json;…`, `environ` = `JKY_PKG=9\0JKY_PAYLOAD=10\0` (built `fileless.py:141-146`). Impact: `ps auxww` + `environ` is a complete IOC and, with (1), a recovery recipe; JOCKY's own `suspicious_cmdline` (`detect.py:37`) misses the bootstrap (verified), so self-detection rests on `exe`.
3. **Identity destroyed.** Probe: `comm` = fd number (`23`, matching `evidence/detection.json:6`); `sys.executable`=`/usr/bin/python3` while `exe`=`/memfd:python3 (deleted)`. Impact: numeric names are a known indicator; `sys.executable` code paths re-exec the **on-disk** interpreter.
4. **8 MB per run, never reused.** `python_elf()` (`fileless.py:47-52`) reads the ELF (8 020 928 B, `evidence/artifacts.json:27`) and `fileless.py:127` writes a fresh memfd every call. Impact: 8 MB shmem + RSS + dirty pages per run ×N, for a byte-identical copy of `/usr/bin/python3.12` adding no confidentiality and being what `detect.py:87` flags first.
5. **"Nothing on disk" covers three dirs.** The interpreter still loads ld.so/libc/libz/libexpat and 54 MB of stdlib from `/usr/lib/python3.12`; `evidence.py:250` snapshots only REPO_ROOT,/tmp,/dev/shm,/var/tmp; the child env sets no `PYTHONDONTWRITEBYTECODE` (`evidence/report.md:25`: 74 bytecode caches from a cold interpreter). Impact: as root with an unwritten prefix, `.pyc` lands outside every measured root; `fileless_code_created_nothing` (`evidence.py:267`) is not filesystem-wide.
6. **Prerequisite denials are silent.** `fileless.py:148-149` does `os._exit(127)` with empty stderr (contrast `memfd.py:122-125`). Unguarded: missing `memfd_create` (`fileless.py:75`; `memfd.py:50-55` raises cleanly), `vm.memfd_noexec≥2` → EACCES (kernel doc), SELinux `memfd_file:execute_no_trans` AVC, AppArmor `deny /proc/*/fd/* x`. Mount `noexec` does not apply (probe succeeded with `/proc` `noexec`): the inode is on the internal shmem mount. Impact: hardened hosts look identical to a payload crash through `client.py:276-277`.
7. **No dump, core or resource hardening.** No `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` or `RLIMIT_AS`; the child closes only the four pipe fds (`fileless.py:139-140`), unlike `memfd.py:118`, so inherited agent fds attach. Probe: `/proc/<pid>/mem` is same-uid readable (live payload extraction). A crash dumps the 8 MB image plus payload to `core_pattern` (default `core` in cwd; apport → `/var/crash`). Untestable here: `core_pattern` is a WSL pipe.
8. **Evidence field broken.** `fileless.py:109` stores `line.split()[-1]`, so `evidence.memfd_maps` is `["(deleted)",…]` (`evidence/detection.json:50-56`; reproduced), while `memfd.py:315` joins `fields[5:]`. Impact: the record cannot name it, weakening `tests/test_fileless_detection.py:80-81`.

## Concrete improvements
1. **Bootstrap hygiene:** inside the payload, `prctl(PR_SET_DUMPABLE,0)`, `prctl(PR_SET_NAME,"kworker/0:1")`, `setrlimit(RLIMIT_CORE,(0,0))`, close elf+payload fds, load the pkg zip into memory. Probe: closing the exec'd memfd is safe (mappings survive). Effort S, risk low; fixes 1,3,7; `exe` stays memfd-backed (unfixable).
2. **Seal:** `MFD_ALLOW_SEALING` + `F_SEAL_SHRINK|GROW|WRITE` (never `F_SEAL_EXEC`); report the payload SHA-256. Effort S, risk low.
3. **Drop or cache the interpreter memfd** (exec the on-disk interpreter, or one memfd per process). Effort S, risk low — changes the `exe` evidence pinned by `tests/test_fileless_detection.py:65` and `docs/DESIGN.md:125`.
4. **Replace `-c BOOTSTRAP`** with a zipapp entry: exec `python3 /proc/self/fd/<pkg_fd>`. Effort M, risk medium (argv still shows the fd path).
5. **`subprocess.Popen(pass_fds=…, close_fds=True, stdin=DEVNULL)` + `PR_SET_PDEATHSIG`** instead of raw `fork` (`fileless.py:137`, `memfd.py:236`): removes the threaded-fork warning (observed) and orphaned runs. Effort S, risk low.
6. **Fail loudly and clean up:** mirror `memfd.py`'s status pipe in `fileless.py`, preflight `memfd_create`/memfd-exec into the evidence, converge the two `create_memfd`s (`fileless.py:75` lacks the `hasattr` guard and short-write loop), fix `fileless.py:109`, drop the unused `inspect`. Effort S, risk low.

## Verification approach
Live test in the style of `tests/test_fileless_detection.py`: while a run is live, assert no `/proc/<pid>/fd/*` other than `exe` resolves to `memfd:`; `cmdline`/`environ` carry no `jky`/`JKY_` token; `comm` is the spoofed name; `/proc/<pid>/mem` raises EACCES; `evidence.memfd_maps[0]` starts with `/memfd:`; the payload fd rejects writes. Then 20 sequential runs must leave `Shmem` and launcher RSS flat, a SIGSEGV'd payload must leave no `core*` in cwd, and a run under `vm.memfd_noexec=1` must return a specific error, not 127.

## Citations
- memfd flags / `vm.memfd_noexec` (EACCES at ≥2): docs.kernel.org/userspace-api/mfd_noexec.html — kernel 6.3, 2023 (canonical-but-dated).
- SELinux `memfd_file`: lore.kernel.org LSM series tweek@google.com (2025-08-26); paul-moore.com/blog/d/2025/12/linux_v619_merge_window.html (Dec 2025).
- Core dumps: man7.org/linux/man-pages/man5/core.5.html.
- Detection engineering: falco.org/docs/reference/rules/supported-fields/; elastic.co/security-labs/threat-command/memfd-create-linux-fileless-execution; sysdig.com/blog/fileless-malware-detection-sysdig-secure (last three undated).
