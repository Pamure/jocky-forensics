# Fileless execution

`jocky fileless script.jky` (alias `jocky memfd`) runs a script — or a built
artifact — with nothing written to the target's filesystem. The interpreter, the
`jocky` runtime and the payload all live in anonymous memory files created with
`memfd_create()`, and the process that ends up running is the memory copy of the
interpreter, not a file on disk:

```bash
./venv/bin/jocky fileless scripts/triage.jky
```

The implementation is `jocky/exec/fileless.py`; the run also goes through
`jocky/runner.py`, so a fileless job uses the same VM, collectors and budgets as
any other mode.

## Three memory files

`create_memfd(name, data, mode)` writes bytes into a `memfd_create()` object and
`fchmod`s it. One run creates three:

| memfd | Contents | Size on this host | Mode | Handed to the child as |
|---|---|---|---|---|
| `python3` | the interpreter ELF, read from `sys.executable` | 8020928 bytes | `0755` | the exec target: `/proc/self/fd/<fd>` |
| `<name>-pkg` | a zip of the whole `jocky` package, built in memory | ~113 KB (94110 bytes measured by the harness) | `0600` | `JKY_PKG`, used as a `sys.path` entry |
| `<name>-payload` | the script text or artifact bytes | the payload size | `0600` | `JKY_PAYLOAD`, read once then closed |

None of the three is given `O_CLOEXEC`, because they must survive the `execve`
that replaces the forked child. After the bootstrap has read the payload it
closes that descriptor; the package descriptor stays open, because `zipimport`
reads it lazily for the lifetime of the process.

## The `-c` bootstrap

The child is started as `/proc/self/fd/<elf_fd>` with argv
`["python3", "-c", BOOTSTRAP]`. The bootstrap is pure argv text — it is never
written to a file — and it is the source of both the capability policy and the
process hardening:

```python
import ctypes, json, os, resource, sys
def _harden():
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(15, b"jky", 0, 0, 0)        # PR_SET_NAME
        if os.environ.get("JKY_DUMPABLE", "1") == "0":
            # Opt-in: PR_SET_DUMPABLE=0 makes /proc/<pid>/* root-only, hiding the
            # payload and maps from same-uid processes. It also hides this process
            # from JOCKY's own triage, so it is off by default (see --private).
            libc.prctl(4, 0, 0, 0, 0)
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
_harden()
sys.path.insert(0, "/proc/self/fd/" + os.environ["JKY_PKG"])
from jocky.runner import policy_ctx, run_bytes
with open("/proc/self/fd/" + os.environ["JKY_PAYLOAD"], "rb") as handle:
    data = handle.read()
try:
    os.close(int(os.environ["JKY_PAYLOAD"]))
except OSError:
    pass
result = run_bytes(data, wall_clock_ms=float(os.environ.get("JKY_WALL", "60000")),
                   ctx=policy_ctx(os.environ.get("JKY_ALLOW")))
sys.stdout.write("JKY_RESULT " + json.dumps(result.to_dict()))
```

Step by step:

1. `_harden()` sets the process name to `jky` (`PR_SET_NAME`), disables core
   dumps (`RLIMIT_CORE = 0`) and, only when `JKY_DUMPABLE=0`, marks the process
   non-dumpable.
2. The package memfd is inserted at the front of `sys.path` as
   `/proc/self/fd/<JKY_PKG>` — `zipimport` accepts that path, so
   `from jocky.runner import …` is satisfied from the zip in memory.
3. The payload is read from `/proc/self/fd/<JKY_PAYLOAD>`; `run_bytes` dispatches
   on the `JKY1` magic, so the same path runs a script or an artifact.
4. The result is written to stdout as one `JKY_RESULT <json>` line that the
   parent parses back into a `RunResult`.

The parent (`run_fileless`) passes only the environment it needs — `PATH`,
`JKY_PKG`, `JKY_PAYLOAD`, `JKY_WALL` and `JKY_ALLOW` — drains the child's
stdout/stderr through pipes, samples the child's `/proc` state, and enforces the
timeout.

## How fileless mode differs from the others

| | source | artifact | fileless |
|---|---|---|---|
| program text | `.jky` on disk | encrypted artifact on disk | memfd |
| interpreter | `/usr/bin/python3` | `/usr/bin/python3` | the same ELF, copied into a memfd |
| runtime modules | imported from disk | imported from disk | `zipimport` from a memfd |
| `/proc/<pid>/exe` | `/usr/bin/python3.12` | `/usr/bin/python3.12` | `/memfd:python3 (deleted)` |
| files created | 0 (warm) / 74 caches (cold) | 0 | 0 |

See [execution modes](/docs/execution/modes) for the measured telemetry each
mode produces.

## Kernel prerequisites

* `memfd_create()` — Linux 3.17 or newer. The flag `MFD_EXEC` (`0x1000`) is
  requested first, because with `vm.memfd_noexec >= 1` a plain memfd is created
  non-executable and a later `fchmod(+x)` fails with `EPERM`. Kernels that do not
  know the flag return `EINVAL` and JOCKY falls back to
  `memfd_create(name, 0)`. On this host `/proc/sys/vm/memfd_noexec` is `0` and
  the kernel is `6.6.87.2-microsoft-standard-WSL2`.
* `/proc` must be mounted (it is needed both to exec `/proc/self/fd/<fd>` and for
  the collectors) and the descriptors must not be `O_CLOEXEC`.
* A Python 3 interpreter must be readable at `sys.executable` — the ELF is copied
  from it, never executed from disk.
* No privilege is required; the `PackageFd`/runtime zip is built from the
  installed package.

`jocky doctor` checks exactly this and runs an end-to-end probe (skip it with
`--quick`):

```text
FILELESS
  [ok  ] memfd_create                 available
  [ok  ] fileless end-to-end          exe=/memfd:python3 (deleted) memfd_maps=4

ready: 12 ok, 1 warning(s), 0 failure(s) in 206 ms
```

## Verifying it yourself

**1. From inside the process.** A script can read its own `/proc/self`:

```jocky
let me = sys.pid()
emit {"pid": me, "exe": proc.exe(me), "cwd": proc.info(me).cwd}
let maps = proc.maps(me)
let memfd = filter(maps, fn(m) { return m.memfd })
emit {"mappings": len(maps), "memfd_mappings": len(memfd),
      "memfd_executable": count(memfd, fn(m) { return m.perms[2] == "x" })}
emit {"memfd_paths": transform(memfd, fn(m) { return m.path })}
```

```text
$ ./venv/bin/jocky fileless /tmp/jdocs/self_probe.jky
{"pid": 49846, "exe": "/memfd:python3 (deleted)", "cwd": "/home/mjonir/f/sih2026/sih148"}
{"mappings": 82, "memfd_mappings": 5, "memfd_executable": 1}
{"memfd_paths": ["/memfd:python3 (deleted)", "/memfd:python3 (deleted)", "/memfd:python3 (deleted)", "/memfd:python3 (deleted)", "/memfd:python3 (deleted)"]}
```

**2. From another process, while it runs.** Start a fileless job that stays
alive for a few seconds (`sleep(4)`) and look at the child from outside:

```text
$ ls -l /proc/$PID/exe
lrwxrwxrwx 1 mjonir mjonir 0 Sep 15 23:14 /proc/40890/exe -> /memfd:python3 (deleted)

$ cat /proc/$PID/comm
jky

$ tr '\0' ' ' < /proc/$PID/cmdline | cut -c1-72
python3 -c import ctypes, json, os, resource, sys
def _harden():
    try:
        libc

$ grep -c 'memfd:' /proc/$PID/maps
5

$ grep 'memfd:' /proc/$PID/maps | head -4
00400000-00420000 r--p 00000000 00:01 24                                 /memfd:python3 (deleted)
00420000-00703000 r-xp 00020000 00:01 24                                 /memfd:python3 (deleted)
00703000-00a28000 r--p 00303000 00:01 24                                 /memfd:python3 (deleted)
00a28000-00a29000 r--p 00627000 00:01 24                                 /memfd:python3 (deleted)

$ ls -l /proc/$PID/fd | grep 'memfd'
lrwx------ 1 mjonir mjonir 64 Sep 15 23:23 4 -> /memfd:python3 (deleted)
lrwx------ 1 mjonir mjonir 64 Sep 15 23:23 6 -> /memfd:slow6.jky-pkg (deleted)
```

So the executable image, its mappings and the runtime zip are all memory files;
the interpreter memfd is `fd 4`, the package zip is `fd 6` and stays open.

**3. With the detector.** The same runtime ships the detection counterpart. Run
it while a fileless job is alive:

```jocky
for f in det.fileless() {
  emit {"check": f.check, "severity": f.severity, "title": f.title,
        "pid": f.evidence.pid, "exe": f.evidence.exe}
}
for f in det.memfd_maps() {
  emit {"check": f.check, "severity": f.severity, "pid": f.evidence.pid,
        "perms": f.evidence.perms, "size_kb": f.evidence.size_kb}
}
emit {"scanned_processes": len(proc.list())}
```

```text
$ ./venv/bin/jocky fileless /tmp/jdocs/slow6.jky &   # sleeps 6 s
$ ./venv/bin/jocky run /tmp/jdocs/det_probe.jky
{"check": "fileless_process", "severity": "high", "title": "process 49770 (jky) runs from memory", "pid": 49770, "exe": "/memfd:python3 (deleted)"}
{"check": "memfd_mapping", "severity": "high", "pid": 49770, "perms": "r-xp", "size_kb": 2956}
{"scanned_processes": 118}
```

**4. No files created.** The harness measures file creation around a fileless
run (`evidence/report.md` §3):

```text
- fileless mode: created 0, modified 0 file(s); exit=0 ok=True
- fileless process image: `/memfd:python3 (deleted)` with 4 memfd-backed mappings
```

**5. With `--json`.** The command reports what it observed:

```bash
./venv/bin/jocky fileless /tmp/jdocs/self_probe.jky --json | jq '{ok, exit_code, pid, duration_ms, evidence: {exe: .evidence.exe, memfd_map_count: .evidence.memfd_map_count, observed: .evidence.observed, in_memory: .evidence.in_memory}}'
```

```text
{
  "ok": true,
  "exit_code": 0,
  "pid": 50190,
  "duration_ms": 177.635,
  "evidence": {
    "exe": "/memfd:python3 (deleted)",
    "memfd_map_count": 4,
    "observed": true,
    "in_memory": {
      "interpreter_bytes": 8020928,
      "package_zip_bytes": 118638,
      "payload_bytes": 409
    }
  }
}
```

## Honest limits

* **argv stays visible.** The bootstrap is passed with `-c`, so
  `/proc/<pid>/cmdline` contains the whole program text of the bootstrap — the
  `tr '\0' ' '` output above is the start of it. `--private` does **not** change
  this: measured during a `--private` run, `cmdline` was still readable while
  `exe` and `maps` were denied.
* **Kernel telemetry sees the mechanics.** `memfd_create`, `execveat`/`execve`
  of `/proc/self/fd/N`, the writes into the memfds and the file reads are all
  visible to eBPF/kprobes, audit rules and LSM hooks. Nothing in user space can
  hide those from a privileged observer; what fileless mode removes is the
  *on-disk artefact*, not the syscalls.
* **The live image is readable while the process runs.** 5 memfd-backed mappings
  and an `r-xp` region of ~2956 KB in the case above; `/proc/<pid>/maps` and
  `/proc/<pid>/mem` are exactly what an analyst should capture, and JOCKY's own
  detector finds it (step 3).
* **Not everything comes from memory.** Measured on a live fileless process: 82
  mappings, of which 25 point at `/usr/lib/python3.12/...` — the standard library
  still loads from the installed filesystem. Only the `jocky` package and the
  payload are memory-only.
* **The process is not hidden.** It has a normal PID and appears in every
  process list; `stat` (and therefore its name) is readable even with
  `--private`.
* **`--private` is a trade, not a free upgrade.** It sets
  `PR_SET_DUMPABLE=0`, which makes `/proc/<pid>/{exe,maps}` readable only by
  root (or a reader with `CAP_SYS_PTRACE`):
  `ls -l /proc/$PID/exe` → `Permission denied`,
  `head -1 /proc/$PID/maps` → `Permission denied`. The same flag hides the job
  from JOCKY's own triage, so a `--private` run is invisible to
  `det.fileless()` — measured: the detector reported no findings for it.
* **Startup costs are real.** A trivial script takes 0.524 s wall through
  `jocky fileless` versus 0.236 s through `jocky exec` on this host, because the
  interpreter image is written to a memfd, a child is forked and the runtime is
  imported from a zip every run.

## Related

* [Execution modes](/docs/execution/modes) — the three modes side by side, with
  process-image and telemetry measurements.
* [Polymorphic artifacts](/docs/execution/artifacts) — what the payload can be
  before it is handed to the fileless path.
* [Detection checks](/docs/runtime/detection) — the checks that find this
  technique, including `fileless_process` and `memfd_mapping`.
