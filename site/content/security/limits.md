# Honest limits

Every claim on this site is supposed to have a measurement behind it, and the
interesting half of that discipline is the list of things JOCKY does **not**
do. This page is that list. Each item names the measurement or the code path
that establishes it, and the last section is a single table of claims against
what was actually verified.

Nothing here is a hedge for a *future* release: these are the properties of the
build in this repository, on Linux, as measured while writing the page.

## Where the numbers come from

| Source | What it is |
|---|---|
| `evidence/report.md` | the full harness run shipped in the repo (1000 builds, 1000 runs), generated 2026-09-15 19:14:23 on this host |
| a quick harness run | `jocky evidence --iterations 60 --quick` on v1.2.0, while writing this page (12 builds, 10 runs) |
| scratch probes | a ptrace syscall counter, a `/proc/<pid>/*` reader, an LD_PRELOAD hook, an artifact decoder, all run from `/tmp` against `./venv/bin/jocky` |

Where the two harness runs disagree, both numbers are given: the full run is the
one in the repository, the quick run is what the current binary does on the same
host today.

| Measurement | Full run (1000) | Quick run (v1.2.0) |
|---|---|---|
| builds → unique SHA-256 | 1000 → 1000 | 12 → 12 |
| artifact sizes | 3625–4175 bytes | 3725–4067 bytes |
| executions → distinct findings hash | 1000 → 1, 0 errors | 10 → 1, 0 errors |
| median run latency | 16.121 ms | 21.316 ms |
| fileless mode files created | 0 | 0 |
| source mode, cold interpreter | 74 bytecode-cache files | 79 bytecode-cache files |
| child processes during collection | 0 | 0 |
| `execve` / write-mode opens / socket calls during collection | 0 / 0 / 0 | 0 / 0 / 0 |
| read-mode opens during collection | 405 | 661 |

## The kernel sees every syscall JOCKY makes

The runtime's whole claim is about *noisy conventions* — spawning tools, writing
files, mangling argv. It is not a claim about invisibility, and the cleanest way
to show the difference is to attach an independent observer. A 90-line ptrace
counter (no `LD_PRELOAD`, no in-process hooks) that counts syscalls for a
process and its whole tree reports:

```text
$ python3 trace_syscalls.py ./venv/bin/jocky triage --json
processes ever seen in tree: 1
total syscalls observed: 17404
      0  fork          0  clone       0  clone3      0  execve
      0  memfd_create  0  socket      0  connect     0  creat
   1905  openat     3068  read        2  write     158  getdents64
```

```text
$ python3 trace_syscalls.py ./venv/bin/jocky fileless /tmp/jky-exp/dwell20.jky
processes ever seen in tree: 5
total syscalls observed: 11487
socket(domain, type, proto) calls: [(1, 526337, 0), (1, 526337, 0)]
      0  fork          0  vfork       2  clone     6  clone3    2  execve
      0  execveat      6  memfd_create            0  unlinkat  0  creat
     96  getdents64  696  openat   1269  read      10  write
      2  socket        2  connect     0  bind      0  listen
```

Read the second table carefully, because it is the honest version of the
fileless story:

* `memfd_create` is called six times and `execve` twice. The initial `execve`
  of the launcher is not counted (the observer starts after it), so the two
  observed calls belong to the fileless child itself.
* **`execveat` is zero.** The README and the `jocky/exec/fileless.py` docstring
  both say `execveat`; what actually runs is `os.execve()` against
  `/proc/self/fd/<fd>`, which is syscall 59. The claim "the kernel sees the
  technique" is true either way — the *name* of the syscall in our prose was
  wrong, and that is what a measurement is for.
* The two `socket`/`connect` pairs are **`AF_UNIX`** (domain `1`, type
  `526337` = `SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK`), not `AF_INET`. No
  network socket is created. These two calls appear in the fileless child and
  not in the equivalent source-mode run; I could not attribute them to a line of
  JOCKY code, so they are recorded rather than explained away.
* 696 `openat` and 1269 `read` calls: reading the host is the job. Those are the
  syscalls an audit rule or an eBPF program attaches to, and their exact counts
  move with the payload and with how many processes the host is running.

The privileged surfaces an observer would use exist on this host and are simply
not available to us as an ordinary user:

```text
$ grep tracefs /proc/mounts
tracefs /sys/kernel/tracing tracefs rw,nosuid,nodev,noexec,relatime 0 0
$ cat /sys/kernel/tracing/events/syscalls/            # uid 1000
Permission denied
$ cat /proc/sys/kernel/unprivileged_bpf_disabled
2
```

So: a privileged observer with `tracefs`, eBPF, auditd or a ptrace capability
sees `memfd_create`, `execve` and every read, and nothing in user space can
change that. `research/findings/res-ebpf-detect.md` in the repository surveys
which off-the-shelf rules fire on exactly this path (Falco's memfd rule, Elastic's
memfd process events, Tracee/Tetragon kprobes). JOCKY does not claim to defeat
them; it claims not to *need* the noisy conventions they are usually tuned to.

## In-memory images stay readable while they run

`fileless` keeps program text off the filesystem. It does not keep it out of
`/proc`, and an investigator reading `/proc` sees more about a running fileless
job than the tool would like:

```text
pid=54775
exe link      : /memfd:python3 (deleted)
comm          : jky                          # PR_SET_NAME, see fileless.py
argv count    : 3
environ       : ['PATH=/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE=1', 'JKY_PKG=5',
                'JKY_PAYLOAD=6', 'JKY_WALL=60000.0', 'JKY_ALLOW=', 'JKY_DUMPABLE=1']
memfd maps    : 5                            # r--p, r-xp, r--p, r--p, rw-p
fds           : 4 -> /memfd:python3 (deleted)
                5 -> /memfd:dwell.jky-pkg (deleted)
                6 -> /memfd:dwell.jky-payload (deleted)
copied exe    : 8020928 bytes sha256 e50d468e8b0adfb05733f5b87b3cff34 …
after exit    : /proc/54775/exe -> FileNotFoundError: [Errno 2] No such file or directory
```

Those file descriptors are readable by the owning user, and they hand over the
whole runtime. Recovering them from a live process:

```text
fd 4: /memfd:python3 (deleted)             8020928 bytes sha256 e50d468e8b0adfb0…
fd 5: /memfd:art.build-pkg (deleted)        118638 bytes sha256 3a0036f699d4d04c…
fd 6: /memfd:art.build-payload (deleted)      1556 bytes sha256 2328d225706e89cb…
recovered payload identical to the on-disk artifact: True
string constants decoded from the recovered payload: ['MEMFD-RECOVERY-MARKER-10.9.8.7']
runtime zip from fd 5: 34 members, first: ['jocky/scaffold.py', 'jocky/cli.py', 'jocky/evidence.py']
```

Two facts fall out of that output. The interpreter image (8020928 bytes) and the
packaged runtime (118638 bytes, 34 modules) are extractable, so "what tool is
this?" is answerable from a live process with no malware-analysis skill. And the
payload descriptor is the artifact itself, byte for byte — from which the
program decodes with no key, because the artifact carries its own key material.

The harness's own sampler reports one less mapping than an independent read
(`memfd_maps=4` in `evidence/report.md` and in the quick run, five `memfd:` lines
in the read above). The count is not truncated — `memfd_map_count` is `len(maps)`
— but the stored path list is capped at four entries (`maps[:4]` in
`_watch_proc`), and both readings took their sample at a different instant in the
interpreter's startup, when the mapping set is still settling.

`--private` exists and does exactly one thing: it sets `PR_SET_DUMPABLE=0`, which
makes `/proc/<pid>/*` root-only. Measured as the same uid, with a longer-running
payload:

| Read by the same uid | default | `--private` |
|---|---|---|
| `/proc/<pid>/exe` | `/memfd:python3 (deleted)` | `PermissionError(errno 13)` |
| `/proc/<pid>/environ` | 112 bytes | `PermissionError(errno 13)` |
| `/proc/<pid>/maps` | 8300 bytes | `PermissionError(errno 13)` |
| `/proc/<pid>/fd` | 7 entries | `PermissionError(errno 13)` |
| `/proc/<pid>/cmdline` | 3 argv | **3 argv** (still readable) |
| `/proc/<pid>/stat` | present | present |
| JOCKY's own `fileless_process` finding | yes | **no** |

The last row is the one that matters: `--private` hides a process from a
user-space collector, including the one shipped in this repository, and it is
off by default for that reason (see the code comment in `fileless.py`). It does
not hide the process from the kernel, from an eBPF rule, or from the run queue.
The `cmdline` row is the other honest surprise: `PR_SET_DUMPABLE` does not cover
argv, so the bootstrap text stays readable — 1160 bytes of it in the default
configuration, quoted in the next section.

## cmdline and argv are exposed

The fileless child is started as `python3 -c <bootstrap>`. The bootstrap has to
be in argv because there is nowhere else to put it, and `/proc/<pid>/cmdline` is
mode `444`:

```text
$ stat -c '%a %n' /proc/50285/cmdline        # the management server from this session
444 /proc/50285/cmdline
$ stat -c '%a %n' /proc/54905/cmdline        # a fileless child, same host, uid 1000
444 /proc/54905/cmdline
$ tr '\0' ' ' < /proc/50285/cmdline
/home/mjonir/f/sih2026/sih148/venv/bin/python3 … jocky serve --host 127.0.0.1
  --port 19543 --token sec-demo-token --state /tmp/jky-sec/state
```

For the fileless child the same file holds the entire bootstrap, and the process
name is a constant (`PR_SET_NAME` → `jky`), so it is even easy to find:

```text
argv[0]       : python3
argv[1]       : -c
argv[2][:120] : import ctypes, json, os, resource, sys
def _harden():
    try:
        libc = ctypes.CDLL(None, use_errno=True)
```

Consequences, stated plainly:

* argv is not mangled for evasion, and JOCKY does not pretend otherwise — this
  is one of the "noisy conventions" it does avoid in the *collector*, and
  deliberately does not avoid in the *payload*.
* One branch of the bootstrap is visible in plaintext to anyone reading argv;
  `JKY_ALLOW`, `JKY_DUMPABLE` and the two descriptor numbers are visible in
  `environ`. The descriptor numbers are meaningless in another process, but the
  memfd *names* (`art.build-payload`) are not.
* Anything a script is told to do that must stay secret — an IOC list, a target
  path — travels in a payload, not in argv, and the payload is readable from the
  process's own descriptors (previous section).

## Polymorphism is uniqueness, not secrecy

The encoder's job is that two builds of one script share no bytes. It does that:
1000 builds of one script → 1000 distinct SHA-256 digests, 3625–4175 bytes, and
the quick run reproduces the property at 12 builds → 12 distinct digests.

It is not encryption of meaning, and the module says so where the code lives:

```text
``header`` is ``hmac_key:32 | header_key:16 | obfuscated JSON``. The JSON
carries the opcode map, the per-proto slot maps, the payload key, the counts …
Honest limitation
-----------------
:meth:`decode` takes no key: the artifact has to carry its own keying material
to be self-describing, so the obfuscation defeats signature reuse, not an
analyst who already holds the artifact. The HMAC is a corruption/tamper check,
not a public-key signature.
```

Measured on an artifact built from a script containing one marker string:

```text
artifact: 1556 bytes, sha256 8dd9c9b41b55962f…
decoded with no key — string constants: ['EXFIL-DESTINATION-10.9.8.7',
 '/tmp/limits-marker-do-not-delete', 'kind', 'probe', 'target', 'marker',
 'EXFIL-D', 'ESTINATION-10.9.', '8.7', '/tmp/limi', 'ts-marker', …]
inspect(): {"build_hash": "3abe5a27d010db8f", "opmap_size": 50, "nops": 31,
 "const_count": 13, "proto_count": 1, "seed_hex": "31598407527e0127…"}
embedded HMAC key (first 16 bytes hex): ac3a5745f5c9a7ba72781bc6ac5f47ea
footer matches body: True
tampered + recomputed footer: decode() ACCEPTED it
tampered, footer untouched: decode() raised JockyArtifactError: artifact
 integrity check failed (truncated or tampered)
```

The split-constant transform is visible in that list (`'EXFIL-D'`,
`'ESTINATION-10.9.'`, `'8.7'`): the obfuscation works as designed, and it changes
nothing about what an analyst holding the file can read. Editing the artifact and
recomputing the footer with the key that ships inside it is accepted by `decode()`
and the result still executes — the same flip without recomputing is rejected,
which is exactly what a corruption check is for and all it is for.

Two operational consequences:

* A hash allowlist of artifacts is pointless: `jocky build` re-encodes any
  script into a new valid artifact, and an editor can also patch one in place.
  Provenance has to come from signatures (`jocky attest`/`verify`/`sign` over a
  case directory) or from behaviour, not from the artifact's bytes.
* "Unique bytes" is the ceiling of the current encoder. Statement-level control
  flow is identical across builds; the roadmap's *behaviour fingerprints* and
  *control-flow flattening* items exist because of that, with
  `research/findings/lim-polymorph.md` as the measurement.

## No Windows or macOS collectors

The collectors are procfs. That is a code fact, not a policy:

* `jocky/rt/procfs.py` — "Every reader here parses kernel procfs directly. No
  external binary is ever spawned (no `ps`, `lsof`, `ss`)"; it is the shape every
  other collector mirrors.
* `jocky/rt/raw.py` — the direct-syscall path only claims x86_64 Linux
  (`_raw_supported()` returns `False` otherwise, and the module falls back to
  libc).
* `jocky/rt/procfs.py` guards `os.sysconf` so the *package* still imports on a
  platform without it, but importing is not collecting.

What the runtime does have on this host is checkable, and `jocky doctor` is the
check:

```text
$ ./venv/bin/jocky doctor --json | jq -r '.checks[] | "\(.status)\t\(.name)\t\(.detail)"'
ok	python >= 3.12	3.12.3
warn	effective uid	1000
ok	procfs mounted	/proc is readable
ok	network tables	/proc/net present
ok	direct syscalls	raw on x86_64
ok	sandbox (Landlock)	Landlock ABI 3 (filesystem rights only; --sandbox=strict adds seccomp)
ok	memfd_create	available
ok	fileless end-to-end	exe=/memfd:python3 (deleted) memfd_maps=4
```

The `warn` on `effective uid` is not cosmetic: as an ordinary user, most other
processes' `exe` links are unreadable, and `det.triage()` reports
`scanned.unreadable_processes` and a `partial_visibility` finding instead of
pretending the host is clean. On this host that coverage was **0.36–0.40** —
78 of 126 processes uninspectable. The roadmap's Windows/macOS item is tier 3,
and it is honest about the size of the job: the language, encoder and agent
protocol are portable, `jocky/rt` is not.

## No kernel-mode anything

JOCKY is a user-space toolkit and `docs/DESIGN.md` lists kernel-mode evasion
(driver loading, callback removal) as a non-goal; the roadmap records the same
boundary under "Explicitly out of scope". Nothing in this repository loads a
module, writes to `/dev/mem`, or talks to `/proc/kcore`. The matching absence is
in the detection story too: `hidden_module` compares two kernel views
(`/proc/modules` against the loadable `/sys/module` subset) and can say *the
views disagree*, but the tool cannot read around a kernel that has been
compromised, because it has no kernel-side view at all.

The floor cannot be lowered from user space. That is the reason this page exists
in this shape: the honest claim is "no console tools, no dropped files, no
mangled argv", and the techniques above are what remains visible anyway.

## No protection against an EDR that kills on behaviour

JOCKY does not survive being killed and does not try to. The behavioural signal
is present by construction — the same runtime ships the detector that finds its
own technique, and the harness runs that check against a live job:

```text
memfd-backed processes observed while the fileless job ran: 1
detector findings: 1 (executable memfd mappings: 1)
example: ['process 51186 (jky) runs from memory']       # full run: 'process 30385 (4) …'
```

So an EDR with an equivalent rule (`/memfd:` in `exe`, an executable anonymous
mapping, `memfd_create` in a kprobe) has everything it needs, and `--private`
does not change that — it only hides the process from *user-space readers*, and
it hides it from JOCKY's own triage as well (measured above). No EDR product was
installed on the development host, so this page states no measured
evasion-versus-detection result; the defensible statement is the telemetry
inventory in the first section plus the self-detection above.

Two related things the runtime deliberately does **not** do, because they would
be user-space lies: it does not drop the interpreter's identity
(`/proc/<pid>/exe` says `/memfd:python3 (deleted)`), and it does not clear or
rewrite `argv` after startup.

## Detection is not prevention: snapshots, blind spots, no memory capture

Findings are observations with timestamps on the raw logs, not proof. Three
measured reasons:

* **Processes move.** The probe above read a live pid's `exe` link and copied the
  image; after it exited, `/proc/54775/exe` raised `FileNotFoundError`. The detector's
  own recommendation says "dump `/proc/<pid>/exe` before the process exits", and
  the runtime cannot do that for you — memory acquisition
  (`/proc/<pid>/mem`, `process_vm_readv`) is a tier-1 roadmap item, not a
  feature. Until it lands, a finding tells you a pid *was* interesting.
* **Two scans of one host differ.** Consecutive `jocky triage --json` runs
  reported `processes 126 / findings 82` and `processes 125 / findings 83`, with
  an identical finding set of `False`.
* **A scan can be blind without saying so loudly.** `partial_visibility` fires
  only below 95% coverage, so one hidden process among 120 moves coverage from
  0.395 to 0.392 and changes nothing — while removing the process from every
  check. The page that shows a host defeating exactly one check is
  [Threat model](/docs/security/threat-model); the section is there because the mitigation
  above does not cover it.

## Claim vs what we actually verified

| Claim | What was actually verified | How |
|---|---|---|
| "Unique bytes per build" | 1000 builds → 1000 SHA-256; 12 → 12 on v1.2.0 | `evidence/report.md`; quick harness run |
| "Same behaviour from a different build" | 25 rebuilt artifacts re-executed, findings hash identical, 0 failures (12/12 in the quick run) | `evidence/report.md` §1 |
| "Repeatable" | 1000 runs → 1 distinct findings hash, 0 errors, median 16.121 ms | `evidence/report.md` §2 |
| "No files written" | fileless mode created 0 / modified 0 files; source mode cold writes 74–79 bytecode caches | `evidence/report.md` §3 |
| "No dropped tools" | 0 child processes, 0 `execve`, 0 write-mode opens, 0 socket calls during a collection run | Python audit hook, `evidence/report.md` §4 |
| "No shell, no `ps`/`ss`/`lsof`" | 0 `fork`/`clone`/`execve` in an independent ptrace trace of `jocky triage`; 1905 `openat`, 3068 `read` | scratch ptrace counter |
| "In memory, not on disk" | `/proc/<pid>/exe` = `/memfd:python3 (deleted)`; 4–5 memfd-backed mappings; interpreter, runtime zip and payload all present as memfds | `evidence/report.md` §5; `/proc/<pid>/{exe,maps,fd}` read |
| "The detector finds the technique" | 1 memfd process observed while the job ran; finding `process 51186 (jky) runs from memory` | `evidence/report.md` §5 |
| "Hidden from kernel telemetry" | **not claimed, and false** — `memfd_create` (6×), `execve` (2×) and 696 `openat` calls are visible to an unprivileged ptrace observer; the privileged rules are in `res-ebpf-detect.md` | scratch ptrace counter |
| "`execveat` is used" | **wrong** — measured `execve` 2, `execveat` 0; the prose in `README.md` and `fileless.py` names the wrong syscall | scratch ptrace counter |
| "The payload is not recoverable" | **not claimed** — the payload memfd is the artifact byte for byte, and `decode()` recovers every string constant with no key | scratch recovery probe, artifact decoder |
| "The artifact is tamper-proof" | **false as authentication**: footer is an HMAC under a key stored in the same file; tamper + recompute is accepted, and the tampered artifact runs | scratch tamper probe |
| "argv is not used for evasion" | 3 argv entries, of which `argv[2]` is the 1160-byte bootstrap; `cmdline` is mode `444` | `/proc/<pid>/cmdline` read + `stat` |
| "Files can be hidden from a same-uid reader" | `--private` → `PermissionError` on `exe`/`environ`/`maps`/`fd`; `cmdline` and `stat` stay readable; JOCKY's own detector no longer sees the process | side-by-side probe, 5/5 runs |
| "Works on Windows/macOS" | **not claimed** — collectors are procfs-only; `doctor` reports platform Linux x86_64, uid 1000 | code references + `jocky doctor --json` |
| "Kernel-mode evasion" | **out of scope** — no module, no `/dev/mem`, no `/proc/kcore`; `hidden_module` can only report that two kernel views disagree | `docs/DESIGN.md`, roadmap |
| "Survives an EDR" | **not claimed** — an EDR can kill the process; no EDR was available to measure against on this host | self-detection measurement above |
| "A clean triage means a clean host" | **no** — coverage was 0.36–0.40 as uid 1000; `partial_visibility` fires below 95% and does not notice a single hidden process | triage runs with and without a hidden process |
| "Findings are evidence" | findings are **snapshots**: a finding's pid was already gone when inspected; consecutive scans differed | `/proc/<pid>/exe` after exit; two triage runs |
| Ingress selection | `--sni`/`--host-header` pick a vhost at an ingress you control; this is **not** domain fronting, which every tier-1 CDN closed between 2018 and 2024 | [Server & agents](/docs/operations/management) |

## Where the limits point

The same runtime ships the detector for every technique it uses
([Detection checks](/docs/runtime/detection)), the fileless mechanics are described with their
telemetry in [Fileless execution](/docs/execution/fileless), the artifact format and its honest
limitation in [Polymorphic artifacts](/docs/execution/artifacts), and the evidence that a reviewer can
re-check in [Evidence harness](/docs/operations/evidence). What is not fixed yet is listed with
effort and rationale in [Roadmap](/docs/project/roadmap); what an attacker can do to the
tool itself, and what JOCKY can and cannot conclude about a compromised host, is
[Threat model](/docs/security/threat-model).
