# Quickstart

Ten minutes, from an empty directory to a script running out of anonymous
memory while JOCKY's own detector finds it. Everything below runs as an
unprivileged user; the interpreter is Python 3.12.3 on
`Linux 6.6.87.2-microsoft-standard-WSL2`, and every output is quoted from that
host. If you have not installed the package yet, see
[Installation](/docs/getting-started/installation).

## 1. Create a case directory

```bash
jocky init /tmp/case
```

```text
initialised /tmp/case
  + README.md
  + .gitignore
  + scripts/hunt.jky
  + scripts/inventory.jky
  + scripts/timeline.jky
  + scripts/triage.jky
  + scripts/watch.jky

next steps:
  jocky doctor
  jocky run scripts/triage.jky
```

The five scripts are the bundled examples listed by `jocky examples`. They
exist so that the first command you type does real work instead of printing a
usage message.

## 2. Run triage

```bash
jocky run /tmp/case/scripts/triage.jky
```

```text
{"kind": "summary", "host": "stormbreaker", "kernel": "6.6.87.2-microsoft-standard-WSL2", "processes": 94, "sockets": 92, "counts": {"info": 1, "low": 32, "medium": 0, "high": 0, "critical": 0}, "duration_ms": 586.093}
{"kind": "tail", "high_or_critical": 0, "total_findings": 33}
```

Each `emit` in the script becomes one JSON object on stdout, in the order the
script emitted it. The script itself is short enough to read in full:

```jocky
let report = det.triage()

emit {
  "kind": "summary",
  "host": report.host.hostname,
  "kernel": report.host.kernel,
  "processes": report.scanned.processes,
  "sockets": report.scanned.sockets,
  "counts": report.counts,
  "duration_ms": report.duration_ms
}

let interesting = filter(report.findings, fn(f) {
  return f.severity == "high" or f.severity == "critical"
})

for f in interesting {
  emit {"severity": f.severity, "check": f.check, "title": f.title, "evidence": f.evidence}
}

emit {"kind": "tail", "high_or_critical": len(interesting), "total_findings": len(report.findings)}
```

`det.triage()` runs every detection check in one pass and returns a structured
report; `report.counts` is the severity histogram, `report.scanned` records how
much of the host was readable, and `report.findings` is a list of maps with
`severity`, `check`, `title` and `evidence`.

Two lines came back on this host and neither is high or critical: the runtime
does not manufacture drama. The counts move with host activity — the shape of
the output does not.

### The same run as structured data

```bash
jocky run /tmp/case/scripts/triage.jky --json
```

```json
{
  "findings": [
    {
      "kind": "summary",
      "host": "stormbreaker",
      "kernel": "6.6.87.2-microsoft-standard-WSL2",
      "processes": 94,
      "sockets": 92,
      "counts": {
        "info": 1,
        "low": 32,
        "medium": 0,
        "high": 0,
        "critical": 0
      },
      "duration_ms": 638.807
    },
    {
      "kind": "tail",
      "high_or_critical": 0,
      "total_findings": 33
    }
  ],
  "output": [],
  "errors": [],
  "steps": 449,
  "native_calls": 4,
  "duration_ms": 639.729,
  "truncated": false
}
```

`findings` is what `emit` produced, `output` is what `print` produced, `steps`
counts bytecode instructions executed, `native_calls` counts calls into the
runtime, and `truncated` says whether a budget stopped the run. Without
`--json`, findings go to stdout and `print` lines follow them; errors go to
stderr and set exit status 1.

## 3. Filter findings by severity

`det.triage()` is an ordinary map, so you can slice it in script. The following
runs triage once and prints a per-severity histogram, then emits only what an
analyst has to act on:

```jocky
# severity.jky - run triage once, then split the findings by severity.
let report = det.triage()

print("scanned {report.scanned.processes} processes, {report.scanned.sockets} sockets")
for level in ["critical", "high", "medium", "low", "info"] {
  let hits = filter(report.findings, fn(f) { return f.severity == level })
  print("{level}: {len(hits)}")
}

let urgent = filter(report.findings, fn(f) {
  return f.severity == "critical" or f.severity == "high"
})

for f in urgent {
  emit {"severity": f.severity, "check": f.check, "title": f.title}
}
```

On a quiet host:

```bash
jocky run /tmp/case/scripts/severity.jky
```

```text
scanned 93 processes, 95 sockets
critical: 0
high: 0
medium: 0
low: 32
info: 1
```

`print` is the human channel; `emit` is the machine channel. Step 6 shows the
same script with something to report, which is where the `emit` line appears.

## 4. Build a polymorphic artifact

```bash
jocky build /tmp/case/scripts/hunt.jky -o /tmp/case/hunt.build
```

```text
wrote /tmp/case/hunt.build (2630 bytes, sha256 11f5697e94426ab1...)
```

```bash
sha256sum /tmp/case/hunt.build
```

```text
11f5697e94426ab15eea3b24e14c73a3d0cc0b67c757dfd1ee7543f272220c2d  /tmp/case/hunt.build
```

Ask for several builds of the same script and compare their hashes:

```bash
jocky build /tmp/case/scripts/hunt.jky --repeat 3 -o /tmp/case/rep.build
```

```json
{
  "builds": 3,
  "unique_hashes": 3,
  "sizes": [
    2741,
    2797,
    2824
  ],
  "sample": {
    "build_hash": "e5e207c4376f54e1",
    "artifact_hash": "bf3e19ce10eabf375284492031ceb7973962ea181f10f56f5eb8f7b2efed370c",
    "size": 2797,
    "opmap_size": 50,
    "nops": 221,
    "const_count": 37,
    "proto_count": 1,
    "seed_hex": "ec2e03f67aff603b14caac7c97b88481153fe27ce998f2cf8ee5ce12e7111b71",
    "source_sha256": "094b36d0af56e22fdf2a7fed764702097e3971d76ebde993ad014dda9eded385"
  }
}
```

Three builds, three distinct SHA-256 digests and three different sizes, all
from one unchanged source file (`source_sha256` is the same in every build).
`jocky exec --inspect` reads the header of an artifact without running it:

```bash
jocky exec /tmp/case/hunt.build --inspect
```

```json
{
  "build_hash": "d72b0b3161c620d5",
  "artifact_hash": "11f5697e94426ab15eea3b24e14c73a3d0cc0b67c757dfd1ee7543f272220c2d",
  "size": 2630,
  "opmap_size": 50,
  "nops": 209,
  "const_count": 32,
  "proto_count": 1,
  "seed_hex": "5d8ad55cbc271124836f4efc8de4aa38363c99fce5155693a0d4de865d6d1c8a"
}
```

`opmap_size` is the number of permuted opcodes, `nops` the count of junk
instructions inserted at safe statement boundaries, `const_count` the encrypted
constant pool entries. The [Polymorphic artifacts](/docs/execution/artifacts)
page explains what each transform buys and what it does not.

## 5. Execute the artifact

```bash
jocky exec /tmp/case/hunt.build
```

```text
{"kind": "flagged_processes", "count": 0, "pids": []}
{"kind": "done", "sockets_scanned": 25}
# 2 finding(s), 0 error(s), 360 steps, 54.9 ms
```

The `#` line is the run summary and goes to stderr, so piping findings into a
consumer stays clean:

```bash
jocky exec /tmp/case/hunt.build --json > findings.json
```

The artifact prints exactly the findings the source script prints — it is the
same program, with different bytes. That equivalence is measured over 25
freshly built artifacts by the evidence harness; see
[Architecture](/docs/getting-started/architecture).

## 6. Run fileless and read `/proc`

`jocky fileless` writes nothing to disk: the interpreter ELF, a zip of the
runtime and the payload each go into their own `memfd_create()` object.

```bash
jocky fileless /tmp/case/scripts/triage.jky
```

```text
{"kind": "summary", "host": "stormbreaker", "kernel": "6.6.87.2-microsoft-standard-WSL2", "processes": 95, "sockets": 92, "counts": {"info": 1, "low": 32, "medium": 0, "high": 0, "critical": 0}, "duration_ms": 98.833}
{"kind": "tail", "high_or_critical": 0, "total_findings": 33}
# exit=0 exe=/memfd:python3 (deleted) memfd_maps=4 pid=44872 342 ms
```

That trailing line (stderr) is the runner's own inspection of the child it
started, sampled the instant after `exec`: process image, memfd-backed
mapping count, pid, wall time.

To see the same thing from outside, start a long-running payload and read
`/proc` while it is alive. `scripts/watch.jky` sleeps for eight seconds, which
is the window. Save the probe below as `probe.sh`, then run one session — the
payload in the background, the probe while it lives:

```sh
#!/bin/sh
# Find every process whose executable image is not backed by a file on disk.
for exe in /proc/[0-9]*/exe; do
  target=$(readlink "$exe" 2>/dev/null) || continue
  case "$target" in
    /memfd:*|*"(deleted)")
      pid=${exe#/proc/}
      pid=${pid%/exe}
      echo "pid=$pid exe=$target"
      sed -n '/memfd/p' "/proc/$pid/maps" | sed 's/^/  /'
      echo "  memfd mappings: $(sed -n '/memfd/p' "/proc/$pid/maps" | wc -l)"
      ;;
  esac
done
```

```bash
jocky fileless /tmp/case/scripts/watch.jky &
sleep 2
sh probe.sh
wait
```

```text
pid=47514 exe=/memfd:python3 (deleted)
  00400000-00420000 r--p 00000000 00:01 15379                              /memfd:python3 (deleted)
  00420000-00703000 r-xp 00020000 00:01 15379                              /memfd:python3 (deleted)
  00703000-00a28000 r--p 00303000 00:01 15379                              /memfd:python3 (deleted)
  00a28000-00a29000 r--p 00627000 00:01 15379                              /memfd:python3 (deleted)
  00a29000-00ba7000 rw-p 00628000 00:01 15379                              /memfd:python3 (deleted)
  memfd mappings: 5
{"kind": "started", "hostname": "stormbreaker", "uptime_s": 22932.6, "exe": "/memfd:python3 (deleted)"}
{"kind": "collect", "passwd_present": true, "listeners": 21}
{"kind": "finished"}
# exit=0 exe=/memfd:python3 (deleted) memfd_maps=4 pid=47514 8328 ms
```

The interpreter's own code and data segments are mapped from an anonymous file
that no path points at: the `exe` link resolves to `/memfd:python3 (deleted)`
and every segment shows the same anonymous backing. The trailing line is the
runner's own inspection of the child it started, sampled the instant the exec
landed, which is why it reports four mappings where a read a few seconds later
shows five segment mappings of the same memfd. Neither number is a guess: both
are read from `/proc/<pid>/maps`.

The loop reports every memory-resident process on the host, so on a busy
machine other blocks can appear alongside this one. Telling them apart is the
defender's problem: the process name is `jky` (set by the bootstrap, not by the
payload) and the image has no path, so the memfd backing is the only
distinguishing evidence in `/proc`.

Nothing was written to the filesystem by that run. The evidence harness
measures this by snapshotting the filesystem before and after — fileless mode
created 0 files, modified 0 files (`evidence/report.md`).

### Detect what you just did

The same runtime ships the detector, so the last step is to point it at the
process you started:

```bash
jocky triage
```

```text
# info=1, low=32, medium=2, high=1  (962.0 ms, 93 processes)
[high    ] process 45007 (jky) runs from memory
```

and the severity script from step 3, run while the payload is alive:

```bash
jocky run /tmp/case/scripts/severity.jky
```

```text
{"severity": "high", "check": "fileless_process", "title": "process 45370 (jky) runs from memory"}
scanned 95 processes, 71 sockets
critical: 0
high: 1
medium: 0
low: 32
info: 1
```

The `emit` line appears before the `print` lines because the CLI prints the
findings list first, even though the emit happens last in the script.

If you cannot find the process, you are probably running it with `--private`,
which marks it non-dumpable: that hides it from other same-uid processes and
from your own triage. The default is deliberately visible so that the detection
claim in this quickstart can be reproduced. See
[Fileless execution](/docs/execution/fileless) for the trade-off.

## 7. Built-in triage without a script

For a host check with no case directory at all:

```bash
jocky triage
```

```text
# info=1, low=32  (692.4 ms, 93 processes)
[low     ] rwx region in pid 4219 (omp), 1048576 KiB
[low     ] tcp listener on port 9993 (unattributed)
[low     ] pid 4219 holds 6 injection-capable descriptor(s)
[info    ] only 18% of processes were inspectable (76 of 93 unreadable)
```

The first line is the severity histogram with the scan duration and process
count. `low` findings are correlation input, not verdicts — `rwx` regions are
what any JIT looks like, and an unattributed listener is a socket the current
uid cannot attribute to a process. The `info` line is the honest part: as an
unprivileged user this scan saw 18% of the host, so a clean result describes
your own processes, not the machine.

`jocky triage --json` emits the full report as one JSON document, and
`jocky triage --deep` runs the slower checks as well. The complete check list,
with severity and data source for each, is in
[Detection checks](/docs/runtime/detection).

## Where to go next

- [Architecture](/docs/getting-started/architecture) — the language pipeline, the encoder and the evidence harness.
- [Language basics](/docs/language/basics) — `let`/`set`, loops, functions and closures.
- [Collectors](/docs/runtime/collectors) — what `proc`, `net`, `fs`, `sys` and `ioc` return.
- [Execution modes](/docs/execution/modes) — when to use `run`, `exec` or `fileless`.
- [Evidence harness](/docs/operations/evidence) — re-run the measurements quoted above.
