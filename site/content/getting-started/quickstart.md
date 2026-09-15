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
{"kind": "summary", "host": "stormbreaker", "kernel": "6.6.87.2-microsoft-standard-WSL2", "processes": 121, "sockets": 88, "counts": {"info": 1, "low": 28, "medium": 33, "high": 0, "critical": 0}, "duration_ms": 461.756}
{"kind": "tail", "high_or_critical": 0, "total_findings": 62}
```

Each `emit` in the script becomes one JSON object on stdout, in the order the
script emitted it. The script itself is short enough to read in full:

```jocky
# Host triage: memory-resident execution, network exposure, kernel tampering.
# Everything below reads /proc and /sys directly - no ps, ss, lsmod or find is
# executed, so the collection itself is invisible to process-spawn telemetry.

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

`--json` wraps the same findings in the run result, adding `output` (what
`print` produced), `errors`, `steps`, `native_calls`, `duration_ms` and
`truncated`.

`det.triage()` runs every detection check in one pass and returns a structured
report; `report.counts` is the severity histogram, `report.scanned` records how
much of the host was readable, and `report.findings` is a list of maps with
`severity`, `check`, `title` and `evidence`.

Two lines came back on this host and neither is high or critical. The counts
move with host activity; the shape of the output does not.

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
scanned 121 processes, 88 sockets
critical: 0
high: 0
medium: 33
low: 28
info: 1
```

`print` is the human channel and `emit` the machine channel; step 6 shows the
same script with something to report.

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
  "sample": { "build_hash": "e5e207c4376f54e1", "artifact_hash": "bf3e19ce10eabf375284492031ceb7973962ea181f10f56f5eb8f7b2efed370c", "size": 2797, "opmap_size": 50, "nops": 221, "const_count": 37, "proto_count": 1, "seed_hex": "ec2e03f67aff603b14caac7c97b88481153fe27ce998f2cf8ee5ce12e7111b71", "source_sha256": "094b36d0af56e22fdf2a7fed764702097e3971d76ebde993ad014dda9eded385" }
}
```

Three builds, three distinct SHA-256 digests and three different sizes, all
from one unchanged source file (`source_sha256` is the same in every build; the
`sample` object is reflowed onto one line above for width).
`jocky exec --inspect` reads the artifact header without running it (reflowed here for width):

```bash
jocky exec /tmp/case/hunt.build --inspect
```

```.text
{"build_hash": "d72b0b3161c620d5", "artifact_hash": "11f5697e94426ab15eea3b24e14c73a3d0cc0b67c757dfd1ee7543f272220c2d", "size": 2630, "opmap_size": 50, "nops": 209, "const_count": 32, "proto_count": 1, "seed_hex": "5d8ad55cbc271124836f4efc8de4aa38363c99fce5155693a0d4de865d6d1c8a"}
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

The `#` line is the run summary and goes to stderr, so `jocky exec … >
findings.json` gives you clean NDJSON on stdout while the human summary stays on
the terminal.

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
defender's problem: the name is `jky`, set by the bootstrap rather than by the
payload, and the image has no path.

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
# info=1, low=27, medium=30, high=1  (400.8 ms, 122 processes)
[high    ] process 52407 (jky) runs from memory
```

The severity script from step 3, run while the payload is alive, puts the same
finding in the `high` bucket and emits it:

```text
{"severity": "high", "check": "fileless_process", "title": "process 52407 (jky) runs from memory"}
```

The `emit` line appears before the `print` lines because the CLI prints the
findings list first, even though the emit happens last in the script.

If you cannot find the process, you are probably running it with `--private`,
which marks it non-dumpable and hides it from same-uid inspection — including
your own triage. The default is visible so this detection claim stays
reproducible; see [Fileless execution](/docs/execution/fileless).

## 7. Confine a run (optional)

`jocky run` and `jocky exec` accept `--sandbox=off|vm|ro|strict`; the default is
`off`, which is what every example above used. `vm` keeps full read access and
grants writes only under the working directory, `ro` grants no writes at all,
and `strict` additionally denies `socket(2)` through a seccomp filter — a
script that needs the network has to run with `vm` or `off`:

```jocky
# sock.jky - can the script create a socket? (needs --allow syscall)
try {
  emit {"socket": mem.syscall(41, 2, 1, 0)}
} catch err {
  print("socket syscall: {err}")
}
```

```bash
jocky run /tmp/case/scripts/sock.jky --allow syscall --sandbox=strict
```

```text
socket syscall: PermissionError: [Errno 1] Operation not permitted
```

Confinement is deny-by-default and filesystem-only, so it also *reduces what a
script can see*: under `--sandbox=vm` the confined run could read no other
process's `/proc/<pid>/maps` or `/proc/<pid>/fd` entries, so `det.triage()` lost
the `rwx_memory`, `injection_primitive` and `deleted_open_file` checks entirely:

```text
# jocky run /tmp/case/scripts/severity.jky --sandbox=off
medium: 30
low: 27
# jocky run /tmp/case/scripts/severity.jky --sandbox=vm
medium: 0
low: 14
```

The numbers move with host activity; the direction does not. Use `off` on an
analysis host where you want the whole picture, and `vm` or stricter for a script
you have not read — `jocky doctor` reports kernel support under `CONFINEMENT`.

## 8. Built-in triage without a script

For a host check with no case directory at all:

```bash
jocky triage
```

```text
# info=1, low=27, medium=30  (369.8 ms, 118 processes)
[low     ] rwx region in pid 4219 (omp), 1048576 KiB
[low     ] tcp listener on port 9993 (unattributed)
[low     ] pid 4219 holds 5 injection-capable descriptor(s)
[info    ] only 36% of processes were inspectable (76 of 118 unreadable)
```

That is an excerpt from one run that printed 59 lines. The first line is the
severity histogram with the scan duration and process count. `low` findings are
correlation input, not verdicts: `rwx` regions are what any JIT looks like, and
an unattributed listener is a socket the current uid cannot attribute to a
process. The `info` line is the honest part — as an unprivileged user this scan
saw 36% of the host, so a clean result describes your own processes, not the
machine.

`jocky triage --json` emits the full report as one JSON document, and
`jocky triage --deep` runs the slower checks as well. The complete check list,
with severity and data source for each, is in
[Detection checks](/docs/runtime/detection).

### Anchor findings in time

A finding is a map with no time of its own, so `--stamp-findings` adds a `ts`
(epoch seconds) to every finding that lacks one — on `run`, `exec`, `triage`,
`fileless` and `memfd` alike. A script that recorded when the *event* happened
keeps its own value; the flag only fills in findings that were collected rather
than observed.

```bash
jocky triage --stamp-findings --json > /tmp/triage.json
```

```json
{
  "check": "rwx_memory",
  "severity": "low",
  "title": "rwx region in pid 4219 (omp), 1048576 KiB",
  "ts": 1789500203.502
}
```

That single field is what lets a run share a timeline with everything else on
the host: `time.iso(f.ts)` renders it, and `tl.merge` orders it together with
parsed log lines:

```jocky
# correlate.jky - one timeline of runtime findings and log events.
let report = json_decode(fs.read("/tmp/triage.json", 2000000))
let events = []
for f in report.findings {
  if f.severity != "info" {
    events.push({"ts": f.ts, "source": "triage", "text": f.title})
  }
}
for h in fs.grep("/var/log/auth.log", r"^Failed password for (\S+) from (\S+)") {
  # A bare log line carries no year; anchor it to the run for this demo.
  events.push({"ts": report.findings[0].ts, "source": "auth.log", "text": h.line})
}
let merged = tl.merge(events)
emit {"events": len(merged), "span_from": time.iso(merged[0].ts),
      "sources": sort(transform(merged, fn(e) { return e.source }))}
```

```text
{"events": 40, "span_from": "2026-09-15T19:23:23Z", …}
```

Each merged row also carries `tl_index` (its position in the merged list) and
`tl_source` (which input it came from), so a finding can be traced back to the
report it was read out of. 40 rows above is the shape of a real run: 39 triage
findings plus one log line, all stamped from the same collection moment.

## Where to go next

- [Architecture](/docs/getting-started/architecture) — the language pipeline, the encoder and the evidence harness.
- [Language basics](/docs/language/basics) — `let`/`set`, loops, functions and closures.
- [Collectors](/docs/runtime/collectors) — what `proc`, `net`, `fs`, `sys` and `ioc` return.
- [Execution modes](/docs/execution/modes) — `run`, `exec` or `fileless`.
- [Evidence harness](/docs/operations/evidence) — re-run the measurements quoted above.
