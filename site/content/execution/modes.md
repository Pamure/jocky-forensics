# Execution modes

JOCKY executes a script in one of three modes, all through the same entry point
(`jocky/runner.py`) and the same VM, collectors and limits. What differs is
where the program text lives and what the process image looks like.

| Mode | Command | Program text | Process image | Child processes |
|---|---|---|---|---|
| source | `jocky run script.jky` | `.jky` file on disk | `/usr/bin/python3` | none |
| artifact | `jocky exec script.jky.build` | encrypted artifact on disk | `/usr/bin/python3` | none |
| fileless | `jocky fileless script.jky` | payload memfd | `/memfd:python3 (deleted)` + memfd mappings | none |

The last column is the same in every mode because collection never spawns
anything — it reads `/proc` and `/sys` directly (see
[collectors](/docs/runtime/collectors)). The first two columns are the actual
difference, and they are measured below.

## Source mode

`jocky run` parses, compiles and executes the script in one process:

```bash
./venv/bin/jocky run scripts/triage.jky
```

* **Written to disk:** nothing by JOCKY itself. The *interpreter* still caches
  its imports, so a cold run leaves bytecode caches behind:

```text
- source mode (warm interpreter): created 0, modified 0 file(s)
- source mode (cold interpreter): 74 bytecode-cache file(s) written — the interpreter caches imported modules, which fileless mode never does
```

  (quoted from `evidence/report.md` §3; the same run measured in
  `/tmp` with `--quick --iterations 40` reported 79 cache files)

* **Process image:** an ordinary Python process — `exe` is the interpreter, no
  `-c` flag, no memfd mapping.
* **Use it when** you are authoring or debugging scripts, or the host is yours:
  it is the fastest path and the stack traces are the most readable.

## Artifact mode

`jocky build` compiles the script and encodes it into a polymorphic artifact;
`jocky exec` decodes and runs it:

```bash
./venv/bin/jocky build scripts/triage.jky -o /tmp/triage.jky.build
./venv/bin/jocky exec /tmp/triage.jky.build
```

* **Written to disk:** one file, the artifact, whose bytes carry no plaintext of
  the program (see [polymorphic artifacts](/docs/execution/artifacts)).
* **Process image:** identical to source mode — the same interpreter, running
  the decoded program in-process. Artifact mode changes the bytes at rest, not
  the runtime footprint.
* **Use it when** a file on the target is acceptable but readable source is not,
  and you want each deployment to be a distinct file (1000 builds → 1000 unique
  SHA-256, `evidence/report.md` §1).

## Fileless mode

`jocky fileless` (alias `jocky memfd`) writes the interpreter ELF, a zip of the
`jocky` package and the payload into three `memfd_create()` objects and execs
`/proc/self/fd/<elf_fd>` with a `-c` bootstrap. Nothing is written to a
filesystem. The mechanics, verification steps and limits have their own page:
[fileless execution](/docs/execution/fileless).

## What the three modes look like from `/proc`

One script, run three ways. It reports its own process image:

```jocky
let argv = proc.cmdline(sys.pid())
emit {"pid": sys.pid(), "exe": proc.exe(sys.pid()), "argv_len": len(argv),
      "argv0": argv[0], "has_dash_c": contains("-c", argv),
      "memfd_maps": count(proc.maps(sys.pid()), fn(m) { return m.memfd })}
```

```text
$ ./venv/bin/jocky run /tmp/jdocs/mode_probe.jky
{"pid": 51820, "exe": "/usr/bin/python3.12", "argv_len": 4, "argv0": "/home/mjonir/f/sih2026/sih148/venv/bin/python3", "has_dash_c": false, "memfd_maps": 0}
$ ./venv/bin/jocky exec /tmp/jdocs/mode_probe.jky.build
{"pid": 51821, "exe": "/usr/bin/python3.12", "argv_len": 4, "argv0": "/home/mjonir/f/sih2026/sih148/venv/bin/python3", "has_dash_c": false, "memfd_maps": 0}
# 1 finding(s), 0 error(s), 441 steps, 0.7 ms
$ ./venv/bin/jocky fileless /tmp/jdocs/mode_probe.jky
{"pid": 51826, "exe": "/memfd:python3 (deleted)", "argv_len": 3, "argv0": "python3", "has_dash_c": true, "memfd_maps": 5}
# exit=0 exe=/memfd:python3 (deleted) memfd_maps=4 pid=51826 166 ms
```

The `#` lines are the CLI's one-line summaries on stderr (`1 finding(s) …` for
`exec`, the exit/process-image line for `fileless`).

Source and artifact mode are the same process shape; only the file on disk
differs. Fileless mode is the only one whose `exe` is not a file on disk — and
the only one where the program arrives through `-c` argv text, which is also
where it stays visible (see the limits section of the
[fileless page](/docs/execution/fileless)).

## Measured telemetry

Collection is where noise is usually created: a shell-out to `ps`, `ss`, `lsof`
or `sha256sum` is visible as a child process and often as a file access. JOCKY's
harness measures this with a Python audit hook wrapped around a real triage run
(`evidence/report.md` §4):

```text
- child processes spawned during collection: **0**
- execve calls: 0 · write-mode opens: 0 · socket calls: 0
- read-mode opens: 405 · imports: 62
- VM steps: 885 · findings: 1 · duration 20.3 ms
```

The three modes differ in disk footprint, not in process tree. From
`evidence/report.md` §3:

| Mode | Files created | Files modified | Program text on disk |
|---|---|---|---|
| source (warm interpreter) | 0 | 0 | script readable, yes |
| source (cold interpreter) | 74 bytecode caches | 0 | script readable, yes |
| fileless | 0 | 0 | no |

The same report measured the fileless image and payload (§3):

```text
- fileless process image: `/memfd:python3 (deleted)` with 4 memfd-backed mappings
- in-memory payload: interpreter 8020928 bytes, runtime zip 94110 bytes
```

A `--quick` reproduction in a scratch directory (`./venv/bin/jocky evidence
--quick --iterations 40 --out /tmp/jdocs/ev`) reports the same structure with
smaller counts: 10 builds → 10 unique SHA-256, artifact sizes 3678–3986 bytes,
source mode (cold) 79 cache files, fileless 0 files created, 0 child processes,
0 execve, 0 write-mode opens, and the fileless job's own report
`exe=/memfd:python3 (deleted)` with 4 memfd mappings.

## Build and run throughput

From `evidence/report.md` (1000 iterations, full mode):

```text
- builds: **1000**, unique SHA-256: **1000** (all unique)
- artifact sizes: 3625–4175 bytes, 367 distinct sizes (per-build padding/structure differs)
- build throughput: 296.0/s

- runs: **1000**, distinct finding-hashes: **1**, errors: 0
- latency ms — min 12.298, median 16.121, p95 21.358, max 28.348
- throughput: 55.2 runs/s
```

The `runs` figures are executions of one artifact; one distinct finding-hash
over 1000 runs is the repeatability claim, and the semantic-equivalence check in
§1 (25 freshly built artifacts, findings hash identical to the reference run, 0
failures) is what ties unique bytes to stable behaviour.

## Choosing a mode

| Situation | Mode |
|---|---|
| writing or debugging a script; host you own | source |
| a file on the target is acceptable, readable source is not | artifact |
| the target is monitored for file creation, or no artifact may be dropped | fileless |
| a job over the management interface | the agent's job kind: `source` or `fileless` |

Practical notes:

* Fileless mode costs memory and a process hand-off: the interpreter image
  (~8 MB), the packed runtime zip and the payload are held in the child's
  address space. The same trivial program (`{"n": 7}`) takes 0.236 s wall for
  `jocky exec` and 0.524 s for `jocky fileless` on this host — the difference is
  writing the interpreter memfd, `fork`/`exec` and the `zipimport` of the runtime.
* All three modes accept `--wall-ms` (default 60000 ms) and, for `run`,
  `--max-steps` (default 50000000). The VM enforces them identically in every
  mode; an over-budget script stops and is reported as truncated rather than
  being allowed to hang:

```text
$ ./venv/bin/jocky run /tmp/busy.jky --wall-ms 100 --json | jq '{truncated, steps, duration_ms, errors}'
{
  "truncated": true,
  "steps": 140288,
  "duration_ms": 100.392,
  "errors": [
    "wall-clock budget exceeded"
  ]
}
```

## What does not change

* **Same VM, same natives.** A script's findings do not depend on the mode:
  `jocky exec` of a build and `jocky run` of its source produce the same
  finding set (that equality is what `evidence/report.md` §1 checks across 25
  fresh builds).
* **Same collection telemetry.** Zero child processes and zero write-mode opens
  in every mode; the only difference is where the program text sits.
* **Exit codes.** `0` on success, `1` when the script or artifact produced
  errors, `2` when the command itself failed (for example a tampered artifact).
