# Installation

JOCKY is a Python package with no third-party dependencies. The language, the
polymorphic encoder, the `/proc` collectors, the fileless runner and the
management server are all built on the Python 3.12 standard library and read
Linux kernel interfaces directly — there is nothing to compile, and nothing is
downloaded at run time.

This page covers the supported install paths, the host requirements, how to
read `jocky doctor`, and what to do when a check fails. For a first run with
real output, continue to [Quickstart](/docs/getting-started/quickstart).

## Requirements

| Requirement | Why it is needed | Where it is checked |
|---|---|---|
| Linux with procfs mounted | every collector reads `/proc`, `/proc/net` or `/sys`; JOCKY never shells out to `ps`, `ss`, `lsof`, `lsmod` or `find` | `doctor` → `procfs mounted`, `network tables` |
| Python 3.12 or newer | `pyproject.toml` declares `requires-python = ">=3.12"`; the VM and collectors use modern typing and `os.memfd_create` | `doctor` → `python >= 3.12` |
| Standard library only | `dependencies = []`, so `pip` installs no packages alongside JOCKY | install output |
| `openssl` binary (optional) | generating the self-signed certificate for `jocky serve` | `doctor` → `openssl binary` |
| uid 0 (optional) | reading other users' `/proc` entries; without it you see only your own processes | `doctor` → `effective uid` |
| `memfd_create` and executable `/proc/self/fd` (optional) | fileless execution | `doctor` → `memfd_create`, `fileless end-to-end` |

The document host is an unprivileged account (uid 1000) on
`Linux 6.6.87.2-microsoft-standard-WSL2`, Python 3.12.3: every output below was
produced without root.

## Install from source with a virtual environment

Run this from the repository root:

```bash
python3 -m venv venv
./venv/bin/pip install -e .
./venv/bin/jocky --version
```

```text
Successfully installed jocky-forensics-1.2.0
jocky 1.2.0
```

The editable install (`-e`) means edits to `jocky/*.py` take effect on the next
command with no reinstall, which is what you want while writing scripts.

## Install the package with pip

A regular (non-editable) install behaves identically for the CLI:

```bash
python3 -m venv /tmp/jky-venv
/tmp/jky-venv/bin/pip install .
```

```text
Successfully built jocky-forensics
Installing collected packages: jocky-forensics
Successfully installed jocky-forensics-1.2.0
```

`pip install .` also works into a system or user environment, but a virtual
environment keeps the console script isolated from other tooling.

## Install with pipx

pipx puts `jocky` on your `PATH` in its own environment, which suits an analyst
workstation that is not a development checkout:

```bash
pipx install .
```

```text
  installed package jocky-forensics 1.2.0, installed using Python 3.12.3
  These apps are now globally available
    - jocky
```

The run quoted here used `PIPX_HOME`/`PIPX_BIN_DIR` overrides so the
documentation host's real pipx environment was untouched; with the defaults the
script lands in `~/.local/bin`.

## Docker

```bash
docker build -t jocky .
docker run --rm jocky --version
docker run --rm --pid=host -v /proc:/proc:ro jocky doctor
docker run --rm -v "$PWD/case:/case" jocky init /case
```

The image is `python:3.12-slim` plus `openssl` and `ca-certificates`, and
nothing else. `procps` is deliberately **not** installed, so the image contains
no `ps`, `ss` or `lsof` — JOCKY reads `/proc` itself, and a container without
those tools proves the claim at run time rather than asserting it. The image
runs as the unprivileged user `analyst` (uid 10001) with
`PYTHONDONTWRITEBYTECODE=1`, and its entrypoint is the `jocky` console script.

Docker is not installed on the host that produced this page, so the image was
not built here; the statements above are read from the `Dockerfile` in the
repository root, which is the authoritative source.

## Run without installing

From the repository root, the package is importable as a plain directory:

```bash
python3 -m jocky --version
```

```text
jocky 1.2.0
```

There is no console script in this mode, so every command is
`python3 -m jocky <command>`. It only works while the repository root is on
`sys.path`; from anywhere else the import fails:

```bash
cd /tmp && python3 -m jocky --version
```

```text
/usr/bin/python3: No module named jocky
```

## The console script

All install paths other than `python -m jocky` expose one executable, `jocky`,
defined in `pyproject.toml` as `jocky = "jocky.cli:main"`:

```text
{run,exec,build,fileless,memfd,disasm,info,doctor,init,examples,triage,evidence,attest,verify,sign,serve,agent}
```

Full flags for each command are in the [CLI reference](/docs/operations/cli).

## Verify the installation

These four commands are the whole smoke test, and they are the same sequence
this page was written from:

```bash
jocky --version
jocky doctor
jocky init /tmp/case
jocky run /tmp/case/scripts/triage.jky
```

```text
jocky 1.2.0
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

`jocky init` copies the five bundled example scripts (list them with
`jocky examples`) into a case directory and adds a `README.md` plus a
`.gitignore` covering the artefacts a case produces (`.jocky-server/`,
`.jocky-agent/`, `*.jky.build`, `*.jky.artifact`, `evidence/`).

```text
{"kind": "summary", "host": "stormbreaker", "kernel": "6.6.87.2-microsoft-standard-WSL2", "processes": 94, "sockets": 92, "counts": {"info": 1, "low": 32, "medium": 0, "high": 0, "critical": 0}, "duration_ms": 586.093}
{"kind": "tail", "high_or_critical": 0, "total_findings": 33}
```

Two JSON lines of findings, exit status 0. Process, socket and finding counts
vary with what the host is doing at the time; the shape of the output does not.

## Reading `jocky doctor`

`jocky doctor` probes every prerequisite and prints one line per check, grouped
by subsystem, with a fix line under anything that is not `ok`:

```text
RUNTIME
  [ok  ] python >= 3.12               3.12.3

PACKAGING
  [ok  ] working directory writable   /home/mjonir/f/sih2026/sih148
  [ok  ] jocky package importable     version 1.2.0

COLLECTION
  [ok  ] procfs mounted               /proc is readable
  [ok  ] network tables               /proc/net present
  [warn] effective uid                1000
          -> reading other users' /proc entries needs root (or CAP_SYS_PTRACE for ptrace); you will still see your own processes

RUNTIME
  [ok  ] direct syscalls              raw on x86_64

CONFINEMENT
  [ok  ] sandbox (Landlock)           Landlock ABI 3 (filesystem rights only; --sandbox=strict adds seccomp)

MANAGEMENT
  [ok  ] tls module                   OpenSSL
  [ok  ] openssl binary               /usr/bin/openssl
  [ok  ] sqlite3                      3.45.1

FILELESS
  [ok  ] memfd_create                 available
  [ok  ] fileless end-to-end          exe=/memfd:python3 (deleted) memfd_maps=4

ready: 12 ok, 1 warning(s), 0 failure(s) in 228 ms
```

What the groups mean:

- **RUNTIME — `python >= 3.12`** is the interpreter version. **`direct syscalls`**
  is the `mem` namespace's raw syscall path: `ok` reports the method and
  architecture, a warning means `mem.syscall` falls back to libc. The fallback
  is not fatal, but the raw path is unavailable.
- **PACKAGING — `working directory writable`** matters because `run`, `build`
  and `exec` may write bytecode caches or artifacts relative to the current
  directory. **`jocky package importable`** confirms the installed version.
- **COLLECTION — `procfs mounted` and `network tables`** gate everything the
  runtime can see. **`effective uid`** is a warning by design for non-root
  users: process inventory, socket attribution and `det` checks silently see
  fewer processes.
- **CONFINEMENT — `sandbox (Landlock)`** reports the Landlock ABI the kernel
  offers and what it can enforce. Filesystem rights only: `--sandbox=strict`
  adds a seccomp filter for `socket(2)`, and a kernel without Landlock fails
  this check, because the sandbox refuses to silently downgrade.
- **MANAGEMENT** covers the dependencies of `jocky serve` / `jocky agent`:
  the `ssl` module, the `openssl` binary (certificate generation) and
  `sqlite3` (the job/finding store).
- **FILELESS** covers `memfd_create` availability and a real end-to-end run of
  a one-line payload from memory, reporting the process image and the number
  of memfd-backed mappings the runner observed.

Exit status is `0` when there are no failures (warnings are allowed) and `1`
when any check fails, so it can gate a deployment script. Two flags help in
scripts and on slow hosts:

```bash
jocky doctor --json     # machine-readable report: ok, counts, host, checks[]
jocky doctor --quick    # skip the end-to-end fileless probe
```

`--quick` on the same host prints `ready: 10 ok, 1 warning(s), 0 failure(s) in 3 ms`
— the fileless probe is the expensive part.

## Troubleshooting

Each row is a check that `jocky doctor` can report as failing or warning, with
the reproduction used for the quotes below.

| Doctor line | Symptom | What it means | What to do |
|---|---|---|---|
| `[FAIL] procfs mounted` `/proc missing` | `NOT ready: 9 ok, 1 warning(s), 3 failure(s)`, exit 1 | the host or container has no usable procfs, so no collector can run | run on a Linux host, or mount `/proc` into the container; `-v /proc:/proc:ro` is not enough if the container also needs `/proc/self` |
| `[warn] network tables` `/proc/net not readable` | socket inventory is empty | the network namespace does not expose socket tables | check container networking; `net.*` returns empty lists rather than failing |
| `[warn] effective uid` `1000` | most processes unreadable; `det.triage()` adds an `info` finding | `/proc/<pid>/{cmdline,environ,maps}` for other users needs root or `CAP_SYS_PTRACE` | keep the warning and read the coverage number, or re-run as root when you must see every process |
| `[warn] openssl binary` `not found` | `jocky serve` cannot create a certificate | no `openssl` on `PATH`; the TLS module itself is fine | install `openssl`, or start the server with `--cert`/`--key` |
| `[FAIL] fileless end-to-end` `payload failed` | exit 1; `[FAIL] /proc/self/fd execution` usually appears with it | executing a file through `/proc/self/fd` is blocked (hardening, `noexec` policy, restricted container) | use `jocky run` or `jocky exec`; both are unaffected |
| `[FAIL] memfd_create` | fileless mode is unavailable entirely | the interpreter or kernel lacks `memfd_create` | use `jocky run`/`jocky exec`, or a newer kernel/Python |
| `[FAIL] python >= 3.12` | `jocky` will not start at all | the interpreter is older than `requires-python` | install Python 3.12+ (the fix text is in `jocky/diagnostics.py`) |

Two of those rows were reproduced on the documentation host.

**Missing procfs.** A private mount namespace with an empty `/proc` shows
exactly what a hardened container looks like:

```bash
unshare -Urm --propagation private sh -c 'mount -t tmpfs none /proc; jocky doctor'
```

```text
COLLECTION
  [FAIL] procfs mounted               /proc missing
          -> collection requires Linux procfs; run inside a Linux host or container with /proc mounted
  [warn] network tables               /proc/net not readable
          -> socket inventory will be empty; check container networking
  [ok  ] effective uid                0 (root)

...
FILELESS
  [ok  ] memfd_create                 available
  [FAIL] /proc/self/fd execution      not available
          -> fileless mode executes through /proc/self/fd
  [FAIL] fileless end-to-end          payload failed
          -> check that executing files from /proc/self/fd is permitted (some hardening policies block it)

NOT ready: 10 ok, 1 warning(s), 3 failure(s) in 31 ms
```

(Inside a user namespace the effective uid is 0, which is why the uid check
reads `ok` there.)

**No `openssl` on `PATH`.** Removing `openssl` from the environment turns the
management certificate check into a warning and nothing else:

```bash
env PATH=/nonexistent jocky doctor
```

```text
MANAGEMENT
  [ok  ] tls module                   OpenSSL
  [warn] openssl binary               not found
          -> certificates must be supplied with --cert/--key; `jocky serve` cannot generate a self-signed pair without openssl
  [ok  ] sqlite3                      3.45.1

...
ready: 11 ok, 2 warning(s), 0 failure(s) in 224 ms
```

### The non-root warning in practice

Running as uid 1000, `det.triage()` reports how much of the host it could
actually read. On the documentation host the coverage line is an `info`
finding:

```text
# info=1, low=27, medium=30  (517.2 ms, 120 processes)
[info    ] only 37% of processes were inspectable (76 of 120 unreadable)
```

The first line is the summary `jocky triage` prints; the second is the coverage
finding in the list below it.

A "clean" triage from an unprivileged account is therefore a statement about
the processes you own, not about the host. The `scanned.coverage` field in the
`det.triage()` report carries the same number for scripts; see
[Detection checks](/docs/runtime/detection) and
[Honest limits](/docs/security/limits).

## Upgrading and uninstalling

Upgrading an editable install re-reads the metadata and reinstalls the package:

```bash
./venv/bin/pip install --upgrade -e .
```

```text
  Attempting uninstall: jocky-forensics
    Found existing installation: jocky-forensics 1.1.0
    Uninstalling jocky-forensics-1.1.0:
      Successfully uninstalled jocky-forensics-1.1.0
Successfully installed jocky-forensics-1.2.0
```

For a pip install, `pip install --upgrade .`; for pipx, `pipx reinstall
jocky-forensics` after updating the checkout.

Uninstalling removes the console script along with the package:

```bash
./venv/bin/pip uninstall jocky-forensics
```

```text
Found existing installation: jocky-forensics 1.2.0
Uninstalling jocky-forensics-1.2.0:
  Successfully uninstalled jocky-forensics-1.2.0
```

After that `jocky` is no longer on `PATH`. Case directories and evidence logs
are plain files under the directories you chose, so they are unaffected.

## Building the documentation site

Two build paths exist for this site, both from the repository root. The primary
one is the SvelteKit build that `site/package.json` defines:

```bash
cd site && npm run build
```

It needs Node and npm. The zero-dependency alternative renders the same
`site/content/**/*.md` files, navigation manifest and stylesheet into plain
HTML with the standard library only — the offline path for an air-gapped
reviewer:

```bash
./venv/bin/python site/tools/build_static.py --out site/dist
```

The static builder owns nothing interactive: search runs client-side against
`assets/search-index.json` and there is no client-side router. It validates the
navigation manifest and prints a warning for every page listed in the manifest
that has no content file yet, which is how this page was checked.

## Next steps

- [Quickstart](/docs/getting-started/quickstart) — a 10-minute path from `init` to a fileless run.
- [Architecture](/docs/getting-started/architecture) — how the language, runtime, encoder and evidence harness fit together.
- [Execution modes](/docs/execution/modes) — source, artifact and fileless, and the telemetry each one leaves.
- [CLI reference](/docs/operations/cli) — every command and flag.
