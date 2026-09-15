# Changelog

Notable changes to JOCKY, newest first, in Keep a Changelog form: the working tree declares `1.2.0`; `1.0.0` was the initial runtime release.

The version string lives in `jocky/__init__.py`: `pyproject.toml` reads it dynamically,
`jocky --version` prints it, and the site builds its version banner from it and `git tag`.

```bash
$ ./venv/bin/jocky --version
jocky 1.2.0
```

The repository has no tags yet (`git tag` is empty; the site generator reports `tags=0`),
so neither entry below carries a release date, and an untagged bump to `1.1.0` that
happened during the same development cycle is folded into the newer section rather than
given a heading of its own. Version numbers and the generated
[releases page](/docs/project/releases) are explained in
[Versioning & releases](/docs/operations/versioning); what is planned next is in the
[roadmap](/docs/project/roadmap).

## [1.2.0]

The version in the working tree. It closes the gaps a twenty-agent review found in the
1.0.0 runtime: privileged natives a script could use to kill processes, TLS verification
that was off by default, unhashed evidence, non-deterministic builds, detection checks
that missed memfd scripts, and a diagnostics/scaffolding story that made installation
guesswork.

### Added

- **Documentation site** (`site/`) — SvelteKit with `marked`, prerendered to static
  files with `adapter-static`. Sidebar, on-this-page rail, ranked search and a
  previous/next pager. The sidebar manifest in `site/src/lib/nav.js` is validated
  against the files that actually exist, so a listed page that is missing fails the
  build instead of shipping a dead link.
- **Generated reference pages** — `site/tools/gen_reference.py` writes
  `language/standard-library.md`, `runtime/api.md`, `runtime/detection.md` and
  `operations/cli.md` from `jocky.rt.builtins`, `jocky.rt.detect.CHECK_CATALOG` and
  `jocky.cli.build_parser()`; `site/tools/gen_versions.py` writes
  `project/releases.md` and the version banner from `git tag`. A new native, check or
  CLI flag therefore changes the published tables in the same commit.
- **Case-directory integrity** — `jocky/case.py` adds a per-file SHA-256 manifest, a
  hash chain over it, the chain head stored both inside the directory and optionally
  at `--anchor` (another host, a ticket system), and an optional HMAC signature over
  the head. `jocky/canon.py` fixes one canonical JSON encoding behind every digest so
  a digest can be recomputed years later. Attestation is an analyst-side step that
  runs after collection, which keeps the measured "0 child processes during a run"
  invariant true.
- **`jocky attest`, `jocky verify`, `jocky sign`** — the CLI surface for the above:

  ```text
  $ ./venv/bin/jocky attest /tmp/jky-case
  attested 7 file(s), 6428 bytes
    chain head 82a3a3de8bdcf8fd8ad9521d977795435a8d61b199f13bd3101a1dd91afcc943
    manifest   /tmp/jky-case/manifest.json
    head       /tmp/jky-case/manifest.head

  next: jocky sign <dir> --key-file <key>   # authenticate the head
  $ ./venv/bin/jocky verify /tmp/jky-case
  verified: 7 file(s) checked in /tmp/jky-case
  ```

- **Deterministic builds** — `jocky build --deterministic --seed-hex <hex>` reproduces
  identical artifact bytes from a seed instead of mixing fresh entropy, which is what
  rebuild-and-compare provenance needs. The default stays polymorphic.
- **`jocky doctor`** (`jocky/diagnostics.py`) — probes the language runtime, host
  collection, fileless execution, management (TLS) and packaging prerequisites
  *before* an investigation starts, and reports `ok` / `warn` / `fail` with the
  remediation for anything that is not ok. A full run ends with a verdict:

  ```text
  FILELESS
    [ok  ] memfd_create                 available
    [ok  ] fileless end-to-end          exe=/memfd:python3 (deleted) memfd_maps=4

  ready: 11 ok, 1 warning(s), 0 failure(s) in 285 ms
  ```

- **`jocky init`** (`jocky/scaffold.py`) — scaffolds a working case directory instead
  of an empty folder: the bundled examples are copied in, with a README and a
  `.gitignore` covering `.jocky-server/`, `.jocky-agent/` and `*.jky.build`.
- **Packaging** — a `Dockerfile` that installs the package without `procps`, so an
  image without `ps`, `ss` or `lsof` still collects, and a `jocky` console script
  instead of a venv path.
- **Two new detection checks** — `memfd_fd_holder` (a process holding an executable
  memfd descriptor, which covers a memfd script whose `exec` image is the on-disk
  interpreter) and `injection_primitive`, plus `partial_visibility` as a catalogue
  entry, so a triage run where most processes are unreadable reports that instead of
  looking clean.
- **Tests for all of the above** — `tests/test_security.py`,
  `tests/test_diagnostics.py`, `tests/test_scaffold.py`, and a live-detection
  end-to-end test in `tests/test_fileless_detection.py`.

### Changed

- **Reference documentation is generated, not hand-written.** The standard library
  table, the native API, the detection catalogue and the CLI options all come from the
  implementation, and `runtime/detection.md` renders `CHECK_CATALOG` — so a check
  missing from the catalogue is a check missing from the docs. Editing a generated
  page by hand is pointless: the next `npm run gen` overwrites it.
- **Fileless mode requests `MFD_EXEC`** where the kernel understands it (Linux 6.3+),
  because with `vm.memfd_noexec >= 1` the older flags fail with `EPERM`. Kernels that
  predate the flag return `EINVAL` and are handled as before.

### Fixed

- `proc.io` / `sysinfo` io counters were always empty because the `/proc/<pid>/io`
  path was built as a literal rather than from the pid
  (`tests/test_runtime.py::test_io_counters_are_read_for_this_process`).
- `sys.users()` read a `tty` key that `read_stat` never returned
  (`tests/test_runtime.py`).
- The lexer raised `KeyError` on a `0` at the end of the input
  (`tests/test_language.py::test_trailing_zero_literal_parses`).
- The constant pool collapsed `1`, `1.0` and `true` into one entry; literal types are
  now kept distinct (`tests/test_language.py`).
- Unknown string escapes dropped their backslash, so a detection pattern such as
  `\d+` silently became `d+` (`tests/test_language.py`).
- The hidden-module check counted built-in kernel subsystems as hidden: `/sys/module`
  lists them and `/proc/modules` does not. The comparison is now restricted to
  loadable modules (`tests/test_runtime.py`, `docs/DESIGN.md` §5).

### Security

- **Privileged natives are deny-by-default.** `mem.syscall` and `mem.memfd_run` are
  wrapped with `_guarded`, so a script that calls them without an explicit grant fails
  with a catchable error naming the capability and what it can do:

  ```text
  $ ./venv/bin/python -m jocky run /tmp/cap.jky
  error: 'syscall' capability is disabled: raw system calls can signal, trace or terminate other processes. Re-run with --allow syscall if this script is trusted.
  exit=1
  $ ./venv/bin/python -m jocky run --allow syscall /tmp/cap.jky
  40818
  ```

  The grant is carried in the VM context
  (`jocky.runner.policy_ctx(allow=["syscall"])`), so embedding applications decide
  independently of the CLI whether a given script is trusted.
- **TLS is verified by default.** The agent pins the server certificate and can be
  pointed at a specific fingerprint with `--pin`; `--insecure` is an explicit opt-in
  that prints a warning about the token being exposed. The management token can come
  from `--token-file` or `JOCKY_TOKEN` instead of `argv`.
- **Job results are authenticated and idempotent.** Every job carries a
  `payload_sha256`, results are accepted only from the agent that claimed the job, and
  a replayed result updates the existing record instead of duplicating findings.
- **State is owner-only.** The server's state directory is created with mode `0700`,
  the sqlite store and the generated TLS key are hardened the same way, so case data
  is not world-readable on a shared host.
- **Evidence manifests are tamper-evident.** `jocky verify` re-checks a case directory
  against `manifest.json` and reports a mismatch instead of a clean verdict, and
  `jocky sign` HMACs the chain head so a rewrite of the whole directory is detectable
  by anyone holding the key.

## [1.0.0]

The initial runtime: a purpose-made forensic language with a polymorphic artifact
format, fileless execution, a detection library that finds the same techniques, a TLS
management server, and an evidence harness that measures the claims.

### Added

- **Language and VM** (`jocky/lang/`) — hand-written lexer → recursive-descent parser
  → bytecode compiler → stack VM. `let`/`set`, `if`/`elif`/`else`, `while`,
  `for … in`, `fn` declarations and lambdas, closures with shared mutable capture,
  `try`/`catch`, string interpolation, lists and maps, member/method dispatch, and
  `emit` for structured findings. The VM enforces step, wall-clock and call-depth
  budgets; hitting one raises an uncatchable `JockyLimitError` and marks the result
  truncated.
- **Polymorphic encoder** (`jocky/poly/`) — per-build opcode permutation, local-slot
  remapping, per-constant encryption and splitting, junk insertion at statement
  boundaries, keystream-encrypted payload, random padding and an integrity footer.
- **Runtime collectors** (`jocky/rt/`) — process, network, filesystem and system views
  read straight from `/proc`, `/proc/net` and `/sys`, exposed to scripts as
  arity-checked natives in the `proc`, `net`, `fs`, `sys`, `det`, `ioc` and `mem`
  namespaces. No external binaries are spawned at any point.
- **Detection library** (`jocky/rt/detect.py`) — fileless processes, executable memfd
  mappings, deleted executables, execution from world-writable drop zones, rwx
  regions, unusual listeners, deleted-open files, `LD_*` injection, suspicious command
  lines, hidden kernel modules, hijackable `PATH` entries and persistence artefacts,
  each with a severity, evidence and a recommended action.
- **Execution modes** — `jocky run` (source), `jocky exec` (polymorphic artifact) and
  `jocky fileless` / `jocky memfd`, which writes the interpreter, a zip of the package
  and the payload to memfds and execs `/proc/self/fd/<fd>`.
- **Management** (`jocky/agent/`) — TLS server with token auth and a sqlite job and
  finding store, plus a polling agent that executes jobs in-process and reports
  results back.
- **Evidence harness** (`jocky/evidence.py`) — build, run, footprint, audit-hook and
  detection measurements written as raw logs plus `evidence/report.md`.
- **Bundled scripts** (`scripts/*.jky`, `jocky/examples/*.jky`) — triage, hunt,
  inventory, timeline, watch, smoke and the harness script.
- **Behavioural test suite** (`tests/`) — language semantics, live collectors,
  detection, encoder round-trips and the agent protocol. The suite collects 119 tests
  across eight files as this page is written
  (`./venv/bin/python -m pytest tests/ --collect-only -q`; re-run it for the present
  number).

### Measured

Numbers in this section come from `evidence/report.md`, produced by
`./venv/bin/python -m jocky evidence --iterations 1000` on the development host; each
row points at the raw log it was computed from.

| Measurement | Result | Raw log |
|---|---|---|
| Polymorphic builds of one script | 1000 builds → **1000 unique SHA-256**, 3625–4175 bytes, 296.0 builds/s | `polymorphism.csv` |
| Semantic equivalence of fresh builds | 25 rebuilt artifacts re-executed, findings hash identical to the reference run, **0 failures** | `runs.json` |
| Repeatability of one build | 1000 runs → **1 distinct findings hash**, 0 errors, median 16.121 ms, 55.2 runs/s | `runs.json` |
| Fileless process image | `/memfd:python3 (deleted)` with 4 memfd-backed mappings | `artifacts.json` |
| On-disk footprint | fileless run creates **0 files**; a cold source-mode run writes 74 bytecode-cache files | `artifacts.json` |
| Process telemetry during collection | **0 child processes, 0 execve, 0 write-mode opens** (405 read-mode opens) | `audit.json` |
| Self-detection | JOCKY's own triage reported the fileless job while it ran (`detected: true`) | `detection.json` |

### Limitations

Recorded with the release rather than discovered later, and expanded in
[Honest limits](/docs/security/limits): kernel-level telemetry still sees
`memfd_create`, `execveat` and the file reads; in-memory payloads remain visible in
`/proc/<pid>/maps` while they run — which is why the same runtime ships the detector;
domain fronting implements the client-side mechanics and needs a real CDN to mean
anything; collection is Linux-only.
