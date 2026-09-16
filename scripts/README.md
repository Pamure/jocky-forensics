# The JOCKY script library

Every `.jky` file in this tree is a runnable script. One command runs one script,
and the library is verified as a whole:

```bash
./venv/bin/jocky run scripts/collection/02_listening_service_inventory.jky --json
./venv/bin/jocky examples            # the same inventory, from the CLI
./venv/bin/python -m pytest tests/test_script_library.py -q   # every script runs clean
```

**Inventory: 38 scripts** — 8 in this directory, 30 under the topic
directories below. `jocky examples` prints the same list, and
`tests/test_script_library.py` fails if this README, the filesystem and the CLI
ever disagree. The count is stated here because a library whose size is only
discoverable by counting files is a library whose size gets misquoted.

## How to read a script

Every script opens with a comment block in the same shape:

1. **The problem this answers** — the question an analyst is holding when they
   reach for this script, in the analyst's terms.
2. **What each finding means** — one paragraph per `kind` the script can emit,
   including when a finding is *expected* on a healthy host and what it means
   when it is not.
3. **Scope and cost** — what the script deliberately does not do, and why the
   check is bounded (files read, processes examined, patterns avoided).

The body is then numbered sections in order, and each finding carries three
fields a consumer can rely on:

| Field | Meaning |
|---|---|
| `kind` | the finding type — stable, lowercase, filterable. `jocky run … --ndjson \| jq 'select(.kind == "…")'` |
| `severity` | `info`, `low`, `medium`, `high`, `critical`. `info` is used for inventory rows and for facts recorded rather than judged |
| `evidence` | everything needed to pivot: pids, paths, addresses, timestamps, the matched pattern, and a `recommendation` naming the next step |

A finding that cannot be acted on is a bug. Findings whose whole point is that
nothing was found are emitted too — an inventory row, or a summary with
`files_readable: 0` — because "no match" and "could not look" must never print
the same.

## Platform

These scripts are written for, and verified on, Linux. They read the kernel's
own interfaces: `/proc`, `/sys`, `/proc/net`, and configuration files under
`/etc`, `/var/log` and the users' home directories. No `ps`, `ss`, `lsof`,
`lsmod`, `find` or `sha256sum` is ever executed — collection spawns no child
processes at all, which is what `jocky evidence` measures.

| Platform column | Meaning |
|---|---|
| **Linux** | reads Linux kernel interfaces or `/etc`, `/var/log`, `/proc` paths. There is no equivalent data on another operating system, so the script skips what is absent rather than failing |
| **Linux + Windows** | every native it calls has a Windows collector in `jocky/rt/winapi.py` (the process list, the socket tables, the loaded-module list, uptime), and it reads no Linux-only path. The runtime's contract covers the Windows path; these scripts were developed and verified on Linux |

Where a concept does not exist on the host — kernel taint bits outside Linux,
for instance — the finding says `not applicable` with the value `nil` rather
than reporting a clean result. A check that cannot run must not look like a
check that passed.

## The library

### Starters — `scripts/*.jky`

The scripts a new analyst meets first. Five of them are also packaged inside the
wheel (`jocky/examples/`) and copied by `jocky init`.

| Script | Platform | Question it answers |
|---|---|---|
| `evidence.jky` | Linux | deterministic workload for the evidence harness: its output must be byte-identical across runs |
| `quickstart.jky` | Linux | a guided tour of the language and of every namespace a triage script reaches for |
| `smoke.jky` | Linux + Windows | the minimal script the harness times thousands of times |
| `triage.jky` | Linux | full host triage: in-memory execution, network exposure, kernel tampering |
| `hunt.jky` | Linux | fileless processes, correlated with the sockets they hold |
| `inventory.jky` | Linux | hardware, kernel view, network exposure, mount policy |
| `timeline.jky` | Linux | recent activity in the drop zones, plus deleted-but-open files |
| `watch.jky` | Linux | a long-running collection loop, kept alive so live detection has a target |

### Collection — `scripts/collection/`

What is on this host, and is it arranged the way real programs arrange
themselves.

| Script | Platform | Question it answers |
|---|---|---|
| `01_process_tree_anomalies.jky` | Linux | does the process tree have the shape a healthy host's tree has? (self-parenting, a child older than its parent, interpreters detached onto init, an unexpected root child) |
| `02_listening_service_inventory.jky` | Linux | what is offering a service, on which address, owned by which process — and which of those are exposed, unattributed, or running from an unlinked or drop-zone binary |
| `03_scheduled_task_inventory.jky` | Linux | every way this host runs a command on a schedule: crontab entries, run-parts scripts and systemd timers, with the risky commands graded |
| `04_session_surface_inventory.jky` | Linux | who is on this host, through which terminal, whether the session descends from a login program, and which uids own processes but have no account |
| `05_mount_policy_inventory.jky` | Linux | what is mounted, and is any of it mounted over a path whose contents define the system (`/etc`, `/usr`, `/home`) |

### Persistence — `scripts/persistence/`

The mechanisms that bring something back after a reboot, one per script.

| Script | Platform | Question it answers |
|---|---|---|
| `01_systemd_unit_hunt.jky` | Linux | which local units and drop-ins exist, what they execute, whether the binary is still on disk, and whether the enablement symlink dangles |
| `02_shell_profile_hunt.jky` | Linux | which files run code when a shell opens, and which of them inject a library, shadow a privileged command, suppress history or prepend a relative PATH |
| `03_authorized_keys_hunt.jky` | Linux | which SSH keys log in as which account, what each key is allowed to do (`command=`, `environment=`), and which blobs are shared between accounts |
| `04_package_hook_persistence.jky` | Linux | which apt/dpkg hooks run as root during a package operation, which package index or registry has been repointed, and which git hook is executable in a repository under a home directory |

### Anti-forensics — `scripts/antiforensics/`

What has been made hard to see.

| Script | Platform | Question it answers |
|---|---|---|
| `01_timestamp_anomaly_scan.jky` | Linux | which file carries a timestamp that cannot be true (a future mtime, epoch zero, a ctime older than the mtime, a pre-boot mtime inside tmpfs, a hardlinked file in a drop zone) |
| `02_log_gap_scan.jky` | Linux | are the logs still being written, is any log a symlink into `/dev/null`, is one writable by others, and where does the record actually stop |
| `03_history_tampering_scan.jky` | Linux | is shell history consistent with the sessions that produced it — including a history emptied *while* its owner's shell is still running, and a live shell with `HISTFILE=/dev/null` |

### Network — `scripts/network/`

What leaves the host, what resolves, and whether anything is watching the wire.

| Script | Platform | Question it answers |
|---|---|---|
| `01_external_connection_scan.jky` | Linux | which processes hold connections to addresses off-host, which of them are shells or interpreters, and which process is fanning out to many peers |
| `02_dns_configuration_drift.jky` | Linux | does this host resolve names the way its operators believe — resolvers, `/etc/hosts` sinkholes, the `nsswitch` order and systemd-resolved's own configuration |
| `03_interface_anomaly_scan.jky` | Linux | is an interface promiscuous, is the loopback interface still loopback, is the host forwarding, and does the ARP table show a sweep or a spoof |

### Credential and access — `scripts/access/`

Who can become someone else, and with what.

| Script | Platform | Question it answers |
|---|---|---|
| `01_suid_sgid_drift_scan.jky` | Linux | what can raise privilege, and which of those files is writable by others, in a drop zone, not owned by root, or a script wearing a setuid bit |
| `02_sudoers_drift_scan.jky` | Linux | who can become root without a password, and which rules grant a program that is root by another name (`sh`, `vim`, `find`, `systemctl`, `docker`, …) |
| `03_ssh_key_exposure_scan.jky` | Linux | which private keys are on this host, who can read them, and whether the SSH client config runs a program on connect |
| `04_root_account_audit.jky` | Linux | is uid 0 still one account, can any account log in without a password, are the credential files as tight as they should be |

### Memory and execution — `scripts/memory/`

What the running processes are actually made of.

| Script | Platform | Question it answers |
|---|---|---|
| `01_rwx_and_mapping_scan.jky` | Linux | what is mapped into the running processes, and which mapping has no file behind it any more (deleted libraries, memfd code, executable mappings from writable paths) |
| `02_process_file_mismatch_scan.jky` | Linux | does each process's identity match the file it runs — a userland process wearing a kernel thread's name, a binary in a writable location, a binary on a `noexec` mount, a scrubbed command line |

### Integrity — `scripts/integrity/`

| Script | Platform | Question it answers |
|---|---|---|
| `01_manifest_baseline_diff.jky` | Linux | what changed since the baseline — compares the live filesystem against a `jocky attest` manifest, including whether the manifest itself was truncated (`JOCKY_MANIFEST=<path>` selects the baseline) |

### End-to-end playbooks — `scripts/solutions/`

The numbered playbooks group the checks above into the scenarios the project was
built for: anti-forensics and process hollowing, container and cloud escape,
stealth persistence, covert channels, Sigma/YARA hunting, super-timeline
attestation, kernel-module (BYOVD) integrity, and offline packet-capture
analysis. Each one opens with the problem statement it is a solution to.

| Script | Platform | Question it answers |
|---|---|---|
| `01_anti_forensics_hunt.jky` | Linux | in-memory execution, masquerading threads and injection primitives, in one pass |
| `02_container_cloud_escape.jky` | Linux | container breakouts, namespace escapes and cgroup tampering |
| `03_stealth_persistence.jky` | Linux | rootkits (module-view mismatch), dynamic-linker injection and PATH hijacking |
| `04_network_covert_channels.jky` | Linux + Windows | unattributed sockets and reverse-shell ports, with a linear process-to-socket correlation |
| `05_sigma_yara_production_hunt.jky` | Linux | evaluating the industry's Sigma and YARA corpora on the runtime's linear-time engine |
| `06_super_timeline_attestation.jky` | Linux + Windows | merging volatile sources into one ordered timeline with chain-of-custody output |
| `07_byovd_kernel_integrity.jky` | Linux | kernel-module integrity: out-of-tree, unsigned, forced, deleted, and late-loaded drivers |
| `08_network_capture_analysis.jky` | Linux | offline network forensics over a packet capture |

## What is deliberately not here

A library's honest boundary matters more than its count, so:

- **No Windows registry checks.** Run keys are the first thing an analyst looks
  for on Windows; the runtime has no registry collector, so there is no script
  pretending to check them.
- **No packet capture of its own.** `solutions/08` analyses a capture that was
  taken elsewhere. Nothing in this library opens an interface.
- **No journald parsing.** journald's on-disk format needs the journal's own
  index; the log scripts read plain files and say what they could not read.
- **No baseline unless you take one.** `integrity/01` compares against a
  `jocky attest` manifest; with no manifest it reports that fact instead of
  inventing a comparison.
- **No timestamps in the socket table.** `/proc/net/tcp` carries none, so
  `network/01` cannot detect beaconing and says so rather than approximating it.
- **Nothing that writes.** Every script is read-only: no file is created,
  modified or deleted, no process is signalled, no network traffic is generated,
  and no interface is reconfigured.

## Conventions every script follows

- **One statement per line, no semicolons.** A `.jky` script has no statement
  terminator; the newline ends the statement.
- **`emit` for findings, `print` only for a tour.** A production script's output
  is its findings.
- **`nil` is not zero.** A native that reports an absent concept returns `nil`,
  and `nil != 0` is true, so presence is checked before a value is compared —
  the BYOVD script's kernel-taint gate is the worked example.
- **Functions are defined before they are used.** JOCKY resolves names in
  source order.
- **Paths are checked before they are scanned.** `fs.scan` refuses to walk
  `/proc`, `/sys`, `/dev` and `/run`, and an account's home field may itself be
  one of those (`sys:/dev`, `rtkit:/proc`), so the home-directory sweeps filter
  them explicitly.
- **A root that could not be read is reported, not omitted.** Every search has a
  matching "I could not look" finding.
