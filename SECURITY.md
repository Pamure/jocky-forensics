# Security policy

JOCKY is investigative tooling: it reads a host's kernel interfaces, executes
scripts, and — in fileless mode — runs code from anonymous memory. That makes
its own attack surface worth stating plainly.

## Reporting a vulnerability

Open a private security advisory on the repository (Security → Advisories →
Report a vulnerability) rather than a public issue. Please include:

* the version (`jocky --version`), kernel and distribution;
* the smallest script or command that reproduces the problem;
* what you expected instead, and what you observed (`--json` output helps);
* whether the issue is exploitable by a *script* (untrusted payload), by a
  *network peer* (management plane), or only by a local user with the same uid.

We aim to acknowledge within 72 hours.

## What is in scope

| Area | Examples |
|---|---|
| Capability escapes | a script reaching privileges it was not granted (e.g. raw syscalls or memfd execution without `--allow`) |
| Artifact handling | a crafted artifact causing code execution, memory corruption or a crash outside `JockyArtifactError` |
| Management plane | authentication bypass, result forgery/replay, pin bypass, request smuggling, unbounded resource use |
| Case integrity | forging, truncating or silently editing a manifest that `jocky verify` still accepts |
| Language runtime | a script escaping its budgets or corrupting the host VM state |

## Known and accepted limitations

These are documented, measured, and deliberately *not* treated as
vulnerabilities (see `docs/DESIGN.md` and the "Honest limits" documentation page):

* **Jobs are code by design.** Anyone holding the management token can run
  arbitrary JOCKY on an agent host. That is the product, not a bug; the token
  is the trust boundary (`--token-file`, `JOCKY_TOKEN` and pinning exist to
  protect it).
* **Kernel telemetry sees fileless execution.** `memfd_create`/`execveat`,
  process creation and file reads are visible to eBPF/LSM observers and auditd.
  Nothing in user space can hide those from a privileged observer.
* **A running payload is visible in `/proc`** unless `--private` is used, which
  trades that visibility (including to your own triage) for non-dumpability.
* **The artifact integrity footer is not authenticity.** The key travels in the
  artifact; it detects corruption, not an adversary. Sign cases with
  `jocky sign` and keep the key off the target.
* **Polymorphism is uniqueness, not secrecy.** The decoded program is recovered
  by anyone who can run `PolyEncoder.decode`.
* **Collection is snapshot-based.** Findings describe the moment of the scan;
  they are not proof that a host is clean, and `partial_visibility` says so
  explicitly when part of the process table was unreadable.

## Hardening checklist for deployments

1. Run `jocky doctor` on every agent host before the engagement.
2. Use `--token-file` (or `JOCKY_TOKEN`) instead of `--token` — argv is
   world-readable in `/proc/<pid>/cmdline`.
3. Keep the pinned fingerprint (`<state>/agent.json`) out of backups you do not
   control, and never pass `--insecure` outside a lab.
4. Attest and sign every case directory (`jocky attest`, `jocky sign`), and
   store the chain head off-host (`--anchor`).
5. Grant capabilities per job, not by default: `--allow` only for scripts you
   have read.
