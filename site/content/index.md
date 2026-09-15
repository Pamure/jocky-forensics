# JOCKY

**A forensic scripting language and runtime built for hosts that are watching.**
Problem statement SIH26148 (NTRO, Blockchain & Cybersecurity): *creation of
scripts/functions with a new programming language to commence computer and
network forensic analysis without triggering security solutions.*

JOCKY collects from `/proc`, `/proc/net` and `/sys` without spawning a single
external tool, compiles scripts into per-build unique artifacts, runs with
nothing written to disk, and ships the detector for the very techniques it uses.

## Start here

| If you want to… | Go to |
|---|---|
| install it | [Installation](/docs/getting-started/installation.html) |
| see it work in ten minutes | [Quickstart](/docs/getting-started/quickstart.html) |
| learn the language | [Language basics](/docs/language/basics.html) |
| write a detection script | [Native API](/docs/runtime/api.html) |
| understand the evasion claims | [Execution modes](/docs/execution/modes.html) |
| check what it cannot do | [Honest limits](/docs/security/limits.html) |
| see the measurements | [Evidence harness](/docs/operations/evidence.html) |

## Measured, not asserted

| Claim | Measurement |
|---|---|
| unique bytes per build | 1000 builds → 1000 distinct SHA-256, 0 semantic-equivalence failures |
| stable behaviour | 1000 executions → 1 distinct findings hash, 0 errors |
| quiet collection | 0 child processes, 0 `execve`, 0 write-mode opens (audit hook) |
| nothing on disk | cold source run writes 74 bytecode caches; fileless run writes 0 |
| fileless process image | `/proc/<pid>/exe` = `/memfd:python3 (deleted)`, 4 memfd mappings |
| self-detection | JOCKY's own triage reports the fileless job while it runs |

## Install in one breath

```bash
git clone <repository> && cd jocky
python3 -m venv venv && ./venv/bin/pip install -e .
./venv/bin/jocky doctor          # verify this host can run every mode
./venv/bin/jocky init case && ./venv/bin/jocky run case/scripts/triage.jky
```

Python 3.12+, Linux, no third-party dependencies.
