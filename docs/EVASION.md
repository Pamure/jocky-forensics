# Comparative evasion evaluation

SIH26148 deliverable 5 asks for a **comparative evasion evaluation report**. This
is it: what was measured, on what, with which controls, and — importantly — what
the measurements do *not* support.

Every number below was produced by a command in this document. The harnesses are
in `evidence/evasion/`.

---

## 1. Methodology, and why the controls matter

An evaluation of the form "our tool was not detected" is worthless without a
**positive control**: if the harness cannot detect anything, "not detected" and
"harness broken" are indistinguishable. Both harnesses below therefore run a
control that *must* be detected, and the artifact results are only reported
because the control passed.

| Harness | Control | Control result | Artifact result |
|---|---|---|---|
| On-disk scan | EICAR test file | **detected** (`ThreatID 2147519003`) | 29 artifacts: clean |
| Execution monitor | EICAR test file | **detected** (detections 5 → 6) | 0 new detections |
| AMSI probe (real host) | Mimikatz string in PowerShell | **blocked** | see §4 |

The instrument itself is the first thing to doubt, not the last.

## 2. Targets

| | |
|---|---|
| Endpoint protection | Microsoft Defender Antivirus |
| Platform | `4.18.26080.4-0` |
| Signature version | `1.459.226.0` |
| Real-time protection | **enabled** |
| Cloud-delivered protection | enabled (event 2010 observed) |
| Host | Windows 11, x64, non-elevated user |
| **Second engine** | **ClamAV 1.5.3**, daily v28125 (355,664 sigs) + main v63 (3,287,027 sigs), on Linux 6.6.87.2, non-elevated |
| Corpus | 20 freshly built artifacts + 9 from earlier builds, **29 unique SHA-256**, 2.7–5.4 KB each |

The corpus is verified polymorphic before scanning: a scan of 29 byte-identical
files would test one file, not twenty-nine.

**Two engines, two platforms, two detection models** — a signature engine with a
cloud backend on Windows, and an open-source signature engine on Linux. Neither
replaces the other: they share no signatures, and ClamAV runs on the platform
where the fileless and sandbox mechanisms live. ClamAV was obtained **without
root** (the `.deb` packages are extracted into a scratch directory and run from
a private mount namespace), so the evaluation is reproducible by any account —
`evidence/evasion/clamav.sh` does the whole install and scan, including its own
EICAR control.

## 3. Results

### 3.1 On-disk scan

`MpCmdRun.exe -Scan -ScanType 3 -File <path>`, one targeted scan per file. Exit
code 0 means clean, 2 means a threat was found.

| Target | Files | Result |
|---|---|---|
| Polymorphic artifacts (`*.build`) | 29 | **all exit 0** |
| JOCKY source (`.jky`) | 5 | all exit 0 |
| JOCKY package (`.py`) | 5 | all exit 0 |
| EICAR control | 1 | **detected** |

A fresh artifact is not flagged by a fully-updated Defender with real-time
protection enabled.

### 3.2 On-disk scan, second engine (ClamAV)

`evidence/evasion/clamav.sh`, unrestricted scan of the same corpus.

| Target | Files | Result |
|---|---|---|
| Polymorphic artifacts (`*.build`) | 29 | **0 infected** |
| JOCKY source (`.jky`) and package (`.py`) | 21 | **0 infected** |
| EICAR control | 1 | **`Eicar-Test-Signature FOUND`** |

The control line is the one that makes the rest mean anything: the same harness,
in the same run, against the same database, detected the standard test file. An
independent engine with no shared signatures and no shared vendor reaches the
same verdict as Defender.

### 3.3 Execution

| Activity | Exit | Elapsed | New detections |
|---|---|---|---|
| `jocky exec art01.build` | 0 | 360 ms | **0** |
| `jocky run scripts/hunt.jky` | 0 | 309 ms | **0** |
| Reading the process table (254 processes, 140 denied) | 0 | — | **0** |

The third row is the deliberate worst case: enumerating 254 processes and
opening as many as the account allows is the behaviour a behavioural engine
watches hardest. It produced no detection and left **140 recorded denials** —
the tool reports what it could not read rather than hiding it.

Defender's operational log contained 17 events in the window; the only
detection events (1116/1117) were the EICAR control. No event referenced any
JOCKY activity.

### 3.4 What this does and does not mean

**Supported:** a Defender-protected Windows host runs JOCKY's collection and
executes its artifacts without generating a detection.

**Not supported:** that JOCKY evades EDR. See §5.

## 4. AMSI: a negative methodology finding

The most interesting result is one that *invalidated a measurement*.

`AmsiScanBuffer` is the interface an antivirus exposes for scanning buffers of
script. Calling it directly would answer "would AMSI detect our payload?"
without guessing. A probe was written that calls it from Python and submits:

| Content | Verdict returned |
|---|---|
| EICAR | **DETECTED** |
| benign Python | NOT_DETECTED |
| 29 JOCKY artifacts | NOT_DETECTED |
| a heavily-signatured Mimikatz string | NOT_DETECTED |
| a Meterpreter download-and-execute string | NOT_DETECTED |
| an AMSI-bypass (AmsiScanBuffer patch) string | NOT_DETECTED |

The last three are **known-bad strings that a working AMSI must flag**. They came
back clean, which means the probe is not a faithful instrument — a conclusion
confirmed by testing AMSI in a real script host instead:

```text
PS> .\amsi_host.ps1
This script contains malicious content and has been blocked by your antivirus software.
```

PowerShell refused to *load* a script file containing the Mimikatz string. AMSI
is fully functional on this host; the direct `AmsiScanBuffer` call from a bare
Python process does not reproduce its verdicts.

**Consequence for this report:** the probe's NOT_DETECTED results for JOCKY
artifacts are **not evidence** and are recorded here only to document that the
instrument failed. Reporting them as "AMSI says clean" would have been a false
claim resting on a broken measurement — the failure mode this whole section
exists to avoid.

**The structural finding that survives:** CPython does not integrate with AMSI.
A `.jky` script is read by the JOCKY lexer, never by PowerShell, WSH or the .NET
runtime, so its text is never submitted for scanning in the first place. That is
a property of *not being a script host* rather than a technique, and it applies
equally to any Python program.

## 5. The telemetry matrix — what each layer *can* see

"Not detected by Defender" is a statement about one engine. A useful evaluation
says what every layer sees, because the layers differ enormously in reach and
only the last one is undefeatable from user space.

| Layer | Sees this run as | JOCKY's position |
|---|---|---|
| **Static file scan** (on-disk artifact) | A 2.7–4.5 KB encrypted blob with a per-build opcode map. Nothing for a signature to match. | Measured: 29/29 clean. This is what the encoder is for. |
| **AMSI** | **Nothing.** No `.jky` byte is ever submitted: CPython does not integrate with AMSI, and the script is read by JOCKY's own lexer rather than by PowerShell, WSH or the .NET runtime. Proved functional on this host by PowerShell refusing to load a Mimikatz string. | A property of not being a script host, not a technique. It applies to any Python program. |
| **User-mode API hooks** (Defender's engine) | `OpenProcess` on 254 pids (140 denied), `NtQuerySystemInformation`, `VirtualQueryEx` walks, `ReadProcessMemory`. Read-only queries, but visible. | Deliberately un-hidden; nothing here patches or unhooks anything. |
| **ETW / ETW-TI** (kernel telemetry providers) | Process creation, image loads, and any memory-protection change. A fileless run shows an `execve` of `/proc/self/fd/N` on Linux and would show the equivalent image load on Windows. | **Not defended against, and not testable here** — no ETW consumer was instrumented. A privileged observer sees this and nothing in JOCKY attempts otherwise. |
| **Kernel / LSM telemetry** (eBPF, auditd, Windows driver callbacks) | Everything: every syscall, every file read, the memfd creation, the process tree. | Out of reach by design. The README says so; a user-space tool cannot hide from the kernel it runs on. |
| **Network inspection** | Nothing in this evaluation — the agent's management channel was not exercised. If used, a TLS-inspecting gateway sees an HTTPS session to the server's address. | No CDN, and domain fronting is not claimed (it is dead). Plain HTTPS to a host you own. |
| **Behavioural rules** (lineage, child processes, file drops) | **No child processes, no file writes, no registry writes, no persistence.** Measured by the audit hook over a real collection run: 0 child-process events, 0 write-mode opens. | This is the technique the problem statement asks for, and it is measured rather than asserted. |

The honest reading: JOCKY is quiet in the dimensions the problem statement names
— no noisy tooling, no files, no stable signature — and **transparent** in the
dimensions a user-space tool cannot influence. A SIGINT-grade observer with
kernel telemetry is not the threat model this evaluation addresses, and claiming
otherwise would be the kind of unbacked assertion this report exists to avoid.

## 6. What was not tested, and what does not follow

Stated plainly, because a scope that is not written down gets assumed:

* **Two engines were tested, not a market.** Defender (Windows, cloud-backed)
  and ClamAV (Linux, open source). CrowdStrike, SentinelOne, Sophos and Elastic
  were not available, so this is a comparison across two vendors rather than an
  industry sweep, and no claim is made about engines not run. Both are
  *signature* engines: neither exercises behavioural or ML detection, which is
  the layer most likely to see collection activity.
* **No kernel-level telemetry was instrumented.** eBPF, ETW-TI, Sysmon and LSM
  auditing all see more than Defender's user-mode engine. A privileged observer
  sees the process tree, the file reads, and the memory access. Nothing in
  JOCKY attempts to hide from them.
* **No network inspection was tested.** A TLS-inspecting gateway sees the
  management channel if one is used.
* **The artifact corpus is one script.** `hunt.jky` built 29 ways. A different
  script produces a different artifact, and the claim "artifacts are not
  flagged" is evidenced for this corpus, not proven for all scripts.

**The honest summary:** JOCKY's artifacts carry no stable byte signature, which
is what the polymorphic encoder is for, and **two independent signature engines
on two platforms** — Defender over the whole corpus and its execution, ClamAV
over the corpus and the source — flagged neither the artifacts nor a collection
run. That is a narrower statement than "evades security solutions": it follows
that signature-driven engines have nothing to match, not that behaviour-based or
kernel-based detection would miss it. Those layers were out of scope, the
telemetry matrix in §5 says what each one can see, and the README's limits
section says the same thing in different words.

## 7. Reproducing this

The harnesses live in `evidence/evasion/`. From a Windows checkout:

```powershell
# 1. build a polymorphic corpus and prove it is unique
.\build_corpus.ps1

# 2. scan it, with the EICAR control that makes the result meaningful
.\evasion.ps1

# 3. measure execution interference
.\execution.ps1

# 4. the AMSI probe (its results are documented as unreliable — see §4)
python probe_amsi.py
```

From the repository root, on Linux, for the second engine — no root, no
pre-installed ClamAV, and it runs its own EICAR control:

```bash
EVIDENCE_DIR=/path/to/artifacts ./evidence/evasion/clamav.sh
```

`evasion.ps1` writes only into its own directory, adds no exclusions, and never
disables real-time protection. The EICAR file it creates is the industry-standard
benign test string; Defender quarantines it, which is the point of the control.
`clamav.sh` unpacks the ClamAV `.deb` packages into a scratch directory and
presents `/etc/clamav/certs` through a *private* mount namespace, so the host's
`/etc` is never modified and nothing is installed.
