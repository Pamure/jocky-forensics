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

## 2. Target

| | |
|---|---|
| Endpoint protection | Microsoft Defender Antivirus |
| Platform | `4.18.26080.4-0` |
| Signature version | `1.459.226.0` |
| Real-time protection | **enabled** |
| Cloud-delivered protection | enabled (event 2010 observed) |
| Host | Windows 11, x64, non-elevated user |
| Corpus | 20 freshly built artifacts + 9 from earlier builds, **29 unique SHA-256**, 2.7–3.1 KB each |

The corpus is verified polymorphic before scanning: a scan of 29 byte-identical
files would test one file, not twenty-nine.

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

### 3.2 Execution

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

### 3.3 What this does and does not mean

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

## 5. What was not tested, and what does not follow

Stated plainly, because a scope that is not written down gets assumed:

* **Only one product was tested.** Defender. CrowdStrike, SentinelOne, Sophos,
  Elastic and the rest were not available on this host, so no comparative claim
  across vendors is made. The deliverable's "comparative" dimension is therefore
  satisfied in the sense of *comparisons against controls*, not *against other
  products*.
* **No kernel-level telemetry was instrumented.** eBPF, ETW-TI, Sysmon and LSM
  auditing all see more than Defender's user-mode engine. A privileged observer
  sees the process tree, the file reads, and the memory access. Nothing in
  JOCKY attempts to hide from them.
* **No network inspection was tested.** A TLS-inspecting gateway sees the
  management channel if one is used.
* **No Linux endpoint protection was tested** — no AV, HIDS or rootkit scanner
  is installed on the development host, so nothing could be measured there. The
  equivalent Linux numbers do not exist in this report.
* **The artifact corpus is one script.** `hunt.jky` built 29 ways. A different
  script produces a different artifact, and the claim "artifacts are not
  flagged" is evidenced for this corpus, not proven for all scripts.

**The honest summary:** JOCKY's artifacts carry no stable byte signature, which
is what the polymorphic encoder is for, and a fully-updated Defender did not flag
them on disk or in execution. It does not follow that JOCKY is invisible; it
follows that a signature-driven engine has nothing to match. Behaviour-based and
kernel-based detection were out of scope for this evaluation, and the README's
limits section says the same thing in different words.

## 6. Reproducing this

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

`evasion.ps1` writes only into its own directory, adds no exclusions, and never
disables real-time protection. The EICAR file it creates is the industry-standard
benign test string; Defender quarantines it, which is the point of the control.
