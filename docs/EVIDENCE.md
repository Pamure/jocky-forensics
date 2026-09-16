# Evidence ledger

One entry per claim, in the problem statement's own terms. Every entry names the
command that produced it, the measured output, the control that proves the
measurement *could* have failed, and — the most important line — **what it does
not prove**.

A claim without a residual gap is not finished. A number without a command is
not evidence.

Re-run everything here with:

```bash
python3 tools/claims_audit.py -v          # every count the repository states
./venv/bin/python -m pytest tests/ -q     # behavioural suite
./venv/bin/jocky test tests/lang          # in-language assertions
for f in $(find scripts -name '*.jky'); do ./venv/bin/jocky run "$f" >/dev/null || echo "FAIL $f"; done
./venv/bin/jocky ci --script scripts/hunt.jky --count 256
```

---

## E1 — Language and compiler, Linux and Windows

**Claim:** a purpose-made language executes forensic scripts on both target
platforms.

- **Command:** `jocky run windows_e2e.jky` (Windows 11, Python 3.13, `python.exe`, non-elevated)
- **Measured:** exit 0, 8 findings, 0 errors, 3324 steps, 121.7 ms. Collected 244
  kernel drivers with distinct names, 164 sockets, 7 named interfaces, 21 routes,
  20 process rows, and its own argv.
- **Control:** the Windows numbers were cross-checked against Windows itself —
  `(Get-Process).Count` = 255 vs JOCKY's 256 in the same run. Two independent
  code paths agreeing on a count is what distinguishes real collection from a
  plausible-looking list.
- **Date / env:** 2026-09-16, Windows 11 26200, Python 3.13.14, Defender `4.18.26080.4-0`
- **Residual gap:** one Windows host, one Linux host. The language is
  platform-neutral by construction but has not been exercised on macOS, BSD or a
  different architecture.

## E2 — Polymorphic engine including control-flow alteration

**Claim:** every build produces unique bytes **and** a different control-flow
shape, with identical behaviour.

- **Command:** build 64 artifacts, decode each with `PolyEncoder.decode`, hash
  `encoder.control_flow_signature` of the *decoded* program, and compare against
  `sha256(artifact)`.
- **Measured:**
  ```
  artifacts: 64  unique sha256: 64
  distinct control-flow signatures: 64
  size: min=3108 max=4513 mean=3667      (was ~2.7 KB before the CFG transforms)
  ```
  The signature was computed on the decoded program, not on the encoder's own
  bookkeeping — the measurement is of what the VM will execute.
- **Control:** `jocky ci --count 256 --sample 8` → `PASS`, 256/256 unique,
  **0 mismatches**. Uniqueness alone would be satisfiable by emitting random
  garbage; the equivalence half re-executes artifacts and compares findings, so a
  build that changed *behaviour* would fail. Measured at 397 builds/s on Linux,
  343/s on Windows, and the artifact executes on both (Windows: 489 steps, 0
  errors). The agent that implemented the indirect jump also ran 300 fresh builds
  against a source run with 0 mismatches.
- **Indirect jump, independently verified:** 32 builds → **239 `JMPI` sites, all
  239 shaped `CONST`/`CONST`/`ADD`/`JMPI`**, none carrying an operand. The
  destination is a pool *value* produced by arithmetic, so a disassembler must
  evaluate it rather than read it — which is what "jump indirection" means, and
  what the previous iterator-based approximation did not achieve.
- **Date / env:** 2026-09-16, Linux 6.6.87.2 and Windows 11
- **Residual gap:** the signature is a branch-skeleton hash (the sequence of
  branch opcodes and their relative distances), which is a proxy for graph shape
  rather than a graph-isomorphism proof. A process that *evaluates* the artifact
  rather than disassembling it recovers the target trivially — indirection
  defeats static reading, not execution. The constant pool is per-build
  encrypted, so recovering the two halves requires decrypting them first.

## E3 — Fileless in-memory execution

**Claim:** a script can run with nothing written to disk, from a memory-backed
image.

- **Command:** `jocky fileless scripts/triage.jky`; evidence harness `jocky evidence`
- **Measured:** `/proc/<pid>/exe` = `/memfd:python3 (deleted)`, 4 memfd-backed
  mappings, **0 files created** (Python audit hook, `evidence/artifacts.json`),
  **0 child processes and 0 execve** during collection (`evidence/audit.json`).
- **Control:** JOCKY's own detector reports the fileless process **while it
  runs** (`detected: true`, `evidence/detection.json`). A tool that claims to be
  invisible and cannot see itself is claiming nothing checkable.
- **Date / env:** 2026-09-16, Linux 6.6.87.2
- **Residual gap:** **Linux only.** memfd has no Windows equivalent here, and
  `jocky doctor` reports that as not-applicable rather than as a fault. Kernel
  telemetry (eBPF, auditd, ETW-TI) still observes `memfd_create` and the
  `execve` of `/proc/self/fd/N`; nothing user-space hides those.

## E4 — BYOVD and kernel-module integrity

**Claim:** the runtime reports the state a driver-abuse technique leaves behind.

- **Command:** `jocky run scripts/solutions/07_byovd_kernel_integrity.jky` on Linux
  and Windows; `sys.vulnerable_drivers()` for the reference table.
- **Measured:**
  - Linux: 29 modules, 2 findings, both `info` — `ip_tables` (CVE-2021-22555 via
    `x_tables`, in-tree) and `tls` loaded 1374 s after boot.
  - Windows: 244 drivers with 244 distinct names, 4 findings, all `info` —
    3 crash-dump stack drivers plus one platform-coverage note.
- **Control:** a synthetic module list containing `RTCore64.sys` grades
  **critical** with "treat the load as hostile", so the detector is not merely
  returning `info` for everything. Every Linux CVE in the table was verified
  against the CISA Known Exploited Vulnerabilities feed; the Windows drivers
  against the CVE record and LOLDrivers.
- **Date / env:** 2026-09-16, Linux 6.6.87.2 and Windows 11
- **Residual gap:** **no vulnerable driver was loaded.** Loading one to validate
  the detector is the difference between studying a technique and deploying one.
  The detection path is therefore verified against synthetic module lists and a
  healthy host, not against a live BYOVD attack.

## E5 — Central management and the web console

**Claim:** jobs dispatch to remote agents and findings come back with provenance.

- **Command:** `jocky serve` → `POST /v1/jobs/submit` → `jocky agent --once` → `GET /v1/findings`
- **Measured:** job `job_8f8d24114e2e504a` submitted, executed by
  `agt_a5c02c43a0bd4f0b`, 1 finding stored with job id, agent id, severity and
  timestamp, visible through the API and the console. Console verified by driving
  **headless Chromium** against the real handler: fleet and findings panels
  rendered, a hostile agent name (`<img src=x onerror=…>`) displayed as text with
  `window.__xss` never set.
- **Control:** a wrong job kind is refused `400` with the allowed values; an
  unauthenticated request gets `401`; the 11th failure in 60 s gets `429`.
- **Date / env:** 2026-09-16, Linux 6.6.87.2
- **Residual gap:** a single agent on a single host. No multi-site deployment, no
  CDN in front (and none claimed — see the domain-fronting correction in the
  README), and the console has not been exercised against a large finding set.

## E6 — Forensic script library

**Claim:** the library is real, and every shipped script works.

- **Command:** `for f in $(find scripts -name '*.jky'); do jocky run "$f"; done`
- **Measured:** **38 scripts, 38 exit 0**, across `access/`, `antiforensics/`,
  `collection/`, `memory/`, `network/`, `persistence/`, `integrity/` and
  `solutions/` (`python3 tools/claims_audit.py -v` reports `scripts 38`, and
  `scripts/README.md` states the same number).
- **Control:** `tests/test_script_library.py` runs **every** script in CI and
  fails on any error, on any truncated run, and on a script that emits nothing
  *while also* reporting an error — so silence from a detector is allowed and a
  failure wearing silence is not. It also fails if a live document's stated count
  disagrees with the tree. The audit itself caught an inflated claim: commit
  `06c829e` states "**108 DFIR solutions**" and the tree held 15 at the time.
- **Date / env:** 2026-09-16
- **Residual gap:** 38, not 108. The commit title is wrong and remains in the log
  as a record of what was claimed; every current document, the audit and the CI
  test state 38.

## E7 — Network forensics

**Claim:** the runtime analyses offline captures, which is the half of "network
forensic analysis" a live socket table cannot reach.

- **Command:** `python3 evidence/make_capture.py` then
  `jocky run scripts/solutions/08_network_capture_analysis.jky`
- **Measured:** 47 frames parsed (`truncated: false`, `malformed_records: 0`), and
  **every planted signal recovered** — 2 long DNS names, 1 TXT query, 2
  executable downloads (`/payload.exe`, `/run.sh`), 1 TLS connection without SNI,
  1 with SNI `www.example.com`, 10 ranked conversations.
- **Control:** **known-answer.** The capture is generated by a script in this
  repository, so its contents are known exactly before parsing; the expected
  findings are enumerated above. Coverage is also fuzzed: **304,000 entry-point
  calls** over random and structurally-mutated input (file readers, packet
  decoder across 9 link types, DNS/TLS/HTTP decoders) with **0 exceptions**.
- **Real captures:** four captures from the official Wireshark test suite
  (`dhcp.pcap`, `dns_port.pcap`, `http.pcap`, `http2-data-reassembly.pcap`) were
  fetched and parsed — all decoded with **0 malformed records**, the DHCP
  handshake and the HTTP request reconstructed correctly, and a TLS ClientHello
  identified in the HTTP/2 capture. That exercise found a **real coverage gap**:
  `dns_port.pcap` is entirely DNS on ports 65282/65333 and the decoder returned
  **zero** queries, because it filtered on port 53. DNS away from port 53 is a
  documented tunnelling technique, so this was a detection hole on the one
  capture that exists to prove the case. The decoder now identifies DNS by
  content (clean parse plus at least one question), flags rows with
  `non_standard_port`, and finds 4 messages where it found 0 — with no false
  positives on the DHCP capture. Pinned by three tests, two of which assert that
  non-DNS UDP payloads are still rejected.
- **Date / env:** 2026-09-16, Linux 6.6.87.2
- **Residual gap:** the real captures are small and protocol-focused — tens of
  kilobytes, no application mix, no adversarial traffic. The DNS/TLS/HTTP
  parsers cover the common cases, not every extension.

### Live capture — implemented, refusal path measured, success path not

`pcap.live()` captures frames from an interface into the same structure the file
readers return, so every decoder accepts it unchanged.

- **Measured here:** `stop_reason="permission-denied"` with the actionable fix
  (`CAP_NET_RAW`; this host's `CapEff` is `0000000000000000` and
  `AF_PACKET/SOCK_RAW` raises `PermissionError`, measured). Off Linux it reports
  `stop_reason="unsupported"`. The capture loop itself — binding an interface,
  the count ceiling, the poll timeout, decoding each frame, the byte and
  malformed counters, and every stop reason — is exercised against a fake socket,
  including that the socket is always closed and that captured frames decode
  through `http_requests()` exactly like read ones.
- **Not measured:** the kernel actually delivering frames. That needs a
  capability this account does not have, and per the project's own rule a
  simulated layer may pre-screen but never conclude — so the success path is
  reported as **untested**, not as working.
- **Residual gap:** live capture also changes what the host does (a raw socket,
  and optionally promiscuous mode). It defaults to **not** promiscuous for that
  reason, and the capability is there for an operator who has the authority, not
  as the recommended path. Analysing an existing capture remains the primary
  mode.

## What could not be closed, and why

Two rubric gaps are blocked on privileges this environment does not grant. Both
were measured rather than assumed:

| Gap | Blocker | Evidence |
|---|---|---|
| Live-capture **success** path (E7) | no `CAP_NET_RAW` | `CapEff: 0000000000000000`; `AF_PACKET/SOCK_RAW` → `PermissionError` |
| A **second AV vendor** (E9) | no `sudo` | `sudo -n true` fails; ClamAV is installable but needs root and ~1 GB |

The second-vendor gap is the significant one, because "comparative evasion
evaluation" is deliverable 5 and one engine is one data point. Closing it needs
no code — only a privileged command:

```bash
sudo apt install -y clamav && sudo freshclam
CLAMSCAN=clamscan python3 tools/  # then re-run evidence/evasion/evasion.ps1 equivalent
```

Until that runs, E9 states one vendor and no cross-vendor claim is made. Writing
"scanned clean by multiple engines" without a second engine would be exactly the
kind of unbacked assertion this file exists to prevent.

## E8 — Documentation and test-bench report

**Claim:** every number the repository states is reproducible by a command.

- **Command:** `python3 tools/claims_audit.py -v`
- **Measured:** `scripts 38 · test functions 390 · in-language checks 535 ·
  namespaces 13 · detection checks 30 · version 1.7.0`; "no drift: every stated
  script count matches the tree". The audit is wired into CI, where a drift fails
  the build.
- **Control:** the audit was written because a claim had already drifted — it
  found the `108 DFIR solutions` title unprompted, which is what makes it a
  working detector rather than a decorative script.
- **Date / env:** 2026-09-16
- **Residual gap:** the audit checks **counts only**. Prose claims ("the fastest",
  "robust") are caught by review, not by the tool, and the drift patterns cover
  script counts rather than every number that could appear in a sentence.

## E9 — Comparative evasion evaluation

**Claim:** a current endpoint protection does not flag the artifacts or the
collection activity.

- **Command:** `evidence/evasion/build_corpus.ps1`, `evasion.ps1`, `execution.ps1`
- **Measured:** Defender `4.18.26080.4-0`, signature `1.459.226.0`, real-time
  protection **on**: 29 polymorphic artifacts scanned (`MpCmdRun -Scan`) — all
  exit 0; sources and package files — all exit 0; `jocky exec` and `jocky run`,
  plus a pass that opened **254 processes** (140 denied) — **0 new detections**.
- **Control:** **EICAR.** The same harness detected the standard test file
  (`ThreatID 2147519003`, detections 5 → 6, events 1116/1117 in Defender's
  operational log), which is what makes "not detected" a result instead of a
  broken test. A second control proved the *instrument* rather than the target:
  PowerShell refused to load a script containing a Mimikatz string, so AMSI is
  functional — which invalidated a separate `AmsiScanBuffer` probe that had
  returned NOT_DETECTED for known-malicious content, and that probe's results were
  **discarded rather than reported**.
- **Date / env:** 2026-09-16, Windows 11 26200, non-elevated
- **Residual gap:** **one vendor.** CrowdStrike, SentinelOne, Sophos, Elastic were
  not available on this host, so no cross-vendor claim is made. No kernel
  telemetry was instrumented (eBPF, ETW-TI, Sysmon and LSM auditing all see more
  than Defender's user-mode engine). No network inspection was tested. No Linux
  endpoint protection was tested — none is installed. The corpus is one script
  built 29 ways.

---

## What is deliberately not attempted

**The offensive half of pillar 3.** Process hollowing, reflective DLL injection,
API unhooking, thread execution hijacking and BYOVD *exploitation* are not
implemented. Where the problem statement names them, this project scores the line
through **detection coverage plus a stated limit** (E4, and `jocky/rt/winject.py`
for the Windows techniques) — a forensic toolkit that weaponises the techniques
it detects is not a forensic toolkit. This is a scope decision, stated here so it
is not mistaken for an oversight.
