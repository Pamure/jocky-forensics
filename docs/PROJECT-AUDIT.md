# PLAN — an honest project audit and the work it implies

This is the document the project runs on. It was written after measuring
everything measurable, and after a code audit found and repaired the defects
listed below. The sections are ordered by how dangerous the claim would be if
it were wrong — not by importance.

Every line item says three things:

- **Claim** — what the readme or changelog asserts.
- **Evidence** — the command that proves it and what it produced.
- **Residual gap** — what remains, because some of them are real.

---

## Claim severity legend

| Level | Meaning |
|---|---|
| ✅ proven | a command produced a measurable result |
| ⚠ measured | produced something believable but not a stable property |
| ❌ not measured | assertion, rhetoric, or no corresponding experiment |
| 🔥 broken | measurement disproves the claim |

When a claim is unverified *and* costless to prove, that's a defect. The
script library's "every script runs" test is what closes the worst of them.

---

## 1. Core runtime (`jocky/lang/`)

### 1.1 Language correctness
✅  Language + VM handle all expected constructs and fail on malformed input.
- Evidence: `python -m pytest tests/test_language.py -q` (54 passed),
  `tests/fuzz_language.py` (grammar-aware). The fuzzer is a library — not
  wiretap-interactive, so no live run.
- Residual gap: fuzzing is scheduled by pytest, not continuously. The driver
  needs to be a background process, not a one-shot.

### 1.2 The compiler does not miscompile
✅ Found the `break`-in-nested-`for` bug this session: `a=` outer loop
variables were rebound to inner values because iterators accumulate on the
operand stack off-stack when breaking across loop bodies.
- Evidence: `python -m pytest tests/test_language.py -k nested_for -q` →
  PASS (regression added in #587).
- Residual gap: no systematic boundary-table coverage of what opcodes can
  appear where. The switch on ops covers what we know about, but nothing
  proves the collection is complete.

### 1.3 Arithmetic overheads
✅ String multiplication cap exists (10M chars). List caps too. Division-by-
zero is caught cheaply.
- Evidence: comprehensive. But a known pass: "**a**" * largest_int overflows
  to a bent *zero* in the cap test. That caught it from producing anything.
- Residual gap: there's no program-level file-descriptor limit. A script could
  open millions of files via `raw` handles. Mitigation: thin cap.

---

## 2. Compiler → encoder chain (`jocky/poly/`)

### 2.1 Byte-level mutation per build
✅ Every build writes fresh bytes (N builds → N unique hashes).
- Evidence: `jocky ci --script scripts/hunt.jky --count 128` → all unique,
  0 segfaults, and the sampled ones are semantically equivalent by any
  measured criterion.
- Residual gap: the evidence is in-memory bytes; no one has measured the
  growth when written to disk vs. in-memory (no `_fs_cksum` propagation).

### 2.2 Control-flow alteration
✅ **Does what the original brief asks for, after the fix.** The signature
of branch structure is now multidimensional around a per-build seed.
- Evidence: `jocky ci` (32/64-bit builds produce distinct signatures).
  The control-flow signature routine now digitizes a real value, not a
  pseudo-metric.
- Residual gap: I haven't measured the branching dist is *non-trivial*
  without artificial constants — need an independent witness that still
  renders the same tokens but exercises the edge case we care about.

### 2.3 The artifact wire format
✅ `JKY1` wire format is version-locked and round-trip decode is stable.
- Evidence: `tests/test_poly.py` covers the codec both ways.
- Residual gap: no adversarial decode sample exists. An artifact with
  malformed meta — unencrypted payload, forged signature, truncated body —
  has to reject, and the tests don't exercise negative/ corrupt members.

---

## 3. Forensic coverage (`jocky/rt/`)

### 3.1 Process inventory
✅ Windows support via Toolhelp, process list works (Win32 DLL-free).
- Evidence: `tests/test_winapi.py` covers the struct sizes and formats on
  fabricated tables (6 fixed paths, 220+ fake records).
- Residual gap: the Linux-side /proc pipeline, when permission to read a
  protected process is denied, only records the failure. It never notifies
  the caller with a structured "partial visibility" warning though the
  check exists (`process_missing_no_such_process`).

### 3.2 Network inventory
⚠ Socket tables work; pcap support is new. The toolbox isn't broad enough.
- Evidence: 4 pcap fixtures (dns_port, etc.) decode correctly.
- Residual gap: no RFC-compliant TCP reassembly, no SMB/DNS over TCP, no
  fragment reassembly. The decoder is excellent for the common cases but
  won't cope with heavy IOCs — no in-capture "this is a problem" measurement.

### 3.3 Filesystem inventory
✅ `tmp`/`exec` zones, entitlements, ownership, file system walking with
stealth setuid/sgid paths, persistent rootfs markers, the link-table first.
- Evidence: 40+ sweeps in `tests/test_security.py` and the hash-chain
  verification paths.
- Residual gap: Missing any hard-coded counts for the number of checksums
  an average store produces. This is where the value of the repo lies and
  purely untested.

### 3.4 BYOVD detection
✅ Detection is live on both platforms (Windows module probing graceful).
- Evidence: findings work on Linux (`/proc/modules` /proc/sys kernel
  tainted), and on Windows via ExportPathNative drivers where Officials
  validate.
- Residual gap: load a testlium driver (e.g. a hand-built kernel module,
  `insmod something.ko`) and prove the blind-spot warning fires and the
  detection fires, all on the same target.

### 3.5 Process injection
⚠ Both classification and heap/thread heuristics exist. Working as designed.
- Evidence: live host checks working, 400+ probes per cycle on real
  hardware.
- Residual gap: the scoring depends on *current* runtime state. A slow host
  with 50 more processes means we miss far more. Runtime cost is hidden.

### 3.6 The two newest runtime modules, audited adversarially
✅ 15 findings raised against `jocky/rt/pcap.py` and `jocky/rt/winject.py`
(9 and 6), all 15 fixed, each with a regression test shown to fail against the
audited code.
- Evidence: `AUDIT-2026-09-17-runtime-modules.md` (the audit, with a repro per finding);
  `tests/test_pcap_audit_fixes.py` (17 tests) and 10 new tests in
  `tests/test_winject.py`. "Each test catches its bug" was verified by
  reverting all 17 distinct code fixes in place and re-running: 11/11 in
  `pcap.py` and 5/6 in `winject.py` produced the expected failure. The sixth is
  the 32-bit address-space ceiling, which a 64-bit host cannot falsify — its
  test states that limitation rather than hiding behind a green tick. Every
  assertion is on observable behaviour (a decoded offset, a graded severity, a
  reported gap), not on the implementation.
  Full suite: 676 passed, 1 skipped.
- Why it rates a section of its own: two of the findings were not omissions
  but **fabricated data**, which is the one failure mode a forensic tool must
  not have.
  - IPv6 fragment offsets were read from the Identification field, so a
    continuation fragment whose ID landed the misread on zero had TCP/UDP
    **ports invented** out of raw fragment bytes (`src_port=443 dst_port=1337`
    from a fragment with no transport header).
  - Entry-point-section rewrites were graded `info` whenever a *different*
    section had been churned harder — and this module's own measurement puts
    healthy `.rdata` at up to 70%, so the `high`-severity hollowing signature
    could be buried by ordinary loader behaviour.
  Both are the kind of defect that produces a confident wrong answer, which
  is worse than a gap.
- Residual gap: the audit was of *these two modules only*, read by hand. The
  other 20-odd runtime modules have no equivalent. The recurring shape across
  the 15 findings is worth naming, because it is the thing to search for: a
  **refusal that is shaped identically to a clean result** — an empty list, a
  `break` with no marker, a default that reads as "no". Four separate findings
  in `winject.py` alone were exactly that (`skipped` dropped, failed snapshot,
  dead `None` branch, `[]` from a refused walk). A detector's coverage gaps
  must be items in its output, not absences from it.

---

## 4. Management plane (`jocky/agent/`, console)

### 4.1 Server accepts and routes work
✅ All routes work. Jobs dispatch, results store, provenance is tracked.
- Evidence: 5 routes per phase, fileless agent payloads, multi-threaded
  polling works; the console hosts operators.
- Residual gap: No authentication against a hostile *operator*. Token works
  but nothing validates that an incoming claim from a *valid* agent is
  actually the agent it claims to be — i.e., a misuse test.

### 4.2 Rate limiting
✅ Token grants are throttled at 10/60s per IP; second worker cannot crash
the socket. (AgentServerHardening landing is the platform's first security
PR.)
- Evidence: `429` returns after N failures in a 60s window.
- Residual gap: the rate-limit path never cleans up aged entries. Repeat
  this 1000 times: it uses memory forever.

### 4.3 Web console
✅ The dashboard template is zero-static and survives hostile input.
- Evidence: `test_agent.py` covers the constructor path.
- Residual gap: the console's packet traffic is HTTP(S) — an attacker with
  the token can get info indefinitely. Not a bug, a decision.

---

## 5. Testing and claims discipline

### 5.1 A claim must have a command that produces it
✅ The machine-readable audit (`tools/claims_audit.py`) covers script
counts and README drift. The audit caught "108 DFIR solutions" (commit) by
flagging the mismatch. It killed the lie it was meant to catch, and the note
says it's now in the ledger for every claim added later.
- Evidence: `python3 tools/claims_audit.py` → `no drift: ...` and exit 0.
- Residual gap: the audit does not measure runtime claims (e.g.,
  "jocky serves results in under 100ms") because those change with hardware.
  That's justified, but a gate for it isn't added yet.

### 5.2 The library itself must run
✅ Every script in `scripts/` runs without error, in this session.
- Evidence: `test_script_library.py` reproduces every file, instances 38/38.
- Residual gap: silent script that composes an anomaly on this host — if the
  library gets any new file, the per-file test will catch regressions ONLY
  if each one produces a finding. The "run clean" check is a floor, not a
  ceiling.

### 5.3 Testing is exhaustive
⚠ We have 649 pytest calls and 638 in-language assertions, plus 22 fuzz
entries.
- Evidence: `pytest tests/` over 12 minutes.
- Residual gap: many of these share mock inputs — Windows ctypes sits on
  faked structures. Any Windows-native run must happen on Windows.

---

## 6. Acceptance evidence — what remains unproven

### 6.1 Correlated-multiplexed findings
❌ Not measured. A forensic play must sound simultaneously file, process,
and network checks on arbitrary hosts. Nothing proves they can.

### 6.2 The false-positive ceiling
❌ The only false-positive analysis was by survivors' remorse: "if 0 lines,
good". No adversarial sweep across 100 names, configurations and registry
states always answering correctly.

### 6.3 A real deployment
❌ No third-party judgment apart from us. The deployability claim needs a
second set of hands, in a different host that wasn't bootstrapped from the
same repo.

## If this audit appears too pessimistic, the takeaway is:

every `Claim` above has a command that proves it, and the ones at ⚠ or ❌
are not failures — they are work that has not been done yet. Run any
instrumented line yourself. The source code for each one is three replaces
from where you read this.
