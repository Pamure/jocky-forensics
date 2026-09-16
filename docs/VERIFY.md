# Five manual tests

Each test checks one claim, takes under two minutes, and has a pass condition
you can judge yourself. The expected outputs below were measured on **Windows 11
(Python 3.13, non-elevated)** and on **Linux (kernel 6.6)**; your numbers will
differ in the counts, never in the shape.

Run these from the checkout, after `venv\Scripts\pip install -e .` (Windows) or
`./venv/bin/pip install -e .` (Linux).

All five are **read-only**. Nothing here writes to the registry, loads a driver,
changes a service, or modifies another process.

---

## Test 1 — the language runs and collects real host state

**Claim:** a purpose-made language executes forensic scripts against the live
host, with no external binaries involved.

```bat
venv\Scripts\jocky run scripts\quickstart.jky
```

**Pass condition:** exit code 0, and the output contains a `host=` line naming
your OS, plus a `quickstart complete:` line.

Measured on Windows:

```text
host=Windows release=11 arch=16 cpus
visible processes: 50
sockets=142 listeners=48
kernel=Windows release=11 machine=AMD64 uptime=23505
captured uid=0
quickstart complete: 0 finding(s) emitted
```

That output came from `ctypes` calls into `kernel32`/`ntdll`/`iphlpapi` — no
`tasklist`, `netstat`, `wmic` or PowerShell was spawned. Test 2 proves that.

---

## Test 2 — the collection is real, cross-checked against Windows itself

**Claim:** JOCKY's numbers describe the same machine Windows describes.

In one terminal:

```bat
venv\Scripts\jocky run scripts\inventory.jky --json
```

In another (or after), ask Windows directly:

```powershell
(Get-Process).Count
```

**Pass condition:** the process counts agree closely. Measured: **JOCKY 256,
`Get-Process` 255** — a difference of one, from the two counts being taken a
moment apart.

The other three numbers differ *by design*, and knowing why is the point:

| Measure | JOCKY | Windows native | Why they differ |
|---|---|---|---|
| processes | 256 | 255 (`Get-Process`) | same set, sampled a moment apart |
| sockets | 123 | 104 (`Get-NetTCPConnection`) | JOCKY includes UDP (25 + 11 v6); the cmdlet is TCP-only |
| listeners | 48 | 41 (`-State Listen`) | MIB table vs the cmdlet's derived state |
| drivers | 244 | 461 (`Win32_SystemDriver`) | JOCKY lists **loaded** modules; CIM lists **installed** drivers, including stopped ones |

Breakdown on the Windows test host, straight from JOCKY:

```json
{"by_proto": {"tcp": 66, "tcp6": 21, "udp": 25, "udp6": 11}, "total": 123}
{"listeners_by_proto": {"tcp": 31, "tcp6": 17}, "listeners_total": 48}
```

---

## Test 3 — polymorphism: unique bytes, identical behaviour

**Claim:** every build of one script produces different bytes, and the rebuilt
artifact still does the same job. Uniqueness without equivalence is worthless,
so both halves are checked.

```bat
venv\Scripts\jocky build scripts\hunt.jky -o hunt.build --repeat 5 --json
venv\Scripts\jocky exec hunt.build --json
```

**Pass condition:** `"unique_hashes": 5` out of `"builds": 5`, a written
`"path"`, and the `exec` exits 0 with the same findings as a source run.

Measured on Windows:

```json
  "builds": 5,
  "unique_hashes": 5,
  "path": "hunt.build"
```

Why it matters: a signature written against yesterday's artifact matches
nothing today, while the operator's script is byte-for-byte the same logic.
`jocky/ci.py` measures the same property with an equivalence check attached —
that is Test 5.

---

## Test 4 — kernel-driver integrity (BYOVD)

**Claim:** the tool reports the state a driver-abuse technique leaves behind,
and is honest about what it cannot see.

```bat
venv\Scripts\jocky run scripts\solutions\07_byovd_kernel_integrity.jky
```

**Pass condition:** exit 0, a `kernel_taint_state` line, a `module_inventory`
line with your driver count, and — on Windows — `"applicable": false` on the
taint line.

Measured on Windows:

```json
{"kind": "kernel_taint_state", "applicable": false, "tainted": false, ...}
{"kind": "module_inventory", "count": 244, "worst_severity": "info", ...}
```

`applicable: false` is the honest answer: Windows publishes no kernel taint
bits, and a script that read `value != 0` naively would report a clean host as
tainted (`nil != 0` is true — that bug was found by running this on Windows).
The run also emits a `partial_visibility` finding naming the five checks that do
not apply, with the note that their absence must **not** be read as a clean
result.

The three `dump_*.sys` findings at `info` are correct and expected: Windows
loads its crash-dump stack drivers into a reserved region at boot, so the image
is resident while absent from the filesystem. They are graded `info` with a "no
action" recommendation so the check keeps its signal for a driver that is
*genuinely* gone.

---

## Test 5 — the CI gate, at the scale CI runs it

**Claim:** the polymorphic pipeline can gate every commit: 256 builds, no hash
collisions, and every sampled rebuild semantically identical to the source.

```bat
venv\Scripts\jocky ci --script scripts\hunt.jky --count 256 --sample 8
```

**Pass condition:** exit code 0 and a `PASS` verdict.

Measured on Windows:

```text
polymorphic build gate: PASS — all builds unique and the sampled artifacts are equivalent to the source
  builds        256
  unique hashes 256
  size range    2617–3095 bytes
  build rate    344/s
  equivalence   8 sampled, 0 mismatch(es)
```

To see it *fail*, point it at a broken script and confirm it exits non-zero:

```bat
echo let x = ( > broken.jky
venv\Scripts\jocky ci --script broken.jky --count 4
echo %ERRORLEVEL%
```

A gate that cannot fail is not a gate; this one reports the reason and exits 1.

---

## Bonus — the management console

The console is pillar 4 of the problem statement, but it needs a TLS certificate
and Windows ships without `openssl` on `PATH`, so `jocky serve` cannot generate
its own. Supply a pair:

```powershell
$cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\CurrentUser\My"
$pwd = ConvertTo-SecureString -String "jocky" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath jocky.pfx -Password $pwd
```

Then start the server with `--cert`/`--key` pointing at a PEM pair (or use a
Linux host, where `jocky serve` generates one itself), open
`https://localhost:8443/`, and paste the token from the banner.

**Pass condition:** the console loads, shows the fleet and findings panels, and
a job you submit from the form appears as a finding after an agent polls:

```bat
venv\Scripts\jocky agent --server https://localhost:8443 --token <TOKEN> --once
```

---

## What is *not* testable on Windows

Two mechanisms are Linux-only, and `jocky doctor` says so rather than failing
silently:

```bat
venv\Scripts\jocky doctor
```

Measured on Windows:

```text
ready: 7 ok, 2 warning(s), 0 failure(s), 4 not applicable on this platform
```

The four `n/a` checks are `memfd_create`, `fileless end-to-end`, `direct
syscalls` and `sandbox (Landlock)`. The two warnings are genuine and
actionable: no `geteuid` (run elevated to read every process) and no `openssl`.

Run `jocky doctor` on Linux and the same four checks report real results — that
is the cross-platform contract, and
[the capability matrix](INSTALL.md#6-platform-capability-matrix) states it in
full.
