# Platform coverage — what a Windows / macOS deployment would actually need

## Scope
`jocky/rt/*`, `exec/*`, `agent/*`, `lang/*`, `poly/encoder.py`, `runner.py`, `cli.py`, `evidence.py`, `docs/DESIGN.md` §7: which layers port, and the minimum viable Windows collector.

## Findings

**1. Unimportable, not merely unimplemented.** `os.sysconf` runs at import (`rt/procfs.py:18-19`), and the chain `cli.py` → `runner.py:25` → `rt/builtins.py:21` → `procfs` makes Windows fail even for `jocky build`/`exec`. `os.uname()` is Unix-only too (`rt/raw.py:256`).

**2. Portable core, verified by imports.** `lang/*` imports no `os`/`sys`/`ctypes`; `poly/encoder.py:66-75` is stdlib plus `jocky.lang`, its only platform touch `os.urandom` (506,520) and LE `struct.pack("<I")` (552-560). Language, bytecode, artifact format, polymorphism and the agent protocol all port (`agent/client.py:231` already guards `getuid`).

**3. Raw syscalls neither port nor help.** `_raw_supported()` allows only x86_64-Linux (`raw.py:64-67`); the fallback needs `libc.syscall` (`raw.py:171-180`), absent on Windows → `RuntimeError`, caught by `vm.py:281-282` as a script error. Windows has no stable syscall ABI (per-build SSN drift; j00ru's table spans Win11 to 25H2, 2026-09-15) and `raw.py:45-56` hardcodes SysV register order, the wrong x64 ABI. `direct_syscall` — a syscall instruction outside the Native API layer — is itself a shipped detection behavior (Elastic, 2024-01-09).

**4. `fileless` has no analogue.** `memfd_create` is guarded and raises (`exec/memfd.py:50-55`); execution needs `os.fork` (`memfd.py:234`) and `execve("/proc/self/fd/N")` (`memfd.py:121`). macOS lacks both `memfd_create` and `fexecve`; Windows offers only in-memory PE loading — a different threat model.

**5. No path or semantics abstraction.** Collectors interpolate `/proc/<pid>/...` (`procfs.py:66,107,134,191,242`); temp prefixes (`filefs.py:37`) and `$PATH` handling (`detect.py:285`) are POSIX constants — no `os.path.join`/`pathlib`, no mount map. SUID/world-writable (`filefs.py:207-208`) and the `/proc/modules`↔`/sys/module` diff (`detect.py:264-281`) have no NTFS or Windows meaning.

**6. Registry, services, scheduled tasks, IFEO, WMI, ETW, AMSI: absent from collector *and* detector.** Persistence is nine POSIX paths (`detect.py:44-54`). macOS is worse: no `/proc` either, so `sysctl`/`libproc` polling is the ceiling without the restricted `com.apple.developer.endpoint-security.client` entitlement (Apple, canonical).

**7. The server assumes Unix tooling:** `openssl` shelled out (`agent/server.py:121-132`), `os.chmod(key, 0o600)` (`server.py:133`) sets no ACL.

**8. Even the POSIX backend is only spot-checked.** `read_io()` opens the literal `"/proc/<pid>/io"` (`procfs.py:227`) — the pid is never substituted — so io counters are always `{}` and `info(with_io=True)` is silently empty and untested.

## Concrete improvements
- **I1 — Lazy constants + backend dispatch (S, low).** `procfs.py:18-19` → per-use helper defaulting to `100`/`4096`; `rt/__init__.py` dispatches on `sys.platform`; `builtins` registers stubs returning `{"unsupported_platform": true}` findings — no import error, no silent empty (the `detect.py:333` contract).
- **I2 — Backend interface (M, medium).** `rt/base.py` with today's public names; `rt/posix/` moved, `rt/win/` new; `builtins.py` untouched. Freeze signatures first.
- **I3 — Minimum viable Windows collector (L, medium).** Pure `ctypes`, no PowerShell (AMSI + EID 4104) or WMI. Processes: `CreateToolhelp32Snapshot` + `Process32FirstW/NextW` + `QueryFullProcessImageNameW`, cmdline via `NtQueryInformationProcess(ProcessCommandLineInformation)`. Sockets: `GetExtendedTcpTable`/`GetExtendedUdpTable` with `TCP_TABLE_OWNER_PID_ALL` — one call yields the owning PID, replacing the `/proc/*/fd` sweep (`procfs.py:347`). Files/ADS: `GetFileAttributesExW`/`FindFirstStreamW`; system: `RtlGetVersion`/`GlobalMemoryStatusEx`/`EnumDeviceDrivers`. Detection: unbacked RX via `VirtualQueryEx` plus module-list diff, autoruns, services outside `%SystemRoot%`. PPL targets refuse image/cmdline queries: degrade to pid+name, never fabricate.
- **I4 — Registry persistence table (S, low)** beside `detect.py:44`, reusing the fail-soft wrapper (`detect.py:333`).
- **I5 — Detect, don't port (M, low):** the Windows memfd analogue is backing-file/call-stack inspection (Elastic, 2024-01-09).
- **I6 — Drop `openssl` (S, low):** try `ssl`, else fail explicitly with a documented pre-generated-cert path; never hand-roll X.509.
- **I7 — Document the boundary (S, low):** README/DESIGN §7 name only Windows — add macOS, and say `rt/`, `exec/` and `evidence.py` stay POSIX.

## Verification approach
- **Import gate:** monkeypatch away `os.sysconf`/`os.uname`, import `jocky.cli`, run `jocky build` then `jocky exec`; fails today at `procfs.py:18`, passes after I1, findings hash equal to a native run.
- **Backend conformance:** one parametrized test over registered backends calling `list_processes`/`connections`/`triage`, asserting key shape, severities, non-zero `scanned` counters, plus a `read_io(pid)` case failing on today's code (`procfs.py:227`).
- **Windows checks:** on a VM plant an unsigned unbacked-RX image and a Run-key autorun; assert both findings, mirroring `tests/test_fileless_detection.py`.
- **Non-regression:** keep the audit-hook assertion of zero child processes (`evidence.py:58-63`).

## Citations
- Elastic Security Labs, *Doubling Down: Detecting In-Memory Threats with Kernel ETW Call Stacks*, 2024-01-09 — https://www.elastic.co/security-labs/threat-command/doubling-down-etw-callstacks
- j00ru, *Windows System Call Tables* (NT → Win11 25H2), accessed 2026-09-15 — https://github.com/j00ru/windows-syscalls
- Apple, *Endpoint Security* (canonical, undated) — https://developer.apple.com/documentation/endpointsecurity
- CPython docs, `os.sysconf`/`os.uname` (Unix-only) — https://docs.python.org/3/library/os.html#os.sysconf
- Microsoft Learn, *GetExtendedTcpTable*, updated 2024-02-22 — https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
