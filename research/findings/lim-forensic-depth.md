# lim-forensic-depth — missing DFIR capability audit

## Scope

JOCKY's runtime (`jocky/rt/{filefs,procfs,detect,netfs,sysinfo}.py`, `scripts/*.jky`) against a DFIR baseline (Sleuth Kit, Volatility 3, Velociraptor, plaso, YARA-X), ranked by NTRO value: artifact preservation and chronology. Only Finding 2 was executed; the rest is static reading.

## Findings

1. **Memory acquisition is absent.** Nothing reads `/proc/<pid>/mem` (procfs.py:187 = maps only) or `process_vm_readv`; the memfd check advises `dd if=/proc/<pid>/mem` (detect.py:110), contradicting README.md:15. **Impact:** payload identified, then lost at exit.
2. **No byte type; byte work is measured-unusable.** Values are str/int/float/list/dict (vm.py:80-125); only `s.bytes()`→ints (vm.py:686); no base64/hex/carve. **Measured:** 200 KB via `.bytes()`+`for` = 1,650,026 steps / 1142 ms (8.25 steps/byte) ⇒ the 50,000,000-step default (runner.py:27) buys ~6 MB per run. **Impact:** carving, content rules and ext4/MFT parsing are impossible in-language.
3. **Findings carry no event time.** `_finding()` has no timestamp (detect.py:57-66); `fs.timeline` sorts one root by mtime (filefs.py:160-166); sqlite keeps only arrival-time `created_at` (server.py:223-233). **Impact:** no super-timeline; dwell time and event order unanswerable.
4. **No log ingestion.** Zero `/var/log`, journald, auditd, syslog or wtmp references in `jockey/`/`scripts/`; only the agent's journal (client.py:48). `logged_in_users()` is tty ownership (sysinfo.py:205-219). **Impact:** pre-collection history is gone.
5. **Account auditing is one mtime.** No passwd/shadow/sudoers/group/key parsing; `authorized_keys` is mtime-scanned only (detect.py:53, 299-322). **Impact:** credential, key and sudo drift invisible.
6. **No package verification.** Zero dpkg/rpm hits; persistence advises checking "the package manifest" (detect.py:317) with nothing doing it. **Impact:** trojanised package-owned binaries look legitimate.
7. **Scheduled jobs never parsed.** Persistence is fixed-path mtime (detect.py:42-51, 299-322). **Impact:** hidden task bodies and next-fire times unknown.
8. **No block-device or image handling.** `SKIP_DIRS` excludes `/dev` (filefs.py:16,140); hashing is regular-file only (filefs.py:44); magic lacks superblock/image signatures (filefs.py:18-35). **Impact:** no disk image, no bad-sector manifest, no LUKS/image ID.
9. **No filesystem metadata parsing.** No ext4/jbd2 journal, `$MFT`, `$UsnJrnl`, `map_files` or `/proc/kcore`. **Impact:** deleted-file recovery and timestomping detection unreachable — the costliest gap.
10. **No carving, rules, containers or case format.** Rules are 9 cmdline regexes (detect.py:27-38), never content; `container()` is two markers plus a cgroup string (sysinfo.py:38-49); output is JSON lines (cli.py:26-30); no artifact table (server.py:223-233); chain-of-custody a non-goal (DESIGN.md:198).

## Concrete improvements

- **F1 · M** · risk ptrace_scope — `proc.memory_dump(pid,out)`: per-region `os.pread` of `/proc/<pid>/mem`, `process_vm_readv` fallback via `raw.syscall` (raw.py:141), sha256 sidecar, `map_files` for memfd.
- **F2 · M** · risk new VM type must survive `poly/` — native `fs.read_bytes(off,len)` handle: `find/slice/hash/to_file` plus base64/hex codecs.
- **F3 · M** · risk sqlite migration — `ts`/`host`/`source` per finding; `tl.merge` normalizes file/proc/socket/log rows; JSONL + bodyfile CSV.
- **F4 · M–L** · risk format upkeep — textual logs first (auth.log, syslog, nginx, audit.log, wtmp via `struct`); journald is LZ4+FSS binary, so parse natively or flag-gate `journalctl --output=json`.
- **F5,F6 · S–M** · risk low — `os.accounts()` (passwd/shadow/group/sudoers, uid-0 duplicates, null passwords, NOPASSWD, key options) and `os.package_verify()` (dpkg `status` + `info/*.md5sums`).
- **F7 · S–M** · risk low — cron/timer parser: crontab, `cron.d`, spool, `systemd/*.timer`, `at`; resolve next-fire, flag pipe payloads.
- **F8 · M** · risk live-device TOCTOU — `fs.image(src,out)`: `os.pread` devices in 4 MiB chunks, sha256 manifest per chunk and whole image, zero-fill bad ranges, `--allow-device` gate.
- **F9 · L** · risk parser surface — ext4 (superblock, extents, jbd2 unlink trails) then NTFS `$MFT`/`$UsnJrnl`; native, fuzz-tested.
- **F10 · M–L** · risk "YARA-subset" labelling — native Aho–Corasick plus a JOCKY rule struct over dumps; `case.zip` with `events.jsonl`, content-addressed `artifacts/`, `manifest.json`.

## Verification approach

Rerun F2: native path must scan ≥100 MB within budget, matching a Python reference's offsets. Memory: launch `jocky fileless scripts/hunt.jky`, dump that PID, assert region sha256 matches the same range read via `/proc/<pid>/map_files` and outlives the process. Timeline: merge file+log+proc sources; assert monotonic order, ts+source per row, synthetic `auth.log` line keeps its timestamp. Parsers: `tests/fixtures/` copies with one injected drift each; exactly that drift reported. Export: re-verify manifest hashes from the zip alone. Imaging: loopback `losetup` file, known digest, assert parity and coverage.

## Citations

- NIST SP 800-86 (2006): https://csrc.nist.gov/pubs/sp/800/86/final
- RFC 3227 (2004): https://www.rfc-editor.org/rfc/rfc3227
- Velociraptor 0.77.2 (2026-08-10): https://github.com/Velocidex/velociraptor/releases
- Volatility 3 (2026-04-30): https://github.com/volatilityfoundation/volatility3/releases
- Sleuth Kit 4.15.0 (2026-04-15): https://github.com/sleuthkit/sleuthkit/releases
- plaso / Timesketch (2026-07-20): https://github.com/log2timeline/plaso/releases
- YARA-X 1.20.0 (2026-08-24): https://github.com/VirusTotal/yara-x/releases
- AVML 0.20.0 (2026-07-08): https://github.com/microsoft/avml/releases
- MFTECmd 1.3.0.0: https://github.com/EricZimmerman/MFTECmd
- `process_vm_readv(2)`: https://man7.org/linux/man-pages/man2/process_vm_readv.2.html
- `dpkg --verify`: https://man7.org/linux/man-pages/man1/dpkg.1.html
- systemd journal: https://www.freedesktop.org/software/systemd/man/latest/systemd-journald.service.html
