# Live response & volatile-evidence collection (Linux): JOCKY's fit and gaps

## Scope
2024–2026 Linux live-response practice — volatility ordering, ISO/IEC 27037, memory acquisition (LiME/AVML/LEMON/Volatility 3), imaging (dc3dd, Guymager), custody tooling, the "least invasive" turn — against JOCKY's zero-subprocess `/proc`-only runtime.

## Findings
1. **No RAM acquisition — the tier-1 class.** Nothing reads `/proc/<pid>/mem`, `/proc/kcore`, `/dev/mem` or `process_vm_readv` (whole-tree grep of `/proc` literals); the detector only advises it (`jocky/rt/detect.py:110`). RFC 3227 §2.1 puts memory first; LEMON exists (2025-12-05) because LiME/AVML fail under Secure Boot + Kernel Lockdown. **Impact:** payload bytes and keys die with the process.
2. **RFC 3227 network-tier artefacts absent.** netfs reads only tcp/tcp6/udp/udp6/raw/unix (`jocky/rt/netfs.py:115-119`): no ARP cache, conntrack, `/proc/kmsg`, `/proc/locks`, `/proc/<pid>/syscall|stack|wchan`, `boot_id`. **Impact:** no volatile topology tier.
3. **Container/netns blindness.** `/proc/net/*` is the reader's netns; only `/proc/1/cgroup` is read (`jocky/rt/sysinfo.py:43`). Socket→PID attribution via inodes (`jocky/rt/procfs.py:158`) never matches other-netns sockets. **Impact:** containerised C2 invisible.
4. **Permission denial looks clean.** `read_status`/`read_environ`/`read_fds` swallow `OSError` (`jocky/rt/procfs.py:126-127,148-163`); triage counts *visible* PIDs (`jocky/rt/detect.py:345`). Under `hidepid`/`ptrace_scope`/non-root the output equals a quiet host. **Impact:** silent false negatives.
5. **`/proc`-only collection is rootkit-fungible.** The sole cross-check, `/proc/modules` vs loadable `/sys/module` (`detect.py:272`), is kernel-mediated too. **Impact:** a procfs-hooking LKM wins.
6. **Nothing hashed at acquisition — findings uncertifiable.** Results carry metrics only (`jocky/agent/client.py:290-300`), timestamped by the *server* (`jocky/agent/server.py:386-394`); only post-hoc findings/artifact hashes exist (`jocky/evidence.py:92-94,153`). SWGDE 06-F-001-2.0 §8/§9 (2026-06-17 draft) requires acquisition *and* verification hashes; BSA §63(4) (2024-07-01) requires a hash value. **Impact:** output cannot be certified.
7. **TLS verification off, unreachable from CLI.** `insecure: bool = True` (`client.py:119,309`) forces `CERT_NONE` (`client.py:135-139`); `jocky agent` has no flag (`jocky/cli.py:228-235`). **Impact:** deployed agents accept a MITM rewriting evidence.
8. **Findings are self-asserted and replayable.** `_h_result` trusts body-supplied `agent_id`/`job_id` (`server.py:645-656`) and ignores `finish_job`'s `False` before re-inserting (`server.py:381-400`). **Impact:** any token holder forges or duplicates evidence.
9. **Results dropped; failures not retried.** Only findings persist (`server.py:654-655`); `output`, `errors`, `metrics`, `truncated` and the fileless `evidence` proof vanish; failed reports only journal (`client.py:411-416`). **Impact:** evidence loss, no custody log — Hypoxia's niche.
10. **Server tier breaks the zero-subprocess/at-rest claim.** `ensure_cert` shells out to `openssl` (`server.py:121-123`) with an unencrypted key; sqlite store and journal are plaintext (`server.py:249`, `client.py:64-74`); scans truncate silently (`jocky/rt/filefs.py:117-159`). **Impact:** `serve` on an audited host contradicts the claim.

## Concrete improvements
1. **Per-process memory capture** — read `/proc/<pid>/mem` per VMA from `/proc/<pid>/maps` via the existing raw-syscall path (`jocky/rt/raw.py`); stream LiME-format pages (network dumps are ~23× more atomic than disk). **L**; denial must be reported, not hidden.
2. **Hash-on-acquisition** — SHA-256 per batch and dump; DFXML/Hypoxia-style manifest, append-only sequenced JSONL. **M**, low risk.
3. **Transport integrity** — verify certs by default, add `--ca`/`--insecure`, per-agent HMAC signatures, reject duplicate `job_id`. **M**, low risk.
4. **Persist + retry** — store the whole result blob; spool failed reports with backoff. **M**, low risk.
5. **Coverage telemetry** — count `EACCES`/`ENOENT`, emit `scanned.denied`, warn on unprivileged/hidepid runs. **S**, low risk.
6. **Missing volatile sources** — `/proc/net/arp`, per-netns `/proc/<pid>/net/{tcp,udp}`, conntrack, `boot_id`, `/proc/<pid>/syscall|stack`; flag truncation. **M**, medium risk.
7. **Volatility handoff** — LiME-format dumps plus a profile from `/sys/kernel/btf/vmlinux` + `/proc/kallsyms` (btf2json recipe). **M**, medium risk.

## Verification approach
- Triage unprivileged with `hidepid=2`, `yama.ptrace_scope=2`: `scanned.denied` must be non-zero.
- Dump a process holding a 32-byte marker; `vol -f dump.lime linux.proc.dump` recovers it; verify with `avml convert`.
- Recompute the manifest hash after transport; one flipped byte in `evidence_json` must fail verification.
- Wrong-CA proxy must abort the agent; a replayed `/v1/jobs/result` must be rejected.

## Citations
- RFC 3227, Feb 2002 (canonical-but-dated) — volatility order, clock drift, hashing. https://www.rfc-editor.org/rfc/rfc3227.txt
- ISO/IEC 27037:2012 — baseline unchanged after 2024/2025 reviews. https://www.iso.org/standard/44381.html
- NIST SP 800-61r3, Apr 2025 — CSF 2.0, minimally disruptive response. https://csrc.nist.gov/pubs/sp/800/61/r3/final
- SWGDE 06-F-001-2.0, draft 2026-06-17 — acquisition/verification hashes, evidence encryption. https://www.swgde.org/wp-content/uploads/2026/06/2026-06-17-Best-Practices-Regarding-Data-Integrity-Within-Digital-Forensics-06-F-001-2.0.pdf
- Oliveri et al., LEMON, DFRWS EU 2026 preprint, 2025-12-05 — eBPF acquisition, atomicity, BTF profiles. https://www.eurecom.fr/publication/8522/download/sec-publi-8522.pdf
- AVML README — sources, lockdown defeat, no TLS on stream mode. https://github.com/microsoft/avml
- LiME README — LKM; digest "will overwrite additional memory". https://github.com/504ensicsLabs/LiME
- Volatility 3 — Linux symbols via dwarf2json. https://github.com/volatilityfoundation/volatility3
- Linux procfs docs — `mem` needs `PTRACE_MODE_ATTACH`; maps racy; `PROCMAP_QUERY` since 6.11; hidepid. https://docs.kernel.org/filesystems/proc.html
- dc3dd, Guymager — imaging with on-the-fly hashing. https://sourceforge.net/projects/dc3dd/ · https://sourceforge.net/projects/guymager/
- Hypoxia — manifest + append-only custody log. https://github.com/xinitd/hypoxia
- UAC — no-install collection, memory via AVML. https://tclahr.github.io/uac-docs/
