# Audit — `jocky/rt/pcap.py` and `jocky/rt/winject.py`

Scope: the two newest runtime modules, read end to end. Every finding below
reproduces with the command shown (run from the repo root; scripts live in
`/tmp/winaudit/` on the audit host — inline here). Baseline: `pytest tests/`
green, `test_pcap.py` + `test_winject.py` green.

---

## Audit Section 1: pcap.py — protocol and container bugs

### A1: A second pcapng section inherits the previous section's interfaces
  - Symptoms: every packet of section N+1 is decoded against section N's
    interface — wrong linktype AND wrong `if_tsresol`. The output's
    `interfaces` list merges all sections as if interface IDs were global.
    Differing linktypes surface as junk decodes or `malformed`; different
    timestamp resolutions misplace every packet silently.
  - Severity: high
  - Where: `jocky/rt/pcap.py:796-802` (the `if is_section:` block never resets
    `result["interfaces"]`), with the poisoned lookup at `:858-864`.
  - Evidence: section 1 = Ethernet IDB, section 2 = LINKTYPE_RAW IDB + one
    raw IPv4 packet:
    ```
    sections: 2  interfaces: [1, 101]
    section-2 packet: linktype decoded as 1 | malformed: unsupported ethertype 0x0000
    ```
    The docstring promises "a capture concatenated from two writers … parses
    on both sides" (`read_pcapng`, :679-680) — byte order yes, interfaces no.
    Per the pcapng spec, interface numbering restarts at each Section Header
    Block; this implementation never restarts it.
  - Fix: on a new SHB, reset `result["sections"]`-scoped state:
    `result["interfaces"] = []` (or carry per-section interface tables and
    resolve EPB/PB/SPB against the current section's table).

### A2: A section block declaring `block_length` 12–15 crashes `read_pcapng`
  - Symptoms: `struct.error: unpack requires a buffer of 4 bytes` escapes —
    in the module whose contract is "malformed blocks recorded rather than
    raised". One corrupt `SHB` mid-file kills the entire read.
  - Severity: high
  - Where: `jocky/rt/pcap.py:782-788`. For sections `already = 12`, so
    `block_length - already` can be 0–3, and `rest[-4:]` is then shorter than
    the trailer `struct.unpack` demands. Non-section blocks are safe because
    the `block_length < 12` guard leaves ≥4 bytes.
  - Evidence:
    ```
    $ python repro_pcapng_shb12.py
    CRASH: error -> unpack requires a buffer of 4 bytes
      pcap.py:788, in read_pcapng — trailer = struct.unpack(endian + "I", rest[-4:])[0]
    ```
    Related, same site: section blocks of length 16–27 are silently accepted
    although the spec minimum SHB is 28 bytes, and the *first* SHB's trailing
    length is never compared to the header value (the loop checks it for
    every other block).
  - Fix: after computing `already`, require
    `block_length >= already + 4` before reading; treat anything smaller as
    malformed/counted, and apply the SHB minimum (28) inside `is_section`.

### A3: IPv6 fragment offset and M-flag are read from the Identification field
  - Symptoms: `fragment_offset` derives from packet Identification, not from
    the offset/flags word. Non-first fragments whose ID happens to land the
    misread at 0 are treated as first fragments: the fragment body is decoded
    as a transport header and bogus ports/flows are *fabricated*.
  - Severity: high
  - Where: `jocky/rt/pcap.py:440-442` — `header = _unpack("!BBHI", ...)`
    yields `(next, reserved, offset_flags, identification)`; the code reads
    `header[3]` (identification) instead of `header[2]`.
  - Evidence:
    ```
    non-first frag (real offset 800, M=1, ID=0x00AB0001):
        decoded fragment_offset=11206656  more_fragments=True
    non-first frag (real offset 1600, M=1, ID=2):
        decoded fragment_offset=0 MF=False -> src_port=443 dst_port=1337
        malformed=None   # ports invented out of fragment bytes
    ```
    The existing tests cover IPv4 fragmentation only; no test builds an IPv6
    fragment header.
  - Fix: `fragment_field = header[2]`; add a test with a nonzero ID so the
    two fields cannot be swapped undetected again.

### A4: Every SPB packet is discarded when the IDB declares `snaplen = 0`
  - Symptoms: `caplen = min(orig_len, snaplen, …)` becomes 0; each Simple
    Packet Block is decoded from an empty buffer and reported as
    `malformed: empty frame` with `incl_len: 0` — the whole capture reads as
    packet-shaped noise.
  - Severity: medium
  - Where: `jocky/rt/pcap.py:894`. Per the pcapng IDB definition, snaplen 0
    means *no limit*; the code treats it as *capture nothing*.
  - Evidence:
    ```
    SPB with snaplen=0 -> packets: 1 | incl_len: 0 | malformed: empty frame | dst_port: None
    ```
  - Fix: `effective = snaplen or caplen_candidate`, i.e. treat 0 as unlimited:
    `caplen = min(orig_len, snaplen if snaplen else orig_len, len(body) - 4)`.

### A5: `live_capture` does raise — on bind failure and on `snaplen < 0`; `snaplen=0` busy-spins
  - Symptoms: (a) binding a nonexistent interface raises `OSError ENODEV`
    straight out of the module — the `try` at :1337 has only a `finally`;
    (b) `snaplen=-1` raises `ValueError` from `recv`, which the loop's
    `except OSError` does not cover; (c) `snaplen=0` makes `recv(0)` return
    `b""` instantly, and the loop burns CPU until the deadline.
  - Severity: medium
  - Where: `jocky/rt/pcap.py:1338-1348`. The docstring (:1278-1296) promises
    failures are "reported, never raised".
  - Evidence:
    ```
    (b) bind failure         : RAISED OSError [Errno 19] No such device
    (c) snaplen=-1           : RAISED ValueError negative buffersize in recv
    (d) snaplen=0            : timeout | packets: 0 | recv() calls in 0.200s: 478107
    ```
    (CAP_NET_RAW is absent on this host, so (a) was driven at the call site
    with the exception the kernel returns; (c) uses a real socket and real
    `recv`.)
  - Fix: validate `snaplen` (reject/normalise ≤0) before opening; wrap the
    `bind` in `try/except OSError` and return `stop_reason="error"` like the
    recv path already does; treat `not frame` as a timeout-continue only when
    `snaplen > 0`.

### A6: JA3 strings include GREASE values
  - Symptoms: `ja3`/`ja3_hash` for any GREASE-bearing ClientHello (Chrome,
    Firefox — i.e. most real clients) embeds random GREASE words in the
    version/cipher/extension/curve lists. Standard JA3 strips them, so these
    hashes match nothing in threat-intel feeds — the stated use of the field.
  - Severity: medium
  - Where: `jocky/rt/pcap.py:1516-1533` (`_ja3` joins lists verbatim); the
    claim lives at `tls_client_hellos` (:1536-1543, "what threat-intel feeds
    key off").
  - Evidence:
    ```
    JA3 here   : 771,2570-4865-4866,2570-0-10,2570-29,0     # 2570 = 0x0A0A
    JA3 stripped: 771,4865-4866,0-10,29,0                    # standard form
    ```
  - Fix: filter values `(v & 0x0F0F) == 0x0A0A` from all four lists before
    joining, per the JA3 spec.

### A7: The obsolete Packet Block reports the claimed length, never the truth
  - Symptoms: `_parse_pb` sets `incl_len = caplen` straight from the block's
    claim. If the block holds fewer bytes than `caplen`, the packet is decoded
    from what exists while reporting what was claimed — and unlike the EPB
    path there is no truncation marker at all.
  - Severity: low
  - Where: `jocky/rt/pcap.py:913-916`; contrast EPB at `:870-879`, which sets
    `incl_len = len(data)` and flags `pcapng: epb data truncated`.
  - Evidence: same truncated block through both decoders:
    ```
    PB  incl_len: 60 malformed: ethernet header truncated   # 10 bytes present
    EPB incl_len: 10 malformed: ethernet header truncated   # flagged honestly
    ```
  - Fix: mirror the EPB shape — `data = body[20:20+caplen]`,
    `incl_len = len(data)`, and mark truncated when `len(data) < caplen`.

### A8: `flows()` bills live traffic by payload bytes, file traffic by wire bytes
  - Symptoms: the same flow shows 42 bytes from a capture file and 0 bytes
    from a live capture result, because only file packets carry `incl_len`
    and the fallback is `payload_len`.
  - Severity: low
  - Where: `jocky/rt/pcap.py:981-983`; live packets are built at
    `:1350-1354` without `incl_len`/`orig_len` (`bytes_read` tracks the sum
    but individual packets don't).
  - Evidence:
    ```
    flow bytes over a live packet : 0   (wire frame was 42 bytes)
    same packet from a file       : 42
    ```
  - Fix: set `decoded["incl_len"] = len(frame)` in the live loop.

### A9: A request whose headers exceed 64 KiB vanishes without a marker
  - Symptoms: the request line matches, the `\r\n\r\n` search is capped at
    `MAX_HTTP_HEADER_BYTES`, not found → `break` — the request (and the rest
    of the stream) is absent from the result, with no record of why.
  - Severity: low
  - Where: `jocky/rt/pcap.py:1682-1685`.
  - Evidence:
    ```
    request with 65670 header bytes -> []   (silently absent)
    ```
  - Fix: when the header cap bites, emit the request with a
    `headers_truncated: True` marker instead of `break`.

---

## Audit Section 2: winject.py — partial-visibility and grading holes

### A1: `unbacked_executable_threads` swallows its own `skipped` list
  - Symptoms: the detector builds a `skipped` list (`_cap_gap` rows for the
    sweep cap, plus the "module map incomplete" refusal-to-accuse rows it
    documents as load-bearing) — then calls
    `_partial_finding(..., denied)` without it. Those processes disappear:
    the sweep returns `[]`, which reads as *clean*.
  - Severity: high
  - Where: `jocky/rt/winject.py:1557` — `note = _partial_finding(
    "unbacked_executable_threads", len(targets), denied)`. Compare the other
    three detectors (:1314, :1432, :1670), which all pass `skipped`.
  - Evidence (one process, module map incomplete — the exact case the code
    comments say must be "reported instead of accusing"):
    ```
    W1 unbacked_executable_threads -> []
    -> process was skipped as 'module map incomplete' but the sweep returned EMPTY (looks clean)
    executable_private_memory with the same gap -> [('partial_visibility', 1)]
    ```
    Same input, one detector reports the gap, the other pretends it scanned.
  - Fix: `_partial_finding("unbacked_executable_threads", len(targets),
    denied, skipped)`.

### A2: Entry-point-section severity is decided by whichever *other* section is noisiest
  - Symptoms: `_hollow_finding` grades content mismatches off the single
    highest-ratio section. If `.rdata`/`.idata` out-noise the entry-point
    section — the module's own measurements say `.rdata` hits 70% on healthy
    hosts — a >5% rewrite of the entry-point section is graded
    `info`/`section_content` instead of `high`/`entry_point_content`.
  - Severity: high
  - Where: `jocky/rt/winject.py:1170-1172` (`worst = _worst_section(report)`
    selects before the entry-point test). The docstring (:1137-1140) claims
    the opposite: "an entry-point-section difference outranks the same
    difference elsewhere".
  - Evidence (6.2% of `.text` rewritten + noisy `.rdata`, vs control):
    ```
     .text   mismatched=  64/1024 (6.2%) entry_point_section=True
     .rdata  mismatched= 717/1024 (70.0%) entry_point_section=False
    graded -> info | section_content
    control (quiet .rdata) -> high | entry_point_content
    ```
  - Fix: evaluate the entry-point section *first* and independently —
    `if the entry-point section exceeds the fraction: high/entry_point_content`
    — then the worst-other-section rule for the informational class.

### A3: A failed process snapshot is a silently "clean" sweep in all four detectors
  - Symptoms: `names = {… _snapshot_processes()}`; when the snapshot fails,
    winapi returns `[]`, `_scan_targets(None, {})` targets nothing, no denial
    is recorded in the per-detector list, and the detector returns `[]` —
    the precise "clean result is not conclusive" case the module exists to
    mark. The failure lands only in winapi's global access log, which the
    findings never surface.
  - Severity: high
  - Where: `jocky/rt/winject.py:1258, :1344, :1462, :1618` (all four
    detectors share the shape).
  - Evidence:
    ```
    W5 hollowed_processes -> []
    W5 executable_private_memory -> []
    W5 modules_from_temp_paths -> []
    unbacked_executable_threads with dead process snapshot -> []
    ```
    Context: on the measured non-elevated host 140 of 254 processes were
    denied (`docs/EVIDENCE.md`), so the distinction between "nothing found"
    and "nothing seen" is the module's whole contract.
  - Fix: detect "snapshot returned empty while the host is Windows" (or have
    `_snapshot_processes` return `None` on failure) and emit the
    `partial_visibility` note in that case.

### A4: `_regions` never returns `None` — docstring and two callers disagree with the code
  - Symptoms: the docstring (:915-924) promises "`None` when the very first
    query failed — the caller reports rather than rounding down to 'no
    regions found'". The implementation always returns
    `{"regions": …, "complete": …}`; the `if walk is None:` branches in
    `executable_private_memory` (:1354) and `_private_region_lookup` (:1572)
    are dead. A first-query refusal is classified "address-space walk
    truncated" (skipped), and the recorded error is then dropped by the
    `continue` at :1362 before the tail's denied accounting.
  - Severity: medium
  - Where: `jocky/rt/winject.py:915-963`.
  - Evidence:
    ```
    W2 _regions returned: dict | docstring promises None
       value: {'regions': [], 'complete': False} | errors recorded: 1
       one pid, one failure -> denied_count = 0 skipped_count = 1
    ```
  - Fix: return `None` when `rows` is empty and the first `VirtualQueryEx`
    failed (track "first call" explicitly), or fix the docstring; either
    way, delete the dead branches or make them reachable.

### A5: The 32-bit address-space walk is always reported truncated
  - Symptoms: the walk's ceiling is the x64-only `_USER_SPACE_TOP`
    (0x7FFFFFFF0000). On a 32-bit build the user space ends at 0x7FFF0000;
    the query right above that fails, the loop breaks without `complete`,
    and `winapi._fail` adds an error — for *every* process, on the very
    build flavour the `_MEMORY_BASIC_INFORMATION32` struct exists to serve.
    One host-wide noise finding per process, plus error pollution.
  - Severity: medium
  - Where: `jocky/rt/winject.py:197, :947-962`.
  - Evidence (faithful 32-bit emulation: regions answer below 0x7FFF0000,
    refuse above):
    ```
    W4 32-bit walk over its ENTIRE user space -> complete = False | errors = 1
    ```
  - Fix: derive the ceiling from pointer size
    (`0x7FFF0000 if _POINTER_SIZE == 4 else 0x7FFFFFFF0000`), or set
    `complete = True` when a *final* query fails after at least one region
    with `state == MEM_FREE` having reached the platform top.

### A6: `_BOUND` is set before `_bind` succeeds — one missing export poisons the module
  - Symptoms: if any declared export is absent on the host, `available()`
    raises `AttributeError` out of `_bind` (the off-platform contract is
    "``available`` … ``False``"; the caller in `detect.py` does not guard
    that call), and `_BOUND` is already `True`, so every later call skips
    binding entirely and runs with undeclared prototypes (c_int restype
    truncation of 64-bit handles on the calls that do run).
  - Severity: low (requires a host missing exports that have existed since XP)
  - Where: `jocky/rt/winject.py:827-830`.
  - Evidence:
    ```
    available() RAISED: AttributeError - 'Lib' object has no attribute 'ReadProcessMemory'
    _BOUND after failure: True
    ```
  - Fix: wrap `_bind`, clear `_BOUND` on failure and report instead of
    raising; only set the flag after the last `_proto` returns.

### A7: The budget comment claims a section order the PE format does not guarantee
  - Symptoms: "the entry-point section is first in the table and is therefore
    compared first and in full" — section order is convention, not format.
    A hostile or exotic image with ≥4 MiB of earlier sections exhausts
    `_MAX_TOTAL_COMPARE` before the entry-point section, which is then
    listed in `skipped_sections` (honest), not "compared in full" (claimed).
  - Severity: low
  - Where: `jocky/rt/winject.py:202-204`.
  - Evidence: reading `_image_mismatch` (:636-742): sections are compared in
    table order against a single shared budget; nothing prioritises the
    entry-point section.
  - Fix: compare the entry-point section first (its RVA is known before the
    loop), or correct the comment.

---

## Audit Section 3: Limit enforcement — proof the caps hold

| Limit | Input driven | Observed |
|---|---|---|
| `MAX_PACKETS` (200 000) | pcap with 200 001 records | exactly 200 000 packets, `stop_reason: limit` |
| `MAX_BYTES` | same capture, `max_bytes=1024` | 33 packets, `stop_reason: max_bytes`, `bytes_read: 1024` |
| `MAX_BLOCK_BYTES` (pcap classic) | record with `incl_len = 16 MiB + 1` | `stop_reason: malformed`, counted, no allocation |
| `MAX_BLOCK_BYTES` (pcapng) | block declaring 16 MiB + 1 | `stop_reason: malformed`, counted |
| `MAX_DNS_JUMPS` (64) | 70-pointer compression chain | `"compression pointer hop limit"`; 64-hop chain parses |
| DNS pointer loop | self-pointing compression | `"compression pointer loop"` (no hang) |
| `MAX_DNS_RECORDS` (128) | message claiming 500 questions | 128 parsed |
| `MAX_STREAM_BYTES` (4 MiB) | 6 MiB of segments in one direction | reassembled stream = 4 194 304 bytes |
| `MAX_HTTP_REQUESTS` (1000) | 1500 pipelined requests in one stream | 1000 rows |
| `MAX_HTTP_HEADER_BYTES` | 65 670-byte header block | request dropped (see A9 — silent) |

Command: `python /tmp/winaudit/repro_limits.py` (full output preserved; each
line above is one row of it, plus the corrected two-DNS-chain probes).

## Audit Section 4: Verified clean

- The fixed-width structures match the published layouts:
  `_MEMORY_BASIC_INFORMATION64` 48 B (RegionSize@24, Protect@36, Type@40,
  the two alignment pads present), `_MEMORY_BASIC_INFORMATION32` 28 B,
  `_MODULEINFO` 24 B on x64 (EntryPoint@16), `_THREADENTRY32` 28 B. No
  sibling of the MIB_TCP6ROW/SOCKET_ADDRESS/_TOKEN_USER class here.
- PE parsing offsets (`AddressOfEntryPoint`+16, `ImageBase`+28/+24,
  `SizeOfImage`+56, `SizeOfHeaders`+60) spot-checked against the PE/COFF
  spec for both 0x10B and 0x20B.
- DNS compression defences genuinely terminate (loop and hop-limit probes).
- `flows()` direction canonicalisation, the hollowing comparison's
  relocation discard and read budgets, and the non-elevated denial path
  (OpenProcess denied → reported, not silent) all behave as documented.
- `pytest tests/` — fully green on this tree; the failures above are in
  code paths the suite does not exercise (IPv6 fragmentation, multi-section
  interface scoping, the thread-detector's skipped list, snapshot failure).
