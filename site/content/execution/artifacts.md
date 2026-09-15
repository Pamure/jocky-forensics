# Polymorphic artifacts

`jocky build` compiles a script and encodes it into an artifact: a single file
whose bytes are unique per build while its behaviour is fixed. Two builds of one
script share no byte signature, which is what stops a file hash, a chunk hash or
a fuzzy hash from transferring between deployments.

```bash
./venv/bin/jocky build scripts/triage.jky -o /tmp/triage.jky.build
./venv/bin/jocky exec /tmp/triage.jky.build
```

The encoder is `jocky/poly/encoder.py` (envelope and per-build transforms); the
inner serialisation of the compiled program is `jocky/poly/wire.py`.

## Two layers

1. **Wire format** (`JKYW`) — a canonical, *non*-polymorphic serialisation of
   the compiled program: constant pool, name pool, then each code unit
   (`Proto`) in `Program.protos` order. It exists so the round-trip
   `decode_program(encode_program(p)) == p` can be reasoned about on its own,
   including tuple/list identity for `TRY_ENTER` arguments.
2. **Envelope** (`JKY1`) — post-processes the program (constant splitting, junk
   insertion, slot permutation, opcode permutation), serialises it, encrypts it
   and wraps it with a header, padding and an HMAC footer.

## Byte layout

```
"JKY1" | version:u8 | header_len:u32le | header | payload_len:u32le |
ciphertext | pad_len:u16le | padding | hmac:16
```

The header is `mac_key:32 | header_key:16 | obfuscated JSON`. Measured on a real
build of `scripts/triage.jky` (throwaway probe that parses the envelope fields,
one build):

```text
artifact: /tmp/jdocs/triage.jky.build
size: 2663
sha256: cb2db52a06e0539b813e0ab4c3f18bb37d469fb37d339c7a1c6e1df51fadbd46
magic: b'JKY1' version: 1
offset 5 header_len: 925
offset 9..934 header blob: 925 bytes (mac_key 32, header_key 16, obfuscated json 877)
offset 934 payload_len: 1682
offset 938..2620 ciphertext: 1682 bytes
offset 2620 pad_len: 25
offset 2622..2647 padding: 25 bytes
offset 2647..2663 hmac: 16 bytes
total: 2663 == size: True
```

The same layout on a two-line script (`let n = 7` / `emit {"n": n}`) — 1304
bytes, header 916, payload 137, padding 220, HMAC 16 — shows that padding length
and header size are drawn per build, not derived from the program.

## What the header carries

```text
header keys: ['build', 'key', 'nconst', 'nops', 'nproto', 'opmap', 'reserved', 'seed', 'slots', 'v']
header nconst: 45 nproto: 2 nops: 131
opcode bytes for 6 canonical opcodes: {'CONST': 53, 'LOADL': 142, 'ADD': 209, 'JMP': 11, 'EMIT': 215, 'HALT': 43}
slot maps (per proto): [[2, 0, 1], [0]]
```

* `opmap` is the per-build bijection `opcode → byte` (bytes are drawn from
  `1..255`, so no zero runs appear in the payload).
* `slots` is the per-code-unit local-slot permutation; `TRY_ENTER`'s slot field
  and `handlers` are remapped with it. The capture prefix `[0, ncaptures)` is
  permuted independently of the rest of the frame, because the VM hands that
  prefix over as pre-boxed cells.
* `key` is the payload key, `build` the build key, `seed` the build seed.
* `reserved` is random filler, so header length varies between builds.
* The JSON is XOR-obfuscated with `header_key` (the 16 bytes before it); the
  32-byte HMAC key sits in clear at the front of the blob.

**This is the honest part:** the header carries the permutation and the keys. It
is self-describing — `PolyEncoder.decode()` takes no key argument and is
expected to work. The obfuscation defeats signature reuse between builds; it
does not lock the artifact against someone who holds it.

## Per-build transforms

| Order | Transform | Effect on the bytes | Defeats |
|---|---|---|---|
| 1 | opcode permutation | every instruction byte changes | opcode histogram and pattern signatures |
| 2 | local-slot permutation | operand bytes change per function | byte-sequence signatures over operand patterns |
| 3 | constant encryption | per-constant 16-byte key, one of three ciphers (SHA-256 keystream XOR, add chain mod 256, rotate-XOR); no literal string or number appears | plaintext markers (paths, patterns) in the artifact |
| 4 | constant splitting | integers > 1 become `CONST a; CONST b; ADD`; strings longer than 6 chars are cut into 2–4 pieces joined by `ADD` | signatures keyed to a literal's representation; the code stream shifts too |
| 5 | junk insertion | 1–3 `NOP0..NOP7` before each statement start, with every absolute index remapped (jumps, `TRY_ENTER`, `handlers`, `starts`) | length fingerprints and control-flow shape matching |
| 6 | keystream encryption + random padding | payload XORed with a `SHA-256(key \|\| counter)` keystream; 0–255 random padding bytes appended | file hashes, chunk hashing, fuzzy/similarity hashing |
| 7 | HMAC footer | truncated HMAC-SHA256 over every preceding byte | silent corruption/tampering (not a signature) |

Transforms run in that order on a private clone of the program, so encoding
never mutates the caller's compiled program.

## What a build actually did

Source of the two-line script, disassembled from the `.jky` file with `jocky
disasm`:

```text
$ ./venv/bin/jocky disasm /tmp/jdocs/small.jky
=== constants ===
[0] 7
[1] 'n'
=== names ===
=== <main> (locals=1) ===
   0  CONST      0
   1  STOREL     0
   2  CONST      1
   3  LOADL      0
   4  MK_MAP     1
   5  EMIT       
   6  HALT       
```

The same program recovered from the artifact it was built into — no key
supplied, because none is needed:

```text
$ ./venv/bin/python -c "
from jocky.poly.encoder import PolyEncoder
prog = PolyEncoder.decode(open('/tmp/jdocs/small.jky.build','rb').read())
print(prog.disassemble())"
=== constants ===
[0] 7
[1] 'n'
[2] 6
[3] 1
=== names ===
=== <main> (locals=1) ===
   0  NOP2       
   1  NOP4       
   2  NOP3       
   3  CONST      2
   4  CONST      3
   5  ADD        
   6  STOREL     0
   7  NOP2       
   8  CONST      1
   9  LOADL      0
  10  MK_MAP     1
  11  EMIT       
  12  HALT       
```

Three transforms are visible in that listing: the constant `7` was split into
`CONST 6; CONST 1; ADD` (constants `[2]` and `[3]`), junk `NOP`s were inserted
before each statement, and the opcodes in the file are not the canonical bytes.

Constants and names are encrypted **as part of the payload**, so nothing about
the program is readable in the file:

```text
$ ./venv/bin/python -c "
raw = open('/tmp/jdocs/triage.jky.build','rb').read()
print('raw has b\"det\":', b'det' in raw, '| raw has b\"triage\":', b'triage' in raw)
from jocky.poly.encoder import PolyEncoder
header, payload = PolyEncoder._open(raw)
print('decrypted has b\"triage\":', b'triage' in payload, '| decrypted has b\"severity\":', b'severity' in payload)
print('opmap sample:', {k: header['opmap'][k] for k in ('CONST','LOADG','CALL','EMIT')})"
raw has b"det": False | raw has b"triage": False
decrypted has b"triage": True | decrypted has b"severity": True
opmap sample: {'CONST': 53, 'LOADG': 32, 'CALL': 207, 'EMIT': 215}
```

(Inside the *decrypted* payload the name pool is plaintext length-prefixed
UTF-8; the encryption is a whole-payload keystream, not per-name obfuscation.)

## Unique bytes, stable behaviour

```bash
./venv/bin/jocky build scripts/triage.jky --repeat 200 | jq '{builds, unique_hashes, distinct_sizes: (.sizes|length), smallest: (.sizes|min), largest: (.sizes|max)}'
```

```text
{
  "builds": 200,
  "unique_hashes": 200,
  "distinct_sizes": 150,
  "smallest": 2519,
  "largest": 3011
}
```

The full harness run in `evidence/report.md` reports the same at a larger scale:

```text
- builds: **1000**, unique SHA-256: **1000** (all unique)
- artifact sizes: 3625–4175 bytes, 367 distinct sizes (per-build padding/structure differs)
- build throughput: 296.0/s
- semantic equivalence: 25 freshly built artifacts re-executed, findings hash identical to the reference run (1 finding(s), 0 failures)
```

Two identities are reported by `--inspect` and they mean different things:
`artifact_hash` is the SHA-256 of the bytes (unique per build), while
`build_hash` identifies the build *profile* derived from the seed — repeated
encodes with one seed share it.

## Inspecting a build

```bash
./venv/bin/jocky exec /tmp/triage.jky.build --inspect
```

```text
{
  "build_hash": "3e27fb0150b5399d",
  "artifact_hash": "cb2db52a06e0539b813e0ab4c3f18bb37d469fb37d339c7a1c6e1df51fadbd46",
  "size": 2663,
  "opmap_size": 50,
  "nops": 131,
  "const_count": 45,
  "proto_count": 2,
  "seed_hex": "30474685052792f8651d2b0e1b00017b5b81894824886d97b6daf18523d1ae6c"
}
```

`--inspect` verifies the HMAC, decrypts the header and reports counts without
executing the program. `opmap_size` is the number of opcodes in the bytecode set
(50 here), `nops` the instruction count after junk insertion, `const_count` the
constant pool after splitting.

## Integrity

The footer is a truncated HMAC-SHA256 (16 bytes) over every preceding byte,
keyed by the 32 random bytes at the front of the header. Flipping one payload
byte makes the artifact refuse to load:

```text
$ ./venv/bin/jocky exec /tmp/tampered.jky.build
jocky: JockyArtifactError: artifact integrity check failed (truncated or tampered)
```

Malformed input is always reported as `JockyArtifactError`: length fields are
bounds-checked against the remaining bytes, collection counts cannot exceed what
is left, and `struct`/`Index`/`Key`/`Unicode` errors are never allowed to leak
out of the artifact layer. The HMAC is a corruption check, not a public-key
signature — anyone who can rewrite the file can also recompute it.

## What the artifacts do and do not defeat

**Defeated:**

* File hashes, chunk hashes and similarity/fuzzy hashing over the artifact:
  1000 builds of one script produced 1000 distinct SHA-256 digests, 367 distinct
  sizes.
* Static string and opcode signatures: literals are encrypted and split, opcode
  bytes are permuted per build, slot operands are remapped, and code length
  varies with junk and padding.
* Cross-deployment reuse of any single signature: every encode mixes fresh
  entropy even when the build seed is fixed.

**Not defeated — stated plainly:**

* **A determined analyst holding the artifact.** The header carries the payload
  key, the opcode map and the slot maps; `PolyEncoder.decode()` needs no key and
  a scripted decode recovers the program (the disassembly above is the decoded
  output). Treat an artifact as *unreadable at a glance*, not as confidential.
* **The decoded program's semantics.** Constant splitting, junk insertion and
  permutation are representation changes: the VM steps are not obfuscated and
  the recovered disassembly is a faithful program. Obfuscation raises the cost
  of pattern matching; it does not hide behaviour from a reader.
* **Kernel and EDR telemetry of the decryption step.** The decode happens
  in-process; file reads, memory writes and the syscalls around execution are
  visible to a privileged observer.
* **Memory scanning while the program runs.** Once decoded, the program and its
  constants exist in the process address space.
* **Correlation by behaviour.** Two builds that read the same files, open the
  same sockets or emit the same findings are still the same job; the encoding
  changes the bytes, not the effects (see
  [execution modes](/docs/execution/modes) for the measured equivalence).

## Related

* [Execution modes](/docs/execution/modes) — where each mode keeps its program
  text, and the measured file/process telemetry.
* [Fileless execution](/docs/execution/fileless) — the payload as an anonymous
  memory file instead of an artifact.
* [CLI reference](/docs/operations/cli) — every flag of `build`, `exec` and
  `disasm`, generated from the parser.
