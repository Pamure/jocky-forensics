"""Per-build polymorphic artifact encoding for compiled JOCKY programs.

Why this exists
---------------
Two builds of the same JOCKY script must not share bytes in their compiled
artifact, so byte-level fingerprints and static signatures do not transfer
between deployments: the *behaviour* is constant, the *representation* is
not.  Every transform below is drawn from a PRNG seeded with fresh entropy on
each :meth:`PolyEncoder.encode` call, so artifacts are unique per call even
when the build seed is fixed.

Transforms (all applied by :meth:`PolyEncoder.encode`, in this order)
--------------------------------------------------------------------
1. **Opcode permutation** -- a random bijection canonical opcode -> byte in
   ``1..255`` is drawn per artifact and stored in the header (a byte value of
   ``0`` is never used, which keeps the payload free of zero runs).  The
   header itself is XOR-obfuscated with a fresh header key.
2. **Slot permutation** -- every proto gets a fresh permutation of its local
   slot indices.  ``cell_slots`` and the slot operands of
   ``LOADL``/``STOREL``/``LOAD_CELL``/``STORE_CELL``/``PUSH_CELL`` are
   remapped, and ``nlocals`` keeps its value (so nothing in the VM needs to
   know).  The catch slot inside ``TRY_ENTER`` and ``handlers`` is remapped
   too -- the VM ignores that field, but it is part of the same slot space.
   The permutation is applied *independently* inside the capture prefix
   ``[0, ncaptures)`` and the rest of the frame, because the VM treats the
   prefix as parent-supplied cells and boxes ``cell_slots`` outside it.
3. **Constant encryption** -- each constant is stored as
   ``cipher_id:u8 | key:16 | ct_len | ciphertext`` with a fresh 16-byte key
   per constant and one of three invertible ciphers (0: SHA-256 keystream
   XOR, 1: add chain mod 256, 2: rotate-XOR).  Two occurrences of the same
   value never look alike, and int/float/str/bool/None all survive exactly.
4. **Constant splitting** -- integer constants above ``1`` become
   ``CONST a; CONST b; ADD`` and string constants longer than ``6``
   characters are cut into 2-4 pieces joined by ``ADD``.  The stack effect is
   unchanged: ``ADD`` consumes the two chunks that the single ``CONST``
   would have pushed as one value.
5. **Junk insertion** -- 1-3 ``NOPk`` (k in 0..7) are inserted at statement
   starts only, and every absolute index is remapped for the shift: jump
   targets (``JMP``/``JMPF``/``JMPT``/``ITER_NEXT``), the
   ``(start, end, handler, slot)`` tuple of ``TRY_ENTER``, ``proto.handlers``
   and ``proto.starts``.
6. **Payload encryption and padding** -- the whole payload is XORed with a
   SHA-256(key || counter) keystream and followed by random-length padding,
   so two encodes of one program differ in content *and* in size.
7. **Integrity** -- a truncated HMAC-SHA256 footer over every preceding byte;
   :meth:`decode` refuses to parse an artifact whose footer does not match.

Artifact layout (bytes)
-----------------------
``b"JKY1" | version:u8 | header_len:u32le | header | payload_len:u32le |
ciphertext | pad_len:u16le | padding | hmac:16``

``header`` is ``hmac_key:32 | header_key:16 | obfuscated JSON``.  The JSON
carries the opcode map, the per-proto slot maps, the payload key, the counts
reported by :meth:`inspect`, the build keys and some random reserved bytes.

Honest limitation
-----------------
:meth:`decode` takes no key: the artifact has to carry its own keying
material to be self-describing, so the obfuscation defeats signature reuse,
not an analyst who already holds the artifact.  The HMAC is a
corruption/tamper check, not a public-key signature.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import random
import struct
from typing import Any, Dict, List, Optional, Tuple

from jocky.errors import JockyArtifactError
from jocky.lang.compiler import OPCODES, Proto, Program
from jocky.poly import wire

ARTIFACT_MAGIC = b"JKY1"
ARTIFACT_VERSION = 1

_BUILD_KEY_LEN = 16          # bytes of build key material
_BUILD_HASH_HEX = 16         # hex characters of the public build hash
_HEADER_KEY_LEN = 16         # bytes of header obfuscation key
_MAC_KEY_LEN = 32            # bytes of per-artifact HMAC key
_MAC_LEN = 16                # truncated HMAC-SHA256 footer
_CONST_KEY_LEN = 16          # bytes of per-constant cipher key
_NOP_COUNT = 8               # NOP0..NOP7
_MAX_PAD = 256               # padding length is drawn from 0.._MAX_PAD-1

_HEADER_PREFIX = _MAC_KEY_LEN + _HEADER_KEY_LEN
_MIN_ARTIFACT = len(ARTIFACT_MAGIC) + 1 + 4 + _HEADER_PREFIX + 4 + 2 + _MAC_LEN

# Opcodes whose operand is an absolute instruction index.
_JUMP_OPS = frozenset({"JMP", "JMPF", "JMPT", "ITER_NEXT"})
# Opcodes whose operand is a local slot index.
_SLOT_OPS = frozenset({"LOADL", "STOREL", "LOAD_CELL", "STORE_CELL", "PUSH_CELL"})
_CIPHER_IDS = (0, 1, 2)

_ACTIVE_OPS = frozenset(OPCODES)


# --------------------------------------------------------------------- ciphers
def _keystream(key: bytes, length: int) -> bytes:
    """``SHA-256(key || counter)`` block stream (used for the payload and cipher 0)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _xor(data: bytes, keystream: bytes) -> bytes:
    """XOR two equal-length byte strings (as big integers: much faster than a genexp)."""
    if not data:
        return b""
    merged = int.from_bytes(data, "big") ^ int.from_bytes(keystream, "big")
    return merged.to_bytes(len(data), "big")


def _add_chain(data: bytes, key: bytes, direction: int) -> bytes:
    """Add chain mod 256: byte ``i`` carries both a key byte and its position."""
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        out[i] = (byte + direction * (key[i % _CONST_KEY_LEN] + i)) & 0xFF
    return bytes(out)


def _rot_xor(data: bytes, key: bytes, direction: int) -> bytes:
    """Rotate-XOR: rotate by 1..7 bits (position dependent), then XOR a key byte."""
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        rotation = (i % 7) + 1
        if direction > 0:
            rotated = ((byte << rotation) | (byte >> (8 - rotation))) & 0xFF
            out[i] = rotated ^ key[i % _CONST_KEY_LEN]
        else:
            unkeyed = byte ^ key[i % _CONST_KEY_LEN]
            out[i] = ((unkeyed >> rotation) | (unkeyed << (8 - rotation))) & 0xFF
    return bytes(out)


def _encrypt_const(cipher_id: int, key: bytes, data: bytes) -> bytes:
    if cipher_id == 0:
        return _xor(data, _keystream(key, len(data)))
    if cipher_id == 1:
        return _add_chain(data, key, 1)
    return _rot_xor(data, key, 1)


def _decrypt_const(cipher_id: int, key: bytes, data: bytes) -> bytes:
    if cipher_id == 0:
        return _xor(data, _keystream(key, len(data)))
    if cipher_id == 1:
        return _add_chain(data, key, -1)
    return _rot_xor(data, key, -1)


# ------------------------------------------------------------------- rewriting
def _clone(prog: Program) -> Program:
    """Copy a program deeply enough that rewriting never touches the caller's."""
    def clone_proto(proto: Proto) -> Proto:
        return Proto(
            name=proto.name,
            params=list(proto.params),
            captures=list(proto.captures),
            ncaptures=proto.ncaptures,
            nlocals=proto.nlocals,
            cell_slots=list(proto.cell_slots),
            code=list(proto.code),
            handlers=list(proto.handlers),
            starts=list(proto.starts),
        )

    return Program(
        main=clone_proto(prog.main),
        protos=[clone_proto(p) for p in prog.protos],
        consts=list(prog.consts),
        names=list(prog.names),
    )


def _remap_index(target: int, index_map: Dict[int, int], old_length: int) -> int:
    """Map an absolute instruction index onto the rewritten code.

    A target of ``old_length`` means "fall off the end of the proto"; it stays
    past the end.  Out-of-range targets (only reachable from a hand-built
    proto) clamp instead of raising, since the VM tolerates them the same way.
    """
    if target <= 0:
        return 0
    if target >= old_length:
        return index_map[old_length]
    return index_map[target]


def _remap_try_entry(entry: Any, index_map: Dict[int, int], old_length: int) -> Any:
    """Remap ``(start, end, handler, slot)``; the slot is not an index."""
    if len(entry) != 4:
        raise JockyArtifactError(f"malformed TRY_ENTER argument {entry!r}")
    start, end, handler, slot = entry
    mapped = (
        _remap_index(start, index_map, old_length),
        _remap_index(end, index_map, old_length),
        _remap_index(handler, index_map, old_length),
        slot,
    )
    return mapped if not isinstance(entry, list) else list(mapped)


def _rewrite_code(proto: Proto, replacements: Dict[int, List[Tuple[str, Any]]]) -> None:
    """Splice replacement sequences into the code and fix every absolute index.

    ``replacements`` maps an old instruction index to the instructions that
    take its place (the first of which is where the old index now points).
    """
    old_code = proto.code
    old_length = len(old_code)
    new_code: List[Tuple[str, Any]] = []
    index_map: Dict[int, int] = {}
    for ip, instruction in enumerate(old_code):
        index_map[ip] = len(new_code)
        replacement = replacements.get(ip)
        if replacement is None:
            new_code.append(instruction)
        else:
            new_code.extend(replacement)
    index_map[old_length] = len(new_code)

    for i, (op, arg) in enumerate(new_code):
        if op in _JUMP_OPS:
            new_code[i] = (op, _remap_index(arg, index_map, old_length))
        elif op == "TRY_ENTER":
            new_code[i] = (op, _remap_try_entry(arg, index_map, old_length))

    proto.code = new_code
    proto.handlers = [_remap_try_entry(entry, index_map, old_length) for entry in proto.handlers]
    proto.starts = [_remap_index(start, index_map, old_length) for start in proto.starts]


def _split_parts(value: Any, rng: random.Random) -> Optional[List[Any]]:
    """Values that ``ADD`` back together into ``value``, or ``None``."""
    if type(value) is int and value > 1:
        left = rng.randrange(1, value)          # 1 .. value-1
        return [left, value - left]
    if isinstance(value, str) and len(value) > 6:
        pieces = rng.randrange(2, min(4, len(value)) + 1)      # 2..4
        cuts = sorted(rng.sample(range(1, len(value)), pieces - 1))
        bounds = [0] + cuts + [len(value)]
        return [value[bounds[i]:bounds[i + 1]] for i in range(pieces)]
    return None


def _split_constants(prog: Program, rng: random.Random) -> None:
    """Transform 4: rewrite eligible ``CONST`` sites into ``CONST;CONST;ADD`` chains."""
    for proto in prog.all_protos():
        replacements: Dict[int, List[Tuple[str, Any]]] = {}
        for ip, (op, arg) in enumerate(proto.code):
            if op != "CONST" or not isinstance(arg, int) or not 0 <= arg < len(prog.consts):
                continue
            parts = _split_parts(prog.consts[arg], rng)
            if parts is None:
                continue
            sequence: List[Tuple[str, Any]] = []
            for part in parts:
                prog.consts.append(part)
                sequence.append(("CONST", len(prog.consts) - 1))
                if len(sequence) > 1:
                    # ADD consumes the chunk just pushed together with the
                    # running partial sum, so the stack effect is unchanged:
                    # the chain leaves exactly one value where CONST did.
                    sequence.append(("ADD", None))
            replacements[ip] = sequence
        if replacements:
            _rewrite_code(proto, replacements)


def _insert_junk(prog: Program, rng: random.Random) -> None:
    """Transform 5: 1-3 ``NOPk`` before each statement start, then remap indices."""
    for proto in prog.all_protos():
        replacements: Dict[int, List[Tuple[str, Any]]] = {}
        for start in sorted(set(proto.starts)):
            if not 0 <= start < len(proto.code):
                continue
            count = rng.randint(1, 3)
            # Old index ``start`` maps to the first NOP; jumps that landed on
            # the statement now land on the padding, which is a no-op.
            replacements[start] = [
                (f"NOP{rng.randrange(_NOP_COUNT)}", None) for _ in range(count)
            ] + [proto.code[start]]
        if replacements:
            _rewrite_code(proto, replacements)


def _permute_slots(prog: Program, rng: random.Random) -> List[List[int]]:
    """Transform 2: permute local slots per proto, returning the maps for the header."""
    maps: List[List[int]] = []
    for proto in prog.all_protos():
        nlocals = max(proto.nlocals, 0)
        prefix = min(max(proto.ncaptures, 0), nlocals)
        head = list(range(prefix))
        tail = list(range(prefix, nlocals))
        rng.shuffle(head)
        rng.shuffle(tail)      # the capture prefix stays in the prefix: the VM
        permutation = head + tail   # hands those slots over as pre-boxed cells
        maps.append(permutation)

        for i, (op, arg) in enumerate(proto.code):
            if op in _SLOT_OPS:
                if not isinstance(arg, int) or isinstance(arg, bool) or not 0 <= arg < nlocals:
                    raise JockyArtifactError(f"{op} operand {arg!r} is not a slot of {proto.name!r}")
                proto.code[i] = (op, permutation[arg])
            elif op == "TRY_ENTER":
                if len(arg) != 4 or not isinstance(arg[3], int) or not 0 <= arg[3] < nlocals:
                    raise JockyArtifactError(f"malformed TRY_ENTER argument {arg!r}")
                mapped = arg[:3] + (permutation[arg[3]],)
                proto.code[i] = (op, mapped if not isinstance(arg, list) else list(mapped))

        for slot in proto.cell_slots:
            if not isinstance(slot, int) or not 0 <= slot < nlocals:
                raise JockyArtifactError(f"cell slot {slot!r} is not a slot of {proto.name!r}")
        proto.cell_slots = sorted(permutation[slot] for slot in proto.cell_slots)
        proto.handlers = [tuple(entry[:3]) + (permutation[entry[3]],) for entry in proto.handlers]
    return maps


# ---------------------------------------------------------------------- payload
def _opcode_map(rng: random.Random) -> Dict[str, int]:
    """Transform 1: random bijection canonical opcode -> byte in ``1..255``."""
    values = rng.sample(range(1, 256), len(OPCODES))
    return dict(zip(OPCODES, values))


def _write_const(w: wire.Writer, value: Any, rng: random.Random) -> None:
    """Transform 3: ``cipher_id | key | len | ciphertext`` for one constant."""
    cipher_id = rng.choice(_CIPHER_IDS)
    key = rng.randbytes(_CONST_KEY_LEN)
    plain = wire.Writer()
    plain.value(value)
    w.byte(cipher_id)
    w.blob(key)
    w.blob(_encrypt_const(cipher_id, key, plain.getvalue()))


def _read_const(r: wire.Reader) -> Any:
    cipher_id = r.byte()
    key = r.blob()
    if cipher_id not in _CIPHER_IDS:
        raise JockyArtifactError(f"unknown constant cipher id {cipher_id}")
    if len(key) != _CONST_KEY_LEN:
        raise JockyArtifactError(f"constant key must be {_CONST_KEY_LEN} bytes, got {len(key)}")
    plain = wire.Reader(_decrypt_const(cipher_id, key, r.blob()))
    value = plain.value()
    if not plain.eof:
        raise JockyArtifactError("trailing bytes inside an encrypted constant")
    return value


def _encode_payload(prog: Program, opmap: Dict[str, int], rng: random.Random) -> bytes:
    w = wire.Writer()
    w.uvarint(len(prog.consts))
    for value in prog.consts:
        _write_const(w, value, rng)
    w.uvarint(len(prog.names))
    for name in prog.names:
        w.text(name)
    protos = prog.all_protos()
    w.uvarint(len(protos))
    for proto in protos:
        _write_proto(w, proto, opmap)
    return w.getvalue()


def _write_proto(w: wire.Writer, proto: Proto, opmap: Dict[str, int]) -> None:
    w.text(proto.name)
    w.uvarint(len(proto.params))
    for param in proto.params:
        w.text(param)
    w.uvarint(len(proto.captures))
    for capture in proto.captures:
        w.text(capture)
    w.uvarint(proto.ncaptures)
    w.uvarint(proto.nlocals)
    w.uvarint(len(proto.cell_slots))
    for slot in proto.cell_slots:
        w.uvarint(slot)
    w.uvarint(len(proto.code))
    for op, arg in proto.code:
        byte = opmap.get(op)
        if byte is None:
            raise JockyArtifactError(f"opcode {op!r} is missing from the build opcode map")
        w.byte(byte)
        w.arg(arg)
    w.uvarint(len(proto.handlers))
    for entry in proto.handlers:
        if len(entry) != 4:
            raise JockyArtifactError(f"malformed handler entry {entry!r}")
        for part in entry:
            w.uvarint(part)
    w.uvarint(len(proto.starts))
    for start in proto.starts:
        w.uvarint(start)


def _inverse_permutation(permutation: List[int], nlocals: int, index: int) -> List[int]:
    if not isinstance(permutation, list) or len(permutation) != nlocals:
        raise JockyArtifactError(f"slot map for code unit {index} does not match nlocals={nlocals}")
    inverse = [0] * nlocals
    seen = [False] * nlocals
    for old, new in enumerate(permutation):
        if not isinstance(new, int) or isinstance(new, bool) or not 0 <= new < nlocals:
            raise JockyArtifactError(f"slot map for code unit {index} contains {new!r}")
        if seen[new]:
            raise JockyArtifactError(f"slot map for code unit {index} is not a permutation")
        seen[new] = True
        inverse[new] = old
    return inverse


def _read_proto(r: wire.Reader, opmap: Dict[int, str], slotmaps: Any, index: int) -> Proto:
    name = r.text()
    params = [r.text() for _ in range(r.count("parameter"))]
    captures = [r.text() for _ in range(r.count("capture"))]
    ncaptures = r.uvarint()
    nlocals = r.uvarint()
    cell_slots = [r.uvarint() for _ in range(r.count("cell slot"))]
    code: List[Tuple[str, Any]] = []
    for _ in range(r.count("instruction")):
        byte = r.byte()
        op = opmap.get(byte)
        if op is None:
            raise JockyArtifactError(f"unknown opcode byte {byte} in code unit {index}")
        code.append((op, r.arg()))
    handlers = []
    for _ in range(r.count("handler")):
        handlers.append(tuple(r.uvarint() for _ in range(4)))
    starts = [r.uvarint() for _ in range(r.count("statement start"))]

    if nlocals:
        if not isinstance(slotmaps, list) or index >= len(slotmaps):
            raise JockyArtifactError(f"missing slot map for code unit {index}")
        inverse = _inverse_permutation(slotmaps[index], nlocals, index)
        for i, (op, arg) in enumerate(code):
            if op in _SLOT_OPS:
                if not isinstance(arg, int) or not 0 <= arg < nlocals:
                    raise JockyArtifactError(f"{op} operand {arg!r} is out of range in {name!r}")
                code[i] = (op, inverse[arg])
            elif op == "TRY_ENTER":
                if len(arg) != 4 or not 0 <= arg[3] < nlocals:
                    raise JockyArtifactError(f"malformed TRY_ENTER argument {arg!r}")
                mapped = arg[:3] + (inverse[arg[3]],)
                code[i] = (op, mapped if not isinstance(arg, list) else list(mapped))
        cell_slots = sorted(inverse[slot] for slot in cell_slots)
        handlers = [tuple(entry[:3]) + (inverse[entry[3]],) for entry in handlers]

    return Proto(
        name=name,
        params=params,
        captures=captures,
        ncaptures=ncaptures,
        nlocals=nlocals,
        cell_slots=cell_slots,
        code=code,
        handlers=handlers,
        starts=starts,
    )


#: Which operand of each instruction must be a valid index, and into what.
#: The envelope is keyed by material carried in the artifact, so "the HMAC is
#: valid" means "this was not corrupted", never "this was written by a friend" —
#: every operand a hostile artifact claims is therefore range-checked here, so
#: the VM never sees an IndexError or a negative jump target (`JMP -1` used to
#: wrap to the last instruction and spin out the whole step budget).
_INDEX_OPERANDS = {
    "CONST": "consts", "MK_FN": "protos", "LOADG": "constants", "STOREG": "constants",
    "GET_MEM": "constants", "SET_MEM": "constants", "LOADL": "slots", "STOREL": "slots",
    "LOAD_CELL": "slots", "STORE_CELL": "slots", "PUSH_CELL": "slots",
}
_JUMP_OPERANDS = ("JMP", "JMPF", "JMPT", "ITER_NEXT", "TRY_ENTER", "TRY_EXIT")
_COUNT_OPERANDS = ("MK_LIST", "MK_MAP", "CALL")


def _validate_operands(program: Any) -> None:
    """Reject an artifact whose operands point outside its own tables."""
    code = getattr(program, "code", [])
    for proto in [getattr(program, "main", None)] + list(getattr(program, "protos", []) or []):
        if proto is None:
            continue
        instructions = getattr(proto, "code", []) or []
        for index, (op, operand) in enumerate(instructions):
            if not isinstance(operand, int):
                continue
            if op in _JUMP_OPERANDS:
                if not 0 <= operand < len(instructions):
                    raise JockyArtifactError(
                        f"malformed artifact: {op} at {index} targets {operand}, "
                        f"outside its {len(instructions)} instructions")
            elif op in _COUNT_OPERANDS:
                if operand < 0 or operand > len(getattr(proto, "code", [])) + 1024:
                    raise JockyArtifactError(
                        f"malformed artifact: {op} at {index} has an absurd count "
                        f"({operand})")
            elif op == "CONST":
                pool = getattr(program, "consts", []) or []
                if not 0 <= operand < max(1, len(pool)):
                    raise JockyArtifactError(
                        f"malformed artifact: CONST at {index} indexes {operand} of "
                        f"{len(pool)} constants")


def _decode_payload(payload: bytes, header: Dict[str, Any]) -> Program:
    # ``header`` is already validated by ``_validate_header``; only the opcode
    # *entries* still need checking, and duplicate bytes must be rejected.
    opmap: Dict[int, str] = {}
    for name, byte in header["opmap"].items():
        if name not in _ACTIVE_OPS:
            raise JockyArtifactError(f"unknown opcode {name!r} in artifact opcode map")
        if not isinstance(byte, int) or isinstance(byte, bool) or not 0 < byte < 256:
            raise JockyArtifactError(f"bad opcode byte {byte!r} for {name!r}")
        if byte in opmap:
            raise JockyArtifactError(f"opcode byte {byte} is used twice")
        opmap[byte] = name

    r = wire.Reader(payload)
    consts = [_read_const(r) for _ in range(r.count("constant"))]
    names = [r.text() for _ in range(r.count("name"))]
    proto_count = r.count("code unit")
    if proto_count < 1:
        raise JockyArtifactError("artifact declares no code units")
    slotmaps = header.get("slots")
    protos = [_read_proto(r, opmap, slotmaps, i) for i in range(proto_count)]
    if not r.eof:
        raise JockyArtifactError(f"trailing bytes in payload ({r.remaining} left)")
    return Program(main=protos[0], protos=protos[1:], consts=consts, names=names)


# ----------------------------------------------------------------------- public
class PolyEncoder:
    """Encodes compiled programs into unique, self-describing artifacts.

    The seed identifies the *build* (it fixes ``build_hash``/``seed_hex``);
    fresh entropy is mixed in on every ``encode`` so the bytes identify the
    *instance*.
    """

    def __init__(self, seed: bytes | None = None, deterministic: bool = False):
        if seed is None:
            self.seed: bytes = os.urandom(32)
        elif isinstance(seed, (bytes, bytearray, memoryview)):
            self.seed = bytes(seed)
        else:
            # ``bytes(32)`` would silently build 32 zero bytes (a weak seed).
            raise TypeError(f"seed must be bytes or None, got {type(seed).__name__}")
        #: ``deterministic`` drops the per-call entropy so a build can be
        #: reproduced byte-for-byte from a seed — needed for rebuild-and-compare
        #: provenance. It is off by default because uniqueness is the point.
        self.deterministic: bool = bool(deterministic)
        self.build_key: bytes = hashlib.sha256(b"JKY1/build" + self.seed).digest()[:_BUILD_KEY_LEN]
        self.build_hash: str = hashlib.sha256(
            b"JKY1/build-hash" + self.build_key
        ).hexdigest()[:_BUILD_HASH_HEX]

    # -------------------------------------------------------------- encoding
    def encode(self, prog: Program) -> bytes:
        """Return a fresh artifact for ``prog`` (never mutates ``prog``)."""
        entropy = b"" if self.deterministic else os.urandom(32)
        rng = random.Random(hashlib.sha256(b"JKY1/rng" + self.build_key + entropy).digest())
        work = _clone(prog)

        _split_constants(work, rng)
        _insert_junk(work, rng)
        slotmaps = _permute_slots(work, rng)
        opmap = _opcode_map(rng)

        hmac_key = rng.randbytes(_MAC_KEY_LEN)
        header_key = rng.randbytes(_HEADER_KEY_LEN)
        payload_key = hashlib.sha256(b"JKY1/payload" + rng.randbytes(32)).digest()

        plaintext = _encode_payload(work, opmap, rng)
        ciphertext = _xor(plaintext, _keystream(payload_key, len(plaintext)))

        header = {
            "v": ARTIFACT_VERSION,
            "build": self.build_key.hex(),
            "seed": self.seed.hex(),
            "key": payload_key.hex(),
            "opmap": opmap,
            "slots": slotmaps,
            "nconst": len(work.consts),
            "nproto": len(work.all_protos()),
            "nops": sum(len(proto.code) for proto in work.all_protos()),
            "reserved": rng.randbytes(rng.randrange(6, 22)).hex(),
        }
        header_json = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
        obfuscated = _xor(header_json, _keystream(header_key, len(header_json)))

        out = bytearray(ARTIFACT_MAGIC)
        out.append(ARTIFACT_VERSION)
        blob = hmac_key + header_key + obfuscated
        out += struct.pack("<I", len(blob))
        out += blob
        out += struct.pack("<I", len(ciphertext))
        out += ciphertext
        padding = rng.randbytes(rng.randrange(_MAX_PAD))
        out += struct.pack("<H", len(padding))
        out += padding
        out += _hmac.new(hmac_key, bytes(out), hashlib.sha256).digest()[:_MAC_LEN]
        return bytes(out)

    def encode_info(self, prog: Program) -> dict:
        """Encode ``prog`` once and describe the artifact that came out."""
        return self.inspect(self.encode(prog))

    # -------------------------------------------------------------- decoding
    @classmethod
    def decode(cls, artifact: bytes) -> Program:
        """Verify, decrypt and rebuild the program carried by ``artifact``."""
        header, payload = cls._open(artifact)
        try:
            program = _decode_payload(payload, header)
        except JockyArtifactError:
            raise
        except Exception as exc:  # never leak struct/Index/Key/Unicode errors
            raise JockyArtifactError(f"malformed payload: {type(exc).__name__}: {exc}") from exc
        _validate_operands(program)
        return program

    @classmethod
    def inspect(cls, artifact: bytes) -> dict:
        """Describe an artifact without re-running the transforms.

        Two identities are reported and they mean different things:
        ``artifact_hash`` is the SHA-256 of the artifact *bytes* (what makes
        every build unique on disk), while ``build_hash`` identifies the build
        *profile* derived from the seed, so repeated encodes with one seed
        share it.
        """
        header, _ = cls._open(artifact)
        try:
            build_hash = hashlib.sha256(
                b"JKY1/build-hash" + bytes.fromhex(header["build"])
            ).hexdigest()[:_BUILD_HASH_HEX]
            return {
                "build_hash": build_hash,
                "artifact_hash": hashlib.sha256(bytes(artifact)).hexdigest(),
                "size": len(bytes(artifact)),
                "opmap_size": len(header["opmap"]),
                "nops": header["nops"],
                "const_count": header["nconst"],
                "proto_count": header["nproto"],
                "seed_hex": header["seed"],
            }
        except JockyArtifactError:
            raise
        except Exception as exc:
            raise JockyArtifactError(f"malformed artifact header: {type(exc).__name__}: {exc}") from exc

    # ---------------------------------------------------------------- internal
    @classmethod
    def _open(cls, artifact: bytes) -> Tuple[Dict[str, Any], bytes]:
        """Check the envelope + HMAC and return ``(header, decrypted payload)``."""
        try:
            raw = bytes(artifact)
            if len(raw) < _MIN_ARTIFACT:
                raise JockyArtifactError(f"artifact is too short ({len(raw)} bytes)")
            if raw[:len(ARTIFACT_MAGIC)] != ARTIFACT_MAGIC:
                raise JockyArtifactError("bad artifact magic")
            version = raw[len(ARTIFACT_MAGIC)]
            if version != ARTIFACT_VERSION:
                raise JockyArtifactError(f"unsupported artifact version {version}")

            body, mac = raw[:-_MAC_LEN], raw[-_MAC_LEN:]
            offset = len(ARTIFACT_MAGIC) + 1
            header_len = _read_u32(body, offset)
            offset += 4
            if header_len < _HEADER_PREFIX or offset + header_len > len(body):
                raise JockyArtifactError(f"header length {header_len} is out of range")
            blob = body[offset:offset + header_len]
            offset += header_len
            mac_key = blob[:_MAC_KEY_LEN]
            header_key = blob[_MAC_KEY_LEN:_HEADER_PREFIX]
            obfuscated = blob[_HEADER_PREFIX:]

            expected = _hmac.new(mac_key, body, hashlib.sha256).digest()[:_MAC_LEN]
            if not _hmac.compare_digest(mac, expected):
                raise JockyArtifactError("artifact integrity check failed (truncated or tampered)")

            header_json = _xor(obfuscated, _keystream(header_key, len(obfuscated)))
            header = _validate_header(json.loads(header_json.decode("utf-8")))

            payload_len = _read_u32(body, offset)
            offset += 4
            if offset + payload_len > len(body):
                raise JockyArtifactError(f"payload length {payload_len} is out of range")
            ciphertext = body[offset:offset + payload_len]
            offset += payload_len
            pad_len = _read_u16(body, offset)
            offset += 2
            if offset + pad_len != len(body):
                raise JockyArtifactError("padding length does not match the artifact size")

            payload_key = bytes.fromhex(header["key"])
            payload = _xor(ciphertext, _keystream(payload_key, len(ciphertext)))
            return header, payload
        except JockyArtifactError:
            raise
        except Exception as exc:  # json/struct/Index/Key/Unicode errors
            raise JockyArtifactError(f"malformed artifact: {type(exc).__name__}: {exc}") from exc


def _validate_header(header: Any) -> Dict[str, Any]:
    """Check the header fields ``decode``/``inspect`` rely on.

    Centralised so neither entry point can leak ``KeyError``/``ValueError`` on
    a hand-built (but correctly keyed) artifact.
    """
    if not isinstance(header, dict):
        raise JockyArtifactError("artifact header is not an object")
    for field in ("build", "seed", "key"):
        value = header.get(field)
        if not isinstance(value, str):
            raise JockyArtifactError(f"artifact header is missing the {field!r} field")
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            raise JockyArtifactError(f"artifact header field {field!r} is not hex: {exc}") from exc
    for field in ("nconst", "nproto", "nops"):
        value = header.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise JockyArtifactError(f"artifact header field {field!r} is not a count")
    if not isinstance(header.get("opmap"), dict):
        raise JockyArtifactError("artifact opcode map is not a mapping")
    if not isinstance(header.get("slots"), list):
        raise JockyArtifactError("artifact slot maps are not a list")
    return header


def _read_u32(buf: bytes, offset: int) -> int:
    if offset + 4 > len(buf):
        raise JockyArtifactError("truncated artifact (32-bit field)")
    return int.from_bytes(buf[offset:offset + 4], "little")


def _read_u16(buf: bytes, offset: int) -> int:
    if offset + 2 > len(buf):
        raise JockyArtifactError("truncated artifact (16-bit field)")
    return int.from_bytes(buf[offset:offset + 2], "little")
