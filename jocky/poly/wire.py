"""Canonical (non-polymorphic) serialization of compiled JOCKY programs.

Why this module exists
----------------------
:mod:`jocky.poly.encoder` rewrites a program before serializing it (opcode
permutation, slot permutation, junk insertion, ...).  The *inner* formats --
varints, constant values, instruction arguments -- are shared, so they live
here where the round-trip guarantee can be reasoned about and tested on its
own: ``decode_program(encode_program(p))`` must reproduce ``p`` exactly,
including the tuple/list identity of ``TRY_ENTER`` arguments.

Format
------
``b"JKYW" | version:u8 | payload_len:u32le | payload``

The payload is a varint blob holding the constant pool, the name pool and
then every proto (the main script first, then the function bodies in
``Program.protos`` order -- ``MK_FN`` operands are indices into exactly that
list, so the order is part of the contract).  Integers use zig-zag varints so
negative constants stay one byte wide and round-trip; floats use IEEE-754
``<d``; strings are length-prefixed UTF-8.  Every collection is length
prefixed and every length is bounded by the bytes still available, so a
truncated or hostile blob fails fast instead of allocating.

Failure policy
--------------
Malformed input is always reported as :class:`jocky.errors.JockyArtifactError`.
A caller of :func:`decode_program` must never see ``struct.error``,
``IndexError``, ``KeyError`` or ``UnicodeDecodeError`` leak out of the
artifact layer.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List, Tuple

from jocky.errors import JockyArtifactError
from jocky.lang.compiler import OPCODES, Proto, Program

WIRE_MAGIC = b"JKYW"
WIRE_VERSION = 1

_U32 = struct.Struct("<I")
_F64 = struct.Struct("<d")

# Constant value tags.
_T_NIL, _T_FALSE, _T_TRUE, _T_INT, _T_FLOAT, _T_STR = range(6)

# Instruction-argument tags.
_A_NONE, _A_INT, _A_TUPLE, _A_LIST = range(4)

# A varint longer than this cannot come from a plausible program and is
# treated as corruption rather than expanded into a huge Python int.
_MAX_VARINT_BYTES = 16

_OP_INDEX: Dict[str, int] = {name: i for i, name in enumerate(OPCODES)}


class Writer:
    """Append-only varint writer.

    Shared with :mod:`jocky.poly.encoder` so both format layers agree on
    integer/string/argument encoding by construction.
    """

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def getvalue(self) -> bytes:
        return bytes(self._buf)

    def __len__(self) -> int:
        return len(self._buf)

    # ------------------------------------------------------------- primitives
    def byte(self, value: int) -> None:
        self._buf.append(value & 0xFF)

    def uvarint(self, value: int) -> None:
        """LEB128-style unsigned varint."""
        if value < 0:
            raise JockyArtifactError(f"negative value {value} cannot be written as a varint")
        while True:
            piece = value & 0x7F
            value >>= 7
            if value:
                self._buf.append(piece | 0x80)
            else:
                self._buf.append(piece)
                return

    def svarint(self, value: int) -> None:
        """Zig-zag signed varint (small negatives stay one byte wide)."""
        self.uvarint((value << 1) if value >= 0 else ((-value << 1) - 1))

    def blob(self, data: bytes) -> None:
        self.uvarint(len(data))
        self._buf += data

    def text(self, value: str) -> None:
        self.blob(value.encode("utf-8"))

    # --------------------------------------------------------------- compound
    def value(self, value: Any) -> None:
        """Write one constant (``int``/``float``/``str``/``bool``/``None``)."""
        if value is None:
            self.byte(_T_NIL)
        elif value is True:
            self.byte(_T_TRUE)
        elif value is False:
            self.byte(_T_FALSE)
        elif isinstance(value, int):
            self.byte(_T_INT)
            self.svarint(value)
        elif isinstance(value, float):
            self.byte(_T_FLOAT)
            self._buf += _F64.pack(value)
        elif isinstance(value, str):
            self.byte(_T_STR)
            self.text(value)
        else:
            raise JockyArtifactError(
                f"unsupported constant of type {type(value).__name__}; "
                "only int/float/str/bool/None can be serialized"
            )

    def arg(self, value: Any) -> None:
        """Write one instruction argument (``None``, an int, or a tuple/list)."""
        if value is None:
            self.byte(_A_NONE)
        elif isinstance(value, bool):
            raise JockyArtifactError("instruction arguments must not be booleans")
        elif isinstance(value, int):
            self.byte(_A_INT)
            self.svarint(value)
        elif isinstance(value, (tuple, list)):
            # Tuple vs list is preserved: the compiler emits TRY_ENTER tuples
            # and an exact round-trip must not silently re-type them.
            self.byte(_A_TUPLE if isinstance(value, tuple) else _A_LIST)
            self.uvarint(len(value))
            for item in value:
                if not isinstance(item, int) or isinstance(item, bool):
                    raise JockyArtifactError(f"instruction argument element {item!r} is not an int")
                self.svarint(item)
        else:
            raise JockyArtifactError(
                f"unsupported instruction argument of type {type(value).__name__}"
            )


class Reader:
    """Bounds-checked counterpart of :class:`Writer`."""

    __slots__ = ("_buf", "_pos")

    def __init__(self, data: bytes) -> None:
        self._buf = bytes(data)
        self._pos = 0

    @property
    def position(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return len(self._buf) - self._pos

    @property
    def eof(self) -> bool:
        return self._pos >= len(self._buf)

    # ------------------------------------------------------------- primitives
    def take(self, count: int) -> bytes:
        if count < 0 or self._pos + count > len(self._buf):
            raise JockyArtifactError(
                f"truncated artifact: wanted {count} byte(s) at offset {self._pos}, "
                f"{self.remaining} left"
            )
        chunk = self._buf[self._pos:self._pos + count]
        self._pos += count
        return chunk

    def byte(self) -> int:
        return self.take(1)[0]

    def uvarint(self) -> int:
        value = 0
        shift = 0
        for _ in range(_MAX_VARINT_BYTES):
            piece = self.byte()
            value |= (piece & 0x7F) << shift
            if not piece & 0x80:
                return value
            shift += 7
        raise JockyArtifactError("varint is longer than any plausible value")

    def svarint(self) -> int:
        zig = self.uvarint()
        return (zig >> 1) if not zig & 1 else -((zig + 1) >> 1)

    def blob(self) -> bytes:
        return self.take(self.uvarint())

    def text(self) -> str:
        try:
            return self.blob().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JockyArtifactError(f"invalid UTF-8 string in artifact: {exc}") from exc

    def count(self, what: str) -> int:
        """Read a collection length, bounded by the bytes still available.

        Every element in this format costs at least one byte, so a count
        larger than ``remaining`` is corruption and would otherwise make the
        decoder spin allocating.
        """
        value = self.uvarint()
        if value > self.remaining:
            raise JockyArtifactError(
                f"{what} count {value} exceeds the {self.remaining} byte(s) left in the artifact"
            )
        return value

    # --------------------------------------------------------------- compound
    def value(self) -> Any:
        tag = self.byte()
        if tag == _T_NIL:
            return None
        if tag == _T_FALSE:
            return False
        if tag == _T_TRUE:
            return True
        if tag == _T_INT:
            return self.svarint()
        if tag == _T_FLOAT:
            return _F64.unpack(self.take(8))[0]
        if tag == _T_STR:
            return self.text()
        raise JockyArtifactError(f"unknown constant tag {tag}")

    def arg(self) -> Any:
        tag = self.byte()
        if tag == _A_NONE:
            return None
        if tag == _A_INT:
            return self.svarint()
        if tag in (_A_TUPLE, _A_LIST):
            items = [self.svarint() for _ in range(self.count("instruction argument"))]
            return tuple(items) if tag == _A_TUPLE else items
        raise JockyArtifactError(f"unknown instruction argument tag {tag}")


# ------------------------------------------------------------------- programs
def encode_program(prog: Program) -> bytes:
    """Serialize a compiled program canonically (no obfuscation)."""
    payload = _encode_payload(prog)
    return WIRE_MAGIC + bytes([WIRE_VERSION]) + _U32.pack(len(payload)) + payload


def decode_program(data: bytes) -> Program:
    """Rebuild a program from :func:`encode_program` bytes.

    Raises :class:`~jocky.errors.JockyArtifactError` for anything that is not
    a well-formed program image.
    """
    try:
        raw = bytes(data)
        head = len(WIRE_MAGIC) + 1 + 4
        if len(raw) < head:
            raise JockyArtifactError("wire image is too short")
        if raw[:len(WIRE_MAGIC)] != WIRE_MAGIC:
            raise JockyArtifactError("bad wire magic")
        version = raw[len(WIRE_MAGIC)]
        if version != WIRE_VERSION:
            raise JockyArtifactError(f"unsupported wire version {version}")
        declared = _U32.unpack_from(raw, len(WIRE_MAGIC) + 1)[0]
        payload = raw[head:]
        if declared != len(payload):
            raise JockyArtifactError(
                f"wire length mismatch: header says {declared} byte(s), got {len(payload)}"
            )
        return _decode_payload(payload)
    except JockyArtifactError:
        raise
    except Exception as exc:  # struct/Index/Key/Unicode errors must not leak
        raise JockyArtifactError(f"malformed wire image: {type(exc).__name__}: {exc}") from exc


def _encode_payload(prog: Program) -> bytes:
    w = Writer()
    w.uvarint(len(prog.consts))
    for value in prog.consts:
        w.value(value)
    w.uvarint(len(prog.names))
    for name in prog.names:
        w.text(name)
    protos = prog.all_protos()
    w.uvarint(len(protos))
    for proto in protos:
        _encode_proto(w, proto)
    return w.getvalue()


def _decode_payload(payload: bytes) -> Program:
    r = Reader(payload)
    consts = [r.value() for _ in range(r.count("constant"))]
    names = [r.text() for _ in range(r.count("name"))]
    proto_count = r.count("proto")
    if proto_count < 1:
        raise JockyArtifactError("wire image declares no code units")
    protos = [_decode_proto(r) for _ in range(proto_count)]
    if not r.eof:
        raise JockyArtifactError(f"trailing bytes in wire payload ({r.remaining} left)")
    return Program(main=protos[0], protos=protos[1:], consts=consts, names=names)


def _encode_proto(w: Writer, proto: Proto) -> None:
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
        w.svarint(slot)
    w.uvarint(len(proto.code))
    for op, arg in proto.code:
        index = _OP_INDEX.get(op)
        if index is None:
            raise JockyArtifactError(f"unknown opcode {op!r}")
        w.uvarint(index)
        w.arg(arg)
    w.uvarint(len(proto.handlers))
    for entry in proto.handlers:
        if len(entry) != 4:
            raise JockyArtifactError(f"malformed handler entry {entry!r}")
        for part in entry:
            w.svarint(part)
    w.uvarint(len(proto.starts))
    for start in proto.starts:
        w.svarint(start)


def _decode_proto(r: Reader) -> Proto:
    name = r.text()
    params = [r.text() for _ in range(r.count("parameter"))]
    captures = [r.text() for _ in range(r.count("capture"))]
    ncaptures = r.uvarint()
    nlocals = r.uvarint()
    cell_slots = [r.svarint() for _ in range(r.count("cell slot"))]
    code: List[Tuple[str, Any]] = []
    for _ in range(r.count("instruction")):
        index = r.uvarint()
        if index >= len(OPCODES):
            raise JockyArtifactError(f"unknown opcode index {index}")
        code.append((OPCODES[index], r.arg()))
    handlers = []
    for _ in range(r.count("handler")):
        handlers.append(tuple(r.svarint() for _ in range(4)))
    starts = [r.svarint() for _ in range(r.count("statement start"))]
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
