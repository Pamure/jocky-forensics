"""Polymorphic artifact layer: unique bytes per build, constant behaviour.

* :mod:`jocky.poly.wire`    -- canonical, unobfuscated program serialization.
* :mod:`jocky.poly.encoder` -- per-build obfuscation (opcode/slot permutation,
  constant encryption and splitting, junk insertion, keystream payload
  encryption and a truncated HMAC footer).
"""
from jocky.poly.wire import WIRE_MAGIC, WIRE_VERSION, decode_program, encode_program
from jocky.poly.encoder import (
    ARTIFACT_MAGIC,
    ARTIFACT_VERSION,
    PolyEncoder,
)

__all__ = [
    "ARTIFACT_MAGIC",
    "ARTIFACT_VERSION",
    "PolyEncoder",
    "WIRE_MAGIC",
    "WIRE_VERSION",
    "decode_program",
    "encode_program",
]
