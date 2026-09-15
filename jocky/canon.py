"""
Canonical serialisation and digests.

One place decides how a value becomes bytes, so that a digest computed while
collecting evidence can be recomputed years later by `jocky verify` on another
machine.  Rules: JSON with sorted keys, compact separators, UTF-8 without ASCII
escaping, and a stringification fallback for values JSON cannot represent.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, Optional

CHUNK = 1 << 20


def canonical_json(value: Any) -> bytes:
    """Deterministic JSON encoding used for every digest in the project."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_text(text: str) -> str:
    return digest_bytes(text.encode("utf-8"))


def digest_json(value: Any) -> str:
    return digest_bytes(canonical_json(value))


def digest_file(path: str, limit: Optional[int] = None) -> str:
    """Streamed file digest (``None``-safe: raises ``OSError`` like ``open``)."""
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as handle:
        while True:
            block = handle.read(CHUNK)
            if not block:
                break
            digest.update(block)
            total += len(block)
            if limit is not None and total >= limit:
                break
    return digest.hexdigest()


def chain_digest(previous: str, digest: str) -> str:
    """Link a file digest to the running chain.

    The chain is what makes removal detectable: dropping or reordering an entry
    changes every subsequent link, and the final link is what gets signed.
    """
    return hashlib.sha256(f"{previous}:{digest}".encode("utf-8")).hexdigest()


GENESIS = "0" * 64


def load_key(source: Optional[str] = None, env: str = "JOCKY_EVIDENCE_KEY") -> Optional[bytes]:
    """Resolve a signing key from a file path or the environment.

    A file is preferred so the key never lands in shell history or ``ps``
    output; if the value looks like a hex string it is decoded as such.
    """
    if source:
        if os.path.isfile(source):
            with open(source, "rb") as handle:
                return handle.read()
        return source.encode("utf-8")
    value = os.environ.get(env)
    if not value:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return value.encode("utf-8")


def key_id(key: bytes) -> str:
    """Short, non-reversible identifier so a signature names its key."""
    return hashlib.sha256(b"jocky/key-id:" + key).hexdigest()[:16]


def describe(entries: Dict[str, Any]) -> str:
    """One-line summary used by CLI output."""
    return ", ".join(f"{key}={value}" for key, value in sorted(entries.items()))
