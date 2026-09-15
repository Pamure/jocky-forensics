"""
Case-directory integrity: hash-chain manifests, verification and signing.

Why this exists
---------------
The evidence harness writes raw logs so a reviewer can re-check the claims. That
promise is empty if the logs can be edited afterwards without detection, and
until now nothing in the project hashed them. This module adds the missing
half: a per-file SHA-256 manifest, a hash chain over it, a separately stored
chain head, and an optional HMAC signature by the analyst.

Design decisions that matter
----------------------------
* **Collection stays clean.** Attestation is an *analyst-side* step that runs
  after collection. Signing during collection would spawn ``openssl``/``gpg``
  and break the measured invariant "0 child processes during a run".
* **The head is stored twice.** ``manifest.head`` inside the directory makes
  truncation obvious; ``--anchor`` writes it somewhere else (another host, a
  ticket system, a signature store) so an attacker who owns the directory
  cannot silently rewrite both the manifest and its head.
* **Anchoring is not signing.** The head file proves ordering and completeness;
  only :func:`sign_head` with an analyst-held key proves authorship. The
  documentation says exactly that, because a hash chain is routinely mistaken
  for authenticity.
"""
from __future__ import annotations

import hmac
import fnmatch
import os
import re
import time
from typing import Sequence, Any, Dict, Iterable, List, Optional

from jocky.canon import (
    GENESIS,
    canonical_json,
    chain_digest,
    digest_bytes,
    digest_file,
    key_id,
    load_key,
)

MANIFEST_NAME = "manifest.json"
HEAD_NAME = "manifest.head"
SIGNATURE_NAME = "manifest.sig"
MANIFEST_VERSION = 1

#: Files that are part of the integrity layer itself and never chained.
SKIP_NAMES = {MANIFEST_NAME, HEAD_NAME, SIGNATURE_NAME}


def _iter_files(directory: str, exclude: Sequence[str] = ()) -> List[str]:
    """Every chainable file, sorted by relative path for a stable chain.

    Nothing is skipped implicitly — not ``.git``, not ``__pycache__``. Those are
    exactly where a payload that runs on the analyst's next command can hide
    (``.git/hooks/*``, ``.git/config`` with ``core.fsmonitor``), and a case
    directory that reports "verified" while a subtree was never looked at is the
    failure this chain exists to prevent. An operator who wants to leave
    something out passes ``exclude`` (globs), and the manifest records the
    exclusions so ``verify`` can report them instead of hiding them.
    """
    matchers = [fnmatch.translate(pattern) for pattern in exclude]
    found: List[str] = []
    for root, dirnames, filenames in os.walk(directory):
        dirnames[:] = sorted(dirnames)
        for name in sorted(filenames):
            if name in SKIP_NAMES:
                continue
            path = os.path.join(root, name)
            relative = os.path.relpath(path, directory)
            if any(re.match(matcher, relative) for matcher in matchers):
                continue
            found.append(path)
    return sorted(found, key=lambda path: os.path.relpath(path, directory))


def build_entries(directory: str, exclude: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    """Hash every non-excluded file and link it into the chain."""
    entries: List[Dict[str, Any]] = []
    chain = GENESIS
    for path in _iter_files(directory, exclude=list(exclude or ())):
        relative = os.path.relpath(path, directory)
        file_digest = digest_file(path)
        chain = chain_digest(chain, file_digest)
        entries.append(
            {
                "path": relative.replace(os.sep, "/"),
                "size": os.path.getsize(path),
                "sha256": file_digest,
                "chain": chain,
            }
        )
    return entries


def chain_head(entries: Iterable[Dict[str, Any]]) -> str:
    last = None
    for entry in entries:
        last = entry["chain"]
    return last or GENESIS


def attest(directory: str, note: Optional[str] = None,
           anchor: Optional[str] = None, exclude: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Write ``manifest.json`` (+ ``manifest.head``) for a directory."""
    directory = os.path.abspath(directory)
    if not os.path.isdir(directory):
        raise FileNotFoundError(f"not a directory: {directory}")

    exclude_list = [str(x) for x in (exclude or [])]
    entries = build_entries(directory, exclude=exclude_list)
    head = chain_head(entries)
    generated_at = time.strftime("%Y-%m-%dT%H:%M:%S%z")

    manifest = {
        "version": MANIFEST_VERSION,
        "generated_at": generated_at,
        "file_count": len(entries),
        "total_bytes": sum(entry["size"] for entry in entries),
        "chain_head": head,
        "note": note,
        "exclude": exclude_list,
        "entries": entries,
    }
    manifest_path = os.path.join(directory, MANIFEST_NAME)
    with open(manifest_path, "wb") as handle:
        handle.write(canonical_json(manifest) + b"\n")

    head_line = f"{head} {len(entries)} {generated_at}\n"
    head_path = os.path.join(directory, HEAD_NAME)
    with open(head_path, "w", encoding="utf-8") as handle:
        handle.write(head_line)
    if anchor:
        os.makedirs(os.path.dirname(os.path.abspath(anchor)) or ".", exist_ok=True)
        with open(anchor, "w", encoding="utf-8") as handle:
            handle.write(head_line)

    return {
        "directory": directory,
        "file_count": len(entries),
        "total_bytes": manifest["total_bytes"],
        "chain_head": head,
        "generated_at": generated_at,
        "manifest": manifest_path,
        "head": head_path,
        "anchor": os.path.abspath(anchor) if anchor else None,
    }


def _load_manifest(directory: str) -> Dict[str, Any]:
    path = os.path.join(directory, MANIFEST_NAME)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"no {MANIFEST_NAME} in {directory}; run `jocky attest` first")
    import json

    with open(path, "rb") as handle:
        raw = handle.read()
    manifest = json.loads(raw)
    # recomputation must be independent of the writer's formatting choices
    if canonical_json(manifest) + b"\n" != raw:
        raise ValueError(
            f"{MANIFEST_NAME} is not in canonical form — it was edited after being written"
        )
    return manifest


def verify(directory: str, key: Optional[bytes] = None,
           anchor: Optional[str] = None) -> Dict[str, Any]:
    """Recompute the chain and compare it with the stored manifest."""
    directory = os.path.abspath(directory)
    problems: List[str] = []
    try:
        manifest = _load_manifest(directory)
    except (FileNotFoundError, ValueError) as exc:
        return {"ok": False, "directory": directory, "errors": [str(exc)],
                "checked": 0, "missing": [], "modified": [], "added": []}

    recorded = {entry["path"]: entry for entry in manifest.get("entries", [])}
    exclude_patterns = manifest.get("exclude") or []
    current = {entry["path"]: entry for entry in build_entries(directory, exclude=exclude_patterns)}
    missing = sorted(set(recorded) - set(current))
    added = sorted(set(current) - set(recorded))
    modified = sorted(
        path for path in set(recorded) & set(current)
        if recorded[path]["sha256"] != current[path]["sha256"]
    )
    for path in missing:
        problems.append(f"missing file: {path}")
    for path in modified:
        problems.append(f"modified file: {path}")
    for path in added:
        problems.append(f"unchained file: {path}")

    recomputed_head = chain_head(entry for _, entry in sorted(current.items()))
    if recomputed_head != manifest.get("chain_head"):
        problems.append(
            "chain head mismatch: recomputed "
            f"{recomputed_head[:16]}… but manifest says {str(manifest.get('chain_head'))[:16]}…"
        )

    head_ok: Optional[bool] = None
    head_source = anchor or os.path.join(directory, HEAD_NAME)
    if os.path.isfile(head_source):
        with open(head_source, "r", encoding="utf-8") as handle:
            fields = handle.read().strip().split()
        head_ok = bool(fields) and fields[0] == manifest.get("chain_head")
        if not head_ok:
            problems.append(f"stored head does not match the manifest ({head_source})")
        elif len(fields) > 1 and fields[1].isdigit() and int(fields[1]) != len(recorded):
            problems.append("stored head file count does not match the manifest")
            head_ok = False
        elif len(fields) > 2 and fields[2] != manifest.get("generated_at"):
            problems.append("stored head timestamp does not match the manifest")
            head_ok = False
    else:
        problems.append(f"no {HEAD_NAME} found (looked at {head_source})")

    signature_ok: Optional[bool] = None
    signature_path = os.path.join(directory, SIGNATURE_NAME)
    if key is not None:
        if not os.path.isfile(signature_path):
            problems.append(f"no {SIGNATURE_NAME}: the manifest is unauthenticated")
            signature_ok = False
        else:
            import json
            try:
                with open(signature_path, encoding="utf-8") as handle:
                    record = json.load(handle)
                if not isinstance(record, dict):
                    raise ValueError("signature file must be a JSON mapping")
            except Exception as exc:
                problems.append(f"malformed {SIGNATURE_NAME}: {exc}")
                signature_ok = False
                record = None

            if record is not None:
                payload = f"{manifest.get('chain_head')}:{manifest.get('file_count')}:{manifest.get('generated_at')}:{manifest.get('note')}"
                expected = hmac.new(key, payload.encode(), "sha256").hexdigest()
                legacy = hmac.new(key, f"{manifest.get('chain_head')}:{manifest.get('file_count')}".encode(), "sha256").hexdigest()
                signature_ok = hmac.compare_digest(record.get("hmac", ""), expected) or hmac.compare_digest(record.get("hmac", ""), legacy)
                if not signature_ok:
                    problems.append("signature does not verify with the supplied key")
                elif record.get("key_id") != key_id(key):
                    problems.append("signature was made with a different key")
                    signature_ok = False
    return {
        "ok": not problems,
        "directory": directory,
        "checked": len(current),
        "file_count": manifest.get("file_count"),
        "chain_head": manifest.get("chain_head"),
        "head_matches": head_ok,
        "signature_valid": signature_ok,
        "missing": missing,
        "modified": modified,
        "added": added,
        "errors": problems,
    }


def sign_head(directory: str, key: Optional[bytes] = None,
              key_source: Optional[str] = None) -> Dict[str, Any]:
    """HMAC the chain head with an analyst-held key (analyst-side operation)."""
    key = key or load_key(key_source)
    if not key:
        raise ValueError(
            "no signing key: pass --key-file <path> or set JOCKY_EVIDENCE_KEY "
            "(hex encoding accepted)"
        )
    directory = os.path.abspath(directory)
    manifest = _load_manifest(directory)
    head = str(manifest.get("chain_head"))
    count = int(manifest.get("file_count", 0))
    payload = f"{head}:{count}:{manifest.get('generated_at')}:{manifest.get('note')}"
    mac = hmac.new(key, payload.encode(), "sha256").hexdigest()
    record = {
        "algorithm": "HMAC-SHA256",
        "key_id": key_id(key),
        "chain_head": head,
        "file_count": count,
        "signed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "hmac": mac,
    }
    path = os.path.join(directory, SIGNATURE_NAME)
    with open(path, "wb") as handle:
        handle.write(canonical_json(record) + b"\n")
    return {"directory": directory, "signature": path, **record}


def head_digest(directory: str) -> str:
    """Digest of the head line itself — handy for external timestamping."""
    path = os.path.join(directory, HEAD_NAME)
    with open(path, "rb") as handle:
        return digest_bytes(handle.read())
