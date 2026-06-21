"""Streaming, bounded-memory content hashing (QS-4).

Digests are computed in fixed-size chunks so a 30 GB model is hashed in bounded
RAM — never loaded whole. Hashing reads bytes only; it never deserializes (I1).

The tree digest is a deterministic hash over ``(relative_path, file_digest)``
pairs in sorted order, so the same set of files always yields the same digest
regardless of filesystem iteration order.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterable

#: Read granularity for streaming hashes (1 MiB).
CHUNK_SIZE = 1024 * 1024

#: Algorithm label prefix on every digest we emit.
_ALGO = "sha256"

_BARE_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def normalize_digest(value: str) -> str:
    """Canonicalise a digest to ``algo:lowerhex``.

    Accepts a bare 64-char hex string (as printed by ``sha256sum``) and assumes
    sha256, so a correct pin in either form compares equal.
    """
    text = value.strip()
    if _BARE_HEX64.match(text):
        return f"{_ALGO}:{text.lower()}"
    algo, sep, hexpart = text.partition(":")
    if sep:
        return f"{algo.lower()}:{hexpart.lower()}"
    return text.lower()


def digests_match(computed: str, expected: str) -> bool:
    """True if two digests are equal after normalisation (algo/case/prefix)."""
    return normalize_digest(computed) == normalize_digest(expected)


def hash_file(path: str, *, chunk_size: int = CHUNK_SIZE) -> str:
    """Return ``"sha256:<hex>"`` for a file, read in bounded chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return f"{_ALGO}:{digest.hexdigest()}"


def hash_tree(root: str, files: Iterable[str]) -> str:
    """Return a deterministic ``"sha256:<hex>"`` digest over a set of files.

    ``files`` are paths relative to ``root``. The digest binds each file's
    relative path to its content hash, so neither reordering nor renaming can
    collide with a different tree.
    """
    digest = hashlib.sha256()
    for rel in sorted(files):
        file_digest = hash_file(os.path.join(root, rel))
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
    return f"{_ALGO}:{digest.hexdigest()}"
