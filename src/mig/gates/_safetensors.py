"""Hardened safetensors header reader (invariant I2).

Parses the safetensors header — an 8-byte little-endian length prefix followed
by that many bytes of JSON metadata — **without ever deserializing tensor
data**. The parser is defensive against the adversarial inputs I2 calls out:

* an oversized declared header length (integer overflow / over-allocation),
* a declared length that runs past the end of the file,
* a truncated file, and
* a header whose JSON is malformed or is not an object.

Only the header bytes are read (bounded by :data:`MAX_HEADER_BYTES`); tensor
payload bytes are never touched, so this is safe to run on untrusted artifacts.
"""

from __future__ import annotations

import json
import os
import struct

#: Hard cap on the declared header length we will read (128 MiB). A real
#: safetensors header is kilobytes; anything near this cap is adversarial.
MAX_HEADER_BYTES = 128 * 1024 * 1024

#: Bytes of the little-endian uint64 length prefix.
_PREFIX_BYTES = 8


class SafetensorsError(ValueError):
    """Raised when a file is not a well-formed, in-bounds safetensors file."""


def read_safetensors_header(path: str) -> dict[str, object]:
    """Return the parsed safetensors header dict, reading header bytes only.

    Raises :class:`SafetensorsError` on any malformed/adversarial input. Never
    reads or deserializes tensor data (I1/I2).
    """
    size = os.path.getsize(path)
    if size < _PREFIX_BYTES:
        raise SafetensorsError("file too small to contain a header length prefix")

    with open(path, "rb") as handle:
        (declared,) = struct.unpack("<Q", handle.read(_PREFIX_BYTES))
        if declared == 0:
            raise SafetensorsError("zero-length header")
        if declared > MAX_HEADER_BYTES:
            raise SafetensorsError(
                f"declared header length {declared} exceeds cap {MAX_HEADER_BYTES}"
            )
        if _PREFIX_BYTES + declared > size:
            raise SafetensorsError(
                f"declared header length {declared} runs past end of file ({size} bytes)"
            )
        raw = handle.read(declared)
    if len(raw) != declared:
        raise SafetensorsError("header truncated: fewer bytes than declared")

    try:
        header = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SafetensorsError(f"invalid JSON header: {exc}") from exc
    if not isinstance(header, dict):
        raise SafetensorsError("header is not a JSON object")
    return header


def tensor_names(header: dict[str, object]) -> list[str]:
    """Tensor entry names in a header (everything but the ``__metadata__`` key)."""
    return [key for key in header if key != "__metadata__"]
