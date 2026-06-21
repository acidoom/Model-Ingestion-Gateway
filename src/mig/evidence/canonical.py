"""Canonical JSON — the deterministic byte encoding for ALL signed bytes.

Kept strictly separate from :func:`mig.core.serde.to_json` (which stays
``sort_keys=False`` for human-readable reports): the bytes a signature commits to
must be stable and reproducible regardless of dict insertion order, so a tweak to
report formatting can never change what was signed.

NaN/Infinity and non-string mapping keys are **rejected**, never silently
coerced — so artifact-controlled metadata cannot make two distinct inputs encode
to the same signed bytes (e.g. ``{5: ...}`` vs ``{"5": ...}``), nor produce
non-canonical output. Stdlib only (I10).
"""

from __future__ import annotations

import dataclasses
import json
import math
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any


def canonicalize(obj: Any) -> Any:
    """Project a dataclass/enum graph to JSON-safe primitives, rejecting anything
    that would make the canonical encoding ambiguous or non-reproducible.

    This is the projection the SIGNED path must use: callers that pre-flatten via
    :func:`mig.core.serde.to_jsonable` (which str-coerces mapping keys) would
    sneak a key collision past these guards, so anything that becomes signed bytes
    runs through here directly.
    """
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {
            f.name: canonicalize(getattr(obj, f.name)) for f in dataclasses.fields(obj)
        }
    if isinstance(obj, Enum):
        return canonicalize(obj.value)
    if isinstance(obj, Mapping):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            # Reject non-str keys (not str-coerce): '{5: ...}' and '{"5": ...}'
            # must NOT collapse to the same signed bytes.
            if not isinstance(key, str):
                raise ValueError(
                    f"non-string mapping key {key!r} is not canonically encodable"
                )
            out[key] = canonicalize(value)
        return out
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (bytes, bytearray, memoryview)):
        raise ValueError("raw bytes are not canonically encodable; encode first")
    if isinstance(obj, Sequence):
        return [canonicalize(value) for value in obj]
    if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
        raise ValueError("non-finite float is not canonically encodable")
    return obj


def canonical_json(obj: Any) -> str:
    """A deterministic JSON string: sorted keys, compact, UTF-8, no NaN/Inf."""
    return json.dumps(
        canonicalize(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(obj: Any) -> bytes:
    """The exact bytes signed/verified — :func:`canonical_json` as UTF-8."""
    return canonical_json(obj).encode("utf-8")
