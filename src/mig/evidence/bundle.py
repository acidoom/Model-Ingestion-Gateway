"""The evidence bundle — a portable archival record (``evidence-bundle/v1``).

A bundle is the signed DSSE envelope (the AUTHENTICATED core) plus the full
:class:`Verdict` and run metadata as *unsigned* descriptive context for humans
and triage. Only the envelope is cryptographically protected — ``mig verify``
reads ONLY ``bundle.envelope`` and re-binds against the live artifact digest,
never against the unsigned verdict mirror, so the descriptive copy can never
launder a tampered decision.

Written via :func:`mig.evidence.canonical.canonical_bytes`, so the bundle is
reproducible and diffable. Decision-only: writes only caller-chosen paths (I6).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from mig.core.serde import to_jsonable
from mig.evidence.canonical import canonical_bytes
from mig.evidence.dsse import encode_envelope

if TYPE_CHECKING:
    from mig.core.verdict import Verdict
    from mig.evidence.dsse import Envelope

#: Schema URI for the evidence bundle.
BUNDLE_SCHEMA = "https://mig.dev/evidence-bundle/v1"


def build_bundle(
    verdict: Verdict,
    envelope: Envelope,
    *,
    mig_version: str,
    created_at: str,
    run_meta: Mapping[str, Any],
) -> dict[str, Any]:
    """Assemble the bundle dict (schema + run + full verdict + signed envelope)."""
    return {
        "schema": BUNDLE_SCHEMA,
        "mig_version": mig_version,
        "created_at": created_at,
        "run": dict(run_meta),
        "verdict": to_jsonable(verdict),
        "envelope": encode_envelope(envelope),
    }


def bundle_bytes(bundle: Mapping[str, Any]) -> bytes:
    """The bundle as canonical (deterministic) JSON bytes."""
    return canonical_bytes(bundle)


def write_bundle(path: str, bundle: Mapping[str, Any]) -> None:
    """Write a bundle to ``path`` as canonical JSON."""
    with open(path, "wb") as handle:
        handle.write(bundle_bytes(bundle))


def load_bundle(path: str) -> dict[str, Any]:
    """Read and minimally validate a bundle file."""
    with open(path, encoding="utf-8") as handle:
        data: Any = json.load(handle)
    if not isinstance(data, dict) or "envelope" not in data:
        raise ValueError(f"{path!r} is not an evidence bundle (no 'envelope')")
    return data
