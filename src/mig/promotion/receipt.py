"""The promotion receipt — an operational record co-located with each CAS entry.

Unsigned by default (the persisted ``attestation.dsse.json`` is the tamper-evident
cryptographic core); the receipt pins ``attestation_digest`` so the record names
exactly which signed attestation authorised the promotion. Serialised via
:func:`canonical_bytes` so it is reproducible and diffable. Secrets are never
written.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

RECEIPT_SCHEMA = "https://mig.dev/promotion-receipt/v1"


@dataclass(frozen=True)
class PromotionReceipt:
    """The canonical record written into a CAS entry as ``receipt.json``."""

    schema: str
    digest: str  # the re-bound CAS key, "sha256:<hex>"
    store_uri: str
    subject_name: str
    artifact_type: str
    decision: str
    verification: Mapping[str, Any]
    gate: Mapping[str, Any]
    attestation_digest: str  # sha256 of the canonical signed envelope bytes
    policy: Mapping[str, Any]
    mig_version: str
    promoted_at: str


def build_receipt(
    *,
    digest: str,
    store_uri: str,
    subject_name: str,
    artifact_type: str,
    decision: str,
    verification: Mapping[str, Any],
    gate: Mapping[str, Any],
    attestation_digest: str,
    policy: Mapping[str, Any],
    mig_version: str,
    promoted_at: str,
) -> PromotionReceipt:
    """Assemble a :class:`PromotionReceipt`."""
    return PromotionReceipt(
        schema=RECEIPT_SCHEMA,
        digest=digest,
        store_uri=store_uri,
        subject_name=subject_name,
        artifact_type=artifact_type,
        decision=decision,
        verification=dict(verification),
        gate=dict(gate),
        attestation_digest=attestation_digest,
        policy=dict(policy),
        mig_version=mig_version,
        promoted_at=promoted_at,
    )


def gate_record(allow: bool, engine: str, reasons: Sequence[str]) -> dict[str, Any]:
    """A small jsonable view of a gate decision for the receipt/audit."""
    return {"allow": allow, "engine": engine, "reasons": list(reasons)}
