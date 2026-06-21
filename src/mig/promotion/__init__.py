"""Gated trusted-store promotion (Zone 3) — where MIG crosses the decision boundary.

This package is the ONLY sanctioned trusted-store writer (I6). It lives OUTSIDE
``core/`` and ``evidence/`` (the ingest path), which therefore stay write-free and
cannot even import it — promotion is reachable only through the gated
:func:`promote_artifact`, which re-verifies the signed attestation and consults a
deny-overrides promotion gate before the single store write.
"""

from __future__ import annotations

from mig.promotion.errors import PromotionError
from mig.promotion.gate import (
    CompositePromotionGate,
    EmbeddedPromotionGate,
    PromotionDecision,
    PromotionGate,
    make_promotion_gate,
)
from mig.promotion.promote import PromotionResult, promote_artifact
from mig.promotion.stores import make_trusted_store

__all__ = [
    "promote_artifact",
    "PromotionResult",
    "PromotionError",
    "PromotionGate",
    "PromotionDecision",
    "EmbeddedPromotionGate",
    "CompositePromotionGate",
    "make_promotion_gate",
    "make_trusted_store",
]
