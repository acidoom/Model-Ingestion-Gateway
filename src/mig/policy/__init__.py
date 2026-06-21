"""Policy seam — embedded declarative engine (PR5).

The embedded engine owns the *ingest* decision; the OPA adapter (the deferred
enforcement seam over the signed attestation, ADR-003) owns *promotion*-time
enforcement and lands with PR8.
"""

from __future__ import annotations

from mig.policy.engine import default_decision, evaluate, matched_rules
from mig.policy.loader import load_policy
from mig.policy.schema import (
    Policy,
    PolicyAction,
    PolicyError,
    PolicyRule,
)

__all__ = [
    "Policy",
    "PolicyAction",
    "PolicyRule",
    "PolicyError",
    "default_decision",
    "evaluate",
    "matched_rules",
    "load_policy",
]
