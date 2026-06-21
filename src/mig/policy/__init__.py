"""Policy seam.

The declarative YAML schema + embedded evaluator land in PR5; the OPA adapter
is the deferred enforcement seam over the signed attestation (ADR-003).
"""

from __future__ import annotations

from mig.policy.engine import default_decision, evaluate
from mig.policy.schema import Policy

__all__ = ["Policy", "default_decision", "evaluate"]
