"""Policy identity — scaffolding stub.

The declarative YAML schema and the embedded evaluator land in **PR5** (PRD §8).
For PR1 this provides only the identity fields the rest of the contract refers
to: a policy has an ``id`` and a ``version``, both of which flow into every
:class:`~mig.evidence.attestation.Attestation` (I5).

Deliberately minimal: PR1 is decision-*model*, not decision-*logic*.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Policy:
    """A named, versioned policy. Rule evaluation arrives in PR5."""

    id: str
    version: str
    rules: Sequence[object] = field(default_factory=tuple)  # typed in PR5
