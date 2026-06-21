"""Evidence bundle + attestation seam.

The :class:`Attestation` contract ships in PR1; bundle assembly and
sigstore/cosign signing land in PR7.
"""

from __future__ import annotations

from mig.evidence.attestation import Attestation

__all__ = ["Attestation"]
