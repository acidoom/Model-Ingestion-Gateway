"""License / metadata gate — records the artifact's license posture.

A *missing* license is recorded as INFO (traceability) and does **not** by
itself force review — many legitimate models ship without an explicit license,
and over-blocking on it would make every such model REVIEW_REQUIRED. A license
that is explicitly restrictive (non-commercial / research-only / proprietary) is
a WARN so a human confirms the use is permitted.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from mig import __version__
from mig.core.artifact import ArtifactType
from mig.core.verdict import (
    Finding,
    GateCost,
    GateResult,
    GateStatus,
    RigorLevel,
    Severity,
)
from mig.gates._common import read_config_json

if TYPE_CHECKING:
    from mig.core.artifact import Artifact

GATE_ID = "license_metadata"

#: Substrings that mark a license as use-restricted (warrants human review).
_RESTRICTIVE_MARKERS = (
    "noncommercial",
    "non-commercial",
    "cc-by-nc",
    "research-only",
    "research only",
    "proprietary",
    "no-derivatives",
    "rail",  # Responsible-AI licenses carry field-of-use restrictions
)


def _has_license_file(files: list[str]) -> bool:
    for rel in files:
        base = os.path.basename(rel).upper()
        if base.startswith(("LICENSE", "COPYING", "LICENCE")):
            return True
    return False


class LicenseMetadataGate:
    """Record license presence/type (INFO for missing, WARN for restrictive)."""

    id = GATE_ID
    cost = GateCost.CHEAP
    applies_to = frozenset(ArtifactType)

    def evaluate(self, artifact: Artifact, ctx: object) -> GateResult:
        files = list(artifact.files)
        config = read_config_json(artifact.quarantine_path, files)
        license_id = config.get("license")
        has_file = _has_license_file(files)

        findings: list[Finding] = []
        if not has_file and not license_id:
            findings.append(
                Finding(
                    gate_id=GATE_ID,
                    severity=Severity.INFO,
                    code="no_license",
                    message="no LICENSE file or config license field found",
                )
            )
        elif license_id and any(
            marker in str(license_id).lower() for marker in _RESTRICTIVE_MARKERS
        ):
            findings.append(
                Finding(
                    gate_id=GATE_ID,
                    severity=Severity.MEDIUM,
                    code="restrictive_license",
                    message=(
                        f"license {license_id!r} restricts use; confirm it is allowed"
                    ),
                    location="config.json",
                    metadata={"license": str(license_id)},
                )
            )

        return GateResult(
            gate_id=GATE_ID,
            status=_status_for(findings),
            rigor=RigorLevel.STATIC,
            findings=findings,
            scanner_name="mig.license_metadata",
            scanner_version=__version__,
            evidence={"license": str(license_id) if license_id else None},
        )


def _status_for(findings: list[Finding]) -> GateStatus:
    # INFO never changes the decision; MEDIUM (restrictive) → WARN/review.
    if any(f.severity.value >= Severity.MEDIUM.value for f in findings):
        return GateStatus.WARN
    return GateStatus.PASS
