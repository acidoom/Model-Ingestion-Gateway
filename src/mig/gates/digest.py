"""Digest / manifest gate (cheap, static).

Confirms the artifact's content digest (and verifies it against a pinned
``expected_digest`` when present), and builds a manifest by parsing safetensors
headers — *header bytes only*, never tensor data (I2). A malformed/adversarial
safetensors header fails the gate; an unpinned reference is noted, not failed.
"""

from __future__ import annotations

import os

from mig import __version__
from mig.core.artifact import Artifact, ArtifactType
from mig.core.hashing import digests_match
from mig.core.verdict import (
    Finding,
    GateCost,
    GateResult,
    GateStatus,
    RigorLevel,
    Severity,
)
from mig.gates._safetensors import (
    SafetensorsError,
    read_safetensors_header,
    tensor_names,
)

GATE_ID = "digest"


class DigestGate:
    """Verify/record the content digest and parse safetensors manifests (I2)."""

    id = GATE_ID
    cost = GateCost.CHEAP
    applies_to = frozenset(ArtifactType)  # every artifact has a digest/manifest

    def evaluate(self, artifact: Artifact, ctx: object) -> GateResult:
        findings: list[Finding] = []
        evidence: dict[str, object] = {"digest": artifact.digest}

        expected = artifact.ref.expected_digest
        if expected and not digests_match(artifact.digest or "", expected):
            findings.append(
                Finding(
                    gate_id=GATE_ID,
                    severity=Severity.CRITICAL,
                    code="digest_mismatch",
                    message=(
                        f"computed digest {artifact.digest!r} does not match the "
                        f"pinned digest {expected!r}"
                    ),
                )
            )
        elif not expected:
            findings.append(
                Finding(
                    gate_id=GATE_ID,
                    severity=Severity.INFO,
                    code="unpinned_reference",
                    message="reference is not digest-pinned; recorded computed digest",
                )
            )

        manifest: dict[str, object] = {}
        for rel in artifact.files:
            if not rel.endswith(".safetensors"):
                continue
            path = os.path.join(artifact.quarantine_path, rel)
            try:
                header = read_safetensors_header(path)
            except SafetensorsError as exc:
                findings.append(
                    Finding(
                        gate_id=GATE_ID,
                        severity=Severity.HIGH,
                        code="malformed_safetensors",
                        message=f"{rel}: {exc}",
                        location=rel,
                    )
                )
                continue
            manifest[rel] = {"tensor_count": len(tensor_names(header))}
        if manifest:
            evidence["safetensors_manifest"] = manifest

        return GateResult(
            gate_id=GATE_ID,
            status=_status_for(findings),
            rigor=RigorLevel.STATIC,
            findings=findings,
            scanner_name="mig.digest",
            scanner_version=__version__,
            evidence=evidence,
        )


def _status_for(findings: list[Finding]) -> GateStatus:
    if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
        return GateStatus.FAIL
    return GateStatus.PASS
