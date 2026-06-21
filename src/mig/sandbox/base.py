"""Shared helpers for sandbox implementations.

Real sandboxes (Docker in PR6a, gVisor/Firecracker in PR6b) translate their
:class:`~mig.sandbox.spec.SandboxObservation` into a behavioral
:class:`~mig.core.verdict.GateResult`. That translation is centralised here so
every backend reports rigor/status consistently.
"""

from __future__ import annotations

from mig.core.verdict import GateResult
from mig.sandbox.spec import SandboxObservation

#: The canonical gate id for the behavioral stage.
BEHAVIORAL_GATE_ID = "behavioral"


def observation_to_result(
    observation: SandboxObservation,
    *,
    scanner_name: str,
    scanner_version: str | None = None,
    duration_ms: int | None = None,
) -> GateResult:
    """Fold a :class:`SandboxObservation` into a behavioral :class:`GateResult`.

    The result's ``rigor`` and ``status`` come straight from the observation, so
    a NoopSandbox observation (SKIPPED / NONE) cannot be laundered into a
    behavioral pass.
    """
    return GateResult(
        gate_id=BEHAVIORAL_GATE_ID,
        status=observation.status,
        rigor=observation.rigor,
        findings=list(observation.findings),
        scanner_name=scanner_name,
        scanner_version=scanner_version,
        duration_ms=duration_ms,
        evidence={
            "syscalls": list(observation.syscalls),
            "dns_queries": list(observation.dns_queries),
            "network_attempts": list(observation.network_attempts),
            "exit_code": observation.exit_code,
            # The raw harness blob is artifact-influenced — namespace it so it can
            # never overwrite the sanitized keys above (attestation integrity).
            "raw": dict(observation.raw),
        },
    )
