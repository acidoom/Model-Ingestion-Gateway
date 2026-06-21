"""Serialization-safety gate — wraps ``picklescan`` (ADR-005, I1).

``picklescan`` statically disassembles pickle opcodes (via ``pickletools``) to
find the ``GLOBAL``/``REDUCE`` references an unpickle would execute. It **never
unpickles or executes** the artifact, so wrapping it honours I1 — MIG inspects
opcodes over bytes, it does not deserialize.

``picklescan`` is an opt-in dependency (``pip install 'mig[scanners]'``). If it
is not installed **and the artifact contains pickle-bearing files**, the gate
returns ``WARN`` (→ review) rather than a silently-non-blocking SKIPPED, so an
un-scanned pickle can never slip to APPROVE; with no pickle files there is
nothing to scan and it passes.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

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
from mig.storage.quarantine import safe_join

if TYPE_CHECKING:
    from mig.core.artifact import Artifact

GATE_ID = "serialization_safety"

#: Extensions picklescan can meaningfully scan (pickle, pytorch-zip, numpy).
_SCANNABLE = {
    ".pkl",
    ".pickle",
    ".bin",
    ".pt",
    ".pth",
    ".ckpt",
    ".pt2",
    ".pte",
    ".npy",
    ".npz",
    ".joblib",
    ".dill",
    ".model",
    ".pdparams",
    ".dat",
    ".data",
}


def _load_picklescan() -> tuple[Any, str]:
    """Return ``(scanner_module, version)`` or ``(None, "")`` if not installed."""
    try:
        import importlib.metadata as importlib_metadata

        from picklescan import scanner
    except ImportError:
        return None, ""
    try:
        version = importlib_metadata.version("picklescan")
    except importlib_metadata.PackageNotFoundError:  # pragma: no cover
        version = "unknown"
    return scanner, version


class SerializationSafetyGate:
    """Scan pickle-bearing files for code-execution opcodes via picklescan."""

    id = GATE_ID
    cost = GateCost.CHEAP
    applies_to = frozenset(ArtifactType)  # pickles can hide in any artifact

    def evaluate(self, artifact: Artifact, ctx: object) -> GateResult:
        scannable = [
            rel
            for rel in artifact.files
            if os.path.splitext(rel)[1].lower() in _SCANNABLE
        ]
        scanner, version = _load_picklescan()

        if scanner is None:
            # If there ARE pickle-bearing files we could not scan, that is a
            # real gap → WARN (review), not a silently-non-blocking SKIPPED.
            # Attributed to MIG's own gate (picklescan version is unknown here).
            if not scannable:
                return GateResult(
                    gate_id=GATE_ID,
                    status=GateStatus.PASS,
                    rigor=RigorLevel.STATIC,
                    scanner_name="mig.serialization_safety",
                    scanner_version=__version__,
                )
            return GateResult(
                gate_id=GATE_ID,
                status=GateStatus.WARN,
                rigor=RigorLevel.STATIC,
                findings=[
                    Finding(
                        gate_id=GATE_ID,
                        severity=Severity.MEDIUM,
                        code="serialization_scan_unavailable",
                        message=(
                            f"{len(scannable)} pickle-bearing file(s) were NOT "
                            "opcode-scanned; install 'mig[scanners]' for picklescan"
                        ),
                    )
                ],
                scanner_name="mig.serialization_safety",
                scanner_version=__version__,
                evidence={"unscanned_files": scannable},
            )

        findings: list[Finding] = []
        for rel in scannable:
            try:
                result = scanner.scan_file_path(safe_join(artifact.quarantine_path, rel))
            except Exception as exc:  # one unscannable file must not abort the gate
                findings.append(
                    Finding(
                        gate_id=GATE_ID,
                        severity=Severity.HIGH,
                        code="serialization_scan_error",
                        message=f"picklescan failed on {rel!r}: {type(exc).__name__}",
                        location=rel,
                    )
                )
                continue
            if getattr(result, "scan_err", False):
                findings.append(
                    Finding(
                        gate_id=GATE_ID,
                        severity=Severity.HIGH,
                        code="serialization_scan_error",
                        message=f"picklescan could not parse {rel!r}",
                        location=rel,
                    )
                )
            for entry in getattr(result, "globals", []):
                findings.append(_finding_for_global(entry, rel))

        return GateResult(
            gate_id=GATE_ID,
            status=_status_for(findings),
            rigor=RigorLevel.STATIC,
            findings=findings,
            scanner_name="picklescan",
            scanner_version=version,
            evidence={"scanned_files": scannable},
        )


def _finding_for_global(entry: Any, rel: str) -> Finding:
    module = getattr(entry, "module", "?")
    name = getattr(entry, "name", "?")
    safety = getattr(getattr(entry, "safety", None), "name", "Unknown")
    if safety == "Dangerous":
        severity, code = Severity.CRITICAL, "unsafe_pickle_global"
    elif safety == "Suspicious":
        severity, code = Severity.MEDIUM, "suspicious_pickle_global"
    else:  # Innocuous still recorded as INFO for traceability
        severity, code = Severity.INFO, "pickle_global"
    return Finding(
        gate_id=GATE_ID,
        severity=severity,
        code=code,
        message=f"pickle references {module}.{name} ({safety.lower()})",
        location=rel,
        metadata={"module": module, "name": name, "safety": safety},
    )


def _status_for(findings: list[Finding]) -> GateStatus:
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities or Severity.HIGH in severities:
        return GateStatus.FAIL
    if Severity.MEDIUM in severities or Severity.LOW in severities:
        return GateStatus.WARN
    return GateStatus.PASS
