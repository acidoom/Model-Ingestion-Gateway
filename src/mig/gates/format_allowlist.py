"""Format-allowlist gate (cheap, static).

For weight-bearing model artifacts, allow ``safetensors``/``gguf`` and reject
pickle-based weight formats outright (``.pkl``/``.pt``/``.bin``/…) — the classic
arbitrary-code-execution-on-load vector. Executable *companions* (custom
``modeling_*.py``, ``trust_remote_code``/``auto_map`` in ``config.json``) are
flagged as WARN findings that route to the static-code gate (PR4) and behavioral
analysis; they are not loaded or executed here (I1).
"""

from __future__ import annotations

import json
import os

from mig import __version__
from mig.core.artifact import Artifact, ArtifactType
from mig.core.verdict import (
    Finding,
    GateCost,
    GateResult,
    GateStatus,
    RigorLevel,
    Severity,
)

GATE_ID = "format_allowlist"

#: Safe, inspectable weight formats for models/adapters.
ALLOWED_WEIGHT_FORMATS = {".safetensors", ".gguf"}
#: Pickle-based / arbitrary-code weight formats — unsafe to load.
UNSAFE_WEIGHT_FORMATS = {".pkl", ".pickle", ".bin", ".pt", ".pth", ".ckpt", ".pte"}
#: Max bytes we will read from a config file (it is text metadata, not weights).
_MAX_CONFIG_BYTES = 8 * 1024 * 1024


def _read_config(quarantine_path: str, files: list[str]) -> dict[str, object]:
    """Read a model ``config.json`` as bounded text (returns {} if absent/bad)."""
    for rel in files:
        if os.path.basename(rel) == "config.json":
            path = os.path.join(quarantine_path, rel)
            try:
                if os.path.getsize(path) > _MAX_CONFIG_BYTES:
                    return {}
                with open(path, encoding="utf-8") as handle:
                    parsed = json.loads(handle.read())
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                return {}
            return parsed if isinstance(parsed, dict) else {}
    return {}


class FormatAllowlistGate:
    """Allow safe model weight formats; flag pickle formats and code companions."""

    id = GATE_ID
    cost = GateCost.CHEAP
    applies_to = frozenset(
        {ArtifactType.MODEL, ArtifactType.ADAPTER, ArtifactType.EMBEDDING_MODEL}
    )

    def evaluate(self, artifact: Artifact, ctx: object) -> GateResult:
        findings: list[Finding] = []
        files = list(artifact.files)

        allowed = [f for f in files if _ext(f) in ALLOWED_WEIGHT_FORMATS]
        unsafe = [f for f in files if _ext(f) in UNSAFE_WEIGHT_FORMATS]

        for rel in unsafe:
            findings.append(
                Finding(
                    gate_id=GATE_ID,
                    severity=Severity.CRITICAL,
                    code="unsafe_serialization_format",
                    message=(
                        f"weight file {rel!r} uses a pickle-based format that "
                        "executes arbitrary code on load; use safetensors/gguf"
                    ),
                    location=rel,
                )
            )

        # Executable companions — flag for the static-code gate (PR4), do NOT run.
        for rel in files:
            base = os.path.basename(rel)
            if base.endswith(".py"):
                findings.append(
                    Finding(
                        gate_id=GATE_ID,
                        severity=Severity.MEDIUM,
                        code="custom_model_code",
                        message=(
                            f"executable companion {rel!r} ships with the model; "
                            "requires static-code review (PR4) before trust"
                        ),
                        location=rel,
                    )
                )

        config = _read_config(artifact.quarantine_path, files)
        if config.get("trust_remote_code") or "auto_map" in config:
            findings.append(
                Finding(
                    gate_id=GATE_ID,
                    severity=Severity.MEDIUM,
                    code="trust_remote_code",
                    message=(
                        "config.json enables custom code (trust_remote_code/"
                        "auto_map); the model executes its own code on load"
                    ),
                    location="config.json",
                )
            )

        if not allowed and not unsafe:
            findings.append(
                Finding(
                    gate_id=GATE_ID,
                    severity=Severity.MEDIUM,
                    code="no_recognised_weight_format",
                    message="no safetensors/gguf weights found; format unverified",
                )
            )

        status = _status_for(findings)
        return GateResult(
            gate_id=GATE_ID,
            status=status,
            rigor=RigorLevel.STATIC,
            findings=findings,
            scanner_name="mig.format_allowlist",
            scanner_version=__version__,
            evidence={
                "allowed_weight_files": allowed,
                "unsafe_weight_files": unsafe,
            },
        )


def _ext(rel: str) -> str:
    return os.path.splitext(rel)[1].lower()


def _status_for(findings: list[Finding]) -> GateStatus:
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities or Severity.HIGH in severities:
        return GateStatus.FAIL
    if findings:
        return GateStatus.WARN
    return GateStatus.PASS
