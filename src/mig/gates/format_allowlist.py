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
import pathlib

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
#: Pickle-based / arbitrary-code weight formats — unsafe to load (CRITICAL/FAIL).
#: Includes pickle (.pkl/.bin/.pt/...) and the pickle-backed serializers
#: joblib/dill, all of which execute arbitrary code on deserialization.
UNSAFE_WEIGHT_FORMATS = {
    ".pkl",
    ".pickle",
    ".bin",
    ".pt",
    ".pth",
    ".ckpt",
    ".pte",
    ".joblib",
    ".dill",
}
#: Formats that *can* execute code on load depending on the loader (numpy
#: allow_pickle, Keras Lambda layers, TF custom ops, archives of checkpoints).
#: Flagged WARN → review, not hard reject.
CODE_ON_LOAD_FORMATS = {
    ".npy",
    ".npz",
    ".h5",
    ".hdf5",
    ".keras",
    ".msgpack",
    ".pb",
    ".nemo",
    ".mar",
    ".pt2",
}
#: Compression/archive layers stripped when classifying a compound extension,
#: and flagged on their own (an archive can conceal a pickle).
_ARCHIVE_SUFFIXES = {
    ".gz",
    ".bz2",
    ".xz",
    ".zst",
    ".lz4",
    ".zip",
    ".tar",
    ".tgz",
    ".7z",
}
#: Max bytes we will read from a config file (it is text metadata, not weights).
_MAX_CONFIG_BYTES = 8 * 1024 * 1024


def _read_config(quarantine_path: str, files: list[str]) -> dict[str, object]:
    """Read a model ``config.json`` as bounded text (returns {} if absent/bad).

    Catches ``ValueError`` (covers JSON/Unicode decode errors) **and**
    ``RecursionError`` — a deeply-nested JSON document raises the latter, and if
    it escaped it would turn the whole gate into an ERROR, silently discarding
    the CRITICAL pickle findings already collected and downgrading a REJECT.
    """
    for rel in files:
        if os.path.basename(rel) == "config.json":
            path = os.path.join(quarantine_path, rel)
            try:
                if os.path.getsize(path) > _MAX_CONFIG_BYTES:
                    return {}
                with open(path, encoding="utf-8") as handle:
                    parsed = json.loads(handle.read())
            except (OSError, ValueError, RecursionError):
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

        allowed: list[str] = []
        unsafe: list[str] = []
        code_on_load: list[str] = []
        archives: list[str] = []
        for rel in files:
            category = _classify(rel)
            if category == "allowed":
                allowed.append(rel)
            elif category == "unsafe":
                unsafe.append(rel)
            elif category == "code_on_load":
                code_on_load.append(rel)
            elif category == "archive":
                archives.append(rel)

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

        for rel in code_on_load:
            findings.append(
                Finding(
                    gate_id=GATE_ID,
                    severity=Severity.MEDIUM,
                    code="code_on_load_format",
                    message=(
                        f"file {rel!r} can execute code on load depending on the "
                        "loader (numpy allow_pickle / Keras Lambda); needs review"
                    ),
                    location=rel,
                )
            )

        for rel in archives:
            findings.append(
                Finding(
                    gate_id=GATE_ID,
                    severity=Severity.MEDIUM,
                    code="archive_format",
                    message=(
                        f"archive {rel!r} may conceal an unsafe payload; its "
                        "contents are not inspected by the format gate"
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

        if not (allowed or unsafe or code_on_load or archives):
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


def _classify(rel: str) -> str:
    """Classify a file by its (compound-aware) extension.

    Strips trailing archive/compression layers so ``model.pkl.gz`` is recognised
    as the pickle it is, rather than as a ``.gz`` and waved through.
    """
    suffixes = [s.lower() for s in pathlib.PurePath(rel).suffixes]
    inner = next((s for s in reversed(suffixes) if s not in _ARCHIVE_SUFFIXES), "")
    if inner in UNSAFE_WEIGHT_FORMATS:
        return "unsafe"
    if inner in CODE_ON_LOAD_FORMATS:
        return "code_on_load"
    if inner in ALLOWED_WEIGHT_FORMATS:
        return "allowed"
    if any(s in _ARCHIVE_SUFFIXES for s in suffixes):
        return "archive"
    return "other"


def _status_for(findings: list[Finding]) -> GateStatus:
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities or Severity.HIGH in severities:
        return GateStatus.FAIL
    if findings:
        return GateStatus.WARN
    return GateStatus.PASS
