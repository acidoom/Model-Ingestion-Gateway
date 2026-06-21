"""Secrets gate — high-signal credential detection over text files.

Scans the artifact's text files for hard-coded credentials (cloud keys, tokens,
private-key blocks). Findings are **WARN, not FAIL**: secret detection is a
heuristic and a hit warrants human review, not an automatic reject (a false
positive must not block a clean artifact). A maintained backend (detect-secrets)
can be layered in later; this is the dependency-free high-confidence core.
"""

from __future__ import annotations

import re
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
from mig.gates._common import read_text

if TYPE_CHECKING:
    from mig.core.artifact import Artifact

GATE_ID = "secrets"

_TEXT_EXTENSIONS = {
    ".py",
    ".json",
    ".txt",
    ".md",
    ".yaml",
    ".yml",
    ".cfg",
    ".ini",
    ".env",
    ".toml",
    ".sh",
    ".js",
    ".ts",
    ".properties",
    ".conf",
}

#: (code, compiled pattern, severity). Severities are for prominence only —
#: the gate status is capped at WARN regardless.
_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.HIGH),
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
        Severity.HIGH,
    ),
    ("github_token", re.compile(r"\bgh[posu]_[A-Za-z0-9]{36,}\b"), Severity.HIGH),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), Severity.HIGH),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
    (
        "generic_secret_assignment",
        re.compile(
            # Optional closing quote on the key handles JSON ("token": "value")
            # as well as env / Python / YAML (token = "value").
            r"(?i)(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)"
            r"['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-/+]{16,}['\"]"
        ),
        Severity.MEDIUM,
    ),
]


class SecretsGate:
    """Flag hard-coded credentials in text files (WARN-only)."""

    id = GATE_ID
    cost = GateCost.CHEAP
    applies_to = frozenset(ArtifactType)

    def evaluate(self, artifact: Artifact, ctx: object) -> GateResult:
        findings: list[Finding] = []
        for rel in artifact.files:
            ext = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
            if ext not in _TEXT_EXTENSIONS:
                continue
            text = read_text(artifact.quarantine_path, rel)
            if text is None:
                continue
            for code, pattern, severity in _PATTERNS:
                if pattern.search(text):
                    findings.append(
                        Finding(
                            gate_id=GATE_ID,
                            severity=severity,
                            code="secret_detected",
                            message=f"possible {code} in {rel!r}",
                            location=rel,
                            metadata={"secret_type": code},
                        )
                    )

        # WARN-only: a heuristic secret hit needs review, not an auto-reject.
        status = GateStatus.WARN if findings else GateStatus.PASS
        return GateResult(
            gate_id=GATE_ID,
            status=status,
            rigor=RigorLevel.STATIC,
            findings=findings,
            scanner_name="mig.secrets",
            scanner_version=__version__,
        )
