"""Prompt-injection gate — WARN-only inspection of model cards / text (I9, ADR-004).

Heuristically flags prompt-injection / jailbreak phrasing in an artifact's
human-readable text (model card, README, config descriptions). Per invariant I9
this is a **WARN signal only**: it MUST NEVER produce a FAIL/reject, because a
keyword heuristic is too weak to be a hard gate. Flagged cases go to human
review.
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

GATE_ID = "prompt_injection"

_TEXT_EXTENSIONS = {".md", ".txt", ".json", ".rst", ".yaml", ".yml"}

_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore (?:all |the |your |any )?(?:previous|prior|above) instructions",
        r"disregard (?:all |the )?(?:previous|prior|above)",
        r"forget (?:all |everything|the above|previous)",
        r"you are now (?:a|an|in)\b",
        r"reveal your (?:system )?prompt",
        r"(?:new|updated) (?:system )?instructions\s*:",
        r"do anything now",
        r"\bjailbreak\b",
        r"override (?:your |the )?(?:safety|guard|system)",
    )
]


class PromptInjectionGate:
    """WARN-only model-card / text inspection for prompt-injection (I9)."""

    id = GATE_ID
    cost = GateCost.MEDIUM
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
            for pattern in _INJECTION_PATTERNS:
                match = pattern.search(text)
                if match:
                    findings.append(
                        Finding(
                            gate_id=GATE_ID,
                            severity=Severity.MEDIUM,
                            code="prompt_injection_suspected",
                            message=(
                                f"injection-like phrasing in {rel!r}: {match.group(0)!r}"
                            ),
                            location=rel,
                        )
                    )
                    break  # one finding per file is enough signal

        # I9: WARN-only. This gate MUST NOT FAIL, ever.
        status = GateStatus.WARN if findings else GateStatus.PASS
        return GateResult(
            gate_id=GATE_ID,
            status=status,
            rigor=RigorLevel.STATIC,
            findings=findings,
            scanner_name="mig.prompt_injection",
            scanner_version=__version__,
        )
