"""Gate implementations.

Gates wrap scanners. The suite: format-allowlist + digest (PR2); behavioral
(PR2/PR6); serialization-safety (wraps picklescan), static-code (AST), secrets,
license/metadata, prompt-injection (PR4). The :class:`~mig.core.protocols.Gate`
seam they implement lives in PR1.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mig.gates.behavioral import BehavioralGate
from mig.gates.digest import DigestGate
from mig.gates.format_allowlist import FormatAllowlistGate
from mig.gates.license_metadata import LicenseMetadataGate
from mig.gates.prompt_injection import PromptInjectionGate
from mig.gates.secrets import SecretsGate
from mig.gates.serialization_safety import SerializationSafetyGate
from mig.gates.static_code import StaticCodeGate

if TYPE_CHECKING:
    from mig.core.protocols import Gate


def default_gates() -> list[Gate]:
    """The built-in gate suite wired by ``mig scan``.

    Order is irrelevant here — the pipeline runner sorts by cost
    (CHEAP → MEDIUM → EXPENSIVE).
    """
    return [
        FormatAllowlistGate(),
        DigestGate(),
        SerializationSafetyGate(),
        SecretsGate(),
        LicenseMetadataGate(),
        StaticCodeGate(),
        PromptInjectionGate(),
        BehavioralGate(),
    ]


__all__ = [
    "FormatAllowlistGate",
    "DigestGate",
    "SerializationSafetyGate",
    "StaticCodeGate",
    "SecretsGate",
    "LicenseMetadataGate",
    "PromptInjectionGate",
    "BehavioralGate",
    "default_gates",
]
