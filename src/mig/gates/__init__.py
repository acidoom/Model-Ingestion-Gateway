"""Gate implementations.

Gates wrap scanners. The suite is built out across PRs: format-allowlist +
digest (PR2); serialization-safety, secrets, license/metadata, static-code
(PR4); prompt-injection (PR4, WARN-only per I9); behavioral (PR2/PR6). The
:class:`~mig.core.protocols.Gate` seam they implement lives in PR1.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mig.gates.behavioral import BehavioralGate
from mig.gates.digest import DigestGate
from mig.gates.format_allowlist import FormatAllowlistGate

if TYPE_CHECKING:
    from mig.core.protocols import Gate


def default_gates() -> list[Gate]:
    """The built-in gate suite wired by ``mig scan`` (PR2).

    Order is irrelevant here — the pipeline runner sorts by cost
    (CHEAP → MEDIUM → EXPENSIVE).
    """
    return [FormatAllowlistGate(), DigestGate(), BehavioralGate()]


__all__ = [
    "FormatAllowlistGate",
    "DigestGate",
    "BehavioralGate",
    "default_gates",
]
