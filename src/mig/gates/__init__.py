"""Gate implementations.

Gates wrap scanners. The suite is built out across PRs: format-allowlist +
digest (PR2); serialization-safety, secrets, license/metadata, static-code
(PR4); prompt-injection (PR4, WARN-only per I9); behavioral (PR6). PR1 only
defines the :class:`~mig.core.protocols.Gate` seam they implement.
"""

from __future__ import annotations

__all__: list[str] = []
