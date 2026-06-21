"""Storage seam: quarantine (untrusted) and the trusted store.

``Quarantine`` (I3) is scaffolded in PR1 and hardened in PR3. The trusted store
and ``promote()`` — the **only** path with write access (I6) — arrive in PR8.
"""

from __future__ import annotations

from mig.storage.quarantine import (
    DEFAULT_LIMITS,
    Quarantine,
    QuarantineError,
    QuarantineLimits,
    safe_join,
    stage_local_tree,
)

__all__ = [
    "Quarantine",
    "QuarantineLimits",
    "QuarantineError",
    "DEFAULT_LIMITS",
    "safe_join",
    "stage_local_tree",
]
