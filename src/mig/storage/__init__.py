"""Storage seam: quarantine (untrusted) and the trusted store.

``Quarantine`` (I3) is scaffolded in PR1 and hardened in PR3. The trusted store
and ``promote()`` — the **only** path with write access (I6) — arrive in PR8.
"""

from __future__ import annotations

from mig.storage.quarantine import Quarantine

__all__ = ["Quarantine"]
