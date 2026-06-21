"""Trusted-store backend seam.

``local`` (the stdlib content-addressed filesystem store) is the default and the
only backend implemented in PR8. ``s3``/``harbor`` are reserved (their extras are
declared) and lazy-raise a clear install hint — so any future backend is forced
to live under ``mig.promotion`` and route through the gated orchestrator (I6).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mig.promotion.errors import PromotionError

if TYPE_CHECKING:
    from mig.promotion.stores.local_fs import LocalTrustedStore


def make_trusted_store(kind: str = "local", *, root: str) -> LocalTrustedStore:
    """Build a trusted store. Default ``local`` is stdlib-only (I10)."""
    if kind == "local":
        from mig.promotion.stores.local_fs import LocalTrustedStore

        return LocalTrustedStore(root)
    if kind in ("s3", "harbor"):
        raise PromotionError(
            f"the {kind!r} trusted store is not implemented in PR8 "
            f"(reserved for mig[{kind}])"
        )
    raise PromotionError(f"unknown trusted store {kind!r} (use: local)")
