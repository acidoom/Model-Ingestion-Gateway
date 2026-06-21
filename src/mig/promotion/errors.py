"""Shared promotion errors."""

from __future__ import annotations


class PromotionError(RuntimeError):
    """An operator-facing promotion failure (bad input, store, or config).

    Distinct from a *policy denial* (the gate refused) and a *verification
    failure* (tamper) — those are reported as structured outcomes, not raised.
    """
