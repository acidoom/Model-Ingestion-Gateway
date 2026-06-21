"""Base helpers and errors for :class:`~mig.core.protocols.Source` adapters.

Concrete sources arrive later: ``local`` in PR2, ``huggingface`` in PR3, then
github/pypi/npm/s3. They all share two obligations from invariant I3 — pin and
verify the digest/SHA at fetch time, and land bytes in quarantine — which is why
the errors that express those failures live here, in one place.
"""

from __future__ import annotations


class SourceError(Exception):
    """Base class for fetch/source failures."""


class DigestMismatchError(SourceError):
    """Raised when fetched bytes do not match the pinned digest/SHA (I3).

    A digest mismatch is non-negotiable: the artifact MUST NOT proceed past
    fetch. This is distinct from a *missing* pin, which sources should also
    reject rather than silently fetch unpinned.
    """

    def __init__(self, *, expected: str, actual: str, locator: str) -> None:
        super().__init__(
            f"digest mismatch for {locator!r}: expected {expected!r}, got {actual!r}"
        )
        self.expected = expected
        self.actual = actual
        self.locator = locator


class UnpinnedReferenceError(SourceError):
    """Raised when a reference lacks the revision/digest needed to pin it (I3)."""
