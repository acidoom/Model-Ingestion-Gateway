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
    fetch.
    """

    def __init__(self, *, expected: str, actual: str, locator: str) -> None:
        super().__init__(
            f"digest mismatch for {locator!r}: expected {expected!r}, got {actual!r}"
        )
        self.expected = expected
        self.actual = actual
        self.locator = locator


class UnpinnedReferenceError(SourceError):
    """Raised by sources that *require* an explicit pin (I3).

    Note: a source may instead **resolve-then-pin** — e.g. the Hugging Face
    source resolves a mutable revision to an immutable commit SHA at fetch and
    records it — which also satisfies I3 without raising this. This error is for
    sources where no immutable anchor can be derived from an unpinned reference.
    """
