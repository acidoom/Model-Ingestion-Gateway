"""Source seam and adapters.

Concrete sources land later: ``local`` (PR2), ``huggingface`` (PR3), then
github/pypi/npm/s3. All MUST pin + verify the digest/SHA at fetch and land
bytes in quarantine (I3).
"""

from __future__ import annotations

from mig.sources.base import (
    DigestMismatchError,
    SourceError,
    UnpinnedReferenceError,
)

__all__ = ["SourceError", "DigestMismatchError", "UnpinnedReferenceError"]
