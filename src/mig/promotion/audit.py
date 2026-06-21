"""Promotion audit — every attempt is recorded, decoupled from the store write.

A denial (which publishes no CAS entry) must still be durably recorded (R6/I6),
so the sink writes independently of :class:`LocalTrustedStore`: it always emits
through ``mig.audit.logger`` and best-effort mirrors to ``index/promotions.jsonl``
(+ ``index/denied/`` for denials). Audit I/O failures degrade to a logged warning
— they never crash the run, but the logger emission is unconditional.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from mig.audit.logger import configure, get_logger
from mig.evidence.canonical import canonical_bytes

#: Terminal outcomes recorded for a promotion attempt.
_DENY_OUTCOMES = frozenset({"denied", "verification_failed", "error"})


class PromotionAuditSink:
    """Structured, fail-closed audit of promotion attempts."""

    def __init__(self, root: str) -> None:
        self._index = os.path.join(os.path.abspath(root), "index")
        # Attach a handler so the audit line is ALWAYS emitted — including a
        # SUCCESS (which logs at INFO and would otherwise be dropped by the
        # default WARNING level), so a trusted-store write is never unrecorded.
        configure()
        self._logger = get_logger("promotion")

    def emit(self, record: Mapping[str, Any]) -> None:
        outcome = str(record.get("outcome", "unknown"))
        digest = record.get("digest")
        # The logger emission is unconditional (visible even with no store on disk).
        if outcome in _DENY_OUTCOMES:
            self._logger.warning("promotion %s: digest=%s", outcome, digest)
        else:
            self._logger.info("promotion %s: digest=%s", outcome, digest)
        self._mirror(record, outcome, digest)

    def _mirror(self, record: Mapping[str, Any], outcome: str, digest: Any) -> None:
        try:
            # canonical_bytes can raise ValueError on a (future) un-encodable record;
            # that must degrade to a logged warning, never crash a run that may have
            # already written to the trusted store.
            line = canonical_bytes(record)
            os.makedirs(self._index, mode=0o700, exist_ok=True)
            with open(os.path.join(self._index, "promotions.jsonl"), "ab") as handle:
                handle.write(line + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            if outcome in _DENY_OUTCOMES:
                self._retain_denied(record, line, digest)
        except (OSError, ValueError) as exc:  # mirror is best-effort; never crash
            self._logger.warning("promotion audit mirror failed: %s", exc)

    def _retain_denied(self, record: Mapping[str, Any], line: bytes, digest: Any) -> None:
        denied = os.path.join(self._index, "denied")
        os.makedirs(denied, mode=0o700, exist_ok=True)
        stamp = str(record.get("promoted_at", "")).translate(
            {ord(":"): None, ord("-"): None}
        )
        short = str(digest or "unknown").split(":")[-1][:16]
        path = os.path.join(denied, f"{stamp}-{short}.json")
        with open(path, "wb") as handle:
            handle.write(line)
