"""Shared, hardened readers for text-inspecting gates (I1: read-only).

All reads go through :func:`~mig.storage.quarantine.safe_join` (traversal guard)
and are byte-bounded; JSON parsing catches ``RecursionError`` so a deeply-nested
document can never crash a gate (and silently discard its other findings).
"""

from __future__ import annotations

import json
import os

from mig.storage.quarantine import safe_join

_DEFAULT_MAX_BYTES = 8 * 1024 * 1024


def read_text(
    quarantine_path: str, rel: str, *, max_bytes: int = _DEFAULT_MAX_BYTES
) -> str | None:
    """Read ``rel`` under quarantine as bounded UTF-8 text, or ``None``."""
    path = safe_join(quarantine_path, rel)
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError):
        return None


def read_config_json(quarantine_path: str, files: list[str]) -> dict[str, object]:
    """Parse a model ``config.json`` as bounded text (``{}`` if absent/bad)."""
    for rel in files:
        if os.path.basename(rel) == "config.json":
            text = read_text(quarantine_path, rel)
            if text is None:
                return {}
            try:
                parsed = json.loads(text)
            except (ValueError, RecursionError):
                return {}
            return parsed if isinstance(parsed, dict) else {}
    return {}
