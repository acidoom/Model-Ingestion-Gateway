"""Structured audit logging.

A tool that gates trusted infrastructure must itself be auditable (R6). This is
a thin, dependency-free wrapper over the stdlib :mod:`logging` module for PR1;
structured sinks (and the trusted-store write audit trail, I6) build on it.
"""

from __future__ import annotations

import logging

_LOGGER_NAME = "mig"


def get_logger(name: str | None = None) -> logging.Logger:
    """Return the MIG logger, or a named child of it."""
    if name:
        return logging.getLogger(f"{_LOGGER_NAME}.{name}")
    return logging.getLogger(_LOGGER_NAME)


def configure(level: int = logging.INFO) -> None:
    """Attach a basic stderr handler to the MIG logger if it has none.

    Idempotent and conservative: it never reconfigures the root logger, so
    embedding MIG inside a host application does not hijack the host's logging.
    """
    logger = get_logger()
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
        logger.addHandler(handler)
    logger.setLevel(level)
