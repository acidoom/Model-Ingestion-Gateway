"""The :class:`ScanContext` seam — ambient services a gate may use.

A gate receives the artifact plus a context carrying the active policy, the
quarantine area, the sandbox, a logger and a run id. The protocol keeps gates
decoupled from how those services are constructed.

:class:`DefaultScanContext` is a plain concrete implementation used by tests and
the PR2 pipeline runner. It defaults ``sandbox`` to :class:`NoopSandbox` (I7) so
the honest, behavioral-skipped path is what you get unless you opt in to more.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from mig.sandbox.noop import NoopSandbox

if TYPE_CHECKING:
    from mig.core.protocols import Sandbox
    from mig.policy.schema import Policy
    from mig.storage.quarantine import Quarantine


@runtime_checkable
class ScanContext(Protocol):
    """Ambient services available to a gate during evaluation.

    ``config`` is the §5 seam for run-level configuration a gate may read
    (thresholds, scanner toggles); it is part of the keystone contract now so
    later PRs do not have to widen the Protocol surface to add it.
    """

    policy: Policy
    quarantine: Quarantine
    sandbox: Sandbox
    run_id: str
    logger: logging.Logger
    config: Mapping[str, object]


def _default_logger() -> logging.Logger:
    return logging.getLogger("mig")


@dataclass
class DefaultScanContext:
    """A concrete :class:`ScanContext` for tests and the embedded pipeline.

    ``sandbox`` defaults to :class:`NoopSandbox`, so a context built without an
    explicit sandbox honestly reports behavioral vetting as SKIPPED (I7).
    """

    policy: Policy
    quarantine: Quarantine
    sandbox: Sandbox = field(default_factory=NoopSandbox)
    run_id: str = "local"
    logger: logging.Logger = field(default_factory=_default_logger)
    config: Mapping[str, object] = field(default_factory=dict)


def make_context(
    policy: Policy,
    quarantine: Quarantine,
    sandbox: Sandbox | None = None,
    run_id: str = "local",
    logger: logging.Logger | None = None,
    config: Mapping[str, object] | None = None,
) -> DefaultScanContext:
    """Convenience constructor that fills in the NoopSandbox + default logger."""
    return DefaultScanContext(
        policy=policy,
        quarantine=quarantine,
        sandbox=sandbox if sandbox is not None else NoopSandbox(),
        run_id=run_id,
        logger=logger if logger is not None else _default_logger(),
        config=config if config is not None else {},
    )
