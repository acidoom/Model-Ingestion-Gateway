"""Confinement request (:class:`SandboxSpec`) and result (:class:`SandboxObservation`).

The library *drives and verifies* confinement; the kernel/network *enforce* it
(PRD §2 non-goal, §4 control-plane-vs-mechanism). A :class:`SandboxSpec` is the
confinement the library asks for; a :class:`SandboxObservation` is what was
actually observed during detonation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mig.core.verdict import GateStatus, RigorLevel

if TYPE_CHECKING:
    from mig.core.verdict import Finding


@dataclass(frozen=True)
class SandboxSpec:
    """The confinement a behavioral gate requests for a detonation.

    Every default encodes a deny-by-default posture (QS-3): no network, read-only
    root, all capabilities dropped, no new privileges, no mounted secrets, and
    bounded memory / pids / cpu / wall-clock. The container runtime/network are
    what *enforce* this; MIG only requests and verifies it.
    """

    image: str | None = None
    network: str = "none"  # "none" | "logging-proxy" — never unrestricted egress
    read_only: bool = True
    # Reserved: MIG never mounts host secret stores into an untrusted detonation,
    # regardless of this flag. (Drivers ignore it today; kept for forward compat.)
    mount_secrets: bool = False
    timeout_s: int = 60
    # Resource caps (deny-by-default).
    memory: str = "512m"
    cpus: str = "1.0"
    pids_limit: int = 256
    # Privilege caps.
    cap_drop: tuple[str, ...] = ("ALL",)
    no_new_privileges: bool = True
    seccomp: str | None = (
        None  # None = the runtime's default profile (never "unconfined")
    )
    runtime: str | None = None  # None = runc; "runsc" = gVisor; "kata"/firecracker later
    env: Mapping[str, str] = field(default_factory=dict)


@dataclass
class SandboxObservation:
    """What a sandbox observed while loading/running an artifact.

    A real sandbox (PR6) populates the syscall/DNS/network fields. The default
    :class:`~mig.sandbox.noop.NoopSandbox` returns ``status=SKIPPED`` at
    ``rigor=NONE`` with a loud finding (I7).
    """

    rigor: RigorLevel
    status: GateStatus
    findings: Sequence[Finding] = field(default_factory=list)
    syscalls: Sequence[str] = field(default_factory=list)
    dns_queries: Sequence[str] = field(default_factory=list)
    network_attempts: Sequence[str] = field(default_factory=list)
    exit_code: int | None = None
    raw: Mapping[str, object] = field(default_factory=dict)
