"""Sandbox seam and implementations.

``NoopSandbox`` (the default, I7) ships in PR1; ``DockerSandbox`` in PR6a;
gVisor/Firecracker hardening + spec-emit mode in PR6b.
"""

from __future__ import annotations

from mig.sandbox.docker import (
    DEFAULT_IMAGE,
    DockerSandbox,
    DockerUnavailableError,
    docker_available,
)
from mig.sandbox.noop import NoopSandbox
from mig.sandbox.spec import SandboxObservation, SandboxSpec

__all__ = [
    "NoopSandbox",
    "SandboxSpec",
    "SandboxObservation",
    "DockerSandbox",
    "DockerUnavailableError",
    "docker_available",
    "DEFAULT_IMAGE",
]
