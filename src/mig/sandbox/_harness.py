"""In-container detonation harness (stdlib-only; runs WITHOUT mig installed).

This script is mounted into the sandbox container and executed as
``python /mig_harness.py /artifact``. It is the ONE place MIG deliberately
*loads* an artifact — but it does so **inside the confined container**, never in
the host process, so it does not violate I1 (which governs the host-side static
gates). The container's ``--network none`` + dropped capabilities are what make
this safe; the harness only loads and *records* behaviour.

It hooks ``socket`` to record (and surface whether the kernel blocked) any
egress attempt, then loads every file — importing ``.py`` modules and
deserialising pickle-family files so their on-load code actually runs — with
per-file isolation. It prints a sentinel-delimited JSON observation that the
host-side :class:`~mig.sandbox.docker.DockerSandbox` parses.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pickle
import socket
import sys
from typing import Any

OBSERVATION_PREFIX = "__MIG_OBSERVATION__"
OBSERVATION_SUFFIX = "__MIG_END__"

_PICKLE_EXTS = {
    ".pkl",
    ".pickle",
    ".bin",
    ".pt",
    ".pth",
    ".ckpt",
    ".joblib",
    ".dill",
    ".dat",
    ".data",
    ".npy",
    ".model",
}

_network_attempts: list[dict[str, Any]] = []
_dns_queries: list[str] = []


def _record_attempt(address: Any) -> dict[str, Any]:
    attempt: dict[str, Any] = {"address": str(address), "blocked": None}
    _network_attempts.append(attempt)
    return attempt


def _install_network_recorder() -> None:
    # Hook the egress chokepoints a malicious load might use. The common paths
    # (socket.create_connection, urllib, http.client, requests) all bottom out
    # in connect(); connect_ex()/sendto() cover the TCP-poll and connectionless
    # (UDP / DNS-over-UDP) variants. This is best-effort *detection* — the
    # --network none kernel block is what actually prevents egress (see
    # DockerSandbox docstring), so a missed channel is still confined, just not
    # surfaced. C/ctypes-level egress bypasses Python hooks entirely.
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_sendto = socket.socket.sendto
    real_getaddrinfo = socket.getaddrinfo

    def recording_connect(self: socket.socket, address: Any) -> Any:
        attempt = _record_attempt(address)
        try:
            result = real_connect(self, address)
        except Exception as exc:  # --network none blocks → attempt detected + denied
            attempt["blocked"] = True
            attempt["error"] = type(exc).__name__
            raise
        attempt["blocked"] = False  # egress SUCCEEDED — a confinement breach
        return result

    def recording_connect_ex(self: socket.socket, address: Any) -> Any:
        attempt = _record_attempt(address)
        try:
            err = real_connect_ex(self, address)
        except Exception as exc:
            attempt["blocked"] = True
            attempt["error"] = type(exc).__name__
            raise
        attempt["blocked"] = err != 0  # nonzero errno → refused/blocked
        return err

    def recording_sendto(self: socket.socket, data: Any, *args: Any) -> Any:
        # sendto(data, address) or sendto(data, flags, address): dest is last.
        attempt = _record_attempt(args[-1] if args else None)
        try:
            result = real_sendto(self, data, *args)
        except Exception as exc:
            attempt["blocked"] = True
            attempt["error"] = type(exc).__name__
            raise
        attempt["blocked"] = False
        return result

    def recording_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        _dns_queries.append(str(host))
        return real_getaddrinfo(host, *args, **kwargs)

    socket.socket.connect = recording_connect  # type: ignore[assignment]
    socket.socket.connect_ex = recording_connect_ex  # type: ignore[assignment]
    socket.socket.sendto = recording_sendto  # type: ignore[assignment]
    socket.getaddrinfo = recording_getaddrinfo


def _detonate_file(path: str) -> None:
    base = os.path.basename(path)
    ext = os.path.splitext(path)[1].lower()
    if base.endswith(".py"):
        spec = importlib.util.spec_from_file_location("mig_detonated", path)
        if spec is not None and spec.loader is not None:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # runs module top-level code
    elif ext in _PICKLE_EXTS:
        with open(path, "rb") as handle:
            pickle.load(handle)  # runs __reduce__ — INSIDE the confined container


def detonate(artifact_dir: str) -> dict[str, Any]:
    _install_network_recorder()
    loaded: list[str] = []
    errors: list[dict[str, str]] = []

    def _on_walk_error(exc: OSError) -> None:
        # Surface a read/traversal failure (e.g. an unreadable mount) instead of
        # os.walk's default silent skip — a silent skip would look like a clean
        # detonation. The host treats a wholly-empty observation as fail-closed.
        errors.append({"file": "<walk>", "error": f"{type(exc).__name__}: {exc}"[:200]})

    for root, _dirs, files in os.walk(artifact_dir, onerror=_on_walk_error):
        for name in sorted(files):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, artifact_dir)
            try:
                _detonate_file(path)
                loaded.append(rel)
            # Contain SystemExit too: an artifact that calls sys.exit() during
            # load must not abort the harness before it emits its observation.
            # (os._exit bypasses Python entirely → no sentinel → host ERROR →
            # REVIEW_REQUIRED, which is fail-safe; see DockerSandbox.)
            except (Exception, SystemExit) as exc:  # one file must not stop the rest
                errors.append(
                    {"file": rel, "error": f"{type(exc).__name__}: {exc}"[:200]}
                )
    return {
        "network_attempts": _network_attempts,
        "dns_queries": _dns_queries,
        "loaded": loaded,
        "errors": errors,
    }


def main(argv: list[str]) -> int:
    artifact_dir = argv[1] if len(argv) > 1 else "/artifact"
    # A per-run nonce the host passes in and stamps into the sentinel. The
    # detonated artifact runs in THIS process and can print to stdout, so it
    # could forge a "clean" sentinel to hide its own egress; without the right
    # nonce the host ignores any forged sentinel. This raises the bar but is not
    # absolute — the artifact can read argv too (see DockerSandbox docstring).
    token = argv[2] if len(argv) > 2 else ""
    observation = detonate(artifact_dir)
    sys.stdout.write(
        f"\n{OBSERVATION_PREFIX}{token}:{json.dumps(observation)}{OBSERVATION_SUFFIX}\n"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - executed in-container / via subprocess
    raise SystemExit(main(sys.argv))
