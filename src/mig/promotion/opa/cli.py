"""OPA-via-CLI promotion gate — a compose twin of the docker/cosign wrappers.

Drives ``opa eval`` over the host ``opa`` binary through the single injectable
seam :func:`_run_opa` (monkeypatched in tests, so no binary is needed). The
canonical promotion input document is fed on **stdin** (never argv). Every
failure mode — missing binary, timeout, non-zero exit, unparseable or non-
``allow=true`` output — yields a DENY, never an allow: an unreachable or garbled
OPA can never authorise a promotion (no fail-open, no silent failover).
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from typing import Any

from mig.evidence.canonical import canonical_bytes
from mig.promotion.gate import PromotionDecision

#: The Rego entrypoint the reference policy exposes.
DECISION_QUERY = "data.mig.promotion.decision"


class OpaUnavailableError(RuntimeError):
    """Raised when the opa CLI cannot be found or run."""


def _run_opa(
    opa_bin: str, args: list[str], *, input_bytes: bytes, timeout_s: int = 30
) -> tuple[int | None, str, str]:
    """Invoke ``opa`` with ``input_bytes`` on stdin; return ``(exit, out, err)``.

    The one seam every OPA invocation passes through — monkeypatched in tests.
    A hung/absent opa becomes a clean :class:`OpaUnavailableError`, never an
    uncaught SubprocessError.
    """
    try:
        proc = subprocess.run(
            [opa_bin, *args],
            input=input_bytes,
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
    except FileNotFoundError as exc:
        raise OpaUnavailableError(f"opa CLI not found: {opa_bin!r}") from exc
    except subprocess.TimeoutExpired as exc:
        raise OpaUnavailableError(f"opa timed out after {timeout_s}s") from exc
    except OSError as exc:
        raise OpaUnavailableError(f"opa could not be run: {exc}") from exc
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


class OpaCliGate:
    """Evaluate the promotion input against a Rego policy via ``opa eval``."""

    engine = "opa-cli"

    def __init__(self, *, opa_bin: str = "opa", policy_path: str | None = None) -> None:
        if not policy_path:
            raise OpaUnavailableError("the OPA gate needs a Rego policy (--opa-policy)")
        self._opa_bin = opa_bin
        self._policy_path = policy_path

    def evaluate(self, input_doc: Mapping[str, Any]) -> PromotionDecision:
        payload = canonical_bytes(input_doc)
        try:
            exit_code, stdout, stderr = _run_opa(
                self._opa_bin,
                [
                    "eval",
                    "--format",
                    "json",
                    "--stdin-input",
                    "--data",
                    self._policy_path,
                    DECISION_QUERY,
                ],
                input_bytes=payload,
            )
        except OpaUnavailableError as exc:
            return PromotionDecision(False, (f"opa: {exc}",), self.engine)
        if exit_code != 0:
            return PromotionDecision(
                False, (f"opa exited {exit_code}: {stderr.strip()[:200]}",), self.engine
            )
        return self._parse(stdout)

    def _parse(self, stdout: str) -> PromotionDecision:
        try:
            data = json.loads(stdout)
            value = data["result"][0]["expressions"][0]["value"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            return PromotionDecision(
                False, (f"opa: unparseable decision ({exc})",), self.engine
            )
        if isinstance(value, Mapping) and value.get("allow") is True:
            return PromotionDecision(True, (), self.engine)
        reasons = value.get("reasons") if isinstance(value, Mapping) else None
        detail = (
            tuple(str(r) for r in reasons)
            if isinstance(reasons, list) and reasons
            else ("opa denied",)
        )
        return PromotionDecision(False, detail, self.engine)


def opa_available(opa_bin: str = "opa") -> bool:
    """True if the opa CLI is reachable (used to skip integration tests + the
    startup probe that turns an absent binary into an operator error)."""
    try:
        exit_code, _out, _err = _run_opa(
            opa_bin, ["version"], input_bytes=b"", timeout_s=10
        )
    except OpaUnavailableError:
        return False
    return exit_code == 0
