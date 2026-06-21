"""The promotion gate — a deny-overrides composite that authorizes a promotion.

ADR-003: the embedded engine owns the *ingest* decision; OPA owns *promotion*
enforcement. Here that is realised as a **safety floor** the operator cannot turn
off: :class:`EmbeddedPromotionGate` (stdlib, always runs) is composed with an
optional OPA gate under **deny-overrides** —

    allow = embedded.allow AND (opa is None OR opa.allow)

so OPA can only ever *further restrict*, never loosen the floor. Both engines are
categorical (I4): an allow/deny plus human-readable reasons, never a score. A
missing/mistyped field fails its clause closed — never a ``KeyError``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

_APPROVE = "approve"
_BEHAVIORAL = "behavioral"
#: Confinement levels that count as a real behavioral detonation (docker.py).
_CONFINED = frozenset({"docker", "gvisor"})
_HMAC_SCHEME = "hmac-sha256"
_CHECKS = ("signature", "digest_rebind", "attribution", "keyid")


@dataclass(frozen=True)
class PromotionDecision:
    """A categorical promotion outcome (I4): allow + reasons, never a score."""

    allow: bool
    reasons: tuple[str, ...]
    engine: str


@runtime_checkable
class PromotionGate(Protocol):
    """Decides whether a verified attestation may be promoted."""

    def evaluate(self, input_doc: Mapping[str, Any]) -> PromotionDecision: ...


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


class EmbeddedPromotionGate:
    """The always-on stdlib safety floor (airgap default, zero deps — I10).

    Re-derives its allow from the SIGNED, VERIFIED attestation only — it never
    re-scans. DENY-by-default; every failed clause adds a reason. It can ONLY
    deny, which is what makes the deny-overrides composite safe.
    """

    engine = "embedded"

    def __init__(
        self,
        *,
        required_keyids: frozenset[str] = frozenset(),
        require_asymmetric: bool = False,
    ) -> None:
        self._required_keyids = required_keyids
        self._require_asymmetric = require_asymmetric

    def evaluate(self, input_doc: Mapping[str, Any]) -> PromotionDecision:
        reasons: list[str] = []
        verification = _as_mapping(input_doc.get("verification"))
        checks = _as_mapping(verification.get("checks"))

        # 1+2. The attestation must have VERIFIED — aggregate and each check.
        if verification.get("ok") is not True:
            reasons.append("attestation verification did not pass")
        for name in _CHECKS:
            if checks.get(name) is not True:
                reasons.append(f"verification check {name!r} not satisfied")

        # 3. The signed decision must be APPROVE — a REJECT/REVIEW is not promotable.
        decision = input_doc.get("decision")
        if decision != _APPROVE:
            reasons.append(f"signed decision is {decision!r}, not 'approve'")

        # 4. Executable types need real behavioral rigor under confinement (I8).
        # Fail CLOSED: anything that isn't explicitly False is treated as executable,
        # so a missing/mistyped flag still demands behavioral rigor (never skips it).
        if input_doc.get("is_executable_type") is not False:
            if input_doc.get("overall_rigor") != _BEHAVIORAL:
                reasons.append(
                    f"executable type needs behavioral rigor, got "
                    f"{input_doc.get('overall_rigor')!r}"
                )
            if input_doc.get("confinement_level") not in _CONFINED:
                reasons.append(
                    f"executable type needs docker/gvisor confinement, got "
                    f"{input_doc.get('confinement_level')!r}"
                )

        # 5. A named, versioned policy must back the decision.
        policy = _as_mapping(input_doc.get("policy"))
        if not (policy.get("id") and policy.get("version")):
            reasons.append("attestation carries no policy id/version")

        # Optional hardening (default OFF for airgap parity).
        if self._require_asymmetric and verification.get("scheme") == _HMAC_SCHEME:
            reasons.append("--require-asymmetric: HMAC is integrity-only, not provenance")
        if (
            self._required_keyids
            and verification.get("keyid") not in self._required_keyids
        ):
            reasons.append(f"keyid {verification.get('keyid')!r} not in the allowlist")

        return PromotionDecision(
            allow=not reasons, reasons=tuple(reasons), engine=self.engine
        )


class CompositePromotionGate:
    """Deny-overrides composite: the floor AND (optional) OPA. OPA only restricts."""

    def __init__(self, embedded: PromotionGate, opa: PromotionGate | None) -> None:
        self._embedded = embedded
        self._opa = opa

    @property
    def engine(self) -> str:
        if self._opa is None:
            return "embedded"
        return f"embedded+{getattr(self._opa, 'engine', 'opa')}"

    def evaluate(self, input_doc: Mapping[str, Any]) -> PromotionDecision:
        base = self._embedded.evaluate(input_doc)
        if self._opa is None:
            return PromotionDecision(base.allow, base.reasons, self.engine)
        opa = self._opa.evaluate(input_doc)
        # allow ONLY if both allow; reasons accumulate from both engines.
        return PromotionDecision(
            allow=base.allow and opa.allow,
            reasons=base.reasons + opa.reasons,
            engine=self.engine,
        )


def make_promotion_gate(
    *,
    opa: str | None = None,
    opa_bin: str = "opa",
    policy_path: str | None = None,
    required_keyids: frozenset[str] = frozenset(),
    require_asymmetric: bool = False,
) -> CompositePromotionGate:
    """Build the gate. Default (``opa=None``) is the stdlib floor alone (I10)."""
    embedded = EmbeddedPromotionGate(
        required_keyids=required_keyids, require_asymmetric=require_asymmetric
    )
    if opa is None:
        return CompositePromotionGate(embedded, None)
    if opa == "cli":
        from mig.promotion.opa.cli import OpaCliGate  # lazy — keeps default stdlib

        return CompositePromotionGate(
            embedded, OpaCliGate(opa_bin=opa_bin, policy_path=policy_path)
        )
    raise ValueError(f"unknown opa transport {opa!r} (use: cli)")
