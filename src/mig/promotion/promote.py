"""The gated promotion orchestrator — where MIG crosses the decision boundary.

A strictly-ordered, fail-closed flow; the store write is structurally dominated
by a passing re-verification AND a gate allow, so an unverified, tampered, or
non-APPROVE artifact can never reach the trusted store:

    1. LOAD   the signed attestation (envelope or bundle.envelope — never the
              unsigned verdict mirror).
    2. FETCH  + re-hash the artifact into a fresh quarantine (I3 isolation).
    3. VERIFY re-run verify_attestation (signature + I3 digest re-bind + I5
              attribution). ``not ok`` → abort (exit 3, tamper).
    4a. GATE  evaluate the embedded floor AND optional OPA (deny-overrides) over
              the VERIFIED attestation. ``not allow`` → abort (exit 1, denied).
    4b. WRITE the only call site of the trusted-store write (idempotent, atomic).
    5. AUDIT  the terminal outcome (every attempt, including denials).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mig.core.hashing import normalize_digest
from mig.core.serde import dsse_envelope_from_dict
from mig.evidence.canonical import canonical_bytes
from mig.evidence.dsse import encode_envelope
from mig.evidence.signing import verify_envelope
from mig.evidence.statement import attestation_from_statement, subject_name
from mig.evidence.verify import verify_attestation
from mig.promotion.errors import PromotionError
from mig.promotion.input_doc import build_promotion_input
from mig.promotion.receipt import build_receipt, gate_record
from mig.sources.base import SourceError
from mig.storage.quarantine import Quarantine, QuarantineError

if TYPE_CHECKING:
    from mig.core.artifact import ArtifactRef
    from mig.core.protocols import Source
    from mig.evidence.signing import Verifier
    from mig.promotion.audit import PromotionAuditSink
    from mig.promotion.gate import PromotionGate
    from mig.promotion.stores.local_fs import LocalTrustedStore

_FETCH_ERRORS = (SourceError, QuarantineError)


@dataclass
class PromotionResult:
    """The structured outcome of a promotion attempt."""

    ok: bool
    outcome: str  # promoted | idempotent_noop | denied | verification_failed | error
    exit_code: int  # 0 ok | 1 denied | 2 operator error | 3 verification failure
    digest: str | None = None
    store_uri: str | None = None
    already_present: bool = False
    decision: str | None = None
    scheme: str | None = None
    keyid: str | None = None
    gate: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)


def _utc_now() -> str:
    return datetime.datetime.now(tz=datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _envelope_only(data: Mapping[str, Any]) -> Mapping[str, Any]:
    """A bundle yields its embedded (signed) envelope; a bare envelope is used
    as-is. The unsigned ``bundle.verdict`` mirror is never consulted."""
    envelope = data.get("envelope")
    return envelope if isinstance(envelope, Mapping) else data


def _load_attestation(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        data: Any = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("attestation file is not a JSON object")
    return data


def promote_artifact(
    ref: ArtifactRef,
    *,
    attestation_path: str,
    verifier: Verifier,
    store: LocalTrustedStore,
    gate: PromotionGate,
    source: Source,
    audit: PromotionAuditSink,
    mig_version: str,
    expected_keyid: str | None = None,
    dry_run: bool = False,
) -> PromotionResult:
    """Run the 5-step fail-closed promotion. Never raises for a denial/tamper —
    those are reported; only an unexpected operator error surfaces as a result."""
    promoted_at = _utc_now()
    base: dict[str, Any] = {
        "schema": "https://mig.dev/promotion-audit/v1",
        "event": "promotion",
        "ref": {"scheme": ref.scheme, "locator": ref.locator, "revision": ref.revision},
        "subject_name": subject_name(ref),
        "promoted_at": promoted_at,
        "mig_version": mig_version,
    }

    def finish(result: PromotionResult, **extra: Any) -> PromotionResult:
        audit.emit(
            {
                **base,
                "outcome": result.outcome,
                "digest": result.digest,
                "store_uri": result.store_uri,
                "decision": result.decision,
                "verification": result.verification,
                "gate": result.gate,
                "problems": result.problems,
                **extra,
            }
        )
        return result

    # STEP 1 — LOAD (no fetch, no write).
    try:
        data = _load_attestation(attestation_path)
    except (OSError, ValueError) as exc:
        return finish(
            PromotionResult(
                ok=False, outcome="error", exit_code=2, problems=[f"load: {exc}"]
            )
        )

    quarantine_root = tempfile.mkdtemp(prefix="mig-promote-")
    try:
        # STEP 2 — FETCH + re-hash into a fresh quarantine.
        try:
            artifact = source.fetch(ref, Quarantine(root=quarantine_root))
        except _FETCH_ERRORS as exc:
            return finish(
                PromotionResult(
                    ok=False, outcome="error", exit_code=2, problems=[f"fetch: {exc}"]
                )
            )

        # STEP 3 — RE-VERIFY (the gate to trusting anything). A malformed (valid
        # JSON but not a well-formed DSSE envelope/bundle) attestation raises
        # ValueError out of verify — map it to a clean, audited operator error.
        try:
            result = verify_attestation(
                data, artifact=artifact, verifier=verifier, expected_keyid=expected_keyid
            )
        except ValueError as exc:
            return finish(
                PromotionResult(
                    ok=False, outcome="error", exit_code=2, problems=[f"verify: {exc}"]
                )
            )
        verification = {
            "ok": result.ok,
            "scheme": result.scheme,
            "keyid": result.keyid,
            "checks": dict(result.checks),
        }
        if not result.ok:
            return finish(
                PromotionResult(
                    ok=False,
                    outcome="verification_failed",
                    exit_code=3,
                    scheme=result.scheme,
                    keyid=result.keyid,
                    verification=verification,
                    problems=list(result.problems),
                )
            )

        # Reconstruct the trusted Attestation from the SIGNED bytes only.
        env = dsse_envelope_from_dict(_envelope_only(data))
        attestation = attestation_from_statement(verify_envelope(env, verifier))
        digest = normalize_digest(attestation.digest)

        # STEP 4a — EVALUATE the promotion gate over the VERIFIED attestation.
        input_doc = build_promotion_input(result, attestation, artifact.ref)
        decision = gate.evaluate(input_doc)
        gate_view = gate_record(decision.allow, decision.engine, decision.reasons)
        if not decision.allow:
            return finish(
                PromotionResult(
                    ok=False,
                    outcome="denied",
                    exit_code=1,
                    digest=digest,
                    decision=attestation.decision.value,
                    scheme=result.scheme,
                    keyid=result.keyid,
                    gate=gate_view,
                    verification=verification,
                    problems=list(decision.reasons),
                )
            )

        if dry_run:  # steps 1–4a ran and allowed; skip the write
            return finish(
                PromotionResult(
                    ok=True,
                    outcome="would_promote",
                    exit_code=0,
                    digest=digest,
                    store_uri=None,
                    decision=attestation.decision.value,
                    scheme=result.scheme,
                    keyid=result.keyid,
                    gate=gate_view,
                    verification=verification,
                ),
                dry_run=True,
            )

        # STEP 4b — WRITE (the sole trusted-store writer).
        attestation_digest = (
            "sha256:" + hashlib.sha256(canonical_bytes(encode_envelope(env))).hexdigest()
        )
        try:
            receipt = build_receipt(
                digest=digest,
                store_uri=store.uri_for(digest.split(":", 1)[1]),
                subject_name=subject_name(artifact.ref),
                artifact_type=attestation.artifact_type.value,
                decision=attestation.decision.value,
                verification=verification,
                gate=gate_view,
                attestation_digest=attestation_digest,
                policy={
                    "id": attestation.policy_id,
                    "version": attestation.policy_version,
                },
                mig_version=mig_version,
                promoted_at=promoted_at,
            )
            store_uri, already_present = store.write(
                artifact, envelope=env, verify_result=result, receipt=receipt
            )
        # The store can raise non-PromotionError too: a symlink/limit in the
        # staged tree (QuarantineError), or a vanished file / cross-fs / fsync
        # failure (OSError). All are a clean, audited operator error.
        except (PromotionError, QuarantineError, OSError) as exc:
            return finish(
                PromotionResult(
                    ok=False,
                    outcome="error",
                    exit_code=2,
                    digest=digest,
                    gate=gate_view,
                    verification=verification,
                    problems=[f"store: {exc}"],
                )
            )

        # STEP 5 — AUDIT the success.
        return finish(
            PromotionResult(
                ok=True,
                outcome="idempotent_noop" if already_present else "promoted",
                exit_code=0,
                digest=digest,
                store_uri=store_uri,
                already_present=already_present,
                decision=attestation.decision.value,
                scheme=result.scheme,
                keyid=result.keyid,
                gate=gate_view,
                verification=verification,
            ),
            store_uri=store_uri,
            already_present=already_present,
        )
    except Exception as exc:  # defense in depth — promote_artifact NEVER raises
        # Any unforeseen error after load is a clean, AUDITED operator error,
        # not an uncaught traceback with a non-contract exit code on the trust
        # boundary. (The verify/gate/write steps above map known errors precisely.)
        return finish(
            PromotionResult(
                ok=False,
                outcome="error",
                exit_code=2,
                problems=[f"unexpected: {type(exc).__name__}: {exc}"],
            )
        )
    finally:
        shutil.rmtree(quarantine_root, ignore_errors=True)
