"""Verify a signed attestation — three fail-closed checks over ONLY signed bytes.

Given a DSSE envelope (or a bundle, from which only ``bundle.envelope`` is read)
and the live artifact, :func:`verify_attestation` checks, in order:

1. **signature** — recompute the PAE and verify it with the OPERATOR-supplied
   verifier (never a key chosen from the envelope's advisory ``keyid``/``scheme``);
2. **digest re-bind** (I3) — re-hash the fetched artifact and compare with the
   subject digest *inside the signed Statement* via :func:`digests_match`;
3. **attribution** (I5) — reconstruct the Attestation from the signed predicate
   and re-assert every executed gate is named + versioned.

The decision is READ from the signed predicate, never recomputed (I4/I6). The
function returns a structured :class:`VerifyResult` rather than raising, so a
caller can map outcomes to exit codes (tamper is distinct from operator error).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mig.core.hashing import digests_match, hash_tree, normalize_digest
from mig.core.serde import dsse_envelope_from_dict
from mig.evidence.signing import VerificationError, verify_envelope
from mig.evidence.statement import attestation_from_statement, subject_digest

if TYPE_CHECKING:
    from mig.core.artifact import Artifact
    from mig.evidence.signing import Verifier


@dataclass
class VerifyResult:
    """The structured outcome of verifying an attestation."""

    ok: bool
    scheme: str
    keyid: str
    decision: str | None
    checks: Mapping[str, bool]
    problems: Sequence[str]


def _envelope_dict(data: Mapping[str, Any]) -> Mapping[str, Any]:
    """A bundle yields its embedded envelope; a bare envelope is used as-is.

    Only the (signed) envelope is ever trusted — never the bundle's unsigned
    verdict mirror.
    """
    envelope = data.get("envelope")
    if isinstance(envelope, Mapping):  # an evidence bundle
        return envelope
    return data  # a bare DSSE envelope


def verify_attestation(
    data: Mapping[str, Any],
    *,
    artifact: Artifact,
    verifier: Verifier,
    expected_keyid: str | None = None,
) -> VerifyResult:
    """Run the three fail-closed checks and report a :class:`VerifyResult`."""
    checks: dict[str, bool] = {
        "signature": False,
        "digest_rebind": False,
        "attribution": False,
        "keyid": True,
    }
    problems: list[str] = []

    env = dsse_envelope_from_dict(_envelope_dict(data))
    matching = [s for s in env.signatures if s.scheme == verifier.scheme]
    keyid = matching[0].keyid if matching else env.signatures[0].keyid

    if expected_keyid is not None:
        checks["keyid"] = any(s.keyid == expected_keyid for s in matching)
        if not checks["keyid"]:
            problems.append(
                f"keyid mismatch: envelope {keyid!r} != expected {expected_keyid!r}"
            )

    # (1) signature — the gate to trusting anything in the payload.
    try:
        statement = verify_envelope(env, verifier)
        checks["signature"] = True
    except VerificationError as exc:
        problems.append(f"signature: {exc}")
        return VerifyResult(
            ok=False,
            scheme=verifier.scheme,
            keyid=keyid,
            decision=None,
            checks=checks,
            problems=problems,
        )

    # From here we trust ONLY the signed statement. A signature-authenticated but
    # malformed/unhashable payload is a verification FAILURE (the decision can't be
    # re-bound), never an operator error or an uncaught crash — so the re-bind and
    # attribution steps live inside this guard too (a vanished file's OSError, a
    # subject-less statement's ValueError all become a uniform fail-closed result).
    decision: str | None = None
    try:
        attestation = attestation_from_statement(statement)
        decision = attestation.decision.value

        # (3) attribution (I5) — re-asserted at verify, not just at build.
        attribution_problems = attestation.attribution_problems()
        checks["attribution"] = not attribution_problems
        problems.extend(attribution_problems)

        # (2) digest re-bind (I3) — recompute the live digest, compare to subject.
        subject = subject_digest(statement)
        # The predicate carries its own ``digest`` field; it MUST be a string and
        # equal the signed subject. Otherwise a divergent/non-string predicate
        # digest (still signed) would later mislabel the receipt/URI or crash a
        # consumer — bind it here so a mismatch is a verification failure.
        if not (
            isinstance(attestation.digest, str)
            and digests_match(attestation.digest, subject)
        ):
            raise ValueError("predicate digest does not match the signed subject")
        live = hash_tree(artifact.quarantine_path, artifact.files)
        checks["digest_rebind"] = digests_match(live, subject)
        if not checks["digest_rebind"]:
            problems.append(
                f"digest mismatch: live {normalize_digest(live)} "
                f"!= attested sha256:{subject}"
            )
    except (ValueError, KeyError, TypeError, OSError) as exc:
        problems.append(f"statement: {exc}")
        return VerifyResult(
            ok=False,
            scheme=verifier.scheme,
            keyid=keyid,
            decision=decision,
            checks=checks,
            problems=problems,
        )

    return VerifyResult(
        ok=all(checks.values()),
        scheme=verifier.scheme,
        keyid=keyid,
        decision=decision,
        checks=checks,
        problems=problems,
    )
