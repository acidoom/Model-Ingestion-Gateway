"""The ``mig`` command-line entry point (PRD §15).

All subcommands are live: ``scan`` (decision-only verdict), ``manifest``,
``policy test`` (PR2/PR5); ``ingest``/``verify``/``evidence`` (signed DSSE
attestations, PR7); and ``promote`` (gated trusted-store promotion, PR8 — the one
command that crosses the decision boundary, I6). Everything before ``promote`` is
decision-only.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import shutil
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mig import __version__
from mig.cli.banner import print_banner
from mig.core.artifact import ArtifactRef, ArtifactType
from mig.core.context import make_context
from mig.core.pipeline import run_pipeline
from mig.core.serde import to_json, to_jsonable
from mig.core.verdict import Decision
from mig.evidence.builder import build_attestation
from mig.evidence.bundle import build_bundle, bundle_bytes, write_bundle
from mig.evidence.canonical import canonical_bytes
from mig.evidence.dsse import encode_envelope
from mig.evidence.signing import (
    HMAC_SCHEME,
    SigningError,
    make_signer,
    make_verifier,
    sign_statement,
)
from mig.evidence.statement import statement_from_attestation
from mig.evidence.verify import verify_attestation
from mig.gates import default_gates
from mig.policy.engine import matched_rules
from mig.policy.loader import load_policy
from mig.policy.schema import Policy, PolicyError
from mig.promotion import (
    PromotionError,
    make_promotion_gate,
    make_trusted_store,
    promote_artifact,
)
from mig.promotion.audit import PromotionAuditSink
from mig.sandbox.docker import DEFAULT_IMAGE, DockerSandbox
from mig.sources.base import SourceError
from mig.sources.huggingface import HuggingFaceSource
from mig.sources.local import LocalSource
from mig.storage.quarantine import Quarantine, QuarantineError

#: Fetch/staging failures that map to a clean exit-2 rather than a traceback.
_FETCH_ERRORS = (SourceError, QuarantineError)
#: Decision severity order, for --fail-on exit codes.
_DECISION_RANK = {
    Decision.APPROVE: 0,
    Decision.REVIEW_REQUIRED: 1,
    Decision.REJECT: 2,
}

if TYPE_CHECKING:
    from mig.core.protocols import Sandbox, Source
    from mig.core.verdict import Verdict
    from mig.evidence.dsse import Envelope
    from mig.evidence.signing import Signer, Verifier
    from mig.promotion.gate import PromotionGate

#: Subcommand -> the PR that implements it. Empty: every subcommand is now live
#: (PR8 implemented `promote`, the last one). Kept as the seam for future commands.
_PENDING: dict[str, str] = {}

#: Signer backends selectable on the CLI (hmac is the zero-dep default).
_SIGNER_CHOICES = ["hmac", "ed25519", "cosign"]

_ARTIFACT_TYPE_CHOICES = [t.value for t in ArtifactType]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mig",
        description="MIG — Model Ingestion Gateway: vet AI artifacts before trust.",
    )
    parser.add_argument("--version", action="version", version=f"mig {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="decision-only verdict for a reference (JSON)")
    _add_ref_args(scan)
    scan.add_argument("--policy", help="policy file (.yaml/.json); default if omitted")
    scan.add_argument(
        "--fail-on",
        choices=["review", "reject"],
        help="exit non-zero if the decision is at least this severe",
    )
    _add_sandbox_args(scan)
    scan.add_argument("--compact", action="store_true", help="emit single-line JSON")

    manifest = sub.add_parser("manifest", help="show the artifact manifest (JSON)")
    _add_ref_args(manifest)
    manifest.add_argument("--compact", action="store_true", help="emit single-line JSON")

    ingest = sub.add_parser(
        "ingest", help="scan + build a signed attestation (DSSE) for a reference"
    )
    _add_ref_args(ingest)
    ingest.add_argument("--policy", help="policy file (.yaml/.json); default if omitted")
    _add_sandbox_args(ingest)
    _add_signer_args(ingest)
    ingest.add_argument("--out", help="write the DSSE envelope here (default: stdout)")
    ingest.add_argument("--bundle", help="also write a full evidence bundle here")
    ingest.add_argument(
        "--fail-on",
        choices=["review", "reject"],
        help="exit non-zero if the decision is at least this severe",
    )
    ingest.add_argument("--compact", action="store_true")

    verify = sub.add_parser("verify", help="verify a signed attestation (DSSE/bundle)")
    _add_ref_args(verify)
    verify.add_argument(
        "--attestation", required=True, help="DSSE envelope or evidence bundle to verify"
    )
    _add_signer_args(verify)
    verify.add_argument("--expected-keyid", help="fail unless the envelope keyid matches")
    verify.add_argument("--compact", action="store_true")

    policy = sub.add_parser("policy", help="policy tooling")
    policy.add_argument("policy_action", choices=["test"], help="policy subcommand")
    policy.add_argument("ref", help="artifact reference to evaluate the policy against")
    policy.add_argument("--policy", required=True, help="policy file (.yaml/.json)")
    policy.add_argument("--type", choices=_ARTIFACT_TYPE_CHOICES)
    policy.add_argument("--compact", action="store_true")

    evidence = sub.add_parser(
        "evidence", help="emit a full, signed evidence bundle for a reference"
    )
    _add_ref_args(evidence)
    evidence.add_argument(
        "--policy", help="policy file (.yaml/.json); default if omitted"
    )
    _add_sandbox_args(evidence)
    _add_signer_args(evidence)
    evidence.add_argument("--out", help="write the bundle here (default: stdout)")
    evidence.add_argument("--compact", action="store_true")

    promote = sub.add_parser(
        "promote", help="gated promotion of a verified attestation to the trusted store"
    )
    _add_ref_args(promote)
    promote.add_argument(
        "--attestation", required=True, help="signed DSSE envelope or evidence bundle"
    )
    _add_signer_args(promote)
    promote.add_argument(
        "--expected-keyid", help="fail unless the envelope keyid matches"
    )
    promote.add_argument(
        "--require-keyid",
        action="append",
        metavar="KID",
        help="only promote attestations signed by an allowlisted keyid (repeatable)",
    )
    promote.add_argument(
        "--require-asymmetric",
        action="store_true",
        help="refuse HMAC (integrity-only) attestations — require ed25519/cosign",
    )
    promote.add_argument("--store", choices=["local"], default="local")
    promote.add_argument(
        "--store-root", help="trusted store root (or $MIG_TRUSTED_STORE; ./.mig-trusted)"
    )
    promote.add_argument(
        "--opa", choices=["cli"], help="add an OPA gate (deny-overrides)"
    )
    promote.add_argument("--opa-bin", default="opa", help="opa binary for --opa cli")
    promote.add_argument("--opa-policy", help="Rego policy file for --opa cli")
    promote.add_argument(
        "--dry-run", action="store_true", help="verify + decide but do not write"
    )
    promote.add_argument("--compact", action="store_true")

    return parser


def _add_sandbox_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--sandbox",
        choices=["noop", "docker"],
        default="noop",
        help="behavioral sandbox (default: noop = loud SKIPPED)",
    )
    parser.add_argument("--sandbox-image", help="container image for --sandbox docker")
    parser.add_argument(
        "--sandbox-runtime",
        choices=["runc", "gvisor"],
        default="runc",
        help="container runtime for --sandbox docker",
    )


def _add_signer_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--signer",
        choices=_SIGNER_CHOICES,
        default="hmac",
        help="signature backend (default: hmac = stdlib, integrity-only)",
    )
    parser.add_argument(
        "--key", help="key file (HMAC secret / ed25519 key / cosign key ref)"
    )
    parser.add_argument(
        "--cosign-bin", default="cosign", help="cosign binary for --signer cosign"
    )


def _add_ref_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("ref", help="artifact reference (a local path in PR2)")
    parser.add_argument(
        "--type",
        choices=_ARTIFACT_TYPE_CHOICES,
        help="artifact type (inferred when omitted)",
    )
    parser.add_argument(
        "--digest", help="expected content digest to pin/verify at fetch (I3)"
    )


def _resolve_ref(
    ref_str: str, type_str: str | None, digest_str: str | None
) -> tuple[ArtifactRef, ArtifactType | None]:
    type_hint = ArtifactType(type_str) if type_str else None

    if ref_str.startswith(("hf://", "huggingface://")):
        body = ref_str.split("://", 1)[1]
        repo_id, _, revision = body.partition("@")
        if not repo_id:
            raise ValueError(
                "huggingface reference needs a repo id, e.g. hf://org/model@<sha>"
            )
        ref = ArtifactRef(
            scheme="huggingface",
            locator=repo_id,
            revision=revision or None,
            expected_digest=digest_str,
        )
        return ref, type_hint

    if "://" in ref_str and not ref_str.startswith(("local://", "file://")):
        scheme = ref_str.split("://", 1)[0]
        raise ValueError(
            f"unsupported scheme {scheme!r}; supported: local paths and hf://"
        )
    ref = ArtifactRef(
        scheme="local", locator=ref_str, revision=None, expected_digest=digest_str
    )
    return ref, type_hint


def _source_for(ref: ArtifactRef, type_hint: ArtifactType | None) -> Source:
    if ref.scheme == "huggingface":
        return HuggingFaceSource(artifact_type=type_hint)
    return LocalSource(artifact_type=type_hint)


def _load_policy(path: str | None) -> Policy:
    """Load a policy file, or the built-in default when no ``--policy`` is given."""
    if path is None:
        return Policy(id="builtin-default", version=__version__)
    return load_policy(path)


def _build_sandbox(args: argparse.Namespace) -> Sandbox | None:
    """The behavioral sandbox for this run (None → NoopSandbox default, I7)."""
    if getattr(args, "sandbox", "noop") != "docker":
        return None
    runtime = "runsc" if getattr(args, "sandbox_runtime", "runc") == "gvisor" else None
    return DockerSandbox(image=args.sandbox_image or DEFAULT_IMAGE, runtime=runtime)


def _exit_code(decision: Decision, fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = Decision.REJECT if fail_on == "reject" else Decision.REVIEW_REQUIRED
    return 1 if _DECISION_RANK[decision] >= _DECISION_RANK[threshold] else 0


def _utc_now() -> str:
    """ISO-8601 UTC timestamp (``...Z``) — stamped per run, caller-controlled."""
    now = datetime.datetime.now(tz=datetime.UTC)
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_key_bytes(args: argparse.Namespace) -> bytes:
    """Resolve HMAC/ed25519 key material from --key FILE or (hmac) the env.

    A key file's trailing newline (what ``echo`` and most editors append) is
    stripped so a file and ``MIG_SIGNING_KEY`` carrying the same secret produce
    the SAME key/keyid — otherwise an honest operator gets a spurious tamper alarm.
    """
    if args.key:
        try:
            with open(args.key, "rb") as handle:
                data = handle.read()
        except OSError as exc:
            raise SigningError(f"cannot read key file {args.key!r}: {exc}") from exc
        return data.rstrip(b"\r\n")
    if args.signer == "hmac":
        env = os.environ.get("MIG_SIGNING_KEY")
        if env:
            return env.encode("utf-8")
    hint = " or MIG_SIGNING_KEY" if args.signer == "hmac" else ""
    raise SigningError(f"{args.signer} needs a key (--key FILE{hint})")


def _build_signer(args: argparse.Namespace) -> Signer:
    if args.signer == "cosign":
        if not args.key:
            raise SigningError("cosign signing needs --key <key-ref>")
        return make_signer("cosign", key_ref=args.key, cosign_bin=args.cosign_bin)
    return make_signer(args.signer, key_bytes=_read_key_bytes(args))


def _build_verifier(args: argparse.Namespace) -> Verifier:
    if args.signer == "cosign":
        if not args.key:
            raise SigningError("cosign verify needs --key <pubkey-ref>")
        return make_verifier("cosign", key_ref=args.key, cosign_bin=args.cosign_bin)
    return make_verifier(args.signer, key_bytes=_read_key_bytes(args))


@dataclass
class _Signed:
    """In-memory result of the fetch → scan → attest → sign pipeline."""

    verdict: Verdict
    envelope: Envelope
    decision: Decision
    created_at: str
    run_meta: dict[str, object]


def _produce_signed(args: argparse.Namespace, command: str) -> _Signed:
    """Fetch + pin + scan + attest (I5 fail-closed) + sign. Decision-only (I6).

    Raises ValueError/PolicyError/SigningError/SourceError/QuarantineError on any
    operator-facing failure; the caller maps those to exit 2.
    """
    ref, type_hint = _resolve_ref(args.ref, args.type, args.digest)
    policy = _load_policy(args.policy)
    signer = _build_signer(args)  # fail on a bad key BEFORE fetching anything
    created_at = _utc_now()

    quarantine_root = tempfile.mkdtemp(prefix="mig-quarantine-")
    try:
        artifact = _source_for(ref, type_hint).fetch(
            ref, Quarantine(root=quarantine_root)
        )
        ctx = make_context(
            policy=policy,
            quarantine=Quarantine(root=quarantine_root),
            sandbox=_build_sandbox(args),
        )
        verdict = run_pipeline(artifact, default_gates(), ctx)
        confinement = getattr(
            ctx.sandbox, "confinement_level", type(ctx.sandbox).__name__
        )
        attestation = build_attestation(
            verdict,
            artifact,
            policy=policy,
            mig_version=__version__,
            confinement_level=confinement,
            created_at=created_at,
        )
        statement = statement_from_attestation(attestation)
        envelope = sign_statement(statement, signer)
    finally:
        shutil.rmtree(quarantine_root, ignore_errors=True)

    run_meta: dict[str, object] = {
        "run_id": ctx.run_id,
        "command": command,
        "policy": {"id": policy.id, "version": policy.version},
        "sandbox": {"confinement_level": confinement},
        "host": {"platform": sys.platform, "python": platform.python_version()},
        "signer": {"scheme": signer.scheme, "keyid": signer.key_id},
    }
    return _Signed(
        verdict=verdict,
        envelope=envelope,
        decision=verdict.decision,
        created_at=created_at,
        run_meta=run_meta,
    )


#: Operator-facing failures from the attest pipeline — all map to a clean exit 2.
_ATTEST_ERRORS = (ValueError, PolicyError, SigningError, SourceError, QuarantineError)


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        ref, type_hint = _resolve_ref(args.ref, args.type, args.digest)
        policy = _load_policy(args.policy)
    except (ValueError, PolicyError) as exc:
        print(f"mig scan: {exc}", file=sys.stderr)
        return 2

    quarantine_root = tempfile.mkdtemp(prefix="mig-quarantine-")
    try:
        try:
            artifact = _source_for(ref, type_hint).fetch(
                ref, Quarantine(root=quarantine_root)
            )
        except _FETCH_ERRORS as exc:
            print(f"mig scan: {exc}", file=sys.stderr)
            return 2
        ctx = make_context(
            policy=policy,
            quarantine=Quarantine(root=quarantine_root),
            sandbox=_build_sandbox(args),
        )
        try:
            verdict = run_pipeline(artifact, default_gates(), ctx)
        except PolicyError as exc:  # an eval-time policy error is an operator error
            print(f"mig scan: {exc}", file=sys.stderr)
            return 2
        print(to_json(verdict, indent=None if args.compact else 2))
        return _exit_code(verdict.decision, args.fail_on)
    finally:
        shutil.rmtree(quarantine_root, ignore_errors=True)


def _cmd_policy(args: argparse.Namespace) -> int:
    try:
        ref, type_hint = _resolve_ref(args.ref, args.type, None)
        policy = load_policy(args.policy)
    except (ValueError, PolicyError) as exc:
        print(f"mig policy: {exc}", file=sys.stderr)
        return 2

    quarantine_root = tempfile.mkdtemp(prefix="mig-quarantine-")
    try:
        try:
            artifact = _source_for(ref, type_hint).fetch(
                ref, Quarantine(root=quarantine_root)
            )
        except _FETCH_ERRORS as exc:
            print(f"mig policy: {exc}", file=sys.stderr)
            return 2
        ctx = make_context(policy=policy, quarantine=Quarantine(root=quarantine_root))
        try:
            verdict = run_pipeline(artifact, default_gates(), ctx)
            fired = matched_rules(policy, artifact, verdict.gate_results)
        except PolicyError as exc:
            print(f"mig policy: {exc}", file=sys.stderr)
            return 2
        report = {
            "policy": {"id": policy.id, "version": policy.version},
            "decision": verdict.decision.value,
            "matched_rules": [
                {
                    "id": rule.id,
                    "action": rule.action.value,
                    "severity": rule.severity.name.lower(),
                }
                for rule in fired
            ],
        }
        print(json.dumps(report, indent=None if args.compact else 2))
        return 0
    finally:
        shutil.rmtree(quarantine_root, ignore_errors=True)


def _cmd_manifest(args: argparse.Namespace) -> int:
    try:
        ref, type_hint = _resolve_ref(args.ref, args.type, args.digest)
    except ValueError as exc:
        print(f"mig manifest: {exc}", file=sys.stderr)
        return 2

    quarantine_root = tempfile.mkdtemp(prefix="mig-quarantine-")
    try:
        try:
            artifact = _source_for(ref, type_hint).fetch(
                ref, Quarantine(root=quarantine_root)
            )
        except _FETCH_ERRORS as exc:
            print(f"mig manifest: {exc}", file=sys.stderr)
            return 2
        manifest = {
            "ref": to_jsonable(artifact.ref),
            "artifact_type": artifact.artifact_type.value,
            "digest": artifact.digest,
            "files": list(artifact.files),
            "metadata": dict(artifact.metadata),
        }
        print(json.dumps(manifest, indent=None if args.compact else 2))
        return 0
    finally:
        shutil.rmtree(quarantine_root, ignore_errors=True)


def _cmd_ingest(args: argparse.Namespace) -> int:
    try:
        signed = _produce_signed(args, "ingest")
    except _ATTEST_ERRORS as exc:
        print(f"mig ingest: {exc}", file=sys.stderr)
        return 2

    try:
        envelope_dict = encode_envelope(signed.envelope)
        if args.out:
            with open(args.out, "wb") as handle:
                handle.write(canonical_bytes(envelope_dict))
        else:
            print(json.dumps(envelope_dict, indent=None if args.compact else 2))
        if args.bundle:
            bundle = build_bundle(
                signed.verdict,
                signed.envelope,
                mig_version=__version__,
                created_at=signed.created_at,
                run_meta=signed.run_meta,
            )
            write_bundle(args.bundle, bundle)
    except OSError as exc:  # a bad/unwritable --out/--bundle path is operator error
        print(f"mig ingest: {exc}", file=sys.stderr)
        return 2
    return _exit_code(signed.decision, args.fail_on)


def _cmd_evidence(args: argparse.Namespace) -> int:
    try:
        signed = _produce_signed(args, "evidence")
    except _ATTEST_ERRORS as exc:
        print(f"mig evidence: {exc}", file=sys.stderr)
        return 2

    bundle = build_bundle(
        signed.verdict,
        signed.envelope,
        mig_version=__version__,
        created_at=signed.created_at,
        run_meta=signed.run_meta,
    )
    try:
        if args.out:
            write_bundle(args.out, bundle)
        else:
            sys.stdout.write(bundle_bytes(bundle).decode("utf-8") + "\n")
    except OSError as exc:
        print(f"mig evidence: {exc}", file=sys.stderr)
        return 2
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        with open(args.attestation, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"mig verify: cannot read attestation: {exc}", file=sys.stderr)
        return 2
    if not isinstance(data, dict):
        print("mig verify: attestation file is not a JSON object", file=sys.stderr)
        return 2

    try:
        ref, type_hint = _resolve_ref(args.ref, args.type, args.digest)
        verifier = _build_verifier(args)
    except (ValueError, SigningError) as exc:
        print(f"mig verify: {exc}", file=sys.stderr)
        return 2

    quarantine_root = tempfile.mkdtemp(prefix="mig-quarantine-")
    try:
        try:
            artifact = _source_for(ref, type_hint).fetch(
                ref, Quarantine(root=quarantine_root)
            )
        except _FETCH_ERRORS as exc:
            print(f"mig verify: {exc}", file=sys.stderr)
            return 2
        try:
            result = verify_attestation(
                data,
                artifact=artifact,
                verifier=verifier,
                expected_keyid=args.expected_keyid,
            )
        except ValueError as exc:  # malformed envelope/bundle — operator error
            print(f"mig verify: {exc}", file=sys.stderr)
            return 2
    finally:
        shutil.rmtree(quarantine_root, ignore_errors=True)

    report: dict[str, object] = {
        "ok": result.ok,
        "scheme": result.scheme,
        "keyid": result.keyid,
        "decision": result.decision,
        "checks": dict(result.checks),
        "problems": list(result.problems),
    }
    if result.scheme == HMAC_SCHEME:
        report["warning"] = (
            "integrity-only (shared-secret HMAC), NOT third-party provenance — "
            "use ed25519/cosign across a trust boundary"
        )
    print(json.dumps(report, indent=None if args.compact else 2))
    return 0 if result.ok else 3  # 3 = verification failure (tamper), distinct from 2


def _store_root(args: argparse.Namespace) -> str:
    return args.store_root or os.environ.get("MIG_TRUSTED_STORE") or ".mig-trusted"


def _build_promotion_gate(args: argparse.Namespace) -> PromotionGate:
    keyids = frozenset(args.require_keyid or [])
    return make_promotion_gate(
        opa=args.opa,
        opa_bin=args.opa_bin,
        policy_path=args.opa_policy,
        required_keyids=keyids,
        require_asymmetric=args.require_asymmetric,
    )


def _cmd_promote(args: argparse.Namespace) -> int:
    if args.opa == "cli" and not args.opa_policy:
        print("mig promote: --opa cli requires --opa-policy FILE", file=sys.stderr)
        return 2
    try:
        ref, type_hint = _resolve_ref(args.ref, args.type, args.digest)
        verifier = _build_verifier(args)
        gate = _build_promotion_gate(args)
        store = make_trusted_store(args.store, root=_store_root(args))
    except (ValueError, SigningError, PromotionError) as exc:
        print(f"mig promote: {exc}", file=sys.stderr)
        return 2

    if args.opa == "cli":  # an explicitly-requested but absent opa is operator error
        from mig.promotion.opa.cli import opa_available

        if not opa_available(args.opa_bin):
            print(
                f"mig promote: opa binary {args.opa_bin!r} not found or unusable",
                file=sys.stderr,
            )
            return 2

    audit = PromotionAuditSink(_store_root(args))
    result = promote_artifact(
        ref,
        attestation_path=args.attestation,
        verifier=verifier,
        store=store,
        gate=gate,
        source=_source_for(ref, type_hint),
        audit=audit,
        mig_version=__version__,
        expected_keyid=args.expected_keyid,
        dry_run=args.dry_run,
    )

    report: dict[str, object] = {
        "ok": result.ok,
        "outcome": result.outcome,
        "promoted": result.outcome in ("promoted", "idempotent_noop"),
        "already_present": result.already_present,
        "digest": result.digest,
        "store_uri": result.store_uri,
        "decision": result.decision,
        "scheme": result.scheme,
        "keyid": result.keyid,
        "gate": result.gate,
        "verification": result.verification,
        "problems": result.problems,
    }
    if result.ok and result.scheme == HMAC_SCHEME:
        report["warning"] = (
            "promoted an HMAC (integrity-only) attestation — across a trust "
            "boundary use ed25519/cosign and --require-asymmetric"
        )
    print(json.dumps(report, indent=None if args.compact else 2))
    return result.exit_code


_COMMANDS = {
    "scan": _cmd_scan,
    "manifest": _cmd_manifest,
    "policy": _cmd_policy,
    "ingest": _cmd_ingest,
    "evidence": _cmd_evidence,
    "verify": _cmd_verify,
    "promote": _cmd_promote,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Cosmetic banner — stderr-only and TTY-gated, so it never touches the JSON on
    # stdout and stays silent when redirected/piped (and under test).
    print_banner()

    command: str | None = getattr(args, "command", None)
    if command is None:
        parser.print_help()
        return 0

    handler = _COMMANDS.get(command)
    if handler is not None:
        return handler(args)

    pending = _PENDING.get(command)
    if pending is not None:
        print(
            f"mig {command}: not implemented yet — lands in {pending}.",
            file=sys.stderr,
        )
        return 2

    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
