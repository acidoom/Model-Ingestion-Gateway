"""The ``mig`` command-line entry point (PRD §15).

Implemented: ``scan`` (decision-only verdict JSON, with ``--policy``/``--fail-on``,
PR2/PR5), ``manifest`` (PR2), ``policy test`` (PR5). The remaining subcommands
land later — ``ingest``/``verify``/``evidence`` (PR7), ``promote`` (PR8) — and
until then print an honest "not yet implemented" message rather than pretending
to vet anything.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections.abc import Sequence
from typing import TYPE_CHECKING

from mig import __version__
from mig.core.artifact import ArtifactRef, ArtifactType
from mig.core.context import make_context
from mig.core.pipeline import run_pipeline
from mig.core.serde import to_json, to_jsonable
from mig.core.verdict import Decision
from mig.gates import default_gates
from mig.policy.engine import matched_rules
from mig.policy.loader import load_policy
from mig.policy.schema import Policy, PolicyError
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

#: Subcommand -> the PR that implements it. Used to print honest placeholders.
_PENDING: dict[str, str] = {
    "ingest": "PR7",
    "verify": "PR7",
    "evidence": "PR7",
    "promote": "PR8",
}

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
    scan.add_argument(
        "--sandbox",
        choices=["noop", "docker"],
        default="noop",
        help="behavioral sandbox (default: noop = loud SKIPPED)",
    )
    scan.add_argument("--sandbox-image", help="container image for --sandbox docker")
    scan.add_argument(
        "--sandbox-runtime",
        choices=["runc", "gvisor"],
        default="runc",
        help="container runtime for --sandbox docker",
    )
    scan.add_argument("--compact", action="store_true", help="emit single-line JSON")

    manifest = sub.add_parser("manifest", help="show the artifact manifest (JSON)")
    _add_ref_args(manifest)
    manifest.add_argument("--compact", action="store_true", help="emit single-line JSON")

    ingest = sub.add_parser("ingest", help="scan + attest a reference (PR7)")
    ingest.add_argument("ref", nargs="?")
    ingest.add_argument("--policy")

    sub.add_parser("verify", help="verify a prior attestation (PR7)")

    policy = sub.add_parser("policy", help="policy tooling")
    policy.add_argument("policy_action", choices=["test"], help="policy subcommand")
    policy.add_argument("ref", help="artifact reference to evaluate the policy against")
    policy.add_argument("--policy", required=True, help="policy file (.yaml/.json)")
    policy.add_argument("--type", choices=_ARTIFACT_TYPE_CHOICES)
    policy.add_argument("--compact", action="store_true")

    evidence = sub.add_parser("evidence", help="emit an evidence bundle (PR7)")
    evidence.add_argument("--out")

    promote = sub.add_parser("promote", help="promote to the trusted store (PR8)")
    promote.add_argument("ref", nargs="?")
    promote.add_argument("--attestation")

    return parser


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


_COMMANDS = {"scan": _cmd_scan, "manifest": _cmd_manifest, "policy": _cmd_policy}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

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
