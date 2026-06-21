"""The ``mig`` command-line entry point (PRD §15).

PR2 implements ``scan`` (decision-only verdict JSON, end to end over a local
path) and ``manifest``. The remaining subcommands land in their respective PRs —
``ingest``/``policy`` (PR5), ``verify``/``evidence`` (PR7), ``promote`` (PR8) —
and until then print an honest "not yet implemented" message rather than
pretending to vet anything.
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
from mig.gates import default_gates
from mig.policy.schema import Policy
from mig.sources.base import SourceError
from mig.sources.huggingface import HuggingFaceSource
from mig.sources.local import LocalSource
from mig.storage.quarantine import Quarantine, QuarantineError

#: Fetch/staging failures that map to a clean exit-2 rather than a traceback.
_FETCH_ERRORS = (SourceError, QuarantineError)

if TYPE_CHECKING:
    from mig.core.protocols import Source

#: Subcommand -> the PR that implements it. Used to print honest placeholders.
_PENDING: dict[str, str] = {
    "ingest": "PR5",
    "verify": "PR7",
    "policy": "PR5",
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
    scan.add_argument("--compact", action="store_true", help="emit single-line JSON")

    manifest = sub.add_parser("manifest", help="show the artifact manifest (JSON)")
    _add_ref_args(manifest)
    manifest.add_argument("--compact", action="store_true", help="emit single-line JSON")

    ingest = sub.add_parser("ingest", help="scan + attest a reference (PR5)")
    ingest.add_argument("ref", nargs="?")
    ingest.add_argument("--policy")

    sub.add_parser("verify", help="verify a prior attestation (PR7)")

    policy = sub.add_parser("policy", help="policy tooling (PR5)")
    policy.add_argument("policy_command", nargs="?")

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


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        ref, type_hint = _resolve_ref(args.ref, args.type, args.digest)
    except ValueError as exc:
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
            policy=Policy(id="builtin-default", version=__version__),
            quarantine=Quarantine(root=quarantine_root),
        )
        verdict = run_pipeline(artifact, default_gates(), ctx)
        print(to_json(verdict, indent=None if args.compact else 2))
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


_COMMANDS = {"scan": _cmd_scan, "manifest": _cmd_manifest}


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
