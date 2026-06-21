"""The ``mig`` command-line entry point.

PR1 ships the argument surface (PRD §15) and ``--version``. The subcommands are
wired in their respective PRs — ``scan`` in PR2, ``ingest``/``policy`` in PR5,
``verify``/``evidence`` in PR7, ``promote`` in PR8 — and until then print an
honest "not yet implemented" message rather than pretending to vet anything.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from mig import __version__

#: Subcommand -> the PR that implements it. Used to print honest placeholders.
_PENDING: dict[str, str] = {
    "scan": "PR2",
    "ingest": "PR5",
    "verify": "PR7",
    "manifest": "PR2",
    "policy": "PR5",
    "evidence": "PR7",
    "promote": "PR8",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mig",
        description="MIG — Model Ingestion Gateway: vet AI artifacts before trust.",
    )
    parser.add_argument("--version", action="version", version=f"mig {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("scan", help="decision-only verdict for a reference (PR2)")

    ingest = sub.add_parser("ingest", help="scan + attest a reference (PR5)")
    ingest.add_argument("ref", nargs="?")
    ingest.add_argument("--policy")

    sub.add_parser("verify", help="verify a prior attestation (PR7)")
    sub.add_parser("manifest", help="show the artifact manifest (PR2)")

    policy = sub.add_parser("policy", help="policy tooling (PR5)")
    policy.add_argument("policy_command", nargs="?")

    evidence = sub.add_parser("evidence", help="emit an evidence bundle (PR7)")
    evidence.add_argument("--out")

    promote = sub.add_parser("promote", help="promote to the trusted store (PR8)")
    promote.add_argument("ref", nargs="?")
    promote.add_argument("--attestation")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    command: str | None = getattr(args, "command", None)
    if command is None:
        parser.print_help()
        return 0

    pending = _PENDING.get(command)
    if pending is not None:
        print(
            f"mig {command}: not implemented yet — lands in {pending}. "
            f"PR1 ships the core contracts only.",
            file=sys.stderr,
        )
        return 2

    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
