"""CLI surface: --version works; unimplemented subcommands say so honestly."""

from __future__ import annotations

import pytest

import mig
from mig.cli.main import build_parser, main


def test_version_flag_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert mig.__version__ in capsys.readouterr().out


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "usage" in capsys.readouterr().out.lower()


@pytest.mark.parametrize(
    ("command", "pr"),
    [
        ("promote", "PR8"),  # ingest/verify/evidence implemented in PR7
    ],
)
def test_pending_subcommands_are_honest(
    command: str, pr: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main([command])
    assert code == 2  # not-yet-implemented exit code
    assert pr in capsys.readouterr().err


def test_parser_builds() -> None:
    parser = build_parser()
    assert parser.prog == "mig"
