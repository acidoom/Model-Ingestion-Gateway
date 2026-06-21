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


def test_no_subcommands_are_pending() -> None:
    """Every subcommand is implemented — PR8 (`promote`) was the last placeholder."""
    from mig.cli.main import _PENDING

    assert _PENDING == {}


def test_parser_builds() -> None:
    parser = build_parser()
    assert parser.prog == "mig"
