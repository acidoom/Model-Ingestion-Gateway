"""The cosmetic CLI banner — TTY-gated, stderr-only, colour-optional.

The load-bearing property is that the banner NEVER appears unless stderr is an
interactive TTY, so it cannot corrupt piped JSON or leak into captured test
output (which is why the rest of the suite is unaffected).
"""

from __future__ import annotations

import io
import pathlib

import pytest

from conftest import make_model_dir
from mig import __version__
from mig.cli.banner import banner_enabled, print_banner, render
from mig.cli.main import main


class _FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_render_colour_has_ansi_plain_does_not() -> None:
    colored = render(color=True)
    plain = render(color=False)
    assert "\033[" in colored  # ANSI escapes present
    assert "\033[" not in plain  # none when colour is off
    assert "Model Ingestion Gateway" in plain
    assert __version__ in plain
    assert r"|_|  |_|___\____|" in plain  # the ASCII logo body


def test_banner_suppressed_on_non_tty() -> None:
    buf = io.StringIO()  # a plain stream is not a TTY
    assert banner_enabled(buf) is False
    print_banner(buf)
    assert buf.getvalue() == ""


def test_banner_shown_on_tty() -> None:
    buf = _FakeTTY()
    assert banner_enabled(buf) is True
    print_banner(buf)
    out = buf.getvalue()
    assert "Model Ingestion Gateway" in out
    assert "\033[" in out  # coloured by default


def test_banner_respects_mig_no_banner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MIG_NO_BANNER", "1")
    buf = _FakeTTY()
    assert banner_enabled(buf) is False
    print_banner(buf)
    assert buf.getvalue() == ""


def test_banner_respects_no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    buf = _FakeTTY()
    print_banner(buf)
    out = buf.getvalue()
    assert out  # still shown...
    assert "\033[" not in out  # ...but without colour


def test_main_emits_no_banner_under_capture(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # capsys' stderr is not a TTY, so a real command run emits no banner — proving
    # the banner cannot interfere with stdout JSON or stderr assertions elsewhere.
    model = make_model_dir(tmp_path)
    assert main(["manifest", str(model)]) == 0
    captured = capsys.readouterr()
    assert "Model Ingestion Gateway" not in captured.err
    assert "Model Ingestion Gateway" not in captured.out
