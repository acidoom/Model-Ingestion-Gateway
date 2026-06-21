"""A small, colourful ASCII banner for the CLI.

Purely cosmetic. It is written to **stderr** (never stdout, which carries the
machine-readable JSON a caller may pipe to ``jq``) and only when stderr is an
interactive TTY — so redirected output, pipelines, and the test suite see nothing.
Colour follows the `NO_COLOR <https://no-color.org/>`_ convention; set
``MIG_NO_BANNER`` to suppress the banner entirely.
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

from mig import __version__

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[38;5;48m"

#: A cyan → blue 256-colour gradient, one tone per logo row.
_ROW_COLORS = (
    "\033[38;5;51m",
    "\033[38;5;45m",
    "\033[38;5;39m",
    "\033[38;5;33m",
    "\033[38;5;27m",
)

_LOGO_ROWS = (
    r" __  __ ___ ____ ",
    r"|  \/  |_ _/ ___|",
    r"| |\/| || | |  _ ",
    r"| |  | || | |_| |",
    r"|_|  |_|___\____|",
)

_TAGLINE = "Model Ingestion Gateway"
_SUBTITLE = "vet AI artifacts before you trust them"


def render(*, color: bool) -> str:
    """The banner as a string (ANSI-coloured when ``color`` is true)."""
    lines: list[str] = []
    for row, tone in zip(_LOGO_ROWS, _ROW_COLORS, strict=True):
        lines.append(f"{tone}{_BOLD}{row}{_RESET}" if color else row)
    if color:
        lines.append(f"  {_GREEN}{_TAGLINE}{_RESET} {_DIM}v{__version__}{_RESET}")
        lines.append(f"  {_DIM}{_SUBTITLE}{_RESET}")
    else:
        lines.append(f"  {_TAGLINE} v{__version__}")
        lines.append(f"  {_SUBTITLE}")
    return "\n".join(lines)


def banner_enabled(stream: TextIO) -> bool:
    """True if the banner should be shown on ``stream`` (TTY + not opted out)."""
    if os.environ.get("MIG_NO_BANNER"):
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def print_banner(stream: TextIO | None = None) -> None:
    """Print the banner to ``stream`` (default stderr) if it is an interactive TTY."""
    out = stream if stream is not None else sys.stderr
    if not banner_enabled(out):
        return
    out.write(render(color=not os.environ.get("NO_COLOR")) + "\n")
