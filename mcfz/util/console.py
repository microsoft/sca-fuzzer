"""
File: Lightweight ANSI console helpers for consistent, readable McFuzz terminal output.

All user-facing status messages emitted by McFuzz should go through these helpers so that
the output has a uniform look (consistent prefixes, colors, and section headers) instead of
the ad-hoc mix of prefixes that different modules used to print. No external dependencies
beyond ``tqdm`` (already a project dependency) are used.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import sys
from typing import Any, Final

from tqdm import tqdm

# Public ANSI style codes, used both internally by this module and by modules that build
# multi-line, inline-styled strings (e.g. the `details` report) rather than emitting one
# status line at a time.
RESET: Final[str] = "\033[0m"
BOLD: Final[str] = "\033[1m"
DIM: Final[str] = "\033[2m"
RED: Final[str] = "\033[31m"
GREEN: Final[str] = "\033[32m"
YELLOW: Final[str] = "\033[33m"
CYAN: Final[str] = "\033[36m"

_HEADER_WIDTH: Final[int] = 62
_PROGRESS_NCOLS: Final[int] = 80
_PROGRESS_BAR_FORMAT: Final[str] = ("  {desc:<22}{percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} "
                                    "[{elapsed}<{remaining}, {rate_fmt}]")


def _use_color() -> bool:
    """Return True only when stdout is an interactive terminal that can render color."""
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _paint(text: str, *codes: str) -> str:
    """Wrap ``text`` in the given ANSI codes, or return it unchanged when color is disabled."""
    if not codes or not _use_color():
        return text
    return "".join(codes) + text + RESET


def paint(text: str, *codes: str) -> str:
    """ Wrap ``text`` in the given ANSI style codes, honoring the TTY color gate """
    return _paint(text, *codes)


def _emit(message: str) -> None:
    """Write a single line without corrupting any active tqdm progress bar."""
    tqdm.write(message)


def section(title: str) -> None:
    """Print a bold section header that visually separates pipeline stages."""
    rule = "\u2500" * max(0, _HEADER_WIDTH - len(title) - 4)
    _emit("")
    _emit(_paint(f"\u2501\u2501 {title} ", BOLD, CYAN) + _paint(rule, CYAN))


def info(message: str) -> None:
    """Print a primary progress message."""
    _emit(_paint("  \u2022 ", CYAN) + message)


def detail(message: str) -> None:
    """Print a secondary, dimmed message for low-importance detail."""
    _emit(_paint(f"    {message}", DIM))


def success(message: str) -> None:
    """Print a success / completion message."""
    _emit(_paint("  \u2713 ", GREEN) + message)


def warn(message: str) -> None:
    """Print a warning message."""
    _emit(_paint("  ! ", YELLOW) + _paint(message, YELLOW))


def error(message: str) -> None:
    """Print an error message."""
    _emit(_paint("  \u2717 ", RED) + _paint(message, RED))


def progress_bar(total: int, desc: str, unit: str = "exec") -> "tqdm[Any]":
    """
    Create a tqdm progress bar with a consistent McFuzz look.

    :param total: Total number of work items the bar tracks.
    :param desc: Short label shown to the left of the bar.
    :param unit: Unit name used in the rate display (e.g. ``exec`` -> ``exec/s``).
    :return: A configured tqdm instance.
    """
    return tqdm(
        total=total,
        desc=desc,
        ncols=_PROGRESS_NCOLS,
        colour="cyan",
        bar_format=_PROGRESS_BAR_FORMAT,
        unit=unit,
        leave=True,
    )
