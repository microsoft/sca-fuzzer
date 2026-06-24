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

# ANSI styling codes
_RESET: Final[str] = "\033[0m"
_BOLD: Final[str] = "\033[1m"
_DIM: Final[str] = "\033[2m"
_RED: Final[str] = "\033[31m"
_GREEN: Final[str] = "\033[32m"
_YELLOW: Final[str] = "\033[33m"
_CYAN: Final[str] = "\033[36m"

_HEADER_WIDTH: Final[int] = 62
_PROGRESS_NCOLS: Final[int] = 80
_PROGRESS_BAR_FORMAT: Final[str] = (
    "  {desc:<22}{percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")


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
    return "".join(codes) + text + _RESET


def _emit(message: str) -> None:
    """Write a single line without corrupting any active tqdm progress bar."""
    tqdm.write(message)


def section(title: str) -> None:
    """Print a bold section header that visually separates pipeline stages."""
    rule = "\u2500" * max(0, _HEADER_WIDTH - len(title) - 4)
    _emit("")
    _emit(_paint(f"\u2501\u2501 {title} ", _BOLD, _CYAN) + _paint(rule, _CYAN))


def info(message: str) -> None:
    """Print a primary progress message."""
    _emit(_paint("  \u2022 ", _CYAN) + message)


def detail(message: str) -> None:
    """Print a secondary, dimmed message for low-importance detail."""
    _emit(_paint(f"    {message}", _DIM))


def success(message: str) -> None:
    """Print a success / completion message."""
    _emit(_paint("  \u2713 ", _GREEN) + message)


def warn(message: str) -> None:
    """Print a warning message."""
    _emit(_paint("  ! ", _YELLOW) + _paint(message, _YELLOW))


def error(message: str) -> None:
    """Print an error message."""
    _emit(_paint("  \u2717 ", _RED) + _paint(message, _RED))


def progress_bar(total: int, desc: str) -> "tqdm[Any]":
    """
    Create a tqdm progress bar with a consistent McFuzz look.

    :param total: Total number of work items the bar tracks.
    :param desc: Short label shown to the left of the bar.
    :return: A configured tqdm instance.
    """
    return tqdm(
        total=total,
        desc=desc,
        ncols=_PROGRESS_NCOLS,
        colour="cyan",
        bar_format=_PROGRESS_BAR_FORMAT,
        leave=True,
    )
