"""
File: Module responsible for logging.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from . import console


class Logger:
    """
    Logger class for managing logging operations.

    Messages are rendered through :mod:`mcfz.util.console` so that they share the same
    consistent, colored look as the rest of McFuzz's output.
    """

    def __init__(self, name: str) -> None:
        self._name = name

    def critical(self, message: str) -> None:
        """Log a critical message with the logger's name and abort."""
        console.error(f"{self._name}: {message}")
        raise SystemExit(1)

    def error(self, message: str) -> None:
        """Log an error message with the logger's name."""
        console.error(f"{self._name}: {message}")

    def warning(self, message: str) -> None:
        """Log a warning message with the logger's name."""
        console.warn(f"{self._name}: {message}")

    def info(self, message: str) -> None:
        """Log an informational message with the logger's name."""
        console.info(f"{self._name}: {message}")
