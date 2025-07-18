"""
File: Module responsible for logging.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations


class Logger:
    """
    Logger class for managing logging operations.
    """

    def __init__(self, name: str) -> None:
        self._name = name

    def critical(self, message: str) -> None:
        """Log a critical message with the logger's name."""
        print(f"[CRITICAL] {self._name}: {message}")
        raise SystemExit(1)

    def error(self, message: str) -> None:
        """Log an error message with the logger's name."""
        print(f"[ERROR] {self._name}: {message}")

    def info(self, message: str) -> None:
        """Log an informational message with the logger's name."""
        print(f"[INFO] {self._name}: {message}")


class Color:
   """
   ANSI color codes.
   """
   PURPLE = '\033[1;35;48m'
   CYAN = '\033[1;36;48m'
   BOLD = '\033[1;37;48m'
   BLUE = '\033[1;34;48m'
   GREEN = '\033[1;32;48m'
   YELLOW = '\033[1;33;48m'
   RED = '\033[1;31;48m'
   BLACK = '\033[1;30;48m'
   UNDERLINE = '\033[4;37;48m'
   END = '\033[1;37;0m'

def printc(color: Color, text: str) -> None:
    """
    Print colored string.
    """
    print(color + str(text) + Color.END)

def getc(color: Color, text: str) -> None:
    """
    Get colored version of a string.
    """
    return color + str(text) + Color.END

