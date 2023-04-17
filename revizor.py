#!/usr/bin/env python3
"""
File: Command Line Interface to Revizor

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

try:
    from src.cli import main
except ImportError:
    from revizor.cli import main


if __name__ == '__main__':
    exit_code = main()
    exit(exit_code)
