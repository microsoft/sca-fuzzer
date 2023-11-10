#!/usr/bin/env python3
"""
File: Command Line Interface to Revizor

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

try:
    from src.cli import main
except ImportError as orig_import_error:
    try:
        from revizor.cli import main
    except ImportError:
        print("Unable to import main from src.cli.")
        print(f"Issue during import of src.cli: `{orig_import_error}`")
        exit(1)


if __name__ == '__main__':
    exit_code = main()
    exit(exit_code)
