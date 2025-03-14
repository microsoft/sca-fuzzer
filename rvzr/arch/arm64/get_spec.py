"""
File: A script that downloads the ARM64 instruction set
      and parses it into a JSON file that can be used by the generator.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List
import shutil

from rvzr.logs import warning, inform


class Downloader:
    """ A class that downloads the ARM64 instruction set and converts it to JSON """

    def __init__(self, extensions: List[str], out_file: str) -> None:
        self._extensions = extensions
        self._out_file = out_file
        warning(
            "downloader", "The ARM64 spec retrieval is not implemented yet, \n"
            "and this script will just copy a spec file from tests/arm64/min_arm64.json")

    def run(self) -> None:
        """ Run the downloader """
        shutil.copy("tests/arm64/min_arm64.json", self._out_file)
        inform("downloader", f"ARM64 spec is copied to {self._out_file}")
