"""
File: A script that downloads the ARM64 instruction set specification (already in the
      JSON format used by the generator) from the Side Channel Fuzzer repository.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List
import subprocess

from rvzr.logs import inform

SPEC_URL = ("https://github.com/microsoft/side-channel-fuzzer/releases/download/"
            "v2.0.0/arm64.json")


class Downloader:
    """ A class that downloads the ARM64 instruction set specification """

    def __init__(self, extensions: List[str], out_file: str) -> None:
        self._extensions = extensions
        self._out_file = out_file

    def run(self) -> None:
        """ Download the ARM64 spec JSON to the output file """
        inform("downloader", f"Downloading ARM64 spec from {SPEC_URL}")
        subprocess.run(["curl", "-L", "-o", self._out_file, SPEC_URL], check=True)
        inform("downloader", f"ARM64 spec is saved to {self._out_file}")
