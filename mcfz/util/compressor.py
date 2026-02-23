"""
File: Utility module responsible for compressing and decompressing trace files.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import Literal, get_args, cast, assert_never
from subprocess import run

from ..config import Config

_Tool = Literal["gzip", "bzip2", "none"]


class Compressor:
    """
    A simple utility class to encapsulate compression and decompression commands
    based on the specified tool in the configuration.
    """

    def __init__(self, config: Config) -> None:
        tool = config.compression_tool
        assert tool in get_args(_Tool), f"Unsupported compression tool: {tool}"
        self._tool: _Tool = cast(_Tool, tool)
        self._config = config

        self._compress_cmd = self._build_compress_cmd()
        self._decompress_cmd = self._build_decompress_cmd()

    def _build_compress_cmd(self) -> str:
        if self._tool == "gzip":
            return "gzip -5 '{file}'"
        if self._tool == "bzip2":
            return "bzip2 -z -5 '{file}'"
        if self._tool == "none":
            return ""
        assert_never(self._tool)

    def _build_decompress_cmd(self) -> str:
        if self._tool == "gzip":
            return "gzip -d '{file}.gz'"
        if self._tool == "bzip2":
            return "bzip2 -d '{file}.bz2'"
        if self._tool == "none":
            return ""
        assert_never(self._tool)

    def compress(self, file_path: str) -> None:
        if self._tool == "none":
            return
        file_path = self._quote_parentheses(file_path)
        cmd = self._compress_cmd.format(file=file_path)
        run(cmd, shell=True, check=True)

    def compress_file_list(self, file_paths: list[str]) -> None:
        if self._tool == "none":
            return
        for file_ in file_paths:
            self.compress(file_)

    def decompress(self, file_path: str) -> None:
        if self._tool == "none":
            return
        file_path = self._quote_parentheses(file_path)
        cmd = self._decompress_cmd.format(file=file_path)
        run(cmd, shell=True, check=True)

    def decompress_universal(self, file_path: str, keep: bool = False) -> str:
        """
        Decompress a file regardless of its compression type based on its extension.
        Supported extensions: .gz (gzip), .bz2 (bzip2)
        """
        keep_flag = "-k" if keep else ""
        file_path = self._quote_parentheses(file_path)

        if file_path.endswith(".gz"):
            cmd = f"gzip {keep_flag} -d -f {file_path}"
            run(cmd, shell=True, check=True)
            return file_path[:-3]
        elif file_path.endswith(".bz2"):
            cmd = f"bzip2 {keep_flag} -d -f {file_path}"
            run(cmd, shell=True, check=True)
            return file_path[:-4]
        else:
            # No known compression extension; assume uncompressed
            return file_path

    @staticmethod
    def _quote_parentheses(str_: str) -> str:
        """ replace all ( and ) with their quoted versions,
        to prevent issues when these characters are in file paths """
        return str_.replace("(", "\\(").replace(")", "\\)")
