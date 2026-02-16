"""
File: Module responsible for fuzzing-based generation of diverse inputs for the target binary.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Final

import os
import sys
import subprocess

if TYPE_CHECKING:
    from .config import Config


class FuzzGen:
    """
    Class responsible for generating diverse inputs for the target binary using AFL++.
    """
    _config: Config
    _wd: Final[str]  # Working directory for AFL++

    _afl_bin: Final[str]  # Path to the AFL++ binary
    _libcompcov: Final[str]  # Path to the libcompcov.so library

    def __init__(self, config: Config) -> None:
        self._config = config
        self._wd = config.stage1_wd
        self._afl_bin = os.path.join(config.afl_root, "afl-fuzz")
        self._libcompcov = os.path.join(config.afl_root, "libcompcov.so")

    def generate(self, target_cov: int, timeout_s: int) -> None:
        """
        Generate diverse inputs for the target binary invoked with the given command.
        The generation continues until either the target coverage is achieved or
        the timeout is reached.

        :param target_cov: Target coverage to achieve
        :param timeout_s: Timeout for the fuzzing process
        :return: 0 if the target coverage or timeout is reached, 1 if error occurs
        """
        self._start_afl_fuzz(target_cov, timeout_s)

    def _start_afl_fuzz(self, _: int, timeout_s: int) -> None:
        """
        Starts the AFL++ fuzzing process.
        """
        assert self._config.afl_seed_dir is not None, "AFL seed directory not set."
        assert self._config.afl_bin is not None  # enforced by config validation

        # Replace the binary placeholder with the AFL-instrumented binary
        patched_cmd = [self._config.afl_bin if s == "@#" else s for s in self._config.target_cmd]

        # configure the AFL++ environment
        env = os.environ.copy()
        env["AFL_COMPCOV_LEVEL"] = "2"
        env["AFL_PRELOAD"] = self._libcompcov
        env["AFL_KEEP_TRACES"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_QUIET"] = "1" if self._config.afl_quiet else "0"

        afl_flags = [
            "-V",
            str(timeout_s), "-c", patched_cmd[0], "-i", self._config.afl_seed_dir, "-o", self._wd,
            "-t", str(self._config.afl_exec_timeout_ms)
        ]

        cmd = [self._afl_bin] + afl_flags + ["--"] + patched_cmd
        # print(cmd, flush=True)

        try:
            subprocess.check_call(cmd, timeout=timeout_s, env=env, shell=False)
        except subprocess.TimeoutExpired:
            # ignore timeout errors
            # it just means a clock mismatch between AFL and this function
            pass
        except subprocess.CalledProcessError as e:
            print(f"[AFL ERROR]: {e}")
            exit(1)
        finally:
            # Workaround: AFL++ corrupts the terminal output under some environments;
            # Force cursor restoration to mitigate this issue.
            sys.stdout.write('\033[?25h')  # ANSI escape to show cursor
            sys.stdout.flush()
