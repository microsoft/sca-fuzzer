"""
File: Module responsible for fuzzing-based generation of diverse inputs for the target binary.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Final, List, Dict, Any

import os
import shutil
import sys
import subprocess

if TYPE_CHECKING:
    from .config import Config


class FuzzGen:
    """
    Class responsible for generating diverse inputs for the target binary using AFL++.

    Supports running multiple AFL++ instances in parallel (one main node with -M,
    and additional secondary nodes with -S) governed by `config.num_workers_fuzz_gen`.
    """
    _config: Config
    _wd: Final[str]  # Working directory for AFL++
    _afl_bin: Final[str]  # Path to the AFL++ binary

    def __init__(self, config: Config) -> None:
        self._config = config
        self._wd = config.stage1_wd
        self._afl_bin = os.path.join(config.afl_root, "afl-fuzz")
        self._afl_cmin = os.path.join(config.afl_root, "afl-cmin.py")
        # self._libcompcov = os.path.join(config.afl_root, "libcompcov.so")

    def _build_env(self) -> Dict[str, str]:
        """Build the environment variables for AFL++ processes."""
        env = os.environ.copy()
        env["AFL_COMPCOV_LEVEL"] = "2"
        # env["AFL_PRELOAD"] = self._libcompcov
        env["AFL_KEEP_TRACES"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_QUIET"] = "1" if self._config.afl_quiet else "0"
        return env

    def _build_cmd(self, patched_cmd: List[str], timeout_s: int, node_flag: str,
                   node_name: str) -> List[str]:
        """
        Build the full afl-fuzz command for a single instance.

        :param patched_cmd: Target command with binary placeholder resolved
        :param timeout_s: Timeout for the fuzzing process
        :param node_flag: Either '-M' (main) or '-S' (secondary)
        :param node_name: Name of this fuzzer node (e.g. 'fuzzer00')
        :return: Complete command list
        """
        afl_flags = [
            "-V",
            str(timeout_s), "-c", patched_cmd[0], "-i", self._config.afl_seed_dir, "-o", self._wd,
            "-t",
            str(self._config.afl_exec_timeout_ms), node_flag, node_name
        ]
        return [self._afl_bin] + afl_flags + ["--"] + patched_cmd

    def generate(self, _: int, timeout_s: int) -> None:
        """
        Generate diverse inputs for the target binary using parallel AFL++ instances.

        Launches `num_workers_fuzz_gen` AFL++ instances: one main node (`-M fuzzer00`)
        and the rest as secondary nodes (`-S fuzzer01`, `-S fuzzer02`, …).
        All instances share the same output directory so AFL++ synchronises their
        findings automatically.

        :param timeout_s: Timeout for the fuzzing process
        """
        # pylint: disable=consider-using-with  # justification: the process outlives this scope
        assert self._config.afl_seed_dir is not None, "AFL seed directory not set."
        assert self._config.bin_instrumented is not None  # enforced by config validation

        patched_cmd = [
            self._config.bin_instrumented if s == "@#" else s for s in self._config.template_cmd
        ]

        env = self._build_env()
        num_workers = self._config.num_workers_fuzz_gen
        procs: List[subprocess.Popen[Any]] = []

        try:
            # Main node (output visible on stdout)
            main_cmd = self._build_cmd(patched_cmd, timeout_s, "-M", "fuzzer00")
            procs.append(subprocess.Popen(main_cmd, env=env, shell=False))

            # Secondary nodes (output suppressed)
            for i in range(1, num_workers):
                node_name = f"fuzzer{i:02d}"
                sec_cmd = self._build_cmd(patched_cmd, timeout_s, "-S", node_name)
                procs.append(
                    subprocess.Popen(
                        sec_cmd,
                        env=env,
                        shell=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL))

            # Wait for every instance to finish
            errors: List[str] = []
            for proc in procs:
                try:
                    proc.wait(timeout=timeout_s + 20)  # +20 to account for minor delays
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait()

                if proc.returncode and proc.returncode != 0:
                    errors.append(
                        f"AFL++ process (pid={proc.pid}) exited with code {proc.returncode}")

            if errors:
                print("[AFL ERROR]: " + "; ".join(errors))
                exit(1)

        except Exception:
            for proc in procs:
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait()
            raise
        finally:
            self._restore_terminal()

        self.minimize(patched_cmd)

    def minimize(self, patched_cmd: List[str]) -> None:
        """
        Minimize the generated corpus using afl-cmin.

        Collects all inputs from every fuzzer instance's queue into a temporary
        directory, then runs afl-cmin.py to produce a minimized corpus in
        ``<stage1_wd>/minimized``.
        The temporary directory is removed after minimization.
        """
        stage1 = self._wd
        all_inputs_dir = os.path.join(stage1, "_all_inputs")
        minimized_dir = os.path.join(stage1, "minimized")

        # Collect all queue inputs into a single temporary directory
        os.makedirs(all_inputs_dir, exist_ok=True)
        for entry in os.listdir(stage1):
            queue_dir = os.path.join(stage1, entry, "queue")
            if not os.path.isdir(queue_dir):
                continue
            for fname in os.listdir(queue_dir):
                src = os.path.join(queue_dir, fname)
                if os.path.isfile(src):
                    # Prefix with fuzzer name to avoid collisions across instances
                    dst = os.path.join(all_inputs_dir, f"{entry}_{fname}")
                    shutil.copy2(src, dst)

        # Run afl-cmin.py
        os.makedirs(minimized_dir, exist_ok=True)
        cmd = [
            self._afl_cmin, "-i", all_inputs_dir, "-o", minimized_dir, "-T",
            str(self._config.num_workers_fuzz_gen), "-t",
            str(self._config.afl_exec_timeout_ms), "--"
        ] + patched_cmd

        try:
            subprocess.check_call(cmd, shell=False)
        except subprocess.CalledProcessError as e:
            print(f"[AFL-CMIN ERROR]: {e}")
            exit(1)
        finally:
            # Clean up the temporary directory
            shutil.rmtree(all_inputs_dir, ignore_errors=True)

    @staticmethod
    def _restore_terminal() -> None:
        """
        Workaround: AFL++ corrupts the terminal output under some environments;
        force cursor restoration to mitigate this issue.
        """
        sys.stdout.write('\033[?25h')  # ANSI escape to show cursor
        sys.stdout.flush()
