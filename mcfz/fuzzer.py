"""
File: Implementation of the high-level fuzzing logic for model-based constant-time testing.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from .fuzz_gen import FuzzGen
from .boost import Boost
from .tracer import Tracer
from .reporter import Reporter

if TYPE_CHECKING:
    from .config import Config


class FuzzerCore:
    """
    Class responsible for orchestrating the fuzzing process.
    """
    _config: Config
    _working_dir: str

    def __init__(self, config: Config) -> None:
        self._config = config

    def all(self, target_cov: int, timeout_s: int) -> None:
        """
        Run all fuzzing stages: fuzzing-based generation, boosting, tracing, and reporting.

        :param target_cov: Target coverage to achieve
        :param timeout_s: Timeout for the fuzzing process
        :return: 0 if successful, 1 if error occurs
        """
        print("\033[32m[ORCHESTRATOR] Starting fuzzing-based input generation...\033[0m")
        self.fuzz_gen(target_cov, timeout_s)
        print("\n\033[32m[ORCHESTRATOR] Fuzzing-based input generation completed.\033[0m")
        print("\033[32m[ORCHESTRATOR] Starting input boosting...\033[0m")
        self.boost()
        print("\033[32m[ORCHESTRATOR] Input boosting completed.\033[0m")
        print("\033[32m[ORCHESTRATOR] Starting tracing...\033[0m")
        self.trace()
        print("\033[32m[ORCHESTRATOR] Tracing completed.\033[0m")
        print("\033[32m[ORCHESTRATOR] Starting report construction...\033[0m")
        self.report(0)
        print("\033[32m[ORCHESTRATOR] Report construction completed.\033[0m")

    def fuzz_gen(self, target_cov: int, timeout_s: int) -> None:
        """
        Fuzzing Stage 1:
            Generate diverse inputs via fuzzing

        :param target_cov: Target coverage to achieve
        :param timeout_s: Timeout for the fuzzing process
        :return: 0 if the target coverage or timeout is reached, 1 if error occurs
        """
        fuzz_gen = FuzzGen(self._config)
        fuzz_gen.generate(target_cov, timeout_s)

    def boost(self) -> None:
        """
        Fuzzing Stage 2:
            Boost inputs by generating public-equivalent variants
        :return: 0 if successful, 1 if error occurs
        """
        boost = Boost(self._config)
        boost.generate()

    def trace(self) -> None:
        """
        Fuzzing Stage 3:
            Collect contract traces for each input pair.
        """
        tracer = Tracer(self._config)
        tracer.collect_traces()

    def report(self, num_traces: int) -> None:
        """
        Fuzzing Stage 4:
            Analyze the target binary for software leakage and generate a report.

        :param num_traces: Process only the first N traces (for debugging purposes);
               if 0, process all traces
        """
        reporter = Reporter(self._config)
        reporter.analyze(num_traces)
        reporter.generate_report()
