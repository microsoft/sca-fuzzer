"""
File: Implementation of the high-level fuzzing logic for model-based constant-time testing.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING
from pathlib import Path

from .fuzz_gen import FuzzGen
from .boost import Boost
from .tracer import Tracer
from .leak_detector import LeakDetector
from .reporter import Reporter
from .util import console

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

    def all(self, timeout_s: int) -> None:
        """
        Run all fuzzing stages: fuzzing-based generation, boosting, tracing, and reporting.

        :param timeout_s: Timeout for the fuzzing process
        :return: 0 if successful, 1 if error occurs
        """
        self.fuzz_gen(timeout_s)
        self.boost()
        self.trace()
        self.report(0)
        console.success(f"All stages complete. Reports are in {self._config.stage4_wd}")

    def fuzz_gen(self, timeout_s: int) -> None:
        """
        Fuzzing Stage 1:
            Generate diverse inputs via fuzzing

        :param timeout_s: Timeout for the fuzzing process
        :return: 0 if the target coverage or timeout is reached, 1 if error occurs
        """
        console.section("Stage 1/4 \u00b7 Fuzzing-based input generation")
        fuzz_gen = FuzzGen(self._config)
        fuzz_gen.generate(timeout_s)
        console.success("Input generation complete.")

    def boost(self) -> None:
        """
        Fuzzing Stage 2:
            Boost inputs by generating public-equivalent variants
        :return: 0 if successful, 1 if error occurs
        """
        console.section("Stage 2/4 \u00b7 Input boosting")
        boost = Boost(self._config)
        boost.generate()
        console.success("Input boosting complete.")

    def trace(self) -> None:
        """
        Fuzzing Stage 3:
            Collect contract traces for each input pair.
        """
        console.section("Stage 3/4 \u00b7 Trace collection")
        tracer = Tracer(self._config)
        tracer.collect_traces()
        console.success("Trace collection complete.")

    def report(self, num_traces: int) -> None:
        """
        Fuzzing Stage 4:
            Analyze the target binary for software leakage and generate a report.

        :param num_traces: Process only the first N traces (for debugging purposes);
               if 0, process all traces
        """
        console.section("Stage 4/4 \u00b7 Leak analysis & reporting")
        detector = LeakDetector(self._config)
        if self._config.use_fast_detector:
            # TODO: find a nicer way to find the fast detector binary
            fast_reporter_dir = Path(__file__).parent.absolute() / "fast-detector"
            leak_detector_path = fast_reporter_dir / "leak_detector"
            merger_path = fast_reporter_dir / "merger"
            leakage_map = detector.build_leakage_map_fast(self._config.stage3_wd, num_traces,
                                                          str(leak_detector_path), str(merger_path))
        else:
            leakage_map = detector.build_leakage_map(self._config.stage3_wd, num_traces)

        reporter = Reporter(self._config)
        reporter.generate_report(leakage_map)
        console.info(f"Reports written to {self._config.stage4_wd}")
