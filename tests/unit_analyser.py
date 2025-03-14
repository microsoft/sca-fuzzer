"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import unittest
from typing import List

import numpy as np
import numpy.typing as npt

from rvzr.analyser import MergedBitmapAnalyser, SetAnalyser, ChiSquaredAnalyser
from rvzr.tc_components.test_case_data import InputData
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.traces import CTrace, HTrace, RawHTraceSample, CTraceEntry
from rvzr.config import CONF


def _htrace_from_trace(trace_list: List[int]) -> HTrace:
    samples: npt.NDArray[np.void] = np.ndarray(len(trace_list), dtype=RawHTraceSample)
    for i, trace in enumerate(trace_list):
        samples[i] = (trace, 0, 0, 0, 0, 0)
    return HTrace(samples)


def _ctrace_from_int(trace: int) -> CTrace:
    return CTrace([CTraceEntry("val", trace)])


class AnalyserTest(unittest.TestCase):

    def test_merged_bitmap_analyser(self) -> None:
        analyser = MergedBitmapAnalyser()
        dummy_input = InputData()
        dummy_tc = TestCaseProgram("")
        inputs = [dummy_input] * 4

        htraces_int = [[0b1101, 0b1101], [0b1011, 0b1011], [0b1000, 0b1000], [0b1000, 0b1000]]
        htraces = [_htrace_from_trace(trace) for trace in htraces_int]

        ctraces_int = [1, 1, 2, 2]
        ctraces = [_ctrace_from_int(trace) for trace in ctraces_int]

        violations = analyser.filter_violations(ctraces, htraces, dummy_tc, inputs)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].ctrace, ctraces[0])

    def test_set_analyser(self) -> None:
        analyser = SetAnalyser()
        dummy_input = InputData()
        dummy_tc = TestCaseProgram("")
        inputs = [dummy_input] * 4

        htraces_int = [[1, 2, 2, 1], [1, 3, 3, 1], [1, 1, 1, 1], [1, 1, 1, 1]]
        htraces = [_htrace_from_trace(trace) for trace in htraces_int]

        ctraces_int = [1, 1, 2, 2]
        ctraces = [_ctrace_from_int(trace) for trace in ctraces_int]

        violations = analyser.filter_violations(ctraces, htraces, dummy_tc, inputs)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].ctrace, ctraces[0])

    def test_chi2_analyser(self) -> None:
        analyser = ChiSquaredAnalyser()
        dummy_input = InputData()
        dummy_tc = TestCaseProgram("")
        inputs = [dummy_input] * 4

        h1 = [1] * CONF.executor_sample_sizes[0]
        h2 = [2] * CONF.executor_sample_sizes[0]
        h2[0] = 1
        h2[1] = 1
        htraces = [
            _htrace_from_trace(h1),
            _htrace_from_trace(h2),
            _htrace_from_trace(h2),
            _htrace_from_trace(h2)
        ]

        ctraces_int = [1, 1, 2, 2]
        ctraces = [_ctrace_from_int(trace) for trace in ctraces_int]

        violations = analyser.filter_violations(ctraces, htraces, dummy_tc, inputs)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].ctrace, ctraces[0])
