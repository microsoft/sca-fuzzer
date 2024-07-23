"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
from src.analyser import MergedBitmapAnalyser, SetAnalyser, ChiSquaredAnalyser
from src.interfaces import Input, HTrace
from src.config import CONF


class AnalyserTest(unittest.TestCase):

    def test_merged_bitmap_analyser(self):
        analyser = MergedBitmapAnalyser()
        dummy_input = Input()
        inputs = [dummy_input] * 4

        h1 = HTrace([0b1101, 0b1101])
        h2 = HTrace([0b1011, 0b1011])
        h3 = HTrace([0b1000, 0b1000])
        h4 = HTrace([0b1000, 0b1000])
        htraces = [h1, h2, h3, h4]
        ctraces = [1, 1, 2, 2]

        violations = analyser.filter_violations(inputs, ctraces, htraces)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].ctrace, 1)

    def test_set_analyser(self):
        analyser = SetAnalyser()
        dummy_input = Input()
        inputs = [dummy_input] * 4

        h1 = HTrace([1, 2, 2, 1])
        h2 = HTrace([1, 3, 3, 1])
        h3 = HTrace([1, 1, 1, 1])
        h4 = HTrace([1, 1, 1, 1])
        htraces = [h1, h2, h3, h4]
        ctraces = [1, 1, 2, 2]

        violations = analyser.filter_violations(inputs, ctraces, htraces)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].ctrace, 1)

    def test_chi2_analyser(self):
        analyser = ChiSquaredAnalyser()
        dummy_input = Input()
        inputs = [dummy_input] * 4

        h1 = [1] * CONF.executor_sample_sizes[0]
        h2 = [2] * CONF.executor_sample_sizes[0]
        h2[0] = 1
        h2[1] = 1
        htraces = [HTrace(h1), HTrace(h2), HTrace(h2), HTrace(h2)]
        ctraces = [1, 1, 2, 2]

        violations = analyser.filter_violations(inputs, ctraces, htraces)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].ctrace, 1)
