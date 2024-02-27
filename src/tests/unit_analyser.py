"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
from src.analyser import MergedBitmapAnalyser, SetAnalyser, MWUAnalyser
from src.interfaces import Input, HTrace


class AnalyserTest(unittest.TestCase):

    def test_merged_bitmap_analyser(self):
        analyser = MergedBitmapAnalyser()
        dummy_input = Input()
        h1 = HTrace([0b1101, 0b1101])
        h2 = HTrace([0b1011, 0b1011])
        h3 = HTrace([0b1000, 0b1000])
        h4 = HTrace([0b1000, 0b1000])
        htraces = [h1, h2, h3, h4]

        # basic collection of eq classes
        clss = analyser._build_equivalence_classes([dummy_input] * 4, [1, 1, 2, 2], htraces)
        self.assertEqual(len(clss), 2)
        self.assertEqual(clss[0].ctrace, 1)
        self.assertEqual(clss[0].measurements[0].htrace.raw, [0b1101, 0b1101])
        self.assertEqual(clss[1].ctrace, 2)
        self.assertEqual(clss[1].measurements[0].htrace.raw, [0b1000, 0b1000])

        # detection of violations
        clss = analyser.filter_violations([dummy_input] * 4, [1, 1, 2, 2], htraces)
        self.assertEqual(len(clss), 1)
        self.assertEqual(clss[0].ctrace, 1)

        # filtering of ineffective inputs
        clss = analyser._build_equivalence_classes([dummy_input] * 4, [1, 2, 2, 2], htraces)
        self.assertEqual(len(clss), 1)
        self.assertEqual(clss[0].ctrace, 2)

    def test_set_analyser(self):
        analyser = SetAnalyser()
        dummy_input = Input()
        h1 = HTrace([1, 2, 2, 1])
        h2 = HTrace([1, 3, 3, 1])
        h3 = HTrace([1, 1, 1, 1])
        h4 = HTrace([1, 1, 1, 1])
        htraces = [h1, h2, h3, h4]

        # basic collection of eq classes
        clss = analyser._build_equivalence_classes([dummy_input] * 4, [1, 1, 2, 2], htraces)
        self.assertEqual(len(clss), 2)
        self.assertEqual(clss[0].ctrace, 1)
        self.assertEqual(clss[0].measurements[0].htrace.raw, [1, 2, 2, 1])
        self.assertEqual(clss[1].ctrace, 2)
        self.assertEqual(clss[1].measurements[0].htrace.raw, [1, 1, 1, 1])

        # detection of violations
        clss = analyser.filter_violations([dummy_input] * 4, [1, 1, 2, 2], htraces)
        self.assertEqual(len(clss), 1)
        self.assertEqual(clss[0].ctrace, 1)

        # filtering of ineffective inputs
        clss = analyser._build_equivalence_classes([dummy_input] * 4, [1, 2, 2, 2], htraces)
        self.assertEqual(len(clss), 1)
        self.assertEqual(clss[0].ctrace, 2)

    def test_mwu_analyser(self):
        analyser = MWUAnalyser()
        dummy_input = Input()
        h1 = [1, 1, 1, 1, 1]
        h2 = [300000, 300000, 300000, 300000, 300000]
        h3 = [1, 1]
        h4 = [1, 1]
        htraces = [HTrace(h1), HTrace(h2), HTrace(h3), HTrace(h4)]

        # basic collection of eq classes
        clss = analyser._build_equivalence_classes([dummy_input] * 4, [1, 1, 2, 2], htraces)
        self.assertEqual(len(clss), 2)
        self.assertEqual(clss[0].ctrace, 1)
        self.assertEqual(clss[0].measurements[0].htrace.raw, h1)
        self.assertEqual(clss[1].ctrace, 2)
        self.assertEqual(clss[1].measurements[0].htrace.raw, h3)

        # detection of violations
        clss = analyser.filter_violations([dummy_input] * 4, [1, 1, 2, 2], htraces)
        self.assertEqual(len(clss), 1)
        self.assertEqual(clss[0].ctrace, 1)

        # filtering of ineffective inputs
        clss = analyser._build_equivalence_classes([dummy_input] * 4, [1, 2, 2, 2], htraces)
        self.assertEqual(len(clss), 1)
        self.assertEqual(clss[0].ctrace, 2)
