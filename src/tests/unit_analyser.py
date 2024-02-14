"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
from src.analyser import EquivalenceAnalyser
from src.interfaces import Input, HTrace


class AnalyserTest(unittest.TestCase):

    def test_subset_comparison(self):
        analyser = EquivalenceAnalyser()
        htrace1 = HTrace(frozenset([0, 1, 2]), hash(frozenset([0, 1, 2])))
        htrace2 = HTrace(frozenset([0, 1]), hash(frozenset([0, 1])))
        htrace3 = HTrace(frozenset([0, 3]), hash(frozenset([0, 3])))

        match = analyser.check_if_all_subsets([htrace1, htrace2])
        self.assertTrue(match)

        match = analyser.check_if_all_subsets([htrace1, htrace2, htrace3])
        self.assertFalse(match)

    def test_build_eq_classes(self):
        analyser = EquivalenceAnalyser()
        dummy_input = Input()
        h1 = HTrace(frozenset([1]), hash(frozenset([1])))
        h2 = HTrace(frozenset([2]), hash(frozenset([2])))
        h3 = HTrace(frozenset([3]), hash(frozenset([3])))
        h4 = HTrace(frozenset([4]), hash(frozenset([4])))
        htraces = [h1, h2, h3, h4]

        # basic collection of eq classes
        clss = analyser._build_equivalence_classes([dummy_input] * 4, [1, 1, 2, 2], htraces)
        self.assertEqual(len(clss), 2)
        self.assertEqual(clss[0].ctrace, 1)
        self.assertEqual(clss[0].measurements[0].htrace.raw, {1})
        self.assertEqual(clss[1].ctrace, 2)
        self.assertEqual(clss[1].measurements[0].htrace.raw, {3})

        # filtering of ineffective inputs
        clss = analyser._build_equivalence_classes([dummy_input] * 4, [1, 2, 2, 2], htraces)
        self.assertEqual(len(clss), 1)
        self.assertEqual(clss[0].ctrace, 2)
