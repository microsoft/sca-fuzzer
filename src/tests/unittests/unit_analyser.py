"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import sys

sys.path.insert(0, '..')
from analyser import EquivalenceAnalyser
from interfaces import Input


class AnalyserTest(unittest.TestCase):

    def test_subset_comparison(self):
        analyser = EquivalenceAnalyser()
        subset = [
            0b100100,
            0b110101,
            0b000001,
        ]
        match = analyser.check_if_all_subsets(subset)
        self.assertTrue(match)

        nonsubset = [
            0b100100,
            0b101000,
            0b100000,
        ]
        match = analyser.check_if_all_subsets(nonsubset)
        self.assertFalse(match)

    def test_build_eq_classes(self):
        analyser = EquivalenceAnalyser()
        dummy_input = Input()

        # basic collection of eq classes
        clss = analyser._build_equivalence_classes([dummy_input] * 4, [1, 1, 2, 2], [1, 2, 3, 4])
        self.assertEqual(len(clss), 2)
        self.assertEqual(clss[0].ctrace, 1)
        self.assertEqual(clss[0].measurements[0].htrace, 1)
        self.assertEqual(clss[1].ctrace, 2)
        self.assertEqual(clss[1].measurements[0].htrace, 3)

        # filtering of ineffective inputs
        clss = analyser._build_equivalence_classes([dummy_input] * 4, [1, 2, 2, 2], [1, 2, 3, 4])
        self.assertEqual(len(clss), 1)
        self.assertEqual(clss[0].ctrace, 2)


if __name__ == '__main__':
    unittest.main()
