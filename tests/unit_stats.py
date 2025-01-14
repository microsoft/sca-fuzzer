"""
File: Unit tests for stats.py

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=missing-function-docstring  # no need in tests
# pylint: disable=missing-class-docstring  # no need in tests

import unittest

from src.stats import FuzzingStats


class StatsTest(unittest.TestCase):

    def test_borg(self) -> None:
        stats1 = FuzzingStats()
        stats1.test_cases = 1
        stats2 = FuzzingStats()
        self.assertEqual(stats2.test_cases, 1)

    def test_str(self) -> None:
        stats = FuzzingStats()
        stats.test_cases = 1
        str_ = str(stats)
        self.assertIn("Test Cases: 1", str_)

        stats.num_inputs = 2
        str_ = str(stats)
        self.assertIn("Inputs per test case: 2.0", str_)

        stats.violations = 3
        str_ = str(stats)
        self.assertIn("Violations: 3", str_)

    def test_get_brief(self) -> None:
        stats = FuzzingStats()
        stats.test_cases = 0
        brief = stats.get_brief()
        self.assertEqual(brief, "")

        stats.test_cases = 1
        stats.eff_classes = 2
        stats.single_entry_classes = 3
        stats.analysed_test_cases = 4
        stats.num_inputs = 5
        stats.executor_reruns = 6
        stats.spec_filter = 7
        stats.observ_filter = 8
        stats.fast_path = 9
        stats.fp_nesting = 10
        stats.fp_taint_mistakes = 11
        stats.fp_early_priming = 12
        stats.fp_large_sample = 13
        stats.fp_priming = 14
        stats.violations = 15

        brief = stats.get_brief()
        self.assertEqual(brief,
                         "Cls:0/1,In:5,R:1,SF:7,OF:8,Fst:9,CN:10,CT:11,P1:12,CS:13,P2:14,V:15")

        stats.analysed_test_cases = 0
        brief = stats.get_brief()
        self.assertEqual(brief,
                         "Cls:0/0,In:5,R:1,SF:7,OF:8,Fst:9,CN:10,CT:11,P1:12,CS:13,P2:14,V:15")
