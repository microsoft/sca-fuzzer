""" File: Global statistics class

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import Any, Dict


class FuzzingStats:
    """
    Class responsible for storing and managing fuzzing statistics.
    Implements the Borg pattern to share the state between instances.
    """
    _borg_shared_state: Dict[Any, Any] = {}

    test_cases: int = 0
    num_inputs: int = 0
    eff_classes: int = 0
    single_entry_classes: int = 0
    violations: int = 0
    analysed_test_cases: int = 0
    executor_reruns: int = 0

    spec_filter: int = 0
    observ_filter: int = 0
    fast_path: int = 0
    fp_nesting: int = 0
    fp_taint_mistakes: int = 0
    fp_early_priming: int = 0
    fp_large_sample: int = 0
    fp_priming: int = 0

    # Implementation of Borg pattern
    def __init__(self) -> None:
        self.__dict__ = self._borg_shared_state

    def __str__(self) -> str:
        total_clss = self.eff_classes + self.single_entry_classes
        total_clss_per_test_case = total_clss / self.analysed_test_cases \
            if self.analysed_test_cases else 0
        effective_clss = self.eff_classes / self.analysed_test_cases \
            if self.analysed_test_cases else 0
        iptc = self.num_inputs / self.test_cases if self.test_cases else 0

        s = ""
        s += f"Test Cases: {self.test_cases}\n"
        s += f"Inputs per test case: {iptc:.1f}\n"
        s += f"Violations: {self.violations}\n"
        s += "Effectiveness: \n"
        s += f"  Total Cls: {total_clss_per_test_case:.1f}\n"
        s += f"  Effective Cls: {effective_clss:.1f}\n"
        s += "Discarded Test Cases:\n"
        s += f"  Speculation Filter: {self.spec_filter}\n"
        s += f"  Observation Filter: {self.observ_filter}\n"
        s += f"  Fast Path: {self.fast_path}\n"
        s += f"  Max Nesting Check: {self.fp_nesting}\n"
        s += f"  Tainting Check: {self.fp_taint_mistakes}\n"
        s += f"  Early Priming Check: {self.fp_early_priming}\n"
        s += f"  Large Sample Check: {self.fp_large_sample}\n"
        s += f"  Priming Check: {self.fp_priming}\n"
        return s

    def get_brief(self) -> str:
        """ Return a brief one-line summary of the statistics """

        if self.test_cases == 0:
            return ""

        if self.analysed_test_cases:
            all_cls = (self.eff_classes + self.single_entry_classes) // self.analysed_test_cases
            eff_cls = self.eff_classes // self.analysed_test_cases
        else:
            all_cls = 0
            eff_cls = 0
        executor_reruns = self.executor_reruns // self.num_inputs
        s = f"Cls:{eff_cls}/{all_cls},"
        s += f"In:{self.num_inputs // self.test_cases},"
        s += f"R:{executor_reruns},"
        s += f"SF:{self.spec_filter},"
        s += f"OF:{self.observ_filter},"
        s += f"Fst:{self.fast_path}," \
             f"CN:{self.fp_nesting}," \
             f"CT:{self.fp_taint_mistakes}," \
             f"P1:{self.fp_early_priming}," \
             f"CS:{self.fp_large_sample}," \
             f"P2:{self.fp_priming}," \
             f"V:{self.violations}"
        return s
