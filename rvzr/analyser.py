"""
File: various ways to compare collected ctraces with htraces

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from collections import Counter
from typing import List, Dict, TYPE_CHECKING, Union, Final
from abc import ABC, abstractmethod
from scipy import stats  # type: ignore

import numpy.typing as npt
import numpy as np

from .traces import HTrace, CTrace, TraceBundle, Violation, ContractEqClass, HardwareEqClass
from .config import CONF, ConfigException
from .stats import FuzzingStats
from .logs import warning, error

if TYPE_CHECKING:
    from .tc_components.test_case_data import InputData
    from .tc_components.test_case_code import TestCaseProgram

IntArrayLike = Union[List[int], npt.NDArray[np.uint64]]

STAT = FuzzingStats()


# ==================================================================================================
# Abstract Analyser Interface
# ==================================================================================================
class Analyser(ABC):
    """ Interface definition for all analysers """

    @abstractmethod
    def filter_violations(self,
                          ctraces: List[CTrace],
                          htraces: List[HTrace],
                          test_case_code: TestCaseProgram,
                          inputs: List[InputData],
                          stats_: bool = False) -> List[Violation]:
        """
        Compare the provided contract and hardware traces and return a list of contract
        violations, if any are found.
        :param ctraces: a list of contract traces to check
        :param htraces: a list of hardware traces to check
        :param test_case_code: the program under test
        :param inputs: a list of inputs under test (one per trace)
        :param stats_: whether to update the global fuzzing statistics based on the results
        :return: a list of violations, if any are found
        """

    @abstractmethod
    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        """ Compare two hardware traces according to the current analyser's rules.

        :param htrace1: first hardware trace
        :param htrace2: second hardware trace
        :return: True if the traces are equivalent, False otherwise
        """


# ==================================================================================================
# Equivalence class-based Analysers
# ==================================================================================================
class EquivalenceAnalyserCommon(Analyser):
    """
    Abstract class implementing the algorithm that compares contract and hardware traces
    by using the concept of equivalence classes.

    The algorithm check if any of the traces fits the definition of a contract violation,
     which is:
       For two pairs of traces (ctrace1, htrace1) and (ctrace2, htrace2),
       where ctrace1 is a contract trace for input1
       and htrace1 is a hardware trace for input1 (and so on),
       the traces violate the contract if
            ctrace1 == ctrace2 and
            htrace1 NOT EQUIVALENT htrace2

    The definition of EQUIVALENT is specific to the concrete implementation of the analyser
    (see subclasses).
    """

    def filter_violations(self,
                          ctraces: List[CTrace],
                          htraces: List[HTrace],
                          test_case_code: TestCaseProgram,
                          inputs: List[InputData],
                          stats_: bool = False) -> List[Violation]:
        # --------
        # NOTE: This implementation is a common algorithm of checking for contract violations in
        # all equivalence class-based analysers. The subclasses modulate the implementation by
        # defining the htraces_are_equivalent method.
        #
        # The algorithm works by first grouping the measurements by their contract trace (ctrace),
        # and then checking if all hardware traces (htraces) in the same group are equivalent
        # according to the htraces_are_equivalent method. If not, a Violation object is created
        # based on the violating traces, and added to the list of violations.
        #
        # Note that the algorithm also filters out measurements with corrupted/ignored htraces.
        # The filtering is done by skipping the measurements with empty or corrupted htraces.
        # This is done to avoid false positives in the analysis.
        # --------

        # Skip if there are no htraces
        if not htraces:
            return []

        # Package all the measurements into TraceBundles
        # and filter out the measurements with corrupted/ignored htraces
        measurements = []
        for i, htrace in enumerate(htraces):
            if htrace.is_empty() or htrace.is_corrupted_or_ignored():
                continue
            measurements.append(TraceBundle(i, inputs[i], ctraces[i], htrace))
        if not measurements:
            return []

        # Build a list of equivalence classes:
        all_classes = ContractEqClass.build_contract_classes(measurements)

        # Filter out ineffective equivalence classes
        effective_classes = [eq_cls for eq_cls in all_classes if len(eq_cls.measurements) >= 2]

        # Sort the classes by ctrace
        effective_classes.sort(key=lambda x: x.ctrace)

        # Compute hardware equivalence classes
        for eq_cls in effective_classes:
            hw_classes = HardwareEqClass.build_hw_classes(
                eq_cls.measurements, equivalence_function=self.htraces_are_equivalent)
            eq_cls.set_hw_classes(hw_classes)

        # Check if any of the equivalence classes is a contract counterexample
        violations: List[Violation] = []
        for eq_cls in effective_classes:
            hw_classes = eq_cls.get_hw_classes()
            if len(hw_classes) >= 2:
                v = Violation.from_contract_eq_class(eq_cls, inputs, test_case_code)
                violations.append(v)

        # Update statistics
        if stats_:
            STAT.eff_classes += len(effective_classes)
            STAT.single_entry_classes += len(all_classes) - len(effective_classes)
            STAT.analysed_test_cases += 1

        return violations


class MergedBitmapAnalyser(EquivalenceAnalyserCommon):
    """ A variant of the analyser that compares the htraces as merged bitmaps. I.e., it merges
    the htrace lists into bitmaps and compares the results.

    It also applies filtering of outliers according to CONF.analyser_outliers_threshold
    """

    _bitmap_cache: Final[Dict[int, int]]
    _MASK: Final[int]

    def __init__(self) -> None:
        super().__init__()
        self._bitmap_cache = {}
        self._MASK = pow(2, 64) - 1

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        bitmaps = [0, 0]

        sample_size = htrace1.sample_size()
        assert sample_size == htrace2.sample_size(), "htraces have different sizes"
        threshold = CONF.analyser_outliers_threshold * sample_size

        for i, htrace in enumerate([htrace1, htrace2]):
            hash_ = hash(htrace)
            raw = htrace.get_raw_traces()

            # check if cached
            if hash_ in self._bitmap_cache:
                bitmaps[i] = self._bitmap_cache[hash_]
                continue

            # remove outliers
            counter = Counter(raw)
            filtered = [x for x in raw if counter[x] >= threshold]

            # merge into bitmap
            for t in filtered:
                bitmaps[i] |= int(t)

            # cache
            self._bitmap_cache[hash_] = bitmaps[i]

        if CONF.analyser_subsets_is_violation:
            return bitmaps[0] == bitmaps[1]

        # check if the bitmaps are disjoint
        inverse = [~bitmaps[0] & self._MASK, ~bitmaps[1] & self._MASK]
        return bool(((bitmaps[0] & inverse[1]) == 0) or ((bitmaps[1] & inverse[0]) == 0))


class SetAnalyser(EquivalenceAnalyserCommon):
    """ A variant of the analyser that compares the htraces as sets. I.e., it squashes
    the htrace lists into sets and compares the results.

    It also applies filtering of outliers according to CONF.analyser_outliers_threshold
    """

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        """ Squash the htrace lists into sets and compare the results """
        sample_size = htrace1.sample_size()
        assert sample_size == htrace2.sample_size(), "htraces have different sizes"
        threshold = CONF.analyser_outliers_threshold * sample_size
        filtered1 = [x for x in htrace1.get_raw_traces() if x >= threshold]
        filtered2 = [x for x in htrace2.get_raw_traces() if x >= threshold]

        trace_set1 = set(filtered1)
        trace_set2 = set(filtered2)

        if CONF.analyser_subsets_is_violation:
            return trace_set1 == trace_set2

        return trace_set1.issubset(trace_set2) or trace_set2.issubset(trace_set1)


class MWUAnalyser(EquivalenceAnalyserCommon):
    """
    A variant of the analyser that uses the Mann-Withney U test to compare htraces.

    WARNING: this is an experimental analyser and it may not work well for all cases.
    """

    def __init__(self) -> None:
        super().__init__()
        warning("analyser",
                "MWUAnalyser is an experimental analyser and may not work well for all cases. ")

        a = [1] * CONF.executor_sample_sizes[0]
        b = [2] * CONF.executor_sample_sizes[0]
        _, p_value = stats.mannwhitneyu(a, b)
        if CONF.analyser_stat_threshold < p_value:
            raise ConfigException("analyser_stat_threshold is too high for the given sample size")

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        """ Use the Mann-Withney U test to compare htraces """
        _, p_value = stats.mannwhitneyu(htrace1.get_raw_traces(), htrace2.get_raw_traces())
        return bool(p_value > CONF.analyser_stat_threshold)


class ChiSquaredAnalyser(EquivalenceAnalyserCommon):
    """
    A variant of the analyser that uses the chi-squared test to compare htraces.
    """

    def __init__(self) -> None:
        super().__init__()
        a = [1] * CONF.executor_sample_sizes[0]
        b = [2] * CONF.executor_sample_sizes[0]
        stat = self.homogeneity_test(a, b)
        if CONF.analyser_stat_threshold > stat:
            error("analyser_stat_threshold is too low for the given sample size")

    def homogeneity_test(self, x: IntArrayLike, y: IntArrayLike) -> float:
        """ Use the chi-squared test to compare htraces """
        assert len(x) == len(y)
        counter1 = Counter(x)
        counter2 = Counter(y)
        keys = set(counter1.keys()) | set(counter2.keys())
        observed = [counter1[k] for k in keys] + [counter2[k] for k in keys]
        expected = [(counter1[k] + counter2[k]) / 2 for k in keys] * 2
        ddof = len(keys) - 1
        stat: float
        stat, _ = stats.chisquare(observed, expected, ddof=ddof)
        stat /= len(x) + len(y)
        return stat

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        stat = self.homogeneity_test(htrace1.get_raw_traces(), htrace2.get_raw_traces())
        return stat < CONF.analyser_stat_threshold
