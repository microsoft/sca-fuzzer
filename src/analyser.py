"""
File: various ways to compare ctraces with htraces

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from collections import defaultdict, Counter
from typing import List, Dict
from scipy import stats  # type: ignore

from .interfaces import HTrace, CTrace, Input, EquivalenceClass, Analyser, Measurement, Violation
from .config import CONF
from .util import STAT, Logger


class EquivalenceAnalyserCommon(Analyser):

    def __init__(self) -> None:
        self.LOG = Logger()
        super().__init__()

    def filter_violations(self,
                          inputs: List[Input],
                          ctraces: List[CTrace],
                          htraces: List[HTrace],
                          stats=False) -> List[Violation]:
        """
        Group the measurements by their ctrace (i.e., build equivalence classes of measurements
        w.r.t. their ctrace) and check if all htraces in the same equivalence class are equal.

        Note that the htraces are not necessarily compared directly (i.e., we don't always
        check if htrace1 == htrace2). This isn't always possible because the measurements
        are noisy, and we need to allow for some differences. Instead, each of the subclasses
        of this class implements a different way to compare the htraces. For example, the
        ProbabilisticAnalyser compares the distributions of traces.

        :param inputs: a list of inputs
        :param ctraces: a list of contract traces
        :param htraces: a list of hardware traces
        :param stats: whether to update the statistics based on the results
        :return: if a violation is found, return a list of equivalence classes that contain
                 contract counterexamples. Otherwise, return an empty list.
        """
        # Skip if there are no htraces
        if not htraces:
            return []

        # Build a list of equivalence classes:
        #   1. Map ctraces to their IDs
        equivalent_inputs_ids = defaultdict(list)
        for i, ctrace in enumerate(ctraces):
            # skip the measurements with corrupted/ignored htraces
            if not htraces[i].raw:
                continue
            equivalent_inputs_ids[ctrace].append(i)

        #   2. Build equivalence classes
        effective_classes: List[EquivalenceClass] = []
        for ctrace, ids in equivalent_inputs_ids.items():
            # skip ineffective eq. classes
            if len(ids) < 2:
                continue

            # get all measurements in the class
            measurements = [Measurement(i, inputs[i], ctrace, htraces[i]) for i in ids]

            # Build htrace groups
            htrace_groups = self._build_htrace_groups(measurements)

            # Create an equivalence class
            eq_cls = EquivalenceClass(ctrace, measurements, htrace_groups)
            effective_classes.append(eq_cls)

        #   3. Sort the equivalence classes by ctrace
        effective_classes.sort(key=lambda x: x.ctrace)

        # Check if any of the equivalence classes is a contract counterexample
        violations: List[Violation] = []
        for eq_cls in effective_classes:
            if len(eq_cls.htrace_groups) >= 2:
                violations.append(Violation(eq_cls, inputs))

        # Update statistics
        if stats:
            STAT.eff_classes += len(effective_classes)
            STAT.single_entry_classes += len(equivalent_inputs_ids) - len(effective_classes)
            STAT.analysed_test_cases += 1

        return violations

    def _build_htrace_groups(self, measurements: List[Measurement]) -> List[List[Measurement]]:
        """
        Group measurements that have equivalent htraces, and set the htrace_groups attribute
        for the given equivalence class

        :param measurements: List of measurements to be grouped
        :return: List of groups of measurements
        """
        groups: List[List[Measurement]] = []
        for m in measurements:
            if not groups:
                groups.append([m])
                continue

            for group in groups:
                if self.htraces_are_equivalent(m.htrace, group[0].htrace):
                    group.append(m)
                    break
            else:
                groups.append([m])
        return groups


class MergedBitmapAnalyser(EquivalenceAnalyserCommon):
    """ A variant of the analyser that compares the htraces as merged bitmaps. I.e., it merges
    the htrace lists into bitmaps and compares the results.

    It also applies filtering of outliers according to CONF.analyser_outliers_threshold
    """

    bitmap_cache: Dict[int, int]
    MASK = pow(2, 64) - 1

    def __init__(self):
        self.bitmap_cache = {}

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        bitmaps = [0, 0]
        sample_size = len(htrace1.raw)
        assert sample_size == len(htrace2.raw), "htraces have different sizes"
        threshold = CONF.analyser_outliers_threshold * sample_size
        for i, htrace in enumerate([htrace1, htrace2]):
            # check if cached
            if htrace.hash_ in self.bitmap_cache:
                bitmaps[i] = self.bitmap_cache[htrace.hash_]
                continue

            # remove outliers
            counter = Counter(htrace.raw)
            filtered = [x for x in htrace.raw if counter[x] >= threshold]

            # merge into bitmap
            for t in filtered:
                bitmaps[i] |= t

            # cache
            self.bitmap_cache[htrace.hash_] = bitmaps[i]

        if CONF.analyser_subsets_is_violation:
            return bitmaps[0] == bitmaps[1]

        # check if the bitmaps are disjoint
        inverse = [~bitmaps[0] & self.MASK, ~bitmaps[1] & self.MASK]
        return (bitmaps[0] & inverse[1]) == 0 or (bitmaps[1] & inverse[0]) == 0


class SetAnalyser(EquivalenceAnalyserCommon):
    """ A variant of the analyser that compares the htraces as sets. I.e., it squashes
    the htrace lists into sets and compares the results.

    It also applies filtering of outliers according to CONF.analyser_outliers_threshold
    """

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        """ Squash the htrace lists into sets and compare the results """
        sample_size = len(htrace1.raw)
        assert sample_size == len(htrace2.raw), "htraces have different sizes"
        threshold = CONF.analyser_outliers_threshold * sample_size
        filtered1 = [x for x in htrace1.raw if x >= threshold]
        filtered2 = [x for x in htrace2.raw if x >= threshold]

        trace_set1 = set(filtered1)
        trace_set2 = set(filtered2)

        if CONF.analyser_subsets_is_violation:
            return trace_set1 == trace_set2

        return trace_set1.issubset(trace_set2) or trace_set2.issubset(trace_set1)


class MWUAnalyser(EquivalenceAnalyserCommon):
    """ A variant of the analyser that uses the Mann-Withney U test to compare htraces.

    WARNING: this is an experimental analyser and it may not work well for all cases."""
    last_p_value: float = 0.0

    def __init__(self) -> None:
        super().__init__()
        self.LOG.warning(
            "analyser",
            "MWUAnalyser is an experimental analyser and may not work well for all cases. ")

        a = [1] * CONF.executor_sample_sizes[0]
        b = [2] * CONF.executor_sample_sizes[0]
        _, p_value = stats.mannwhitneyu(a, b)
        if CONF.analyser_stat_threshold < p_value:
            self.LOG.error("analyser_stat_threshold is too low for the given sample size")

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        """ Use the Mann-Withney U test to compare htraces """
        _, p_value = stats.mannwhitneyu(htrace1.raw, htrace2.raw)

        # print(set(htrace1.raw), set(htrace2.raw), p_value)
        # if p_value <= CONF.analyser_stat_threshold:
        # print(f"p_value={p_value:.6f}")
        return p_value > CONF.analyser_stat_threshold


class ChiSquaredAnalyser(EquivalenceAnalyserCommon):

    def __init__(self) -> None:
        super().__init__()
        a = [1] * CONF.executor_sample_sizes[0]
        b = [2] * CONF.executor_sample_sizes[0]
        stat = self.homogeneity_test(a, b)
        if CONF.analyser_stat_threshold > stat:
            self.LOG.error("analyser_stat_threshold is too low for the given sample size")

    def homogeneity_test(self, x: List[int], y: List[int]) -> bool:
        """ Use the chi-squared test to compare htraces """
        assert len(x) == len(y)
        counter1 = Counter(x)
        counter2 = Counter(y)
        keys = set(counter1.keys()) | set(counter2.keys())
        observed = [counter1[k] for k in keys] + [counter2[k] for k in keys]
        expected = [(counter1[k] + counter2[k]) / 2 for k in keys] * 2
        ddof = len(keys) - 1
        stat, _ = stats.chisquare(observed, expected, ddof=ddof)
        stat /= len(x) + len(y)
        return stat

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        stat = self.homogeneity_test(htrace1.raw, htrace2.raw)
        return stat < CONF.analyser_stat_threshold
