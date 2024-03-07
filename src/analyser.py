"""
File: various ways to compare ctraces with htraces

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from collections import defaultdict, Counter
from typing import List, Dict
from scipy import stats  # type: ignore

from .interfaces import HTrace, CTrace, Input, EquivalenceClass, Analyser, Measurement
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
                          stats=False) -> List[EquivalenceClass]:
        """
        Group the measurements by their ctrace (i.e., build equivalence classes of measurements
        w.r.t. their ctrace) and check if all htraces in the same equivalence class are equal.

        Note that the htraces are not necessarily compared directly (i.e., we don't always
        check if htrace1 == htrace2). This isn't always possible because the measurements
        are noisy, and we need to allow for some differences. Instead, each of the subclasses
        of this class implements a different way to compare the htraces. For example, the
        ProbabilisticAnalyser compares the distributions of traces.

        :return A list of contract violations, i.e., the equivalence classes that
                contain contract-equivalent measurements with non-equivalent htraces
        """
        if not htraces:  # might be empty due to tracing errors
            return []

        equivalence_classes: List[EquivalenceClass] = self._build_equivalence_classes(
            inputs, ctraces, htraces, stats)

        violations: List[EquivalenceClass] = []
        for eq_cls in equivalence_classes:
            # if all htraces in the class match, it's definitely not a violation
            if len(eq_cls.htrace_groups) < 2:
                continue

            violations.append(eq_cls)

        return violations

    def _build_equivalence_classes(self,
                                   inputs: List[Input],
                                   ctraces: List[CTrace],
                                   htraces: List[HTrace],
                                   stats=False) -> List[EquivalenceClass]:
        """
        Collect inputs into equivalence classes based on ctraces and group the inputs within
        the equivalence class by the htrace
        """

        # map ctraces to their IDs
        equivalent_inputs_ids = defaultdict(list)
        for i, ctrace in enumerate(ctraces):
            equivalent_inputs_ids[ctrace].append(i)

        # build all equivalence. classes
        all_classes: List[EquivalenceClass] = []
        for ctrace, ids in equivalent_inputs_ids.items():
            eq_cls = EquivalenceClass(ctrace, inputs)
            for i in ids:
                # skip the measurements with corrupted/ignored htraces
                if not htraces[i].raw:
                    continue
                eq_cls.measurements.append(Measurement(i, inputs[i], ctrace, htraces[i]))
            all_classes.append(eq_cls)

        # find effective classes
        effective_classes: List[EquivalenceClass] = []
        for eq_cls in all_classes:
            if len(eq_cls.measurements) > 1:
                effective_classes.append(eq_cls)
        effective_classes.sort(key=lambda x: x.ctrace)

        if stats:
            STAT.eff_classes += len(effective_classes)
            STAT.single_entry_classes += len(all_classes) - len(effective_classes)
            STAT.analysed_test_cases += 1

        # build maps of htraces
        for eq_cls in effective_classes:
            self.build_htrace_groups(eq_cls)

        return effective_classes

    def build_htrace_groups(self, eq_cls: EquivalenceClass) -> None:
        """ see interfaces.py:Analyser for the docstring """
        groups: List[List[Measurement]] = []
        for m in eq_cls.measurements:
            if not groups:
                groups.append([m])
                continue

            for group in groups:
                if self.htraces_are_equivalent(m.htrace, group[0].htrace):
                    group.append(m)
                    break
            else:
                groups.append([m])

        eq_cls.htrace_groups = groups


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
        threshold = CONF.analyser_outliers_threshold * CONF.executor_sample_size
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
        threshold = CONF.analyser_outliers_threshold * CONF.executor_sample_size
        filtered1 = [x for x in htrace1.raw if x >= threshold]
        filtered2 = [x for x in htrace2.raw if x >= threshold]

        trace_set1 = set(filtered1)
        trace_set2 = set(filtered2)

        if CONF.analyser_subsets_is_violation:
            return trace_set1 == trace_set2

        return trace_set1.issubset(trace_set2) or trace_set2.issubset(trace_set1)


class MWUAnalyser(EquivalenceAnalyserCommon):
    """ A variant of the analyser that uses the Mann-Withney U test to compare htraces """

    def __init__(self) -> None:
        super().__init__()
        if CONF.analyser_p_value_threshold == 0.01:
            self.LOG.warning(
                "analyser", "Using the default p-value threshold of 0.01 for the MWU test\n"
                "may lead to false positives. Consider running `rvzr tune`\n"
                "to find a threshold that fits your testing target")

    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        """ Use the Mann-Withney U test to compare htraces """
        _, p_value = stats.mannwhitneyu(htrace1.raw, htrace2.raw)

        # print(set(htrace1.raw), set(htrace2.raw), p_value)
        # if p_value <= CONF.analyser_p_value_threshold:
        # print(f"p_value={p_value:.6f}")
        return p_value > CONF.analyser_p_value_threshold
