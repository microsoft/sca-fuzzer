"""
File: various ways to compare ctraces with htraces

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from collections import defaultdict
from typing import List, Dict

from .interfaces import HTrace, CTrace, Input, EquivalenceClass, Analyser, Measurement
from .config import CONF
from .util import STAT, TWOS_COMPLEMENT_MASK_64, bit_count


class EquivalenceAnalyser(Analyser):
    """
    TODO: the description is outdated
    The main analysis function.

    Checks if all inputs that agree on their contract traces (ctraces) also agree
    on the hardware traces (htraces). To this end, we use relational theory
    [see https://en.wikipedia.org/wiki/Equivalence_class]

    From the theory perspective, the fuzzing results establish a relation between the ctraces
    and the htraces. E.g., if an input produced a ctrace C and an htrace H, then C is
    related to H. Because of the retries, though, we may have several htraces per input.
    Therefore, the actual relation is C->set(H).

    Based on this relations, we establish equivalence classes for all ctraces.
    This function checks if all equivalence classes have only one entry.

    :return A list of input IDs where ctraces disagree with htraces and a list of inputs that
        require retries
    """

    def filter_violations(self,
                          inputs: List[Input],
                          ctraces: List[CTrace],
                          htraces: List[HTrace],
                          stats=False) -> List[EquivalenceClass]:

        equivalence_classes: List[EquivalenceClass] = self._build_equivalence_classes(
            inputs, ctraces, htraces, stats)

        if self.coverage:
            self.coverage.analyser_hook(equivalence_classes)

        violations: List[EquivalenceClass] = []
        for eq_cls in equivalence_classes:
            # if all htraces in the class match, it's definitely not a violation
            if len(eq_cls.htrace_map) < 2:
                continue

            if not CONF.analyser_permit_subsets:
                violations.append(eq_cls)
                continue

            htraces = list(eq_cls.htrace_map.keys())
            if not self.check_if_all_subsets(htraces):
                violations.append(eq_cls)

        return violations

    @staticmethod
    def check_if_all_subsets(htraces: List[HTrace]) -> bool:
        max_htrace = max(htraces, key=bit_count)
        mask = max_htrace ^ TWOS_COMPLEMENT_MASK_64
        for htrace in htraces:
            masked_trace = htrace & mask
            if masked_trace != 0:
                return False

        return True

    def _build_equivalence_classes(self,
                                   inputs: List[Input],
                                   ctraces: List[CTrace],
                                   htraces: List[HTrace],
                                   stats=False) -> List[EquivalenceClass]:
        """
        Collect inputs into equivalence classes based on ctraces and group the inputs within
        the equivalence class by the htrace
        """

        # build eq. classes
        eq_class_map: Dict[CTrace, EquivalenceClass] = defaultdict(lambda: EquivalenceClass())
        for i, ctrace in enumerate(ctraces):
            eq_cls = eq_class_map[ctrace]
            eq_cls.ctrace = ctrace
            eq_cls.measurements.append(Measurement(i, inputs[i], ctrace, htraces[i]))

        # fine effective classes
        effective_classes: List[EquivalenceClass] = []
        for eq_cls in eq_class_map.values():
            if len(eq_cls.measurements) > 1:
                effective_classes.append(eq_cls)
        effective_classes.sort(key=lambda x: x.ctrace)

        if stats:
            STAT.eff_classes += len(effective_classes)
            STAT.single_entry_classes += len(eq_class_map) - len(effective_classes)
            STAT.analysed_test_cases += 1

        # build maps of htraces
        for eq_cls in effective_classes:
            eq_cls.build_htrace_map()

        return effective_classes
