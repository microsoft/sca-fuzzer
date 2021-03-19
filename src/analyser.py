"""
File: various ways to compare ctraces with htraces

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from abc import ABC, abstractmethod
from collections import defaultdict
from custom_types import List, Tuple, Set, HTrace, CTrace, Input, EquivalenceClass, \
    EquivalenceClassMap
from helpers import pretty_bitmap, bit_count, STAT

from config import CONF

TWOS_COMPLEMENT_MASK_64 = pow(2, 64) - 1


class Analyser(ABC):
    coverage = None

    @abstractmethod
    def filter_violations(self, equivalence_classes: EquivalenceClassMap,
                          debug=False) -> List[EquivalenceClass]:
        pass

    @staticmethod
    def build_equivalence_classes(inputs: List[Input], ctraces: List[CTrace],
                                  htraces: List[HTrace], stats=False) -> EquivalenceClassMap:
        """
        Collect inputs into equivalence classes based on ctraces and group the inputs within
        the equivalence class by the htrace
        """
        equivalence_classes: EquivalenceClassMap = defaultdict(lambda: EquivalenceClass())
        for i, ctrace in enumerate(ctraces):
            eq_cls = equivalence_classes[ctrace]
            eq_cls.ctrace = ctrace
            eq_cls.original_positions.append(i)
            eq_cls.inputs.append(inputs[i])
            eq_cls.htraces.append(htraces[i])

        # Statistics:
        # calculate who many classes were useless because they contained only one input
        # and how many classes we had in total
        if stats:
            single_entry = 0
            for eq_cls in equivalence_classes.values():
                if len(eq_cls.inputs) == 1:
                    single_entry += 1
            STAT.single_entry_eq_classes += single_entry
            STAT.effective_eq_classes += len(equivalence_classes) - single_entry

        if CONF.ignore_single_entry_classes:
            single_entry = []
            for ctrace, eq_cls in equivalence_classes.items():
                if len(eq_cls.inputs) == 1:
                    single_entry.append(ctrace)
            for ctrace in single_entry:
                equivalence_classes.pop(ctrace, None)

        for eq_cls in equivalence_classes.values():
            eq_cls.update_groups()

        return equivalence_classes

    def set_coverage(self, coverage):
        self.coverage = coverage


class EquivalenceAnalyser(Analyser):
    def filter_violations(self, equivalence_classes: EquivalenceClassMap,
                          debug=False) -> List[EquivalenceClass]:
        """
        TODO: the description is outdated
        The main analysis function.

        Checks if all inputs that agree on their contract traces (ctraces) also agree
        on the hardware traces (htraces). To this end, we use relational theory
        [see https://en.wikipedia.org/wiki/Equivalence_class]

        From the theory perspective, the fuzzing results establish a relation between the ctraces and
        the htraces. E.g., if an input produced a ctrace C and an htrace H, then C is related to H.
        Because of the retries, though, we may have several htraces per input. Therefore, the actual
        relation is C->set(H).

        Based on this relations, we establish equivalence classes for all ctraces.
        This function checks if all equivalence classes have only one entry.

        :return A list of input IDs where ctraces disagree with htraces and a list of inputs that
            require retries
        """
        # check if any of the equivalence classes contains several sets of uniques htraces.
        # from the practical perspective, we are checking if all inputs that produced identical
        # ctraces also produced identical htraces
        # otherwise, it indicates an input-dependent leakage not included in the contract
        violations = []
        for eq_cls in equivalence_classes.values():
            if len(eq_cls.htrace_groups) <= 1:  # no mismatches
                continue

            if not CONF.compare_only_same_size:
                violations.append(eq_cls)
                continue

            # group by size
            traces_by_size = defaultdict(list)
            for htrace in eq_cls.htrace_groups.keys():
                traces_by_size[bit_count(htrace)].append(htrace)

            max_size = max(traces_by_size.keys())
            mask = traces_by_size[max_size][0] ^ TWOS_COMPLEMENT_MASK_64
            for size, traces in traces_by_size.items():
                # if we have several non-matching traces of the same size, it's a violation
                if len(traces) > 1:
                    # print(traces)
                    violations.append(eq_cls)
                    break
                if traces[0] & mask != 0:
                    violations.append(eq_cls)
                    break

        return violations


class SubsetAnalyser(Analyser):
    pass
    # def filter_violations(self, htraces: List[CombinedHTrace], ctraces: List[CTrace],
    #                       debug=False, stats=False) -> Tuple[List[int], List[int]]:
    #     unique_htraces = aggregate_htraces(htraces)
    #
    #     violation_ids: List[int] = []
    #     for i, ctrace in enumerate(ctraces):
    #         mask = ctrace ^ TWOS_COMPLEMENT_MASK_64
    #         for trace in unique_htraces[i]:
    #             if trace & mask != 0:
    #                 violation_ids.append(i)
    #                 # if bit_count(trace & mask) > 2:
    #                 #     print(f"Distance {bit_count(trace & mask)}")
    #                 break
    #
    #     return violation_ids, []


class DirectAnalyser(Analyser):
    pass


def print_ctrace_htrace_list(ctrace: CTrace, htraces: Set[Tuple[HTrace]]):
    """ A debugging function"""
    print(f"\nC: {int(ctrace):064b}")
    for tup in htraces:
        print(f"> {len(tup)}")
        for htrace in tup:
            print(f"   {pretty_bitmap(htrace)}")


def get_analyser() -> Analyser:
    options = {
        'equivalence-classes': EquivalenceAnalyser,
        'subsets': SubsetAnalyser,
        'direct': DirectAnalyser,
    }
    if CONF.analyser not in options:
        print("Error: unknown analyser in the config file")
        exit(1)
    return options[CONF.analyser]()
