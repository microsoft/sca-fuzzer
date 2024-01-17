"""
File: x86 implementation of the test case generator

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from subprocess import run
from typing import List

from fuzzer import Fuzzer
from interfaces import TestCase, Input
from service import STAT
from config import CONF
from x86.x86_executor import X86IntelExecutor


class X86Fuzzer(Fuzzer):
    executor: X86IntelExecutor

    def filter(self, test_case: TestCase, inputs: List[Input]) -> bool:
        """ This function implements a multi-stage algorithm that gradually filters out
        uninteresting test cases """
        if CONF.enable_speculation_filter or CONF.enable_observation_filter:
            self.executor.load_test_case(test_case)
            non_fenced_htraces = self.executor.trace_test_case(inputs, repetitions=1)

        # 1. Speculation filter:
        # Execute on the test case on the HW and monitor PFCs
        # if there are no mispredictions, this test case is unlikely
        # to produce a violation, so just move on to the next one
        if CONF.enable_speculation_filter:
            pfc_feedback = self.executor.get_last_feedback()
            for i, pfc_values in enumerate(pfc_feedback):
                if pfc_values[0] > 0 and pfc_values[2] > pfc_values[1]:
                    break
            else:
                return True
            STAT.spec_filter += 1

        # 2. Observation filter:
        # Check if any of the htraces contain a speculative cache eviction
        # for this create a fenced version of the test case and collect traces for it
        if CONF.enable_observation_filter:
            run(CONF.exe_awk + ' \'//{print $0, "\\nlfence"}\' ' + test_case.asm_path + '> fenced.asm',
                shell=True)
            self.generator.assemble('fenced.asm', 'fenced.o')
            fenced_test_case = TestCase()
            fenced_test_case.bin_path = 'fenced.o'
            self.executor.load_test_case(fenced_test_case)
            fenced_htraces = self.executor.trace_test_case(inputs, repetitions=1)

            if fenced_htraces == non_fenced_htraces:
                return True

            # check for corrupted measurements
            fenced_htraces2 = self.executor.trace_test_case(inputs, repetitions=1)
            if fenced_htraces != fenced_htraces2:
                return True
            STAT.observ_filter += 1

        return False
