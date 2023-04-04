"""
File: x86 implementation of the test case generator

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from subprocess import run
from typing import List

from ..fuzzer import Fuzzer, ArchitecturalFuzzer
from ..interfaces import TestCase, Input, InstructionSetAbstract
from ..util import STAT
from ..config import CONF
from .x86_executor import X86IntelExecutor


def update_instruction_list():
    """
    Remove those instructions that trigger unhandled exceptions.
    This functionality is implemented as a module-level function
    to avoid code duplication between X86Fuzzer and X86ArchitecturalFuzzer
    """
    if 'DE-overflow' not in CONF.permitted_faults:
        if "IDIV" not in CONF._default_instruction_blocklist:
            CONF._default_instruction_blocklist.append("IDIV")
        if "REX IDIV" not in CONF._default_instruction_blocklist:
            CONF._default_instruction_blocklist.append("REX IDIV")
    if 'UD' not in CONF.permitted_faults:
        CONF._default_instruction_blocklist.extend(["UD", "UD2"])
    if 'UD-sgx' not in CONF.permitted_faults:
        CONF._default_instruction_blocklist.extend(["ENCLU"])
    if 'UD-vtx' not in CONF.permitted_faults:
        CONF._default_instruction_blocklist.extend([
            'INVEPT', 'INVVPID', 'VMCALL', 'VMCLEAR', 'VMLAUNCH', 'VMPTRLD', 'VMPTRST', 'VMREAD',
            'VMRESUME', 'VMWRITE', 'VMXOFF'
        ])
    if 'UD-svm' not in CONF.permitted_faults:
        CONF._default_instruction_blocklist.extend(
            ["VMRUN", "VMLOAD", "VMSAVE", "CLGI", "VMMCALL", "INVLPGA"])
    if 'DB-instruction' not in CONF.permitted_faults:
        CONF._default_instruction_blocklist.append("INT1")
    if 'BP' not in CONF.permitted_faults:
        CONF._default_instruction_blocklist.append("INT3")


def check_instruction_list(instruction_set: InstructionSetAbstract):
    all_instruction_names = set([i.name for i in instruction_set.instructions])
    if 'DE-overflow' in CONF.permitted_faults:
        assert "DIV" in all_instruction_names or "IDIV" in all_instruction_names
    if 'UD' in CONF.permitted_faults:
        assert "UD" in all_instruction_names or "UD2" in all_instruction_names
    if 'UD-sgx' in CONF.permitted_faults:
        assert "ENCLU" in all_instruction_names
        cpu_flags = run(
            "grep 'flags' /proc/cpuinfo", shell=True, capture_output=True).stdout.decode()
        assert "sgx" in cpu_flags
    if 'UD-vtx' in CONF.permitted_faults:
        assert "VMCALL" in all_instruction_names
    if 'UD-svm' in CONF.permitted_faults:
        assert "VMMCALL" in all_instruction_names
    if 'DB-instruction' in CONF.permitted_faults:
        assert "INT1" in all_instruction_names
    if 'BP' in CONF.permitted_faults:
        assert "INT3" in all_instruction_names


class X86Fuzzer(Fuzzer):
    executor: X86IntelExecutor

    def _adjust_config(self, existing_test_case):
        super()._adjust_config(existing_test_case)
        update_instruction_list()

    def start(self,
              num_test_cases: int,
              num_inputs: int,
              timeout: int,
              nonstop: bool = False) -> bool:
        check_instruction_list(self.instruction_set)
        return super().start(num_test_cases, num_inputs, timeout, nonstop)

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
                if pfc_values[0] > pfc_values[1] or pfc_values[2] > 0:
                    break
            else:
                return True
            STAT.spec_filter += 1

        # 2. Observation filter:
        # Check if any of the htraces contain a speculative cache eviction
        # for this create a fenced version of the test case and collect traces for it
        if CONF.enable_observation_filter:
            run('awk \'//{print $0, "\\nlfence"}\' ' + test_case.asm_path + '> fenced.asm',
                shell=True)
            self.generator.assemble('fenced.asm', 'fenced.o')
            fenced_test_case = TestCase(0)
            fenced_test_case.bin_path = 'fenced.o'
            self.executor.load_test_case(fenced_test_case)
            fenced_htraces = self.executor.trace_test_case(inputs, repetitions=1)

            if fenced_htraces == non_fenced_htraces:
                return True

            STAT.observ_filter += 1

        return False


class X86ArchitecturalFuzzer(ArchitecturalFuzzer):

    def _adjust_config(self, existing_test_case):
        super()._adjust_config(existing_test_case)
        update_instruction_list()

    def start(self,
              num_test_cases: int,
              num_inputs: int,
              timeout: int,
              nonstop: bool = False) -> bool:
        check_instruction_list(self.instruction_set)
        return super().start(num_test_cases, num_inputs, timeout, nonstop)
