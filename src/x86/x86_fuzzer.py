"""
File: x86 implementation of the test case generator

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from subprocess import run
from typing import List, Optional
import tempfile
import os

from ..fuzzer import FuzzerGeneric, ArchitecturalFuzzer
from ..interfaces import TestCase, Input, InstructionSetAbstract, EquivalenceClass, Measurement
from ..util import STAT, Logger
from ..config import CONF
from .x86_executor import X86IntelExecutor


def update_instruction_list():
    """
    Remove those instructions that trigger unhandled exceptions.
    This functionality is implemented as a module-level function
    to avoid code duplication between X86Fuzzer and X86ArchitecturalFuzzer
    """
    if 'opcode-undefined' not in CONF.generator_faults_allowlist:
        CONF._default_instruction_blocklist.extend(["UD", "UD2"])
    if 'bounds-range-exceeded' not in CONF.generator_faults_allowlist:
        CONF._default_instruction_blocklist.extend(['BOUND', 'BNDCL', 'BNDCU'])
    if 'breakpoint' not in CONF.generator_faults_allowlist:
        CONF._default_instruction_blocklist.extend(["INT3"])
    if 'debug-register' not in CONF.generator_faults_allowlist:
        CONF._default_instruction_blocklist.extend(["INT1"])


def check_instruction_list(instruction_set: InstructionSetAbstract):
    LOG = Logger()
    cpu_flags = run("grep 'flags' /proc/cpuinfo", shell=True, capture_output=True).stdout.decode()
    all_instruction_names = set([i.name for i in instruction_set.instructions])
    if 'div-by-zero' in CONF.generator_faults_allowlist:
        if 'DIV' not in all_instruction_names and 'IDIV' not in all_instruction_names:
            LOG.warning("fuzzer", "div-by-zero enabled, but DIV/IDIV instructions are missing")
    if 'div-overflow' in CONF.generator_faults_allowlist:
        if 'DIV' not in all_instruction_names and 'IDIV' not in all_instruction_names:
            LOG.warning("fuzzer", "div-overflow enabled, but DIV/IDIV instructions are missing")
    if 'opcode-undefined' in CONF.generator_faults_allowlist:
        if 'UD' not in all_instruction_names and 'UD2' not in all_instruction_names:
            LOG.warning("fuzzer", "opcode-undefined enabled, but UD/UD2 instructions are missing")
    if 'bounds-range-exceeded' in CONF.generator_faults_allowlist:
        if "BNDCU" not in all_instruction_names:
            LOG.warning("fuzzer", "bounds-range-exceeded enabled, but BNDCU instruction is missing")
        assert "mpx" in cpu_flags
    if 'breakpoint' in CONF.generator_faults_allowlist:
        if 'INT3' not in all_instruction_names:
            LOG.warning("fuzzer", "breakpoint enabled, but INT3 instruction is missing")
    if 'debug-register' in CONF.generator_faults_allowlist:
        if 'INT1' not in all_instruction_names:
            LOG.warning("fuzzer", "debug-register enabled, but INT1 instruction is missing")


class X86Fuzzer(FuzzerGeneric):
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
        self.executor.set_quick_and_dirty(True)
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
                self.executor.set_quick_and_dirty(False)
                STAT.spec_filter += 1
                return True

        # 2. Observation filter:
        # Check if any of the htraces contain a speculative cache eviction
        # for this create a fenced version of the test case and collect traces for it
        if CONF.enable_observation_filter:
            fenced = tempfile.NamedTemporaryFile(delete=False)
            with open(test_case.asm_path, 'r') as f:
                with open(fenced.name, 'w') as fenced_asm:
                    started = False
                    for line in f:
                        fenced_asm.write(line + '\n')
                        line = line.strip().upper()
                        if line == '.TEST_CASE_ENTER:':
                            started = True
                            continue
                        if not started:
                            continue
                        if line and line[0] not in ["#", ".", "J"] and "LOOP" not in line:
                            fenced_asm.write('lfence\n')

            fenced_test_case = self.asm_parser.parse_file(fenced.name))
            self.executor.load_test_case(fenced_test_case)
            fenced_htraces = self.executor.trace_test_case(inputs, repetitions=1)
            os.remove(fenced.name)

            if fenced_htraces == non_fenced_htraces:
                self.executor.set_quick_and_dirty(False)
                STAT.observ_filter += 1
                return True

        self.executor.set_quick_and_dirty(False)
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


class X86ArchDiffFuzzer(FuzzerGeneric):
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

    def get_arch_traces(self, inputs) -> List[List[int]]:
        htraces: List[List[int]] = [
            [t] for t in self.executor.trace_test_case(inputs, repetitions=1)
        ]
        for i, trace in enumerate(self.executor.get_last_feedback()):
            htraces[i].extend(trace)
        return htraces

    def _build_dummy_ecls(self,) -> EquivalenceClass:
        eq_cls = EquivalenceClass()
        eq_cls.ctrace = 0
        eq_cls.measurements = [Measurement(0, Input(), 0, 0)]
        eq_cls.build_htrace_map()
        return eq_cls

    def fuzzing_round(self, test_case: TestCase, inputs: List[Input]) -> Optional[EquivalenceClass]:
        self.executor.set_quick_and_dirty(True)

        # collect non-fenced traces
        self.executor.load_test_case(test_case)
        htraces = self.get_arch_traces(inputs)

        # collect fenced traces
        with open(test_case.asm_path, 'r') as f:
            with open('fenced.asm', 'w') as fenced_asm:
                started = False
                for line in f:
                    fenced_asm.write(line + '\n')
                    line = line.strip().upper()
                    if line == '.TEST_CASE_ENTER:':
                        started = True
                        continue
                    if not started:
                        continue
                    if line and line[0] not in ["#", ".", "J"] and "LOOP" not in line:
                        fenced_asm.write('lfence\n')

        fenced_test_case = self.asm_parser.parse_file('fenced.asm')
        self.executor.load_test_case(fenced_test_case)
        fenced_htraces = self.get_arch_traces(inputs)

        for i, input_ in enumerate(inputs):
            if fenced_htraces[i] != htraces[i]:
                if "dbg_violation" in CONF.logging_modes:
                    print(f"Input #{i}")
                    print(f"Fenced:       {[hex(v) for v in fenced_htraces[i]]}")
                    print(f"Non-fenced:   {[hex(v) for v in htraces[i]]}")

                eq_cls = EquivalenceClass()
                eq_cls.ctrace = fenced_htraces[i][0]
                eq_cls.measurements = [
                    Measurement(i, inputs[i], fenced_htraces[i][0], htraces[i][0])
                ]
                eq_cls.build_htrace_map()
                return self._build_dummy_ecls()

            if "dbg_traces" in CONF.logging_modes:
                print(f"Input #{i}")
                print(f"Fenced:       {[hex(v) for v in fenced_htraces[i]]}")
                print(f"Non-fenced:   {[hex(v) for v in htraces[i]]}")

        return None
