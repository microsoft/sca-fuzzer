"""
File: x86 implementation of the test case generator

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from subprocess import run
from typing import List, Optional, Generator
from contextlib import contextmanager
import tempfile
import os

from ..fuzzer import FuzzerGeneric, ArchitecturalFuzzer
from ..interfaces import TestCase, Input, InstructionSetAbstract, Violation, Measurement, \
    HTrace, HardwareTracingError, CTrace
from ..util import STAT, Logger
from ..config import CONF
from .x86_config import _buggy_instructions
from .x86_executor import X86Executor, X86IntelExecutor


# ==================================================================================================
# Helper functions
# ==================================================================================================
def update_instruction_list():
    """
    Remove those instructions that trigger unhandled exceptions.
    This functionality is implemented as a module-level function
    to avoid code duplication between X86Fuzzer and X86ArchitecturalFuzzer
    """
    if 'opcode-undefined' not in CONF.generator_faults_allowlist:
        CONF.instruction_blocklist.extend(["ud", "ud2"])
    if 'bounds-range-exceeded' not in CONF.generator_faults_allowlist:
        CONF.instruction_blocklist.extend(['bound', 'bndcl', 'bndcu'])
    if 'breakpoint' not in CONF.generator_faults_allowlist:
        CONF.instruction_blocklist.extend(["int3"])
    if 'debug-register' not in CONF.generator_faults_allowlist:
        CONF.instruction_blocklist.extend(["int1"])


def check_instruction_list(instruction_set: InstructionSetAbstract):
    LOG = Logger()

    # Check if the instruction set contains the instructions required for the faults
    cpu_flags = run("grep 'flags' /proc/cpuinfo", shell=True, capture_output=True).stdout.decode()
    all_instruction_names = set([i.name for i in instruction_set.instructions])
    if 'div-by-zero' in CONF.generator_faults_allowlist:
        if 'div' not in all_instruction_names and 'idiv' not in all_instruction_names:
            LOG.warning("fuzzer", "div-by-zero enabled, but DIV/IDIV instructions are missing")
    if 'div-overflow' in CONF.generator_faults_allowlist:
        if 'div' not in all_instruction_names and 'idiv' not in all_instruction_names:
            LOG.warning("fuzzer", "div-overflow enabled, but DIV/IDIV instructions are missing")
    if 'bounds-range-exceeded' in CONF.generator_faults_allowlist:
        if "bndcu" not in all_instruction_names:
            LOG.warning("fuzzer", "bounds-range-exceeded enabled, but BNDCU instruction is missing")
        assert "mpx" in cpu_flags
    if 'breakpoint' in CONF.generator_faults_allowlist:
        if 'int3' not in all_instruction_names:
            LOG.warning("fuzzer", "breakpoint enabled, but INT3 instruction is missing")
    if 'debug-register' in CONF.generator_faults_allowlist:
        if 'int1' not in all_instruction_names:
            LOG.warning("fuzzer", "debug-register enabled, but INT1 instruction is missing")

    # Print a warning if the instruction set contains instructions that are known to be problematic
    for inst_name in _buggy_instructions:
        if inst_name in all_instruction_names and not CONF._no_generation:
            LOG.warning(
                "fuzzer", f"Instruction {inst_name} is known to cause false positives\n"
                "Consider adding it to instruction_blocklist")


@contextmanager
def quick_and_dirty_mode(executor: X86Executor) -> Generator[None, None, None]:
    """
    Context manager that enables us to use quick and dirty mode in the form of `with` statement
    """
    try:
        executor.set_quick_and_dirty(True)
        yield
    finally:
        executor.set_quick_and_dirty(False)


def create_fenced_test_case(test_case: TestCase, fenced_name: str, asm_parser) -> TestCase:
    with open(test_case.asm_path, 'r') as f:
        with open(fenced_name, 'w') as fenced_asm:
            started = False
            for line in f:
                fenced_asm.write(line + '\n')
                line = line.strip().lower()
                if line == '.test_case_enter:':
                    started = True
                    continue
                if not started:
                    continue
                if line and line[0] not in ["#", ".", "j"] \
                        and "loop" not in line \
                        and "macro" not in line:
                    fenced_asm.write('lfence\n')
    fenced_test_case = asm_parser.parse_file(fenced_name)
    return fenced_test_case


# ==================================================================================================
# Fuzzer classes
# ==================================================================================================
class X86Fuzzer(FuzzerGeneric):
    executor: X86IntelExecutor

    def _adjust_config(self, existing_test_case):
        super()._adjust_config(existing_test_case)
        update_instruction_list()

    def _start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
               save_violations: bool) -> bool:
        check_instruction_list(self.instruction_set)
        return super()._start(num_test_cases, num_inputs, timeout, nonstop, save_violations)

    def filter(self, test_case: TestCase, inputs: List[Input]) -> bool:
        """
        This function implements a multi-stage algorithm that gradually filters out
        uninteresting test cases

        :param test_case: the target test case
        :param inputs: list of inputs to be tested
        :return: True if the test case should be filtered out; False otherwise
        """
        # Exit if not filtering is enabled
        if not CONF.enable_speculation_filter and not CONF.enable_observation_filter:
            return False

        # Number of repetitions for each input
        reps = CONF.executor_filtering_repetitions

        # Enable quick and dirty mode to speed up the process
        with quick_and_dirty_mode(self.executor):
            # Collect hardware traces for the test case
            try:
                self.executor.load_test_case(test_case)
                org_htraces = self.executor.trace_test_case(inputs, reps)
            except HardwareTracingError:
                return True

            # 1. Speculation filter:
            # Execute on the test case on the HW and monitor PFCs
            # if there are no mispredictions, this test case is unlikely
            # to produce a violation, so just move on to the next one
            if CONF.enable_speculation_filter:
                for i, htrace in enumerate(org_htraces):
                    pfc_values = htrace.perf_counters_max
                    if pfc_values[0] == 0:  # zero indicates an error; filtering is not possible
                        break
                    if pfc_values[0] > pfc_values[1] or pfc_values[2] > 0:
                        break
                else:
                    STAT.spec_filter += 1
                    return True

            # 2. Observation filter:
            # Check if any of the htraces contain a speculative cache eviction
            # for this create a fenced version of the test case and collect traces for it
            if CONF.enable_observation_filter:
                fenced = tempfile.NamedTemporaryFile(delete=False)
                fenced_test_case = create_fenced_test_case(test_case, fenced.name, self.asm_parser)
                try:
                    self.executor.load_test_case(fenced_test_case)
                    fenced_htraces = self.executor.trace_test_case(inputs, reps)
                except HardwareTracingError:
                    return True
                os.remove(fenced.name)

                traces_match = True
                for i, _ in enumerate(inputs):
                    if not self.analyser.htraces_are_equivalent(fenced_htraces[i], org_htraces[i]):
                        traces_match = False
                        break
                if traces_match:
                    STAT.observ_filter += 1
                    return True

            return False


class X86ArchitecturalFuzzer(ArchitecturalFuzzer):

    def _adjust_config(self, existing_test_case):
        super()._adjust_config(existing_test_case)
        update_instruction_list()

    def _start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
               save_violations: bool) -> bool:
        check_instruction_list(self.instruction_set)
        return super()._start(num_test_cases, num_inputs, timeout, nonstop, save_violations)


class X86ArchDiffFuzzer(FuzzerGeneric):
    executor: X86IntelExecutor

    def _adjust_config(self, existing_test_case):
        super()._adjust_config(existing_test_case)
        update_instruction_list()

    def _start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
               save_violations: bool) -> bool:
        check_instruction_list(self.instruction_set)
        return super()._start(num_test_cases, num_inputs, timeout, nonstop, save_violations)

    def _build_dummy_ecls(self) -> Violation:
        inputs = [Input()]
        ctrace = CTrace.get_null()
        measurements = [Measurement(0, inputs[0], ctrace, HTrace([0]))]
        violation = Violation.from_measurements(ctrace, measurements, [], inputs)
        return violation

    def fuzzing_round(self,
                      test_case: TestCase,
                      inputs: List[Input],
                      _: List[int] = []) -> Optional[Violation]:
        with quick_and_dirty_mode(self.executor):
            # collect non-fenced traces
            self.arch_executor.load_test_case(test_case)
            reg_values: List[List[int]] = []
            try:
                htraces: List[HTrace] = self.arch_executor.trace_test_case(inputs, 1)
            except HardwareTracingError:
                return None
            for htrace in htraces:
                reg_values.append([htrace.raw[0]] + [int(v) for v in htrace.perf_counters[0]])

            # collect fenced traces
            fenced = tempfile.NamedTemporaryFile(delete=False)
            fenced_test_case = create_fenced_test_case(test_case, fenced.name, self.asm_parser)
            self.arch_executor.load_test_case(fenced_test_case)
            fenced_reg_values: List[List[int]] = []
            try:
                htraces = self.arch_executor.trace_test_case(inputs, 1)
            except HardwareTracingError:
                return None
            for htrace in htraces:
                fenced_reg_values.append([htrace.raw[0]]
                                         + [int(v) for v in htrace.perf_counters[0]])
            os.remove(fenced.name)

            for i, input_ in enumerate(inputs):
                if fenced_reg_values[i] == reg_values[i]:
                    if "dbg_dump_htraces" in CONF.logging_modes:
                        print(f"Input #{i}")
                        print(f"Fenced:       {[v for v in fenced_reg_values[i]]}")
                        print(f"Non-fenced:   {[v for v in reg_values[i]]}")
                    continue

                if "dbg_violation" in CONF.logging_modes:
                    print(f"Input #{i}")
                    print(f"Fenced:       {[v for v in fenced_reg_values[i]]}")
                    print(f"Non-fenced:   {[v for v in reg_values[i]]}")

                return self._build_dummy_ecls()
            return None
