"""
File: All kinds of postprocessing actions performed after a violation has been detected.
Currently, it's a stripped-down version of the main fuzzer, modified to find the minimal
set of inputs that reproduce the vulnerability and to minimize the test case.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import shutil
from subprocess import run
from typing import List
from .fuzzer import Fuzzer
from .interfaces import HTrace, EquivalenceClass, Input, TestCase, Minimizer
from .config import CONF


class MinimizerViolation(Minimizer):

    def __init__(self, instruction_set_spec):
        CONF.coverage_type = 'none'
        self.instruction_set_spec = instruction_set_spec

    def _get_all_violations(self, fuzzer: Fuzzer, test_case: TestCase,
                            inputs: List[Input]) -> List[EquivalenceClass]:
        # Initial measurement
        fuzzer.model.load_test_case(test_case)
        fuzzer.executor.load_test_case(test_case)
        ctraces = fuzzer.model.trace_test_case(inputs, CONF.model_max_nesting)
        htraces: List[HTrace] = fuzzer.executor.trace_test_case(inputs, CONF.executor_repetitions)

        # Check for violations
        violations: List[EquivalenceClass] = fuzzer.analyser.filter_violations(
            inputs, ctraces, htraces, stats=True)
        if not violations:
            return []
        if not CONF.enable_priming:
            return violations

        # Try priming the inputs that disagree with the other ones within the same eq. class
        true_violations = []
        while violations:
            violation: EquivalenceClass = violations.pop()
            if fuzzer.priming(violation, inputs):
                true_violations.append(violation)

        return true_violations

    def _get_test_case_from_instructions(self, fuzzer, instructions: List[str]) -> TestCase:
        minimized_asm = "/tmp/minimised.asm"
        run(f"touch {minimized_asm}", shell=True, check=True)
        with open(minimized_asm, "w+") as f:
            f.seek(0)  # is it necessary??
            for line in instructions:
                f.write(line)
            f.truncate()  # is it necessary??
        tc = fuzzer.generator.load(minimized_asm)
        fuzzer.generator.create_pte(tc)
        return tc

    def _probe_test_case(self, fuzzer: Fuzzer, test_case: TestCase, inputs: List[Input],
                         modifier) -> TestCase:
        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()

        cursor = len(instructions)

        # Try removing instructions, one at a time
        previous_removed = False
        while True:
            cursor -= 1
            line = instructions[cursor].strip()

            # Did we reach the header?
            if line == ".test_case_enter:":
                break

            # Preserve instructions used for sandboxing, fences, and labels
            if not line or \
               "LFENCE" in line or \
               line[0] == '.':
                continue

            # Remove instrumentation only if the instrumented instruction is also removed
            if "instrumentation" in line and not previous_removed:
                continue

            # Create a test case with one line missing
            tmp_instructions = modifier(instructions, cursor)
            if not tmp_instructions:
                continue

            tmp_test_case = self._get_test_case_from_instructions(fuzzer, tmp_instructions)

            # Run and check if the vuln. is still there
            retries = 1
            for _ in range(0, retries):
                violations = self._get_all_violations(fuzzer, tmp_test_case, inputs)
                if violations:
                    break
            if violations:
                previous_removed = True
                print(".", end="", flush=True)
                instructions = tmp_instructions
            else:
                previous_removed = False
                print("-", end="", flush=True)

        new_test_case = self._get_test_case_from_instructions(fuzzer, instructions)
        return new_test_case

    def minimize(self, test_case_asm: str, outfile: str, num_inputs: int, add_fences: bool):
        # initialize fuzzer
        fuzzer: Fuzzer = Fuzzer(self.instruction_set_spec, "", test_case_asm)
        fuzzer.initialize_modules()

        # Parse the test case and inputs
        test_case: TestCase = fuzzer.generator.load(test_case_asm)
        inputs: List[Input] = fuzzer.input_gen.generate(num_inputs)

        # Load, boost inputs, and trace
        fuzzer.generator.create_pte(test_case)
        fuzzer.model.load_test_case(test_case)
        boosted_inputs: List[Input] = fuzzer.boost_inputs(inputs, CONF.model_max_nesting)

        print("Trying to reproduce...")
        violations = self._get_all_violations(fuzzer, test_case, boosted_inputs)
        if not violations:
            print("Could not reproduce the violation. Exiting...")
            return
        print(f"Found {len(violations)} violations")

        print("Minimizing the test case...")
        min_test_case: TestCase = self.minimize_test_case(fuzzer, test_case, boosted_inputs)

        if add_fences:
            print("Trying to add fences...")
            min_test_case = self.add_fences(fuzzer, min_test_case, boosted_inputs)

        print("Storing the results")
        shutil.copy(min_test_case.asm_path, outfile)

    def minimize_test_case(self, fuzzer: Fuzzer, test_case: TestCase,
                           inputs: List[Input]) -> TestCase:

        def skip_instruction(instructions, i) -> List:
            return instructions[:i] + instructions[i + 1:]

        return self._probe_test_case(fuzzer, test_case, inputs, skip_instruction)

    def add_fences(self, fuzzer: Fuzzer, test_case: TestCase, inputs: List[Input]) -> TestCase:

        def push_fence(instructions, i) -> List:
            curr_instr = instructions[i].upper()
            if curr_instr[0] == "J" or curr_instr[0:3] == "LOOP":
                return []  # skip control-flow instructions - their target is already fenced
            return instructions[:i] + ["LFENCE\n"] + instructions[i:]

        return self._probe_test_case(fuzzer, test_case, inputs, push_fence)
