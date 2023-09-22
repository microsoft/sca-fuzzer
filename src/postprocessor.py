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
from .interfaces import Input, TestCase, Minimizer, Fuzzer, InstructionSetAbstract
from .config import CONF


class MinimizerViolation(Minimizer):

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSetAbstract):
        CONF.coverage_type = 'none'
        self.instruction_set_spec = instruction_set_spec
        self.fuzzer = fuzzer
        self.fuzzer.initialize_modules()

    def _get_test_case_from_instructions(self, instructions: List[str]) -> TestCase:
        minimized_asm = "/tmp/minimised.asm"
        run(f"touch {minimized_asm}", shell=True, check=True)
        with open(minimized_asm, "w+") as f:
            f.seek(0)  # is it necessary??
            for line in instructions:
                f.write(line)
            f.truncate()  # is it necessary??
        tc = self.fuzzer.asm_parser.parse_file(minimized_asm)
        self.fuzzer.generator.create_pte(tc)
        return tc

    def _probe_test_case(self, test_case: TestCase, inputs: List[Input], modifier) -> TestCase:
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

            tmp_test_case = self._get_test_case_from_instructions(tmp_instructions)

            # Run and check if the vuln. is still there
            retries = 1
            for _ in range(0, retries):
                violations = self.fuzzer.fuzzing_round(tmp_test_case, inputs)
                if violations:
                    break
            if violations:
                previous_removed = True
                print(".", end="", flush=True)
                instructions = tmp_instructions
            else:
                previous_removed = False
                print("-", end="", flush=True)

        new_test_case = self._get_test_case_from_instructions(instructions)
        return new_test_case

    def minimize(self, test_case_asm: str, outfile: str, num_inputs: int, add_fences: bool):
        # Parse the test case and inputs
        test_case: TestCase = self.fuzzer.asm_parser.parse_file(test_case_asm)
        inputs: List[Input] = self.fuzzer.input_gen.generate(num_inputs)

        # Load, boost inputs, and trace
        self.fuzzer.generator.create_pte(test_case)
        self.fuzzer.model.load_test_case(test_case)
        boosted_inputs: List[Input]
        _, boosted_inputs = self.fuzzer.trace_and_boost(inputs, CONF.model_max_nesting)

        print("Trying to reproduce...")
        violations = self.fuzzer.fuzzing_round(test_case, boosted_inputs)
        if not violations:
            print("Could not reproduce the violation. Exiting...")
            return
        print(f"Found {len(violations)} violations")

        print("Minimizing the test case...")
        min_test_case: TestCase = self.minimize_test_case(test_case, boosted_inputs)

        if add_fences:
            print("Trying to add fences...")
            min_test_case = self.add_fences(min_test_case, boosted_inputs)

        print("Storing the results")
        shutil.copy(min_test_case.asm_path, outfile)

    def minimize_test_case(self, test_case: TestCase, inputs: List[Input]) -> TestCase:

        def skip_instruction(instructions, i) -> List:
            return instructions[:i] + instructions[i + 1:]

        return self._probe_test_case(test_case, inputs, skip_instruction)

    def add_fences(self, test_case: TestCase, inputs: List[Input]) -> TestCase:

        def push_fence(instructions, i) -> List:
            curr_instr = instructions[i].upper()
            if curr_instr[0] == "J" or curr_instr[0:3] == "LOOP":
                return []  # skip control-flow instructions - their target is already fenced
            return instructions[:i] + ["LFENCE\n"] + instructions[i:]

        return self._probe_test_case(test_case, inputs, push_fence)
