"""
File: All kinds of postprocessing actions performed after a violation has been detected.
Currently, it's a stripped-down version of the main fuzzer, modified to find the minimal
set of inputs that reproduce the vulnerability and to minimize the test case.

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from subprocess import run
from fuzzer import Fuzzer
from model import Model, get_model
from executor import Executor, get_executor
from analyser import Analyser, get_analyser
from input_generator import InputGenerator, get_input_generator
from coverage import get_coverage, Coverage
from typing import List
from interfaces import HTrace, EquivalenceClass, Input, InputTaint, TestCase
from config import CONF


class Postprocessor:
    def __init__(self):
        pass

    def minimize(self, test_case: str, outfile: str, num_inputs: int, add_fences: bool):
        fuzzer: Fuzzer = Fuzzer("", "", test_case)
        executor: Executor = get_executor()
        model: Model = get_model(executor.read_base_addresses())
        input_gen: InputGenerator = get_input_generator()
        analyser: Analyser = get_analyser()

        # connect them with coverage
        coverage: Coverage = get_coverage()
        executor.set_coverage(coverage)
        model.set_coverage(coverage)
        input_gen.set_coverage(coverage)
        analyser.set_coverage(coverage)

        # Prepare initial inputs
        inputs: List[Input] = input_gen.generate(CONF.input_generator_seed, num_inputs)

        # ensure that we have many inputs in each input classes
        model.load_test_case(TestCase(test_case))
        taints: List[InputTaint]
        _, taints = model.trace_test_case(inputs, CONF.max_nesting)
        if CONF.dependency_tracking and CONF.inputs_per_class > 1:
            new_inputs: List[Input] = inputs
            orig_taints: List[InputTaint] = list(taints)
            for i in range(CONF.inputs_per_class - 1):
                new_inputs = input_gen.extend_equivalence_classes(new_inputs, orig_taints)
                inputs += new_inputs


        # Check if we can reproduce a violation with the given configuration
        print("Trying to reproduce...")

        violations: List[EquivalenceClass] = self.get_all_violations(TestCase(test_case), model, executor,
                                                                     analyser, fuzzer, inputs)
        if not violations:
            print("Could not reproduce the violation. Exiting...")
            return

        print(f"Found {len(violations)} violations\nSearching for a minimal input set...")
        min_inputs = []
        for violation in violations:
            for i in range(len(violation.inputs)):
                input_id = violation.original_positions[i]
                expected_htrace = violation.htraces[i]
                primer = fuzzer.get_min_primer(executor, inputs, input_id, expected_htrace, 1)
                min_inputs.extend(primer)

        # Make sure these inputs indeed reproduce
        violations = self.get_all_violations(TestCase(test_case), model, executor, analyser, fuzzer,
                                             min_inputs)
        if not violations or len(min_inputs) > len(inputs):
            print("Failed to build a minimal input sequence. Falling back to using all inputs...")
            min_inputs = inputs
        else:
            print(f"Reduced to {len(min_inputs)} inputs")

        with open(test_case, "r") as f:
            instructions = f.readlines()

        print("Minimizing the test case...")
        min_instructions = self.minimize_test_case(instructions, model, executor, analyser, fuzzer,
                                                   min_inputs)

        if add_fences:
            print("Trying to add fences...")
            min_instructions = self.add_fences(instructions, model, executor, analyser,
                                               fuzzer, min_inputs)

        print("Storing the results")
        with open(outfile, "w") as f:
            for line in min_instructions:
                f.write(line)

    def get_all_violations(self, test_case, model: Model, executor: Executor, analyser: Analyser,
                           fuzzer: Fuzzer, inputs: List[Input]) -> List[EquivalenceClass]:
        # Initial measurement
        model.load_test_case(test_case)
        ctraces, _ = model.trace_test_case(inputs, CONF.max_nesting)

        executor.load_test_case(test_case)
        htraces: List[HTrace] = executor.trace_test_case(inputs)

        # Check for violations
        violations: List[EquivalenceClass] = analyser.filter_violations(inputs, ctraces,
                                                                        htraces, stats=True)
        if not violations:
            return []
        if CONF.no_priming:
            return violations

        # Try priming the inputs that disagree with the other ones within the same eq. class
        true_violations = []
        while violations:
            violation: EquivalenceClass = violations.pop()
            if fuzzer.verify_with_priming(violation, executor, inputs):
                true_violations.append(violation)

        return true_violations

    def minimize_test_case(self, instructions, model: Model, executor: Executor, analyser: Analyser,
                           fuzzer: Fuzzer, inputs: List[Input]) -> List:
        minimised = "/tmp/minimised.asm"
        cursor = len(instructions)

        # Try removing instructions, one at a time
        while True:
            cursor -= 1

            # Did we reach the header?
            if instructions[cursor] == ".bb0:\n":
                break

            # Preserve those instructions used for sandboxing
            if "instrumentation" in instructions[cursor]:
                continue

            # Preserve labels
            if instructions[cursor][0] == '.' and instructions[cursor][-2] == ':':
                continue

            if instructions[cursor] == "LFENCE\n":
                continue

            if instructions[cursor] == "\n":
                continue

            # Create a test case with one line missing
            run(f"touch {minimised}", shell=True, check=True)
            with open(minimised, "r+") as f:
                f.seek(0)
                for i, line in enumerate(instructions):
                    if i == cursor:
                        continue  # skip one line
                    f.write(line)
                f.truncate()

            # Run and check if the vuln. is still there
            violations = self.get_all_violations(TestCase(minimised), model, executor, analyser, fuzzer,
                                                 inputs)
            if violations:
                print(".", end="", flush=True)
                del instructions[cursor]
            else:
                print("-", end="", flush=True)

        return instructions

    def add_fences(self, instructions, model: Model, executor: Executor, analyser: Analyser,
                   fuzzer: Fuzzer, inputs: List[Input]) -> List:
        minimised = "/tmp/minimised.asm"
        cursor = len(instructions)

        while True:
            cursor -= 1

            # Did we reach the header?
            if instructions[cursor] == ".bb0:\n":
                break

            # Create a test case with one additional fence
            run(f"touch {minimised}", shell=True, check=True)
            with open(minimised, "r+") as f:
                f.seek(0)
                for i, line in enumerate(instructions):
                    if i == cursor:
                        f.write("LFENCE\n")
                    f.write(line)
                f.truncate()

            # Run and check if the vuln. is still there
            violations = self.get_all_violations(TestCase(minimised), model, executor, analyser, fuzzer,
                                                 inputs)
            if violations:
                print(".", end="", flush=True)
                instructions = instructions[:cursor] + ["LFENCE\n"] + instructions[cursor:]
            else:
                print("-", end="", flush=True)

        return instructions

    def replace_with_nops(self, instructions, model: Model, executor: Executor, analyser: Analyser,
                          fuzzer: Fuzzer, inputs: List[Input]) -> List:
        minimised = "/tmp/minimised.asm"

        for num_nops in range(1, 9):

            # Try removing instructions, one at a time
            cursor = len(instructions)
            while True:
                cursor -= 1

                # Did we reach the header?
                if instructions[cursor] == ".bb0:\n":
                    break

                # Preserve those instructions used for sandboxing
                if "instrumentation" in instructions[cursor]:
                    continue

                if instructions[cursor] == "LFENCE\n":
                    continue
                if instructions[cursor] == "NOP\n":
                    continue

                # Create a test case with one line replaced with nops
                run(f"touch {minimised}", shell=True, check=True)
                with open(minimised, "r+") as f:
                    f.seek(0)
                    for i, line in enumerate(instructions):
                        if i == cursor:
                            f.write("NOP\n" * num_nops)
                        else:
                            f.write(line)
                    f.truncate()

                # Run and check if the vuln. is still there
                violations = self.get_all_violations(TestCase(minimised), model, executor, analyser, fuzzer,
                                                     inputs)
                if violations:
                    print(".", end="", flush=True)
                    instructions[cursor] = "NOP\n" * num_nops
                else:
                    print("-", end="", flush=True)

        return instructions
