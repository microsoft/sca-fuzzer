"""
File: All kinds of postprocessing actions performed after a violation has been detected.
Currently, it's a stripped-down version of the main fuzzer, modified to find the minimal
set of inputs that reproduce the vulnerability and to minimize the test case.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import shutil

from copy import deepcopy
from subprocess import run
from typing import List
from .interfaces import Input, TestCase, Minimizer, Fuzzer, InstructionSetAbstract
from .config import CONF
from .util import Logger

INSTRUCTION_REPLACEMENTS = {
    "cmov": "mov",
    "xchg": "mov",
    "rep": "",
    "lock": "",
    "add": "mov",
    "sub": "mov",
    "or": "mov",
    "xor": "mov",
    "cmp": "mov",
    "bsr": "mov",
    "bsf": "mov",
    "bt": "mov",
    "bts": "mov",
    "btr": "mov",
    "btc": "mov",
    "bzhi": "mov",
    "bextr": "mov",
    "blsi": "mov",
    "blsmsk": "mov",
    "adc": "add",
    "sbb": "sub",
}


class MinimizerViolation(Minimizer):

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSetAbstract):
        self.instruction_set_spec = instruction_set_spec
        self.fuzzer = fuzzer
        self.fuzzer.initialize_modules()
        self.LOG = Logger()
        self.LOG.info = False

    def run(self, test_case_asm: str, outfile: str, num_inputs: int, enable_minimize: bool,
            enable_simplify: bool, enable_add_fences: bool, enable_find_sources: bool,
            enable_minimize_inputs: bool):
        assert CONF.instruction_set == "x86-64", "Postprocessor supports only x86-64 so far"

        # Parse the test case and inputs
        test_case: TestCase = self.fuzzer.asm_parser.parse_file(test_case_asm)
        self.fuzzer.input_gen.n_actors = len(test_case.actors)
        inputs: List[Input] = self.fuzzer.input_gen.generate(num_inputs)

        # Load, boost inputs, and trace

        print("Trying to reproduce...")
        violations = self.fuzzer.fuzzing_round(test_case, inputs)
        if not violations:
            print("Could not reproduce the violation. Exiting...")
            return
        print(f"Found {len(violations)} violations")

        if enable_minimize:
            print("\nMinimizing the test case:\n  Progress: ", end='', flush=True)
            test_case = self.minimize_test_case(test_case, inputs)

            print("\nMinimize labels:\n  Progress: ", end='', flush=True)
            test_case = self.minimize_labels(test_case, inputs)

        if enable_simplify:
            print("\nSimplifying instructions:\n  Progress: ", end='', flush=True)
            test_case = self.simplify(test_case, inputs)

        if enable_add_fences:
            print("\nTrying to add fences:\n  Progress: ", end='')
            test_case = self.add_fences(test_case, inputs)

        if enable_find_sources:
            print("\nIdentifying speculation sources:\n  Progress: ", end='')
            test_case = self.find_spec_source(test_case, inputs)

            print("\nIdentifying speculation sink:\n  Progress: ", end='')
            test_case = self.find_spec_sink(test_case, inputs)

        if enable_minimize_inputs:
            print("\n Searching for a minimal sequence of inputs:\n  Progress: ", end='')
            self.find_min_inputs(test_case, inputs)

        print("\nStoring the results")
        shutil.copy(test_case.asm_path, outfile)

    # ==============================================================================================
    # Abstract implementation of a test case processor
    def _probe_test_case(self,
                         test_case: TestCase,
                         inputs: List[Input],
                         modify_func,
                         check_func,
                         removed_ids: bool = True,
                         skip_instrumentation: bool = True) -> List[int]:
        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()

        cursor = len(instructions)

        # Try removing instructions, one at a time
        previous_removed = False
        passing_ids = []
        while True:
            cursor -= 1
            line = instructions[cursor].strip().lower()

            # Did we reach the header?
            if line == ".test_case_enter:":
                break

            # Preserve instructions used for sandboxing, fences, and labels
            if not line or \
               "lfence" in line or \
               line[0] == '.' or \
               'macro' in line or \
               'fixed' in line:
                continue

            # Remove instrumentation only if the instrumented instruction is also removed
            if skip_instrumentation and "instrumentation" in line and not previous_removed:
                continue

            # Create a modified test case
            tmp_instructions = modify_func(instructions, cursor)
            if not tmp_instructions:
                print("-", end="", flush=True)
                continue

            tmp_test_case = self._get_test_case_from_instructions(tmp_instructions)

            # Run and check if the vuln. is still there
            check_passed = False
            for i in range(10):
                if check_func(tmp_test_case, inputs):
                    check_passed = True
                    break

            if check_passed:
                previous_removed = True
                print(".", end="", flush=True)
                instructions = tmp_instructions
                if removed_ids:
                    passing_ids.append(cursor)
            else:
                previous_removed = False
                print("-", end="", flush=True)
                if not removed_ids:
                    passing_ids.append(cursor)

        return passing_ids

    # ==============================================================================================
    # Concrete implementations of test case processors
    def minimize_test_case(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        inst_ids = self._probe_test_case(
            test_case, inputs, self._skip_instruction, self._check_for_violation, removed_ids=True)

        instructions = []
        with open(test_case.asm_path, "r") as f:
            for i, line in enumerate(f):
                if i not in inst_ids:
                    instructions.append(line)
        return self._get_test_case_from_instructions(instructions, "/tmp/pipe.asm")

    def simplify(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        inst_ids = self._probe_test_case(
            test_case,
            inputs,
            modify_func=self._simplify_instruction,
            check_func=self._check_for_violation,
            removed_ids=True)

        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = self._simplify_instruction(instructions, i)
        return self._get_test_case_from_instructions(instructions, "/tmp/pipe.asm")

    def minimize_labels(self, test_case: TestCase, _) -> TestCase:
        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()

        for i in range(len(instructions)):
            print(".", end="", flush=True)
            line = instructions[i].strip().lower()
            if not line.startswith("."):
                continue
            if ".test_case_enter:" in line or \
               ".test_case_exit:" in line or \
               ".section" in line or \
               ".function" in line or \
               ".macro" in line or \
               "syntax" in line:
                continue

            label = instructions[i].strip().replace(":", "")
            found = False
            for inst in instructions:
                if label in inst and inst != instructions[i]:
                    found = True
                    break
            if found:
                continue

            instructions[i] = ""
        return self._get_test_case_from_instructions(instructions, "/tmp/pipe.asm")

    def add_fences(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        inst_ids = self._probe_test_case(
            test_case, inputs, self._push_fence, self._check_for_violation, removed_ids=True)

        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = instructions[:i] + ["lfence\n"] + instructions[i:]
        return self._get_test_case_from_instructions(instructions, "/tmp/pipe.asm")

    def find_spec_source(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        inst_ids = self._probe_test_case(
            test_case,
            inputs,
            self._skip_instruction,
            self._check_for_speculation,
            removed_ids=False,
            skip_instrumentation=False)

        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()
        if not inst_ids:
            print("[WARNING] No speculation source found")

        for i in inst_ids:
            if "# " in instructions[i]:
                if "speculation source" not in instructions[i]:
                    instructions[i] = instructions[i][:-1] + ", speculation source ?\n"
            else:
                instructions[i] = instructions[i][:-1] + "  # speculation source ?\n"
        return self._get_test_case_from_instructions(instructions, "/tmp/pipe.asm")

    def find_spec_sink(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        inst_ids = self._probe_test_case(
            test_case, inputs, self._skip_instruction, self._check_for_violation, removed_ids=False)

        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()
        if not inst_ids:
            print("[WARNING] No speculation sink found")

        i = inst_ids[0]
        if "# " in instructions[i]:
            if "speculation sink" not in instructions[i]:
                instructions[i] = instructions[i][:-1] + ", speculation sink ?\n"
        else:
            instructions[i] = instructions[i][:-1] + "  # speculation sink ?\n"
        return self._get_test_case_from_instructions(instructions, "/tmp/pipe.asm")

    def find_min_inputs(self, test_case: TestCase, inputs: List[Input]):
        # find a minimal set of inputs that trigger the violation
        tmp_inputs = list(inputs)  # copy
        for i in range(len(inputs) - 1, -1, -1):
            if self._check_for_violation(test_case, tmp_inputs[:i] + tmp_inputs[i + 1:]):
                print(".", end="", flush=True)
                tmp_inputs = tmp_inputs[:i] + tmp_inputs[i + 1:]
            else:
                print("-", end="", flush=True)

        inputs = tmp_inputs

        print("\nModifying inputs:\n  Progress: \n", end="", flush=True)
        violation = self.fuzzer.fuzzing_round(test_case, inputs)
        assert violation
        violating_input_ids = [i.input_id for i in violation.measurements]
        assert len(violating_input_ids) == 2, "Cannot (yet) handle more than 2 violating inputs"

        input_a = inputs[violating_input_ids[0]]
        input_b = inputs[violating_input_ids[1]]
        input_a_org = deepcopy(input_a)
        input_b_org = deepcopy(input_b)

        leaked = []
        i = -1
        while i < (len(input_a) - 1):
            i += 1

            # try zeroing a 64-byte block
            if i % 64 == 0:
                print("")
                for j in range(64):
                    input_a[i + j] = 0
                    input_b[i + j] = 0
                if self._check_for_violation(test_case, inputs):
                    print("." * 64, end="", flush=True)
                    i += 63
                    continue
                for j in range(64):
                    input_a[i + j] = input_a_org[i + j]
                    input_b[i + j] = input_a_org[i + j]

            # try zeroing out the byte
            input_a[i] = 0
            input_b[i] = 0
            if self._check_for_violation(test_case, inputs):
                print(".", end="", flush=True)
                continue

            # otherwise, try copying the byte between the two inputs
            input_a[i] = input_a_org[i]
            input_b[i] = input_a_org[i]
            if self._check_for_violation(test_case, inputs):
                print("+", end="", flush=True)
                continue

            # if failing, restore the original value
            print("-", end="", flush=True)
            leaked.append(i)
            input_a[i] = input_a_org[i]
            input_b[i] = input_b_org[i]

        print("\nLeaked bytes:")
        print(leaked)

        print("Saving inputs")
        for i in range(len(inputs)):
            inputs[i].save(f"input{i}.bin")

    # ==============================================================================================
    # Hook functions
    def _check_for_violation(self, test_case: TestCase, inputs: List[Input]) -> bool:
        return bool(self.fuzzer.fuzzing_round(test_case, inputs))

    def _check_for_speculation(self, test_case: TestCase, inputs: List[Input]) -> bool:
        global CONF
        conf_state = deepcopy(CONF)
        CONF.enable_speculation_filter = True
        CONF.enable_observation_filter = False
        res = self.fuzzer.filter(test_case, inputs)
        CONF = conf_state
        return not res

    def _check_for_observation(self, test_case: TestCase, inputs: List[Input]) -> bool:
        global CONF
        conf_state = deepcopy(CONF)
        CONF.enable_speculation_filter = False
        CONF.enable_observation_filter = True
        res = self.fuzzer.filter(test_case, inputs)
        CONF = conf_state
        return not res

    @staticmethod
    def _skip_instruction(instructions, i) -> List:
        return instructions[:i] + instructions[i + 1:]

    @staticmethod
    def _simplify_instruction(instructions, i) -> List:
        tmp = list(instructions)  # make a copy
        words = tmp[i].lower().split(" ")
        for key in INSTRUCTION_REPLACEMENTS:
            if key in words[0]:
                tmp[i] = " ".join([INSTRUCTION_REPLACEMENTS[key]] + words[1:])
                break
        else:
            return []  # no replacement found
        return tmp

    @staticmethod
    def _push_fence(instructions, i) -> List:
        curr_instr = instructions[i].lower()
        if curr_instr[0] == "j" or curr_instr[0:3] == "loop":
            return []  # skip control-flow instructions - their target is already fenced
        return instructions[:i] + ["lfence\n"] + instructions[i:]

    # ==============================================================================================
    # Helpers
    def _get_test_case_from_instructions(self,
                                         instructions: List[str],
                                         path: str = "/tmp/minimised.asm") -> TestCase:
        run(f"touch {path}", shell=True, check=True)
        with open(path, "w+") as f:
            f.seek(0)  # is it necessary??
            for line in instructions:
                f.write(line)
            f.truncate()  # is it necessary??
        tc = self.fuzzer.asm_parser.parse_file(path)
        return tc
