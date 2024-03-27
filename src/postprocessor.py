"""
File: All kinds of postprocessing actions performed after a violation has been detected.
Currently, it's a stripped-down version of the main fuzzer, modified to find the minimal
set of inputs that reproduce the vulnerability and to minimize the test case.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import shutil
import re
from math import log2

from copy import deepcopy
from subprocess import run
from typing import List
from .interfaces import Input, TestCase, Minimizer, Fuzzer, InstructionSetAbstract
from .model import CTTracer
from .x86.x86_model import X86UnicornDEH, SANDBOX_CODE_SIZE
from .config import CONF
from .util import Logger

INSTRUCTION_REPLACEMENTS = {
    "cmova": lambda _: "mov",
    "cmovae": lambda _: "mov",
    "cmovb": lambda _: "mov",
    "cmovbe": lambda _: "mov",
    "cmovc": lambda _: "mov",
    "cmove": lambda _: "mov",
    "cmovg": lambda _: "mov",
    "cmovge": lambda _: "mov",
    "cmovl": lambda _: "mov",
    "cmovle": lambda _: "mov",
    "cmovna": lambda _: "mov",
    "cmovnae": lambda _: "mov",
    "cmovnb": lambda _: "mov",
    "cmovnbe": lambda _: "mov",
    "cmovnc": lambda _: "mov",
    "cmovne": lambda _: "mov",
    "cmovng": lambda _: "mov",
    "cmovnge": lambda _: "mov",
    "cmovnl": lambda _: "mov",
    "cmovnle": lambda _: "mov",
    "cmovno": lambda _: "mov",
    "cmovnp": lambda _: "mov",
    "cmovns": lambda _: "mov",
    "cmovnz": lambda _: "mov",
    "cmovo": lambda _: "mov",
    "cmovp": lambda _: "mov",
    "cmovs": lambda _: "mov",
    "cmovz": lambda _: "mov",
    "xchg": lambda _: "mov",
    "cmpxchg": lambda _: "xchg",
    "rep": lambda _: "",
    "lock": lambda _: "",
    "add": lambda _: "mov",
    "sub": lambda _: "add",
    "or": lambda _: "add",
    "xor": lambda _: "add",
    "and": lambda _: "add",
    "cmp": lambda _: "add",
    "bsr": lambda _: "add",
    "bsf": lambda _: "add",
    "bt": lambda _: "add",
    "bts": lambda _: "add",
    "btr": lambda _: "add",
    "btc": lambda _: "add",
    "bzhi": lambda _: "add",
    "bextr": lambda _: "add",
    "blsi": lambda _: "add",
    "blsmsk": lambda _: "add",
    "xadd": lambda _: "add",
    "test": lambda _: "add",
    "adc": lambda _: "add",
    "sbb": lambda _: "sub",
    "mul": lambda _: "inc",
    "div": lambda _: "inc",
    "setb": lambda _: "inc",
    "not": lambda _: "inc",
    "idiv": lambda _: "div",
    "imul": lambda line: "add" if len(line.split(",")) == 2 else "imul",
}

MASK_REPLACEMENTS = {
    "0b1111111111111": "0b1111111111110",
    "0b1111111111110": "0b1111111111100",
    "0b1111111111100": "0b1111111111000",
    "0b1111111111000": "0b1111111110000",
    "0b1111111110000": "0b1111111100000",
    "0b1111111100000": "0b1111111000000",
    "0b1111111000000": "0b1111110000000",
    "0b1111110000000": "0b1111100000000",
    "0b1111100000000": "0b1111000000000",
    "0b1111000000000": "0b1110000000000",
    "0b1110000000000": "0b1100000000000",
    "0b1100000000000": "0b1000000000000",
    "0b1000000000000": "0b0000000000000",
}


class MinimizerViolation(Minimizer):
    ignore_list: List[int]

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSetAbstract):
        self.instruction_set_spec = instruction_set_spec
        self.fuzzer = fuzzer
        self.fuzzer.initialize_modules()
        self.ignore_list = []
        self.LOG = Logger()
        self.LOG.info = False

    def run(self, test_case_asm: str, outfile: str, num_inputs: int, enable_minimize: bool,
            enable_simplify: bool, enable_add_fences: bool, enable_find_sources: bool,
            enable_minimize_inputs: bool, enable_multipass: bool, enable_violation_comments: bool):
        assert CONF.instruction_set == "x86-64", "Postprocessor supports only x86-64 so far"

        # Parse the test case and inputs
        test_case: TestCase = self.fuzzer.asm_parser.parse_file(test_case_asm)
        self.fuzzer.input_gen.n_actors = len(test_case.actors)
        inputs: List[Input] = self.fuzzer.input_gen.generate(num_inputs)

        # Load, boost inputs, and trace
        print("Trying to reproduce...")
        violation = self.fuzzer.fuzzing_round(test_case, inputs)
        if not violation:
            print("Could not reproduce the violation. Exiting...")
            return
        print("Reproduced successfully.")

        # Try to reproduce the same with fewer inputs
        org_len = len(inputs)
        while len(inputs) > 5:
            new_inputs = inputs[:len(inputs) // 2]
            new_violation = self.fuzzer.fuzzing_round(test_case, new_inputs)
            if not new_violation:
                break
            inputs = new_inputs
            violation = new_violation
        if len(inputs) < org_len:
            print("Reduced the number of inputs to ", len(inputs))

        # Set the non-violating inputs as the ignore list
        violating_input_ids = [m.input_id for m in violation.measurements]
        print(f"Violating inputs: {violating_input_ids}")
        n_inputs = len(inputs) * CONF.inputs_per_class
        self.ignore_list = [i for i in range(n_inputs) if i not in violating_input_ids]

        if enable_minimize_inputs:
            print("\n Analyzing inputs:\n  Progress: ", end='')
            inputs = self.find_min_inputs(test_case, inputs, violation)
            CONF.inputs_per_class = 1  # disable boosting from now on

        # Remove/simplify instructions in multiple passes
        attempts = 1 if not enable_multipass else 10
        for attempt in range(attempts):
            if not enable_minimize and not enable_simplify:
                break
            print(f"\nMinimization attempt {attempt + 1}/{attempts}")
            old_instruction_count = len([i for i in open(test_case.asm_path, "r")])

            if enable_minimize:
                print("\n  Minimizing the test case: ", end='', flush=True)
                test_case = self.minimize_test_case(test_case, inputs)
                shutil.copy(test_case.asm_path, outfile)

            if enable_simplify:
                print("\n  Simplifying instructions: ", end='', flush=True)
                test_case = self.simplify(test_case, inputs)

                print("\n  Simplifying constants: ", end='', flush=True)
                test_case = self.simplify_constants(test_case, inputs)
                shutil.copy(test_case.asm_path, outfile)

                # print("\n  Simplifying masks: ", end='', flush=True)
                # test_case = self.simplify_masks(test_case, inputs)
                # shutil.copy(test_case.asm_path, outfile)

            new_instruction_count = len([i for i in open(test_case.asm_path, "r")])
            if new_instruction_count == old_instruction_count:
                break

        if enable_minimize:
            print("\nMinimize labels: ", end='', flush=True)
            test_case = self.minimize_labels(test_case, inputs)
            shutil.copy(test_case.asm_path, outfile)

        if enable_add_fences:
            print("\nTrying to add fences: ", end='')
            test_case = self.add_fences(test_case, inputs)
            shutil.copy(test_case.asm_path, outfile)

        if enable_find_sources:
            print("\nIdentifying speculation sources: ", end='')
            test_case = self.find_spec_source(test_case, inputs)

            print("\nIdentifying speculation sink: ", end='')
            test_case = self.find_spec_sink(test_case, inputs)
            shutil.copy(test_case.asm_path, outfile)

        if enable_violation_comments:
            print("\n Adding comments with violation details:\n", end='')
            test_case = self.add_violation_comments(test_case, violation)
            shutil.copy(test_case.asm_path, outfile)

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
        passing_ids = []
        while True:
            cursor -= 1
            line = instructions[cursor].strip().lower()

            # Did we reach the header?
            if line == ".test_case_enter:":
                break

            # don't waste time on comments and empty lines
            if not line or line[0] == "#":
                continue

            # Preserve instructions used for sandboxing, fences, and labels
            if "lfence" in line or \
               '.' == line[0] or \
               'noremove' in line:
                continue

            # Remove instrumentation only if the instrumented instruction is also removed
            if skip_instrumentation and "instrumentation" in line:
                continue

            # Create a modified test case
            tmp_instructions = modify_func(instructions, cursor)
            if not tmp_instructions:
                print("-", end="", flush=True)
                continue

            tmp_test_case = self._get_test_case_from_instructions(tmp_instructions)

            # Run and check if the vuln. is still there
            check_passed = False
            for _ in range(CONF.minimizer_retries):
                if check_func(tmp_test_case, inputs):
                    check_passed = True
                    break

            if check_passed:
                print(".", end="", flush=True)
                instructions = tmp_instructions
                if removed_ids:
                    passing_ids.append(cursor)
            else:
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
                    # This instruction is essential for the violation; keep it
                    instructions.append(line)
                else:
                    # This instruction could be removed. In addition, if it has instrumentation
                    # which cannot be removed, clear the instrumentation tag
                    if "instrumentation" in instructions[-1].lower():
                        instructions[-1] = instructions[-1].replace("instrumentation", "")

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

    def simplify_constants(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        inst_ids = self._probe_test_case(
            test_case,
            inputs,
            modify_func=self._simplify_constant,
            check_func=self._check_for_violation,
            removed_ids=True)

        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = self._simplify_constant(instructions, i)
        return self._get_test_case_from_instructions(instructions, "/tmp/pipe.asm")

    def simplify_masks(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        inst_ids = self._probe_test_case(
            test_case,
            inputs,
            modify_func=self._simplify_mask,
            check_func=self._check_for_violation,
            removed_ids=True,
            skip_instrumentation=False)

        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = self._simplify_mask(instructions, i)
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

    def find_min_inputs(self, test_case: TestCase, inputs: List[Input], violation) -> List[Input]:
        inputs = violation.input_sequence

        org_conf = (CONF.inputs_per_class, CONF.minimizer_retries)
        CONF.inputs_per_class = 1  # disable boosting from now on
        CONF.minimizer_retries = 5

        violating_input_ids = [i.input_id for i in violation.measurements]
        if len(violating_input_ids) > 2:
            violating_input_ids = violating_input_ids[:2]

        # make a copy of the inputs
        input_a = inputs[violating_input_ids[0]]
        input_b = inputs[violating_input_ids[1]]
        input_a_org = deepcopy(input_a)
        input_b_org = deepcopy(input_b)

        leaked = []
        n_actors = len(CONF._actors)
        assert len(input_a) == n_actors
        assert len(input_b) == n_actors

        # print header
        print(f'\n{"Address":<11}', end="", flush=True)
        for i in range(0, 64, 8):
            print(f"+0x{i * 8:<6x}", end="", flush=True)

        for actor_id in range(n_actors):
            region_offset = 0
            for region_name in ['main', 'faulty', 'gpr', 'simd']:
                i = -1
                region_size = len(input_a[actor_id][region_name])
                while i < (region_size - 1):
                    i += 1

                    # progress indicator
                    absolute_address = actor_id * 0x4000 + region_offset + i * 8
                    if i % 64 == 0:
                        print(f"\n0x{absolute_address:08x} ", end="", flush=True)
                    elif i % 8 == 0:
                        print(" ", end="", flush=True)

                    # skip if the bytes are equal
                    if input_a[actor_id][region_name][i] == input_b[actor_id][region_name][i]:
                        print("=", end="", flush=True)
                        continue

                    # Try zeroing out blocks of decreasing size:
                    # 1. find a suitable starting block size, fulfilling the following conditions:
                    #    * the block size is less then 512 bytes (64 * 8)
                    block_size = 64 - (i % 64)
                    #    * the block does not overlap with the next region
                    if block_size > region_size - i:
                        block_size = region_size - i
                    #    * the block size is a power of 2
                    block_size = 2**int(log2(block_size))
                    #    * i mod block_size == 0
                    while block_size > 1 and i % block_size != 0:
                        block_size //= 2
                    # 2. binary search for the largest zeroed-out block that
                    #    still triggers the violation
                    success = False
                    while block_size > 1:
                        for j in range(block_size):
                            input_a[actor_id][region_name][i + j] = 0
                            input_b[actor_id][region_name][i + j] = 0
                        if self._check_for_violation(test_case, inputs):
                            n_64byte_blocks = block_size // 8
                            n_remainder_bytes = block_size % 8
                            if n_remainder_bytes > 0:
                                print("." * n_remainder_bytes, end="", flush=True)
                                if n_64byte_blocks > 0:
                                    print(" ", end="", flush=True)
                            if n_64byte_blocks > 0:
                                print(("." * 8 + " ") * (n_64byte_blocks - 1), end="", flush=True)
                                print("." * 8, end="", flush=True)
                            i += block_size - 1
                            success = True
                            break
                        for j in range(block_size):
                            input_a[actor_id][region_name][i + j] = \
                                input_a_org[actor_id][region_name][i + j]
                            input_b[actor_id][region_name][i + j] = \
                                input_b_org[actor_id][region_name][i + j]
                        block_size //= 2
                    if success:
                        continue

                    # try zeroing out a single byte
                    input_a[actor_id][region_name][i] = 0
                    input_b[actor_id][region_name][i] = 0
                    if self._check_for_violation(test_case, inputs):
                        print(".", end="", flush=True)
                        continue

                    # try copying the byte between the two inputs
                    input_a[actor_id][region_name][i] = input_a_org[actor_id][region_name][i]
                    input_b[actor_id][region_name][i] = input_a_org[actor_id][region_name][i]
                    if self._check_for_violation(test_case, inputs):
                        print("+", end="", flush=True)
                        continue

                    # if failing, restore the original value
                    print("^", end="", flush=True)
                    leaked.append(absolute_address)
                    input_a[actor_id][region_name][i] = input_a_org[actor_id][region_name][i]
                    input_b[actor_id][region_name][i] = input_b_org[actor_id][region_name][i]

                region_offset += region_size * 8

        print("\nLeaked bytes:")
        print([hex(x) for x in leaked])

        print("Saving inputs")
        for i in range(len(inputs)):
            inputs[i].save(f"input_{i}.bin")

        CONF.inputs_per_class = org_conf[0]
        CONF.minimizer_retries = org_conf[1]
        return inputs

    def add_violation_comments(self, test_case: TestCase, violation) -> TestCase:
        v_inputs = [m.input_ for m in violation.measurements[:2]]
        v_input_ids = [m.input_id for m in violation.measurements[:2]]

        # create a model that will collect PC and memory traces
        sandbox_base, code_base = 0x2000000, 0x1000000
        model = X86UnicornDEH(sandbox_base, code_base)
        model.tracer = CTTracer()

        # collect traces
        ctraces = []
        model.load_test_case(test_case)
        for v_input in v_inputs:
            model.tracer.enable_tracing = True  # trace everything
            ctrace_str = model.dbg_get_trace_detailed(v_input, 30, True)
            ctraces.append([int(x) for x in ctrace_str])

        # select loads and stores form the traces
        ctrace_maps = []
        for ctrace in ctraces:
            ctrace_map = {}
            for v1, v2, v3 in zip(ctrace, ctrace[1:], ctrace[2:]):
                if v1 >= code_base and v1 < sandbox_base and v2 >= sandbox_base:
                    pc = v1 - code_base
                    ld_addr = v2 - sandbox_base
                    st_addr = v3 - sandbox_base if v3 >= sandbox_base else 0
                    ctrace_map[pc] = (ld_addr, st_addr)
            ctrace_maps.append(ctrace_map)

        # get the contents of the asm file
        lines = []
        with open(test_case.asm_path, "r") as f:
            lines = [(i, line) for i, line in enumerate(f)]

        # to simplify the next step, get a dictionary mapping assembly lines to PCs
        line_num_to_pc = {}
        for actor_id in test_case.address_map:
            for inst in test_case.address_map[actor_id].values():
                pc = inst.section_id * SANDBOX_CODE_SIZE + inst.section_offset
                line_num = inst.line_num
                if line_num != 0:
                    line_num_to_pc[line_num] = pc

        # add a comment with the load/store addresses to the assembly
        with open(test_case.asm_path, 'w') as f:
            for i, line in lines:
                f.write(line)
                if i not in line_num_to_pc:
                    continue
                pc = line_num_to_pc[i]
                if pc not in ctrace_maps[0] or pc not in ctrace_maps[1]:
                    continue

                ld, st, cl, of = [0, 0], [0, 0], [0, 0], [0, 0]
                iid = v_input_ids
                for i in range(2):
                    ld[i], st[i] = ctrace_maps[i][pc]
                    cl[i] = (ld[i] % 0x1000) // 64
                    of[i] = (ld[i] % 0x1000) % 64

                if st[0] != 0 or st[1] != 0:
                    f.write(
                        f"# mem access: [{iid[0]}] {hex(ld[0])}-{hex(st[0])} CL {cl[0]}:{of[0]} | "
                        f"[{iid[1]}] {hex(ld[1])}-{hex(st[1])} CL {cl[1]}:{of[1]}\n")
                else:
                    f.write(f"# mem access: [{iid[0]}] {hex(ld[0])} CL {cl[0]}:{of[0]} | "
                            f"[{iid[1]}] {hex(ld[1])} CL {cl[1]}:{of[1]}\n")

                if st[0] == 0xff8 or st[1] == 0xff8:
                    f.write("# exception?\n")

        return test_case

    # ==============================================================================================
    # Hook functions
    def _check_for_violation(self, test_case: TestCase, inputs: List[Input]) -> bool:
        return self.fuzzer.fuzzing_round(test_case, inputs, self.ignore_list) is not None

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
        clean_line = tmp[i].strip().lower()
        words = clean_line.split(" ")
        key = words[0]
        replacement_func = INSTRUCTION_REPLACEMENTS.get(key, None)
        if not replacement_func:
            return []
        tmp[i] = " ".join([replacement_func(clean_line)] + words[1:]) + "\n"

        return tmp

    @staticmethod
    def _simplify_constant(instructions, i) -> List:
        tmp = list(instructions)  # make a copy
        clean_line = tmp[i].strip().lower()
        words = clean_line.split(",")
        for word_id, word in enumerate(words):
            word = word.strip()
            if word == "0":  # already replaced
                break
            if re.match(r"^-?[0-9]+$", word) or re.match(r"^-?0x[0-9a-f]+$", word) \
               or re.match(r"^-?0b[01]+$", word):
                tmp[i] = ", ".join(words[:word_id] + ["0"] + words[word_id + 1:]) + "\n"
                return tmp

        return []

    @staticmethod
    def _simplify_mask(instructions, i) -> List:
        tmp = list(instructions)  # make a copy

        comment_split = tmp[i].split("#")
        clean_line = comment_split[0].strip().lower()
        comment = "#".join(comment_split[1:]) if len(comment_split) > 1 else ""

        words = clean_line.split(",")
        for word_id, word in enumerate(words):
            word = word.strip()
            replacement = MASK_REPLACEMENTS.get(word, None)
            if replacement:
                tmp[i] = ", ".join(words[:word_id] + [replacement] + words[word_id + 1:]) \
                    + "#" + comment + "\n"
                return tmp

        return []

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
