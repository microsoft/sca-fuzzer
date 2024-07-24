"""
File: All kinds of postprocessing actions performed after a violation has been detected.
Currently, it's a stripped-down version of the main fuzzer, modified to find the minimal
set of inputs that reproduce the vulnerability and to minimize the test case.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import shutil
import os
import re
import abc
import tempfile
from math import log2

from copy import deepcopy
from subprocess import run
from typing import List, NamedTuple, Dict
from .interfaces import Input, TestCase, Minimizer, Fuzzer, InstructionSetAbstract, Violation
from .model import CTTracer
from .x86.x86_model import X86UnicornDEH, SANDBOX_CODE_SIZE
from .config import CONF
from .util import Logger

TMP_DIR = "/tmp/rvzr_minimize"


# ==================================================================================================
# Helper functions and classes
# ==================================================================================================
def get_test_case_from_instructions(fuzzer: Fuzzer,
                                    instructions: List[str],
                                    path: str = "") -> TestCase:
    """
    Create a test case object from a list of instructions.
    The test case is stored in a file at the given path.
    :param instructions: List of instructions
    :param path: Path to store the test case; if empty, a temporary file is created
    :return: Test case object
    """
    # create a temporary file if no path is given
    if not path:
        fp = tempfile.NamedTemporaryFile(dir=TMP_DIR, delete=False)
        path = fp.name
        fp.close()
    # print(path)

    # write the instructions to the file
    with open(path, "w+") as f:
        for line in instructions:
            f.write(line)
    tc = fuzzer.asm_parser.parse_file(path)
    return tc


def check_for_violation(fuzzer, test_case: TestCase, inputs: List[Input],
                        ignore_list: List[int]) -> bool:
    """
    Check if the test case triggers the violation.
    :param test_case: The test case to check
    :param inputs: List of inputs to use for verification
    :param ignore_list: List of input IDs to ignore
    :return: True if the violation is triggered, False otherwise
    """
    for _ in range(CONF.minimizer_retries):
        if fuzzer.fuzzing_round(test_case, inputs, ignore_list) is not None:
            return True
    return False


class ProgressPrinter():
    """
    A simple class to print progress in the terminal.
    Used to ensure that all minimization classes
    provide a uniform output.
    """
    line_width: int = 64
    curr_width: int = 0
    offset: int = 2
    pass_id: int = 0
    progress_bar_on: bool = False

    def pass_start(self, label: str, offset: int = 2):
        self.pass_id += 1
        self.offset = offset
        self.curr_width = 0
        self.progress_bar_on = False
        print(f"[PASS {self.pass_id}] {label}", flush=True)

    def pass_finish(self):
        print("")  # finish the line

    def pass_msg(self, msg: str):
        print(" " * self.offset + "> " + msg)
        self.progress_bar_on = False

    def next(self, success: bool):
        if not self.progress_bar_on:
            print("")
            self.progress_bar_on = True

        self.curr_width += 1
        if self.curr_width > self.line_width:
            print("\n", end="", flush=True)
            self.curr_width = self.offset

        if success:
            print(".", end="", flush=True)
        else:
            print("-", end="", flush=True)

    def global_msg(self, msg: str):
        print(f"[INFO] {msg}")


class PassDesc(NamedTuple):
    """ A named tuple to store the minimization pass description """
    cls_: type
    is_instruction_pass: bool
    is_input_pass: bool
    is_analysis_pass: bool


# ==================================================================================================
# Minimization Passes
# ==================================================================================================
class BaseInstructionMinimizationPass(abc.ABC):
    """
    Base class for a minimization pass that operates on instructions.
    """
    name: str = ""
    ignore_list: List[int]

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSetAbstract,
                 progress: ProgressPrinter):
        self.fuzzer = fuzzer
        self.instruction_set_spec = instruction_set_spec
        self.progress = progress
        self.ignore_list = []

    # ------------------------------------------------
    # Abstract interface
    @abc.abstractmethod
    def run(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        """ Main function that runs the minimization pass """
        pass

    @abc.abstractmethod
    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        """
        Modify the instruction at the given cursor according to
        the algorithm defined by subclass
        """
        pass

    @abc.abstractmethod
    def verify_modification(self, test_case: TestCase, inputs: List[Input]) -> bool:
        """
        Verify if the modification made to the test case is valid according to
        the algorithm defined by subclass
        """
        pass

    def set_ignore_list(self, ignore_list: List[int]):
        self.ignore_list = ignore_list

    def minimization_loop(self,
                          test_case: TestCase,
                          inputs: List[Input],
                          skip_instrumentation_lines: bool = True) -> List[int]:
        """
        Standard minimization loop that iteratively applies the modification
        algorithm (modify_instruction) to each line of the test case and checks if the resulting
        test case still passes the verification function (verify_modification).

        :param test_case: The test case object to minimize
        :param inputs: List of inputs to use for verification
        :param skip_instrumentation_lines: If True, skip lines with the `instrumentation` comment
        :return List of instruction IDs that passed the verification
        """

        def line_is_skipped(line: str) -> bool:
            # We skip lines that meet the following criteria:
            is_skipped = (line == "")  # empty line
            is_skipped |= (line[0] == "#")  # comment
            is_skipped |= ("lfence" in line)  # fences
            is_skipped |= ('.' == line[0])  # labels
            is_skipped |= ('noremove' in line)  # explicitly marked as non-removable
            is_skipped |= (skip_instrumentation_lines and 'instrumentation' in line)
            return is_skipped

        # get all lines of the test case
        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()

        # Iterate over all instructions, backwards, and collect a list of instructions that
        # can be modified while still passing the verification
        cursor = len(instructions)
        modifiable_ids = []
        while True:
            cursor -= 1
            line = instructions[cursor].strip().lower()
            # Check if we are done
            if cursor == 0 or line == ".test_case_enter:":
                break

            # Leave certain lines untouched
            if line_is_skipped(line):
                continue

            # Create a modified test case
            modified_instructions = self.modify_instruction(instructions, cursor)
            if not modified_instructions:  # skip line if the modification failed
                self.progress.next(False)
                continue

            # Create a test case object from the modified instructions
            tmp_test_case = get_test_case_from_instructions(self.fuzzer, modified_instructions)

            # Verify modification and update the list of modifiable instructions
            check_passed = self.verify_modification(tmp_test_case, inputs)
            if check_passed:
                self.progress.next(True)
                instructions = modified_instructions
                modifiable_ids.append(cursor)
            else:
                self.progress.next(False)

        return modifiable_ids


class BaseInputMinimizationPass(abc.ABC):
    """
    Base class for a minimization pass that operates on inputs.
    """
    ignore_list: List[int]

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSetAbstract,
                 progress: ProgressPrinter):
        self.fuzzer = fuzzer
        self.instruction_set_spec = instruction_set_spec
        self.progress = progress
        self.ignore_list = []

    @abc.abstractmethod
    def run(self, test_case: TestCase, org_inputs: List[Input],
            org_violation: Violation) -> List[Input]:
        """ Main function that runs the minimization pass
        :param test_case: The test case object to work on
        :param org_inputs: List of inputs to minimize
        :param org_violation: The original violation
        :return: List of minimized inputs
        """
        pass

    def set_ignore_list(self, ignore_list: List[int]):
        self.ignore_list = ignore_list


# ==================================================================================================
# Concrete implementations of minimization passes
# ==================================================================================================
class InstructionRemovalPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively removes instructions from the test case
    (one at a time, starting from the end) and checks if the violation is still triggered.
    """
    name = "Instruction Removal Pass"

    def run(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        modifiable_ids = self.minimization_loop(test_case, inputs)
        self.progress.pass_finish()

        instructions: List[str] = []
        with open(test_case.asm_path, "r") as f:
            for i, line in enumerate(f):
                if i in modifiable_ids:
                    # This instruction could be removed.
                    # Additionally, clear the instrumentation tag from the previous line
                    if "instrumentation" in instructions[-1].lower():
                        instructions[-1] = instructions[-1].replace("instrumentation", "")
                else:
                    # This instruction is essential for the violation; keep it
                    instructions.append(line)

        return get_test_case_from_instructions(self.fuzzer, instructions)

    def modify_instruction(self, instructions: List[str], i: int) -> List[str]:
        return instructions[:i] + instructions[i + 1:]

    def verify_modification(self, test_case: TestCase, inputs: List[Input]) -> bool:
        return check_for_violation(self.fuzzer, test_case, inputs, self.ignore_list)


class InstructionSimplificationPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively replaces instructions with simpler ones
    (e.g., `cmov` with `mov`, `add` with `mov`, etc.) and checks
    if the violation is still triggered.
    """
    name = "Instruction Simplification Pass"

    instruction_replacements = {
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

    def run(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        inst_ids = self.minimization_loop(test_case, inputs)
        self.progress.pass_finish()

        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = self.modify_instruction(instructions, i)
        return get_test_case_from_instructions(self.fuzzer, instructions)

    def modify_instruction(self, instructions: List[str], i: int) -> List[str]:
        tmp = list(instructions)  # make a copy
        clean_line = tmp[i].strip().lower()
        words = clean_line.split(" ")
        key = words[0]
        replacement_func = self.instruction_replacements.get(key, None)
        if not replacement_func:
            return []
        tmp[i] = " ".join([replacement_func(clean_line)] + words[1:]) + "\n"

        return tmp

    def verify_modification(self, test_case: TestCase, inputs: List[Input]) -> bool:
        return check_for_violation(self.fuzzer, test_case, inputs, self.ignore_list)


class ConstantSimplificationPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively replaces constants in the test case with zeros
    and checks if the violation is still triggered.
    """
    name = "Constant Simplification Pass"

    def run(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        inst_ids = self.minimization_loop(test_case, inputs)
        self.progress.pass_finish()

        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = self.modify_instruction(instructions, i)
        return get_test_case_from_instructions(self.fuzzer, instructions)

    def modify_instruction(self, instructions: List[str], i: int) -> List[str]:
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

    def verify_modification(self, test_case: TestCase, inputs: List[Input]) -> bool:
        return check_for_violation(self.fuzzer, test_case, inputs, self.ignore_list)


class MaskSimplificationPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively replaces masks of the instrumentation
    instructions with smaller masks and checks if the violation is still triggered.
    E.g., `and rax, 0b1111111111111` -> `and rax, 0b1111111111110`
    """
    name = "Mask Simplification Pass"

    mask_replacements = {
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

    def run(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        inst_ids = self.minimization_loop(test_case, inputs, skip_instrumentation_lines=False)
        self.progress.pass_finish()

        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = self.modify_instruction(instructions, i)
        return get_test_case_from_instructions(self.fuzzer, instructions)

    def modify_instruction(self, instructions: List[str], i: int) -> List[str]:
        tmp = list(instructions)  # make a copy

        comment_split = tmp[i].split("#")
        clean_line = comment_split[0].strip().lower()
        comment = "#".join(comment_split[1:]) if len(comment_split) > 1 else ""

        words = clean_line.split(",")
        for word_id, word in enumerate(words):
            word = word.strip()
            replacement = self.mask_replacements.get(word, None)
            if replacement:
                tmp[i] = ", ".join(words[:word_id] + [replacement] + words[word_id + 1:]) \
                    + " #" + comment
                return tmp

        return []

    def verify_modification(self, test_case: TestCase, inputs: List[Input]) -> bool:
        return check_for_violation(self.fuzzer, test_case, inputs, self.ignore_list)


class NopReplacementPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively replaces instructions with NOPs
    of the same size and checks if the violation is still triggered.
    """
    name = "NOP Replacement Pass"

    replacements = {
        1: "nop  # 1 B",
        2: ".byte 0x66, 0x90  # 2 B",
        3: "nop dword ptr [rax]  # 3 B",
        4: "nop qword ptr [rax]  # 4 B",
        5: "nop qword ptr [rax + 1]  # 5 B",
        6: "nop qword ptr [rax + rax + 1]  # 6 B",
        7: "nop dword ptr [rax + 0xff]  # 7 B",
        8: "nop qword ptr [rax + 0xff]  # 8 B",
        9: "nop qword ptr [rax + rax + 0xff]  # 9 B",
    }

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSetAbstract,
                 progress: ProgressPrinter):
        super().__init__(fuzzer, instruction_set_spec, progress)
        self.LOG = Logger()

    def run(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        modified_ids = self.minimization_loop(test_case, inputs, skip_instrumentation_lines=True)
        self.progress.pass_finish()

        with open(test_case.asm_path, "r") as f:
            lines = f.readlines()

        instructions = []
        for i, line in enumerate(lines):
            # skip non-modifiable lines
            if i not in modified_ids:
                instructions.append(line)
                continue

            # get the NOP replacement
            replacement = self.modify_instruction([line], 0)
            if not replacement:
                self.LOG.warning("postprocessor", f"Inconsistent NOP output: {line}")
                instructions.append(line)
                continue

            # This instruction could be replaced with a NOP
            instructions.append(replacement[0])

            # And the instrumentation tag from the previous line can be cleared
            if "instrumentation" in instructions[-2].lower():
                instructions[-2] = instructions[-2].replace("instrumentation", "")

        return get_test_case_from_instructions(self.fuzzer, instructions)

    def modify_instruction(self, instructions: List[str], i: int) -> List[str]:
        tmp = list(instructions)  # make a copy

        line = tmp[i].strip().lower()
        if "nop" in line:
            return []

        # skip jumps as replacing them with nops will confuse our assembly parser
        if line.startswith("j") or line.startswith("loop"):
            return []

        # determine the instruction size
        with open("tmp.asm", "w") as f:
            f.write(".intel_syntax noprefix\n")
            f.write(line)
            f.write("\n")
        run("as tmp.asm -o tmp.o", shell=True, check=True)
        run("objcopy -O binary --only-section=.text tmp.o tmp.o", shell=True, check=True)
        size = os.path.getsize("tmp.o")
        os.remove("tmp.asm")
        os.remove("tmp.o")

        if size not in self.replacements:
            return []

        tmp[i] = self.replacements[size] + "\n"
        return tmp

    def verify_modification(self, test_case: TestCase, inputs: List[Input]) -> bool:
        return check_for_violation(self.fuzzer, test_case, inputs, self.ignore_list)


class LabelRemovalPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively removes unused labels from the test case.
    Note that no verification is performed in this pass as labels are not executed.
    """
    name = "Label Removal Pass"

    def run(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()

        for i in range(len(instructions)):
            line = instructions[i].strip().lower()

            # skip non-labels
            if not line.startswith("."):
                self.progress.next(False)
                continue

            # skip reserved labels
            if ".test_case_enter:" in line or \
               ".test_case_exit:" in line or \
               ".section" in line or \
               ".function" in line or \
               ".macro" in line or \
               "syntax" in line:
                continue

            # check if the label is used by other instructions
            label = instructions[i].strip().replace(":", "")
            used = False
            for inst in instructions:
                if label in inst and inst != instructions[i]:
                    used = True
                    break

            # remove unused labels
            if not used:
                self.progress.next(True)
                instructions[i] = ""
            else:
                self.progress.next(False)

        self.progress.pass_finish()
        return get_test_case_from_instructions(self.fuzzer, instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        return []  # unused

    def verify_modification(self, test_case: TestCase, inputs: List[Input]) -> bool:
        return True  # unused


class FenceInsertionPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively inserts LFENCE instructions before each instruction
    and checks if the violation is still triggered.
    """
    name = "Fence Insertion Pass"

    def run(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        inst_ids = self.minimization_loop(test_case, inputs)
        self.progress.pass_finish()

        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = instructions[:i] + ["lfence\n"] + instructions[i:]
        return get_test_case_from_instructions(self.fuzzer, instructions)

    def modify_instruction(self, instructions: List[str], i: int) -> List[str]:
        curr_instr = instructions[i].lower()
        if curr_instr[0] == "j" or curr_instr[0:3] == "loop":
            return []  # skip control-flow instructions - their target is already fenced
        return instructions[:i] + ["lfence\n"] + instructions[i:]

    def verify_modification(self, test_case: TestCase, inputs: List[Input]) -> bool:
        return check_for_violation(self.fuzzer, test_case, inputs, self.ignore_list)


class FindSpecSourcePass(BaseInstructionMinimizationPass):
    """
    An analysis pass that iterates over the test case and identifies instructions
    that could be the source of speculation.
    """
    name = "Speculation Source Identification"

    def run(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        inst_ids = self.minimization_loop(test_case, inputs, skip_instrumentation_lines=False)
        self.progress.pass_finish()

        with open(test_case.asm_path, "r") as f:
            instructions = f.readlines()
        if not inst_ids:
            self.progress.pass_msg("No speculation source found")

        for i in inst_ids:
            if "# " in instructions[i]:
                if "speculation source" not in instructions[i]:
                    instructions[i] = instructions[i][:-1] + ", speculation source ?\n"
            else:
                instructions[i] = instructions[i][:-1] + "  # speculation source ?\n"
        return get_test_case_from_instructions(self.fuzzer, instructions)

    def modify_instruction(self, instructions: List[str], i: int) -> List[str]:
        return instructions[:i] + instructions[i + 1:]

    def verify_modification(self, test_case: TestCase, inputs: List[Input]) -> bool:
        global CONF
        sf = CONF.enable_speculation_filter
        of = CONF.enable_observation_filter
        CONF.enable_speculation_filter = True
        CONF.enable_observation_filter = False
        res = self.fuzzer.filter(test_case, inputs)
        CONF.enable_speculation_filter = sf
        CONF.enable_observation_filter = of
        return res


class AddViolationCommentsPass(BaseInstructionMinimizationPass):
    """
    An instrumentation pass that iterates over the test case and adds comments
    with the memory addresses of the loads and stores that caused the violation.
    """
    name = "Violation Comment Insertion"
    violation: Violation

    def set_violation(self, violation: Violation):
        self.violation = violation

    def run(self, test_case: TestCase, inputs: List[Input]) -> TestCase:
        # reproduce the violation to get violating input IDs
        v_inputs = [m.input_ for m in self.violation.measurements[:2]]
        v_input_ids = [m.input_id for m in self.violation.measurements[:2]]

        # create a model that will collect PC and memory traces
        sandbox_base, code_base = 0x2000000, 0x1000000
        model = X86UnicornDEH(sandbox_base, code_base, CTTracer())

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

    def modify_instruction(self, _: List[str], __: int) -> List[str]:
        return []  # unused

    def verify_modification(self, _: TestCase, __: List[Input]) -> bool:
        return True  # unused


class InputSequenceMinimizationPass(BaseInputMinimizationPass):
    """
    A minimization pass that iteratively removes inputs from the violating the input sequence
    and checks if the violation is still triggered.
    """
    name = "Input Sequence Minimization"

    def run(self, test_case: TestCase, org_inputs: List[Input],
            org_violation: Violation) -> List[Input]:
        self.progress.pass_msg("Reducing the number of inputs by halving")
        org_len = len(org_inputs)

        violation = org_violation
        nonboosted_inputs = org_inputs
        while len(nonboosted_inputs) > 5:
            new_inputs = nonboosted_inputs[:len(nonboosted_inputs) // 2]
            new_violation = self.fuzzer.fuzzing_round(test_case, new_inputs)
            if not new_violation:
                break
            nonboosted_inputs = new_inputs
            violation = new_violation

        if len(nonboosted_inputs) < org_len:
            self.progress.pass_msg(f"Result: Reduced to {len(nonboosted_inputs)} inputs")
        else:
            self.progress.pass_msg("Result: Could not reduce the number of inputs")

        # Get boosted inputs and disable boosting from now on
        inputs = violation.input_sequence
        org_ipc = CONF.inputs_per_class
        CONF.inputs_per_class = 1  # disable boosting from now on

        n_iterations = 10
        self.progress.pass_msg("Reducing the input sequence iteratively")
        for iteration in range(n_iterations):
            self.progress.pass_msg(f"Iteration {iteration + 1}")
            org_len = len(inputs)
            for input_id in range(org_len, 0, -1):
                new_inputs = inputs[0:input_id] + inputs[input_id + 1:]
                new_violation = self.fuzzer.fuzzing_round(test_case, inputs)
                if not new_violation:
                    self.progress.next(False)
                    continue
                self.progress.next(True)
                inputs = new_inputs
                violation = new_violation
            self.progress.pass_finish()
            if len(inputs) == org_len:
                break
        self.progress.pass_msg(f"Result: Reduced to {len(inputs)} inputs")
        CONF.inputs_per_class = org_ipc
        return violation.input_sequence


class DifferentialInputMinimizerPass(BaseInputMinimizationPass):
    """
    A minimization pass that iteratively minimizes the difference between two violating inputs.
    It tries to zero out blocks of decreasing size and checks if the violation is still triggered.
    If this is not possible, it tries to copy the byte between the two inputs.
    """
    name = "Differential Input Minimizer"

    def run(self, test_case: TestCase, _: List[Input], violation: Violation) -> List[Input]:
        inputs = violation.input_sequence

        # Disable boosting for this pass as we already operate on the boosted inputs
        org_conf = (CONF.inputs_per_class,)
        CONF.inputs_per_class = 1

        # Determine the violating input IDs
        violating_input_ids = [i.input_id for i in violation.measurements]
        if len(violating_input_ids) > 2:
            violating_input_ids = violating_input_ids[:2]

        # Set the non-violating inputs as the ignore list; do it locally to avoid side effects
        local_ignore_list = [
            i for i in range(len(violation.input_sequence)) if i not in violating_input_ids
        ]

        # make a copy of the inputs
        input_a = inputs[violating_input_ids[0]]
        input_b = inputs[violating_input_ids[1]]
        input_a_org = deepcopy(input_a)
        input_b_org = deepcopy(input_b)
        input_a.data_size

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
                        if check_for_violation(self.fuzzer, test_case, inputs, local_ignore_list):
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
                    if check_for_violation(self.fuzzer, test_case, inputs, local_ignore_list):
                        print(".", end="", flush=True)
                        continue

                    # try copying the byte between the two inputs
                    input_a[actor_id][region_name][i] = input_a_org[actor_id][region_name][i]
                    input_b[actor_id][region_name][i] = input_a_org[actor_id][region_name][i]
                    if check_for_violation(self.fuzzer, test_case, inputs, local_ignore_list):
                        print("+", end="", flush=True)
                        continue

                    # if failing, restore the original value
                    print("^", end="", flush=True)
                    leaked.append(absolute_address)
                    input_a[actor_id][region_name][i] = input_a_org[actor_id][region_name][i]
                    input_b[actor_id][region_name][i] = input_b_org[actor_id][region_name][i]

                region_offset += region_size * 8
        print("")

        self.progress.pass_msg(f"Result: Leaked {len(leaked)} bytes")
        self.progress.pass_msg(f"Addresses: {[hex(x) for x in leaked]}")

        CONF.inputs_per_class = org_conf[0]
        return inputs


# ==================================================================================================
# High-level minimization algorithm
# ==================================================================================================
class MainMinimizer(Minimizer):
    """
    Main class for the postprocessing module. It selects the appropriate minimization passes
    based on the command-line arguments, and then runs them.
    """

    ignore_list: List[int]
    """ List of input IDs that will be ignored during minimization """

    pass_map: Dict[str, PassDesc]
    """ Mapping of pass names to their classes """

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSetAbstract):
        self.fuzzer = fuzzer
        self.fuzzer.initialize_modules()
        self.LOG = Logger()
        self.progress = ProgressPrinter()
        self.instruction_set_spec = instruction_set_spec
        self.LOG.info = False
        self.ignore_list = []

        # manage tmp directory
        if not os.path.exists(TMP_DIR):
            os.makedirs(TMP_DIR)

        # initialize the pass map
        self.pass_map = {
            "instruction_pass": PassDesc(InstructionRemovalPass, True, False, False),
            "simplification_pass": PassDesc(InstructionSimplificationPass, True, False, False),
            "nop_pass": PassDesc(NopReplacementPass, True, False, False),
            "constant_pass": PassDesc(ConstantSimplificationPass, True, False, False),
            "mask_pass": PassDesc(MaskSimplificationPass, True, False, False),
            "label_pass": PassDesc(LabelRemovalPass, False, False, False),
            "fence_pass": PassDesc(FenceInsertionPass, False, False, True),
            "input_seq_pass": PassDesc(InputSequenceMinimizationPass, False, True, False),
            "input_diff_pass": PassDesc(DifferentialInputMinimizerPass, False, True, False),
            "source_analysis": PassDesc(FindSpecSourcePass, False, False, True),
            "comment_pass": PassDesc(AddViolationCommentsPass, False, False, True),
        }

    def __del__(self):
        # remove tmp directory
        if os.path.exists(TMP_DIR):
            shutil.rmtree(TMP_DIR)

    def run(self, test_case_asm: str, n_inputs: int, test_case_outfile: str, input_outdir: str,
            n_attempts: int, **enabled_passes):
        """
        Run the minimization passes based on the command-line arguments, passed as arguments
        to this function. It first reproduces the violation, then run input passes,
        then instruction passes, and finally the analysis passes. The resulting minimized program
        is stored into `test_case_outfile` and the resulting minimized input sequence is stored
        into `input_outdir`.

        :param test_case_asm: Path to the test case assembly file
        :param n_inputs: Number of inputs to use during the minimization
        :param test_case_outfile: Path to store the minimized test case
        :param input_outdir: Path to store the minimized inputs
        :param n_attempts: Number of attempts to run the instruction minimization passes
        :param enabled_passes: Dictionary of arguments to enable/disable the passes.
               Supported keys:
               - enable_instruction_pass
               - enable_simplification_pass
               - enable_nop_pass
               - enable_constant_pass
               - enable_mask_pass
               - enable_label_pass
               - enable_fence_pass
               - enable_input_seq_pass
               - enable_input_diff_pass
               - enable_source_analysis
               - enable_comment_pass
        :return: None
        """

        # Check arguments
        assert CONF.instruction_set == "x86-64", "Postprocessor supports only x86-64 so far"

        # Reset the ignore list
        self.ignore_list = []

        # Adjust the sample size to reduce non-reproducibility
        CONF.executor_sample_sizes = [CONF.executor_sample_sizes[-1]]

        # Parse the test case and inputs
        test_case: TestCase = self.fuzzer.asm_parser.parse_file(test_case_asm)
        self.fuzzer.input_gen.n_actors = len(test_case.actors)
        inputs: List[Input] = self.fuzzer.input_gen.generate(n_inputs)

        # Check if the violation can be reproduced
        self.progress.pass_start("Reproducing the violation")
        for _ in range(CONF.minimizer_retries):
            violation = self.fuzzer.fuzzing_round(test_case, inputs)
            if violation:
                self.progress.pass_msg("Violation reproduced. Proceeding with minimization")
                break
        else:
            self.progress.pass_msg("Could not reproduce the violation. Exiting")
            return

        # Get lists of enabled passes
        passes: List[PassDesc] = \
            [v for k, v in self.pass_map.items() if enabled_passes.get(f"enable_{k}", False)]
        input_passes = [p.cls_ for p in passes if p.is_input_pass]
        program_passes = [p.cls_ for p in passes if p.is_instruction_pass]
        analysis_passes = [p.cls_ for p in passes if p.is_analysis_pass]

        # Run the input minimization passes
        if input_passes:
            inputs = self._run_input_passes(test_case, inputs, violation, input_outdir,
                                            input_passes)

            # Disable boosting from now on: The minimized input sequence is guaranteed to be boosted
            CONF.inputs_per_class = 1

            # Since the input sequence have changed, we need to recreate the violation
            violation = self.fuzzer.fuzzing_round(test_case, inputs)
            if not violation:
                self.LOG.error("Non-reproducible input sequence minimization. Exiting")

        # Set the non-violating inputs as the ignore list
        violating_ids = [m.input_id for m in violation.measurements]
        self.ignore_list = \
            [i for i in range(len(violation.input_sequence)) if i not in violating_ids]
        self.progress.pass_msg(f"Violating input IDs: {violating_ids}")

        # Run the instruction minimization passes
        for attempt in range(n_attempts):
            self.progress.global_msg(f"Minimization attempt {attempt + 1}/{n_attempts}")
            old_tc = deepcopy(test_case)
            test_case = self._run_instruction_passes(program_passes, test_case, inputs, violation,
                                                     test_case_outfile)
            if test_case == old_tc:  # break if no progress was made
                break

        # Run the analysis passes
        test_case = self._run_instruction_passes(analysis_passes, test_case, inputs, violation,
                                                 test_case_outfile)

        # Get rid of unused labels
        if enabled_passes.get("enable_label_pass", False):
            test_case = self._run_instruction_passes([LabelRemovalPass], test_case, inputs,
                                                     violation, test_case_outfile)

        # Store the results
        self.progress.pass_start("Storing the results")
        shutil.copy(test_case.asm_path, test_case_outfile)

    def _run_input_passes(self, test_case: TestCase, inputs: List[Input],
                          org_violation: Violation, outdir: str,
                          passes: List) -> List[Input]:
        violation = org_violation

        for pass_cls in passes:
            # Create the pass object
            pass_ = pass_cls(self.fuzzer, self.instruction_set_spec, self.progress)
            self.progress.pass_start(pass_.name)

            # Run the pass
            new_inputs = pass_.run(test_case, inputs, violation)

            # If new input sequence was produced, recreate the violation
            if new_inputs != inputs:
                new_violation = self.fuzzer.fuzzing_round(test_case, new_inputs)
                if new_violation:
                    violation = new_violation
                    inputs = new_inputs
                else:
                    self.progress.pass_msg("[WARNING] Non-reproducible sequence minimization"
                                           ". Rolling back to the previous state")

        # Create the output directory, if not already exists
        if outdir and not os.path.exists(outdir):
            try:
                os.makedirs(outdir)
            except OSError:
                self.LOG.error(f"Creation of the directory {outdir} failed")
            outdir = os.path.abspath(outdir)

        # Store the results
        self.progress.pass_msg(f"Saving new inputs in '{outdir}'")
        for i in range(len(inputs)):
            inputs[i].save(f"{outdir}/min_input_{i:04}.bin")

        return inputs

    def _run_instruction_passes(self, passes: List, test_case: TestCase, inputs: List[Input],
                                org_violation: Violation, outfile: str) -> TestCase:
        # create pass objects
        pass_objs = [c(self.fuzzer, self.instruction_set_spec, self.progress) for c in passes]
        for pass_obj in pass_objs:
            pass_obj.set_ignore_list(self.ignore_list)
            if getattr(pass_obj, 'set_violation', None):
                pass_obj.set_violation(org_violation)

        # run passes
        for pass_obj in pass_objs:
            self.progress.pass_start(pass_obj.name)
            test_case = pass_obj.run(test_case, inputs)
            shutil.copy(test_case.asm_path, outfile)

        return test_case
