""" File: Collection of minimization passes that operate on instructions
    (i.e., simplify test case code).

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import abc
import os
import re
from subprocess import run
from typing import TYPE_CHECKING, List, Dict, Callable

from .pass_abc import BaseMinimizationPass
from ..logs import warning

if TYPE_CHECKING:
    from ..traces import Violation
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_data import InputData


class BaseInstructionMinimizationPass(BaseMinimizationPass):
    """
    Base class for a minimization pass that operates on instructions.
    """
    name: str = ""
    ignore_list: List[int]

    # ------------------------------------------------
    # Abstract interface
    @abc.abstractmethod
    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        """ Main function that runs the minimization pass """

    @abc.abstractmethod
    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        """
        Modify the instruction at the given cursor according to
        the algorithm defined by subclass
        """

    @abc.abstractmethod
    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        """
        Verify if the modification made to the test case is valid according to
        the algorithm defined by subclass
        """

    def minimization_loop(self,
                          test_case: TestCaseProgram,
                          inputs: List[InputData],
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
            if not line:
                return True
            # We skip lines that meet the following criteria:
            is_skipped = line == ""  # empty line
            is_skipped |= (line[0] == "#")  # comment
            is_skipped |= ("lfence" in line)  # fences
            is_skipped |= ('.' == line[0])  # labels
            is_skipped |= ('noremove' in line)  # explicitly marked as non-removable
            is_skipped |= (skip_instrumentation_lines and 'instrumentation' in line)
            return is_skipped

        # get all lines of the test case
        with open(test_case.asm_path(), "r") as f:
            instructions = f.readlines()

        # Iterate over all instructions, backwards, and collect a list of instructions that
        # can be modified while still passing the verification
        cursor = len(instructions)
        modifiable_ids = []
        while True:
            cursor -= 1
            line = instructions[cursor].strip().lower()
            # Check if we are done
            if cursor == 0:
                break

            # Leave certain lines untouched
            if line_is_skipped(line):
                continue

            # Create a modified test case
            modified_instructions = self.modify_instruction(instructions, cursor)
            if not modified_instructions:  # skip line if the modification failed
                self._progress.next(False)
                continue

            # Create a test case object from the modified instructions
            tmp_test_case = self._get_test_case_from_instructions(modified_instructions)

            # Verify modification and update the list of modifiable instructions
            check_passed = self.verify_modification(tmp_test_case, inputs)
            if check_passed:
                self._progress.next(True)
                instructions = modified_instructions
                modifiable_ids.append(cursor)
            else:
                self._progress.next(False)

        return modifiable_ids

    def set_violation(self, violation: Violation) -> None:
        """ Set the violation that is being minimized """


class InstructionRemovalPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively removes instructions from the test case
    (one at a time, starting from the end) and checks if the violation is still triggered.
    """
    name = "Instruction Removal Pass"

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        modifiable_ids = self.minimization_loop(test_case, inputs)
        self._progress.pass_finish()

        instructions: List[str] = []
        with open(test_case.asm_path(), "r") as f:
            for i, line in enumerate(f):
                if i in modifiable_ids:
                    # This instruction could be removed.
                    # Additionally, clear the instrumentation tag from the previous line
                    if "instrumentation" in instructions[-1].lower():
                        instructions[-1] = instructions[-1].replace("instrumentation", "")
                else:
                    # This instruction is essential for the violation; keep it
                    instructions.append(line)

        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        return instructions[:cursor] + instructions[cursor + 1:]

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        return self._check_for_violation(test_case, inputs, self.ignore_list)


class InstructionSimplificationPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively replaces instructions with simpler ones
    (e.g., `cmov` with `mov`, `add` with `mov`, etc.) and checks
    if the violation is still triggered.
    """
    name = "Instruction Simplification Pass"

    _instruction_replacements: Dict[str, Callable[[str], str]] = {
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

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        inst_ids = self.minimization_loop(test_case, inputs)
        self._progress.pass_finish()

        with open(test_case.asm_path(), "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = self.modify_instruction(instructions, i)
        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        tmp = list(instructions)  # make a copy
        clean_line = tmp[cursor].strip().lower()
        words = clean_line.split(" ")
        key = words[0]
        replacement_func = self._instruction_replacements.get(key, None)
        if not replacement_func:
            return []
        tmp[cursor] = " ".join([replacement_func(clean_line)] + words[1:]) + "\n"

        return tmp

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        return self._check_for_violation(test_case, inputs, self.ignore_list)


class ConstantSimplificationPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively replaces constants in the test case with zeros
    and checks if the violation is still triggered.
    """
    name = "Constant Simplification Pass"

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        inst_ids = self.minimization_loop(test_case, inputs)
        self._progress.pass_finish()

        with open(test_case.asm_path(), "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = self.modify_instruction(instructions, i)
        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        tmp = list(instructions)  # make a copy
        clean_line = tmp[cursor].strip().lower()
        words = clean_line.split(",")
        for word_id, word in enumerate(words):
            word = word.strip()
            if word == "0":  # already replaced
                break
            if re.match(r"^-?[0-9]+$", word) or re.match(r"^-?0x[0-9a-f]+$", word) \
               or re.match(r"^-?0b[01]+$", word):
                tmp[cursor] = ", ".join(words[:word_id] + ["0"] + words[word_id + 1:]) + "\n"
                return tmp
        return []

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        return self._check_for_violation(test_case, inputs, self.ignore_list)


class MaskSimplificationPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively replaces masks of the instrumentation
    instructions with smaller masks and checks if the violation is still triggered.
    E.g., `and rax, 0b1111111111111` -> `and rax, 0b1111111111110`
    """
    name = "Mask Simplification Pass"

    _mask_replacements = {
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

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        inst_ids = self.minimization_loop(test_case, inputs, skip_instrumentation_lines=False)
        self._progress.pass_finish()

        with open(test_case.asm_path(), "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = self.modify_instruction(instructions, i)
        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        tmp = list(instructions)  # make a copy

        comment_split = tmp[cursor].split("#")
        clean_line = comment_split[0].strip().lower()
        comment = "#".join(comment_split[1:]) if len(comment_split) > 1 else ""

        words = clean_line.split(",")
        for word_id, word in enumerate(words):
            word = word.strip()
            replacement = self._mask_replacements.get(word, None)
            if replacement:
                tmp[cursor] = ", ".join(words[:word_id] + [replacement] + words[word_id + 1:]) \
                    + " #" + comment
                return tmp

        return []

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        return self._check_for_violation(test_case, inputs, self.ignore_list)


class NopReplacementPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively replaces instructions with NOPs
    of the same size and checks if the violation is still triggered.
    """
    name = "NOP Replacement Pass"

    _replacements = {
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

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        modified_ids = self.minimization_loop(test_case, inputs, skip_instrumentation_lines=True)
        self._progress.pass_finish()

        with open(test_case.asm_path(), "r") as f:
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
                warning("postprocessor", f"Inconsistent NOP output: {line}")
                instructions.append(line)
                continue

            # This instruction could be replaced with a NOP
            instructions.append(replacement[0])

            # And the instrumentation tag from the previous line can be cleared
            if "instrumentation" in instructions[-2].lower():
                instructions[-2] = instructions[-2].replace("instrumentation", "")

        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        tmp = list(instructions)  # make a copy

        line = tmp[cursor].strip().lower()
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

        if size not in self._replacements:
            return []

        tmp[cursor] = self._replacements[size] + "\n"
        return tmp

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        return self._check_for_violation(test_case, inputs, self.ignore_list)


class LabelRemovalPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively removes unused labels from the test case.
    Note that no verification is performed in this pass as labels are not executed.
    """
    name = "Label Removal Pass"
    _reserved = [
        ".intel_syntax noprefix", ".test_case_exit:", ".section", ".function", ".macro", "syntax"
    ]

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        with open(test_case.asm_path(), "r") as f:
            instructions = f.readlines()
            n_instructions = len(instructions)

        for i in range(n_instructions):
            line = instructions[i].strip().lower()

            # skip non-labels
            if not line.startswith("."):
                self._progress.next(False)
                continue

            # skip reserved labels
            if any(reserved in line for reserved in self._reserved):
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
                self._progress.next(True)
                instructions[i] = ""
            else:
                self._progress.next(False)

        self._progress.pass_finish()
        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        return []  # unused

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        return True  # unused


class FenceInsertionPass(BaseInstructionMinimizationPass):
    """
    A minimization pass that iteratively inserts LFENCE instructions before each instruction
    and checks if the violation is still triggered.
    """
    name = "Fence Insertion Pass"

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        inst_ids = self.minimization_loop(test_case, inputs)
        self._progress.pass_finish()

        with open(test_case.asm_path(), "r") as f:
            instructions = f.readlines()
        for i in inst_ids:
            instructions = instructions[:i] + ["lfence\n"] + instructions[i:]
        return self._get_test_case_from_instructions(instructions)

    def modify_instruction(self, instructions: List[str], cursor: int) -> List[str]:
        curr_instr = instructions[cursor].lower()
        if curr_instr[0] == "j" or curr_instr[0:3] == "loop":
            return []  # skip control-flow instructions - their target is already fenced
        return instructions[:cursor] + ["lfence\n"] + instructions[cursor:]

    def verify_modification(self, test_case: TestCaseProgram, inputs: List[InputData]) -> bool:
        return self._check_for_violation(test_case, inputs, self.ignore_list)
