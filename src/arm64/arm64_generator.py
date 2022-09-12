"""
File:

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import abc
import math
import re

from subprocess import run, CalledProcessError
from typing import Dict, List

from isa_loader import InstructionSet
from interfaces import TestCase, Operand, RegisterOperand, MemoryOperand, LabelOperand, \
    ImmediateOperand, AgenOperand, CondOperand, Instruction, BasicBlock, InstructionSpec, OT
from generator import ConfigurableGenerator, RandomGenerator, Pass, \
    Printer, GeneratorException, AsmParserException, parser_assert
from config import CONF

from arm64.arm64_target_desc import ARMTargetDesc


class ARMGenerator(ConfigurableGenerator, abc.ABC):

    def __init__(self, instruction_set: InstructionSet):
        super(ARMGenerator, self).__init__(instruction_set)
        self.passes = [
            ARMSandboxPass(),
        ]
        self.printer = ARMPrinter()
        self.target_desc = ARMTargetDesc()
        self.re_tokenize = re.compile(r"^([^ .]+\.?)([^ ]+)? ([^ ,]+)(,[^ ,]+)?(,[^ ,]+)?( //.*)?")

    def map_addresses(self, test_case: TestCase, bin_file: str) -> None:
        # get a list of relative instruction addresses
        dump = run(
            f"aarch64-linux-gnu-objdump -D -b binary -m aarch64 {bin_file} "
            "| awk '/ [0-9a-f]+:/{print $1}'",
            shell=True,
            check=True,
            capture_output=True)
        address_list = [int(addr[:-1], 16) for addr in dump.stdout.decode().split("\n") if addr]

        # connect them with instructions in the test case
        address_map: Dict[int, Instruction] = {}
        counter = test_case.num_prologue_instructions
        for func in test_case.functions:
            for bb in func:
                for inst in list(bb) + bb.terminators:
                    address = address_list[counter]
                    address_map[address] = inst
                    counter += 1

        # map prologue and epilogue to dummy instructions
        for address in address_list:
            if address not in address_map:
                address_map[address] = Instruction("UNMAPPED", True)

        test_case.address_map = address_map

    def get_return_instruction(self) -> Instruction:
        return Instruction("RET", False, "general", True)

    def get_unconditional_jump_instruction(self) -> Instruction:
        return Instruction("B", False, "general", True)

    @staticmethod
    def assemble(asm_file: str, bin_file: str) -> None:
        """Assemble the test case into a stripped binary"""
        try:
            run(f"aarch64-linux-gnu-as {asm_file} -o {bin_file}",
                shell=True,
                check=True,
                capture_output=True)
        except CalledProcessError as e:
            error_msg = e.stderr.decode()
            if "Assembler messages:" not in error_msg:
                print(error_msg)
                raise e

            for msg in error_msg.split("\n"):
                msg = msg.removeprefix(asm_file + ":")
                print(msg)
            raise e

        run(f"aarch64-linux-gnu-strip --remove-section=.note.gnu.property {bin_file}",
            shell=True,
            check=True)
        run(f"aarch64-linux-gnu-objcopy {bin_file} -O binary {bin_file}", shell=True, check=True)



class ARMSandboxPass(Pass):

    def __init__(self):
        super().__init__()
        input_memory_size = CONF.input_main_region_size + CONF.input_faulty_region_size
        mask_size = int(math.log(input_memory_size, 2))
        self.sandbox_address_mask = "0b" + \
                                    "1" * (mask_size - CONF.memory_access_zeroed_bits) + \
                                    "0" * CONF.memory_access_zeroed_bits

    def run_on_test_case(self, test_case: TestCase) -> None:
        for func in test_case.functions:
            for bb in func:
                if bb == func.entry:
                    continue

                # collect all instructions that require sandboxing
                memory_instructions = []
                for inst in bb:
                    if inst.has_mem_operand(True):
                        memory_instructions.append(inst)

                # sandbox them
                for inst in memory_instructions:
                    self.sandbox_memory_access(inst, bb)

    def sandbox_memory_access(self, instr: Instruction, parent: BasicBlock):
        """ Force the memory accesses into the page starting from R14 """
        mem_operands = instr.get_mem_operands()
        implicit_mem_operands = instr.get_implicit_mem_operands()
        if mem_operands and not implicit_mem_operands:
            assert len(mem_operands) == 1, f"Unexpected instruction format {instr.name}"
            mem_operand: Operand = mem_operands[0]
            address_reg = mem_operand.value
            imm_width = mem_operand.width if mem_operand.width <= 32 else 32
            apply_mask = Instruction("AND", True) \
                .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                .add_op(ImmediateOperand(self.sandbox_address_mask, imm_width))
            parent.insert_before(instr, apply_mask)
            add_base = Instruction("ADD", True) \
                .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                .add_op(RegisterOperand("X30", 64, True, True))
            parent.insert_before(instr, add_base)
            return

        if implicit_mem_operands:
            raise GeneratorException("Implicit memory accesses are not supported")

        raise GeneratorException("Attempt to sandbox an instruction without memory operands")

    @staticmethod
    def requires_sandbox(inst: InstructionSpec):
        if inst.has_mem_operand:
            return True
        return False


class ARMPrinter(Printer):
    prologue_template = [
        "ISB  // instrumentation\n",
        ".test_case_enter:\n",
    ]
    epilogue_template = [
        ".test_case_exit:\n",
        "ISB  // instrumentation\n",
    ]

    def print(self, test_case: TestCase, outfile: str) -> None:
        with open(outfile, "w") as f:
            # print prologue
            for line in self.prologue_template:
                f.write(line)

            # print the test case
            for func in test_case.functions:
                f.write(f"{func.name}:\n")
                for bb in func:
                    self.print_basic_block(bb, f)

            # print epilogue
            for line in self.epilogue_template:
                f.write(line)

        for i in self.prologue_template:
            if i[0] == ".":
                test_case.num_prologue_instructions += 1

    def print_basic_block(self, bb: BasicBlock, file):
        file.write(f"{bb.name}:\n")
        for inst in bb:
            file.write(self.instruction_to_str(inst) + "\n")
        for inst in bb.terminators:
            file.write(self.instruction_to_str(inst) + "\n")

    def instruction_to_str(self, inst: Instruction):
        if inst.operands and isinstance(inst.operands[0], CondOperand):
            cond = inst.operands[0].value
            operands = inst.operands[1:]
        else:
            cond = ""
            operands = inst.operands

        operands_str = ", ".join([self.operand_to_str(op) for op in operands])
        comment = "// instrumentation" if inst.is_instrumentation else ""
        return f"{inst.name}{cond} {operands_str} {comment}"

    def operand_to_str(self, op: Operand) -> str:
        if isinstance(op, MemoryOperand) or isinstance(op, AgenOperand):
            return f"[{op.value}]"

        if isinstance(op, ImmediateOperand) or isinstance(op, AgenOperand):
            return f"#{op.value}"

        return op.value


class ARMRandomGenerator(ARMGenerator, RandomGenerator):

    def __init__(self, instruction_set: InstructionSet):
        super().__init__(instruction_set)
