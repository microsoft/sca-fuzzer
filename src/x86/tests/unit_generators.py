"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import tempfile
import subprocess
import os
from pathlib import Path

from src.x86.x86_generator import X86RandomGenerator, X86Printer, X86PatchUndefinedFlagsPass, \
    X86Generator
from src.factory import get_program_generator
from src.isa_loader import InstructionSet
from src.interfaces import TestCase, Function
from src.config import CONF

CONF.instruction_set = "x86-64"
test_path = Path(__file__).resolve()
test_dir = test_path.parent

ASM_OPCODE = """
.intel_syntax noprefix
.test_case_enter:
.byte 0x90, 0x90
.test_case_exit:
"""


class X86RandomGeneratorTest(unittest.TestCase):

    @staticmethod
    def load_tc(asm_str: str):
        min_x86_path = test_dir / "min_x86.json"
        instruction_set = InstructionSet(min_x86_path.absolute().as_posix())
        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)

        asm_file = tempfile.NamedTemporaryFile(delete=False)
        with open(asm_file.name, "w") as f:
            f.write(asm_str)
        tc: TestCase = generator.load(asm_file.name)
        asm_file.close()
        os.unlink(asm_file.name)
        return tc

    def test_x86_configuration(self):
        CONF.generator = "random"
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(),
                                         CONF.instruction_categories)
        gen = get_program_generator(instruction_set, CONF.program_generator_seed)
        self.assertEqual(gen.__class__, X86RandomGenerator)

    def test_x86_all_instructions(self):
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(),
                                         CONF.instruction_categories)
        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)
        func = generator.generate_function(".function_main")
        printer = X86Printer()
        all_instructions = ['.intel_syntax noprefix\n']

        # try generating instruction strings
        for bb in func:
            for instruction_spec in generator.non_control_flow_instructions:
                # fill up with random operand, following the spec
                inst = generator.generate_instruction(instruction_spec)
                bb.insert_after(bb.get_last(), inst)

            for instr in bb:
                instr_str = printer.instruction_to_str(instr)
                self.assertTrue(instr_str, f'Instruction {instr} was not generated.')
                all_instructions.append(instr_str + "\n")

        asm_file = tempfile.NamedTemporaryFile("w", delete=False)
        bin_file = tempfile.NamedTemporaryFile("w", delete=False)
        for i in all_instructions:
            asm_file.write(i)

        # check if the generated instructions are valid
        assembly_failed = False
        try:
            generator.assemble(asm_file.name, bin_file.name)
        except subprocess.CalledProcessError:
            assembly_failed = True
        else:
            bin_file.close()
            os.unlink(bin_file.name)
        asm_file.close()
        os.unlink(asm_file.name)

        if assembly_failed:
            self.fail("Generated invalid instruction(s)")

    def test_create_test_case(self):
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(),
                                         CONF.instruction_categories)
        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)

        asm_file = tempfile.NamedTemporaryFile(delete=False)
        name = asm_file.name
        # name = "tmp.asm"
        tc: TestCase = generator.create_test_case(name)
        size = len([i for bb in tc.functions for i in bb])
        self.assertNotEqual(size, 0)

        dump = subprocess.run(
            f"objdump --no-show-raw-insn -D -M intel -b binary -m i386:x86-64 {tc.bin_path} "
            "| awk '/ [0-9a-f]+:/{print $1, $2, $3}'",
            shell=True,
            check=True,
            capture_output=True).stdout.decode().split("\n")
        for line in dump:
            words = line.split(" ")
            if len(words) < 2:
                continue
            pc = int(words[0][:-1], 16)
            inst_obj = tc.address_map[pc]
            if inst_obj.name == "UNMAPPED" or '.byte' in inst_obj.name:
                continue
            disasm_name = words[1].upper()
            if disasm_name in X86Generator.asm_synonyms:
                disasm_name = X86Generator.asm_synonyms[disasm_name]
            self.assertIn(disasm_name, inst_obj.name)

        asm_file.close()
        os.unlink(asm_file.name)

    def test_x86_asm_parsing_basic(self):
        CONF.register_blocklist = []
        CONF.setattr_internal("_default_instruction_blocklist", [])

        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix())
        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)
        tc: TestCase = generator.load((test_dir / "asm_basic.asm").absolute().as_posix())
        self.assertEqual(len(tc.functions), 1)

        main = tc.functions[0]
        self.assertEqual(main.name, ".function_main")
        self.assertEqual(len(main), 4)
        main_iter = iter(main)

        entry = next(main_iter)
        bb0 = next(main_iter)
        bb1 = next(main_iter)
        exit_ = next(main_iter)

        self.assertEqual(entry.successors[0], bb0)
        self.assertEqual(bb0.successors[0], bb1)
        self.assertEqual(bb1.successors[0], exit_)

    def test_x86_asm_parsing_opcode(self):
        CONF.register_blocklist = []
        CONF.setattr_internal("_default_instruction_blocklist", [])

        tc = self.load_tc(ASM_OPCODE)

        main_iter = iter(tc.functions[0])
        bb0 = next(main_iter)
        self.assertEqual(bb0.get_first().name, "OPCODE")

    def test_x86_undef_flag_patch(self):
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(),
                                         CONF.instruction_categories)
        undef_instr_spec = list(filter(lambda x: x.name == 'BSF', instruction_set.instructions))[0]
        read_instr_spec = list(filter(lambda x: x.name == 'LAHF', instruction_set.instructions))[0]

        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)
        undef_instr = generator.generate_instruction(undef_instr_spec)
        read_instr = generator.generate_instruction(read_instr_spec)

        test_case = TestCase(0)
        test_case.functions = [Function(".function_main")]
        bb = test_case.functions[0].entry
        bb.insert_after(bb.get_last(), undef_instr)
        bb.insert_after(bb.get_last(), read_instr)

        X86PatchUndefinedFlagsPass(instruction_set, generator).run_on_test_case(test_case)
        self.assertEqual(len(bb), 3)
