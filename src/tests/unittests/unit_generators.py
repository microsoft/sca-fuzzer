"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import tempfile
import sys
import subprocess
import os

sys.path.insert(0, '..')
from generator import X86RandomGenerator, X86Printer, X86PatchUndefinedFlagsPass
from isa_loader import InstructionSet
from interfaces import TestCase, Function
from config import CONF


class X86RandomGeneratorTest(unittest.TestCase):

    def test_x86_all_instructions(self):
        instruction_set = InstructionSet('unittests/min_x86.json',
                                         CONF.supported_categories)
        generator = X86RandomGenerator(instruction_set)
        func = generator.generate_function("function_main")
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

    def test_x86_asm_parsing_basic(self):
        CONF.gpr_blocklist = []
        CONF.instruction_blocklist = []

        instruction_set = InstructionSet('unittests/min_x86.json')
        generator = X86RandomGenerator(instruction_set)
        tc: TestCase = generator.parse_existing_test_case("unittests/asm_basic.asm")
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

    def test_x86_undef_flag_patch(self):
        instruction_set = InstructionSet('unittests/min_x86.json')
        undef_instr_spec = list(filter(lambda x: x.name == 'BSF', instruction_set.instructions))[0]
        read_instr_spec = list(filter(lambda x: x.name == 'LAHF', instruction_set.instructions))[0]

        generator = X86RandomGenerator(instruction_set)
        undef_instr = generator.generate_instruction(undef_instr_spec)
        read_instr = generator.generate_instruction(read_instr_spec)

        test_case = TestCase()
        test_case.functions = [Function(".function_main")]
        bb = test_case.functions[0].entry
        bb.insert_after(bb.get_last(), undef_instr)
        bb.insert_after(bb.get_last(), read_instr)

        X86PatchUndefinedFlagsPass(instruction_set, generator).run_on_test_case(test_case)
        self.assertEqual(len(bb), 3)


if __name__ == '__main__':
    unittest.main()
