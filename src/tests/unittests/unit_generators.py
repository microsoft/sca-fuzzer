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
from generator import X86RandomGenerator, X86Printer
from instruction_set import InstructionSet
from config import CONF


class X86RandomGeneratorTest(unittest.TestCase):
    def test_x86_all_instructions(self):
        instruction_set = InstructionSet('../instruction_sets/x86/base.xml',
                                         CONF.supported_categories)
        generator = X86RandomGenerator(instruction_set)
        func = generator.generate_function("function_main")
        printer = X86Printer()
        all_instructions = ['.intel_syntax noprefix\n']

        # try generating instruction strings
        for bb in func:
            for instruction_spec in generator.instruction_set.all:
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

        self.assertTrue(all_instructions, 'No instructions were generated.')


if __name__ == '__main__':
    unittest.main()
