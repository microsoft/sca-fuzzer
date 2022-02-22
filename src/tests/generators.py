"""
File: Unit tests for all generators

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest

import sys

sys.path.insert(0, '..')
from generator import X86RandomGenerator, X86Printer
from instruction_set import InstructionSet
from config import CONF


class X86RandomGeneratorTest(unittest.TestCase):
    def test_x86_all_instructions(self):
        instruction_set = InstructionSet('../instruction_sets/x86/base.xml',
                                         CONF.supported_categories)
        generator = X86RandomGenerator(instruction_set)
        func = generator.generate_function("test_case_main")
        printer = X86Printer()
        all_instructions = ''
        for bb in func:
            for instruction_spec in generator.instruction_set.all:
                # fill up with random operand, following the spec
                inst = generator.generate_instruction(instruction_spec)
                bb.insert_after(bb.get_last(), inst)

            for instr in bb:
                all_instructions += printer.instruction_to_str(instr)

        self.assertTrue(all_instructions, 'No instructions were generated.')


if __name__ == '__main__':
    unittest.main()
