"""
File: Unit tests for all generators

Copyright (C) 2021 Oleksii Oleksenko
SPDX-License-Identifier: MIT
"""
import unittest

import sys

sys.path.insert(0, '..')
from generator import X86RandomGenerator, X86Printer


class X86RandomGeneratorTest(unittest.TestCase):
    def test_x86_all_instructions(self):
        generator = X86RandomGenerator('../instruction_sets/x86/base.xml')
        func = generator.generate_function("test_case_main", shuffle=False)
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
