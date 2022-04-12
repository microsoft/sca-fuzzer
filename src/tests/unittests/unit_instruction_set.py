"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest

import sys

sys.path.insert(0, '..')
from instruction_set import InstructionSet
from interfaces import OT, InstructionSpec


class InstructionSetParserTest(unittest.TestCase):
    def test_parsing(self):
        instruction_set = InstructionSet('./unittests/basic_parsing.xml')
        spec: InstructionSpec = instruction_set.all[0]
        self.assertEqual(spec.name, "TEST")
        self.assertEqual(spec.category, "CATEGORY")
        self.assertEqual(spec.has_mem_operand, True)
        self.assertEqual(spec.has_write, True)
        self.assertEqual(spec.control_flow, False)

        self.assertEqual(len(spec.operands), 1)
        op1 = spec.operands[0]
        self.assertEqual(op1.type, OT.MEM)
        self.assertEqual(op1.width, 16)
        self.assertEqual(op1.src, True)
        self.assertEqual(op1.dest, True)

        self.assertEqual(len(spec.implicit_operands), 2)
        op2 = spec.implicit_operands[0]
        self.assertEqual(op2.type, OT.REG)
        self.assertEqual(op2.values, ["AX"])
        self.assertEqual(op2.src, True)
        self.assertEqual(op2.dest, False)

        flags = spec.implicit_operands[1]
        self.assertEqual(flags.type, OT.FLAGS)
        self.assertEqual(flags.values, ['r/w', 'w', 'w', 'w', 'w', '', '', '', 'w'])

    def test_dedup_identical(self):
        instruction_set = InstructionSet('./unittests/two_identical_specs.xml')
        self.assertEqual(len(instruction_set.all), 1, "No deduplication")

if __name__ == '__main__':
    unittest.main()
