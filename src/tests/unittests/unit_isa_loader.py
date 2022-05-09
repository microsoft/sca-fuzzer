"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest

import sys
import os
import tempfile

sys.path.insert(0, '..')
from isa_loader import InstructionSet
from interfaces import OT, InstructionSpec

basic = """
[
{"name": "TEST", "category": "CATEGORY", "control_flow": true,
  "operands": [
    {"type_": "MEM", "values": [], "src": true, "dest": true, "width": 16},
    {"type_": "REG", "values": ["AX"], "src": true, "dest": false, "width": 16}
  ],
  "implicit_operands": [
    {"type_": "FLAGS", "values": ["w", "r", "undef", "w", "w", "", "", "", "w"], "src": false, "dest": false, "width": 0}
  ]
}
]
"""

duplicate = """
[
{"name": "TEST", "category": "CATEGORY", "control_flow": false,
  "operands": [
    {"type_": "MEM", "values": [], "src": true, "dest": true, "width": 16}
  ],
  "implicit_operands": []
},
{"name": "TEST", "category": "CATEGORY", "control_flow": false,
  "operands": [
    {"type_": "MEM", "values": [], "src": true, "dest": true, "width": 16}
  ],
  "implicit_operands": []
}
]
"""


class InstructionSetParserTest(unittest.TestCase):

    def test_parsing(self):
        spec_file = tempfile.NamedTemporaryFile("w", delete=False)
        with open(spec_file.name, "w") as f:
            f.write(basic)

        instruction_set = InstructionSet(spec_file.name)
        spec_file.close()
        os.unlink(spec_file.name)

        spec: InstructionSpec = instruction_set.instructions[0]
        self.assertEqual(spec.name, "TEST")
        self.assertEqual(spec.category, "CATEGORY")
        self.assertEqual(spec.has_mem_operand, True)
        self.assertEqual(spec.has_write, True)
        self.assertEqual(spec.control_flow, True)

        self.assertEqual(len(spec.operands), 2)
        op1 = spec.operands[0]
        self.assertEqual(op1.type, OT.MEM)
        self.assertEqual(op1.width, 16)
        self.assertEqual(op1.src, True)
        self.assertEqual(op1.dest, True)

        op2 = spec.operands[1]
        self.assertEqual(op2.type, OT.REG)
        self.assertEqual(op2.values, ["AX"])
        self.assertEqual(op2.src, True)
        self.assertEqual(op2.dest, False)

        self.assertEqual(len(spec.implicit_operands), 1)
        flags = spec.implicit_operands[0]
        self.assertEqual(flags.type, OT.FLAGS)
        self.assertEqual(flags.values, ['w', 'r', 'undef', 'w', 'w', '', '', '', 'w'])

    def test_dedup_identical(self):
        spec_file = tempfile.NamedTemporaryFile("w", delete=False)
        with open(spec_file.name, "w") as f:
            f.write(duplicate)

        instruction_set = InstructionSet(spec_file.name)
        spec_file.close()
        os.unlink(spec_file.name)

        self.assertEqual(len(instruction_set.instructions), 1, "No deduplication")


if __name__ == '__main__':
    unittest.main()
