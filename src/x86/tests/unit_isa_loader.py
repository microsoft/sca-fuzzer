"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest

from isa_loader import InstructionSet
from config import CONF

CONF.instruction_set = "x86-64"


class x86ISALoaderTest(unittest.TestCase):

    def test_instruction_filtering(self):
        instruction_set = InstructionSet('isa_spec/base.json', ["BASE-BINARY"])
        inst_names = [i.name for i in instruction_set.instructions]
        self.assertNotIn("HLT", inst_names)
