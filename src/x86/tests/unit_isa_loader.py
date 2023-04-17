"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
from pathlib import Path

from src.isa_loader import InstructionSet
from src.config import CONF

test_path = Path(__file__).resolve()
test_dir = test_path.parent
CONF.instruction_set = "x86-64"


class x86ISALoaderTest(unittest.TestCase):

    def test_instruction_filtering(self):
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(),
                                         ["BASE-BINARY"])
        inst_names = [i.name for i in instruction_set.instructions]
        self.assertNotIn("HLT", inst_names)
