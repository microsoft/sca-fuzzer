"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
from pathlib import Path

from rvzr.isa_spec import InstructionSet
from rvzr.config import CONF

test_path = Path(__file__).resolve()
test_dir = test_path.parent
CONF.instruction_set = "arm64"


class ARM64ISALoaderTest(unittest.TestCase):

    def test_loading(self) -> None:
        instruction_set = InstructionSet((test_dir / "min_arm64.json").absolute().as_posix(),
                                         ["general"])
        inst_names = [i.name for i in instruction_set.instructions]
        self.assertIn("mov", inst_names)
