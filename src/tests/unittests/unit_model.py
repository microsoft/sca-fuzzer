"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import sys

sys.path.insert(0, '..')
from model import TaintTracker
from interfaces import Instruction, RegisterOperand, MemoryOperand, InputTaint
from config import CONF


class X86UnicornModelTest(unittest.TestCase):

    def test_taint_tracking(self):
        tracker = TaintTracker([])

        # reg -> reg
        tracker.start_instruction(Instruction("ADD")
                                  .add_op(RegisterOperand("RAX", 64, True, True))
                                  .add_op(RegisterOperand("RBX", 64, True, False)))  # yapf: disable
        tracker.finalize_instruction()
        self.assertEqual(tracker.src_regs, ["A", "B"])
        self.assertEqual(tracker.dest_regs, ["A"])
        self.assertEqual(tracker.reg_dependencies, {'A': ['A', 'B']})

        # chain of dependencies
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RCX", 64, False, True))
                                  .add_op(RegisterOperand("RAX", 64, True, False)))  # yapf: disable
        tracker.finalize_instruction()
        self.assertEqual(tracker.reg_dependencies, {'A': ['A', 'B'], 'C': ['A', 'B']})

        # memory -> reg
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RDX", 64, False, True))
                                  .add_op(MemoryOperand("RCX", 64, True, False)))  # yapf: disable
        tracker.track_memory_access(100, 8, False)
        tracker.finalize_instruction()
        self.assertEqual(tracker.reg_dependencies['D'], ['0x40', '0x80'])

        # reg -> mem
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(MemoryOperand("RAX", 64, False, True))
                                  .add_op(RegisterOperand("RSI", 64, True, False)))  # yapf: disable
        tracker.track_memory_access(64, 8, True)
        tracker.finalize_instruction()
        self.assertEqual(tracker.mem_dependencies, {'0x40': ['SI']})

        # store -> load
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RDI", 64, False, True))
                                  .add_op(MemoryOperand("RAX", 64, True, False)))  # yapf: disable
        tracker.track_memory_access(64, 8, False)
        tracker.finalize_instruction()
        self.assertEqual(tracker.reg_dependencies['DI'], ['SI'])

        # dependency overwriting
        self.assertEqual(tracker.reg_dependencies['A'], ['A', 'B'])
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RAX", 64, False, True))
                                  .add_op(RegisterOperand("RSI", 64, True, False)))  # yapf: disable
        tracker.finalize_instruction()
        self.assertEqual(tracker.reg_dependencies['A'], ['SI'])

        # tracker.start_instruction(inst)
        # tracker.track_memory_access(20, 8, False)
        # tracker.taint_memory_access_address()
        # tracker.finalize_instruction()

        # taint: InputTaint = tracker.get_taint(0)

        # print(f"Reg deps: {tracker.reg_dependencies}")
        # print(f"Mem deps: {tracker.mem_dependencies}")
        # print(f"Taint labels: {tracker.tainted_labels}")

        # print(taint)


if __name__ == '__main__':
    unittest.main()
