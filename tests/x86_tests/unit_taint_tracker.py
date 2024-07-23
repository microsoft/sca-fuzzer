"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest

import src.x86.x86_model as x86_model

from src.interfaces import Instruction, RegisterOperand, MemoryOperand, InputTaint, LabelOperand, \
    FlagsOperand, AgenOperand


# ==================================================================================================
# Helper functions
# ==================================================================================================
def get_r64_src(reg: str) -> RegisterOperand:
    return RegisterOperand(reg, 64, True, False)


def get_r64_dest(reg: str) -> RegisterOperand:
    return RegisterOperand(reg, 64, False, True)


def get_r64_src_dest(reg: str) -> RegisterOperand:
    return RegisterOperand(reg, 64, True, True)


def get_r32_src(reg: str) -> RegisterOperand:
    return RegisterOperand(reg, 32, True, False)


def get_r32_dest(reg: str) -> RegisterOperand:
    return RegisterOperand(reg, 32, False, True)


def get_r32_src_dest(reg: str) -> RegisterOperand:
    return RegisterOperand(reg, 32, True, True)


def get_m64_src(reg: str) -> MemoryOperand:
    return MemoryOperand(reg, 64, True, False)


def get_m64_dest(reg: str) -> MemoryOperand:
    return MemoryOperand(reg, 64, False, True)


def get_m64_src_dest(reg: str) -> MemoryOperand:
    return MemoryOperand(reg, 64, True, True)


# ==================================================================================================
# Tests
# ==================================================================================================
class X86TaintTrackerTest(unittest.TestCase):

    def test_dependency_tracking_basic(self):
        """ Basic dependency tracking: reg to reg, reg to mem, mem to reg, and mem to mem """
        tracker = x86_model.X86TaintTracker([])

        # reg <- reg
        inst = Instruction("ADD").add_op(get_r64_src_dest("RAX")).add_op(get_r64_src("RBX"))
        tracker.start_instruction(inst)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.reg_deps['A'], ['A', 'B'])

        # chain of dependencies
        inst = Instruction("MOV").add_op(get_r64_dest("RCX")).add_op(get_r64_src("RAX"))
        tracker.start_instruction(inst)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.reg_deps['A'], ['A', 'B'])
        self.assertCountEqual(tracker.reg_deps['C'], ['A', 'B'])

        # reg <- mem
        inst = Instruction("MOV").add_op(get_r64_dest("RDX")).add_op(get_m64_src("RCX"))
        tracker.start_instruction(inst)
        tracker.track_memory_access(0x100, 8, False)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.reg_deps['D'], ['0x100'])

        # mem <- reg
        inst = Instruction("MOV").add_op(get_m64_dest("RAX")).add_op(get_r64_src("RSI"))
        tracker.start_instruction(inst)
        tracker.track_memory_access(0x200, 8, True)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.mem_deps['0x200'], ['0x200', 'SI'])

        # load <- store
        inst = Instruction("MOV").add_op(get_r64_dest("RDI")).add_op(get_m64_src("RAX"))
        tracker.start_instruction(inst)
        tracker.track_memory_access(0x200, 8, False)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.reg_deps['DI'], ['SI', '0x200'])

    def test_dependency_tracking_split_access(self):
        """ Memory accesses that split 8-byte boundaries must taint both parts """
        tracker = x86_model.X86TaintTracker([])

        inst = Instruction("MOV").add_op(get_r64_dest("RAX")).add_op(get_m64_src("RCX"))
        tracker.start_instruction(inst)
        tracker.track_memory_access(0x104, 8, False)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.reg_deps['A'], ['0x100', '0x108'])


    def test_tainting_memory_access(self):
        """ Test that memory accesses are tainted correctly """
        tracker = x86_model.X86TaintTracker([])

        # Initial dependency
        inst = Instruction("MOV").add_op(get_r64_dest("RAX")).add_op(get_r64_src("RBX"))
        tracker.start_instruction(inst)
        tracker._finalize_instruction()

        # Taint memory address
        inst = Instruction("MOV").add_op(get_r64_dest("RAX")).add_op(get_m64_src("RAX"))
        tracker.start_instruction(inst)
        tracker.track_memory_access(0x100, 8, True)
        tracker.taint_memory_access_address()
        tracker._finalize_instruction()

        taint: InputTaint = tracker.get_taint()
        self.assertCountEqual(tracker.tainted_labels, {'B'})
        self.assertEqual(taint[0]['gpr'][1], True)  # RBX is tainted

    def test_tainting_pc(self):
        """ Test that the program counter is tainted correctly """
        tracker = x86_model.X86TaintTracker([])

        # Initial dependency
        inst = Instruction("ADD").add_op(get_r64_src_dest("RAX")).add_op(get_r64_src("RBX")) \
            .add_op(FlagsOperand(["w", "", "", "", "", "", "", "", ""]))
        tracker.start_instruction(inst)
        tracker._finalize_instruction()

        # Taint PC
        jmp_instruction = Instruction("JC")\
            .add_op(LabelOperand(".bb0"))\
            .add_op(FlagsOperand(["r", "", "", "", "", "", "", "", ""]), True)\
            .add_op(RegisterOperand("RIP", 64, True, True), True)
        jmp_instruction.control_flow = True
        tracker.start_instruction(jmp_instruction)
        tracker.taint_pc()
        tracker._finalize_instruction()

        taint: InputTaint = tracker.get_taint()
        self.assertEqual(tracker.tainted_labels, {'A', 'B', 'RIP'})
        self.assertEqual(taint[0]['gpr'][0], True)  # RAX
        self.assertEqual(taint[0]['gpr'][1], True)  # RBX

    def test_tainting_load_value(self):
        tracker = x86_model.X86TaintTracker([])

        # Initial dependency
        inst = Instruction("MOV").add_op(get_r64_dest("RAX")).add_op(get_r64_src("RBX"))
        tracker.start_instruction(inst)
        tracker._finalize_instruction()

        # Taint load value
        inst = Instruction("MOV").add_op(get_r64_dest("RAX")).add_op(get_m64_src("RAX"))
        tracker.start_instruction(inst)
        tracker.track_memory_access(0x100, 8, is_write=False)
        tracker.taint_memory_access_address()
        tracker.taint_loaded_value()
        tracker._finalize_instruction()

        taint: InputTaint = tracker.get_taint()
        self.assertEqual(tracker.tainted_labels, {'B', '0x100'})
        self.assertEqual(taint[0]['gpr'][1], True)
        self.assertEqual(taint[0]['main'][0x100 // 8], True)

    def test_label_to_taint(self):
        tracker = x86_model.X86TaintTracker([])
        tracker.tainted_labels = {'0x0', '0x40', '0x640', 'D', 'SI', '8', '14', 'DF', 'RIP'}
        taint: InputTaint = tracker.get_taint()

        expected: InputTaint = InputTaint()
        expected.fill(0)
        expected[0]['main'][0] = True  # 0x0
        expected[0]['main'][8] = True  # 0x40
        expected[0]['main'][200] = True  # 640
        expected[0]['gpr'][3] = True  # D
        expected[0]['gpr'][4] = True  # SI
        expected[0]['gpr'][6] = True  # DF - flags
        # 8, 14, RIP - not a part of the input

        self.assertListEqual(list(taint), list(expected))


if __name__ == '__main__':
    unittest.main()
