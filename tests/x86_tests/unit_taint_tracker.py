"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=missing-function-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=protected-access

import unittest

from src.model_unicorn import taint_tracker
from src.x86.x86_target_desc import X86TargetDesc

from src.tc_components.instruction import Instruction, RegisterOp, MemoryOp, LabelOp, \
    FlagsOp, AgenOp
from src.tc_components.test_case_data import InputTaint


# ==================================================================================================
# Helper functions
# ==================================================================================================
def get_r64_src(reg: str) -> RegisterOp:
    return RegisterOp(reg, 64, True, False)


def get_r64_dest(reg: str) -> RegisterOp:
    return RegisterOp(reg, 64, False, True)


def get_r64_src_dest(reg: str) -> RegisterOp:
    return RegisterOp(reg, 64, True, True)


def get_r32_src(reg: str) -> RegisterOp:
    return RegisterOp(reg, 32, True, False)


def get_r32_dest(reg: str) -> RegisterOp:
    return RegisterOp(reg, 32, False, True)


def get_r32_src_dest(reg: str) -> RegisterOp:
    return RegisterOp(reg, 32, True, True)


def get_m64_src(reg: str) -> MemoryOp:
    return MemoryOp(reg, 64, True, False)


def get_m64_dest(reg: str) -> MemoryOp:
    return MemoryOp(reg, 64, False, True)


def get_m64_src_dest(reg: str) -> MemoryOp:
    return MemoryOp(reg, 64, True, True)


TD = X86TargetDesc()


# ==================================================================================================
# Tests
# ==================================================================================================
class X86TaintTrackerTest(unittest.TestCase):

    def test_dependency_tracking_basic(self) -> None:
        """ Basic dependency tracking: reg to reg, reg to mem, mem to reg, and mem to mem """
        tracker = taint_tracker.UnicornTaintTracker((0, 0), TD)

        # reg <- reg
        inst = Instruction("ADD").add_op(get_r64_src_dest("RAX")).add_op(get_r64_src("RBX"))
        tracker.track_instruction(inst)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.reg['A'], ['A', 'B'])

        # chain of dependencies
        inst = Instruction("MOV").add_op(get_r64_dest("RCX")).add_op(get_r64_src("RAX"))
        tracker.track_instruction(inst)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.reg['A'], ['A', 'B'])
        self.assertCountEqual(tracker._dependencies.reg['C'], ['A', 'B'])

        # reg <- mem
        inst = Instruction("MOV").add_op(get_r64_dest("RDX")).add_op(get_m64_src("RCX"))
        tracker.track_instruction(inst)
        tracker.track_memory_access(0x1100, 8, False)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.reg['D'], ['0x1100'])

        # mem <- reg
        inst = Instruction("MOV").add_op(get_m64_dest("RAX")).add_op(get_r64_src("RSI"))
        tracker.track_instruction(inst)
        tracker.track_memory_access(0x1200, 8, True)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.mem['0x1200'], ['0x1200', 'SI'])

        # load <- store
        inst = Instruction("MOV").add_op(get_r64_dest("RDI")).add_op(get_m64_src("RAX"))
        tracker.track_instruction(inst)
        tracker.track_memory_access(0x1200, 8, False)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.reg['DI'], ['SI', '0x1200'])

    def test_dependency_tracking_split_access(self) -> None:
        """ Memory accesses that split 8-byte boundaries must taint both parts """
        tracker = taint_tracker.UnicornTaintTracker((0, 0), TD)

        inst = Instruction("MOV").add_op(get_r64_dest("RAX")).add_op(get_m64_src("RCX"))
        tracker.track_instruction(inst)
        tracker.track_memory_access(0x1104, 8, False)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.reg['A'], ['0x1100', '0x1108'])

    def test_dependency_xmm(self) -> None:
        """ Test dependency tracking for XMM registers """
        tracker = taint_tracker.UnicornTaintTracker((0, 0), TD)

        inst = Instruction("MOVAPS").add_op(RegisterOp("XMM0", 128, False, True)).add_op(
            RegisterOp("XMM1", 128, True, False))
        tracker.track_instruction(inst)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.reg['XMM0'], ['XMM0', 'XMM1'])

    def test_dependency_override(self) -> None:
        """ Test that dependencies are overridden when a 64-bit register is written to"""
        tracker = taint_tracker.UnicornTaintTracker((0, 0), TD)

        inst = Instruction("MOV").add_op(get_r64_dest("RAX")).add_op(get_r64_src("RBX"))
        tracker.track_instruction(inst)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.reg['A'], ['B'])

        inst = Instruction("MOV").add_op(get_r64_dest("RAX")).add_op(get_r64_src("RCX"))
        tracker.track_instruction(inst)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.reg['A'], ['C'])

    def test_dependency_override_32bit(self) -> None:
        """ Test that dependencies are NOT overridden when a 32-bit register is written to"""
        tracker = taint_tracker.UnicornTaintTracker((0, 0), TD)

        inst = Instruction("MOV").add_op(get_r32_dest("EAX")).add_op(get_r32_src("EBX"))
        tracker.track_instruction(inst)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.reg['A'], ['B', 'A'])

        inst = Instruction("MOV").add_op(get_r32_dest("EAX")).add_op(get_r32_src("ECX"))
        tracker.track_instruction(inst)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.reg['A'], ['B', 'C', 'A'])

    def test_dependency_override_partial(self) -> None:
        """ Test that partial update instructions (e.g., MOVHPS) do NOT override dependencies """
        tracker = taint_tracker.UnicornTaintTracker((0, 0), TD)

        inst = Instruction("MOVHPS").add_op(RegisterOp("XMM1", 128, False,
                                                       True)).add_op(get_m64_src("RCX"))
        tracker.track_instruction(inst)
        tracker.track_memory_access(0x1100, 8, False)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.reg['XMM1'], ['XMM1', '0x1100'])

    def test_dependency_lea(self) -> None:
        """ Test that LEA instructions are handled correctly """
        tracker = taint_tracker.UnicornTaintTracker((0, 0), TD)

        inst = Instruction("LEA").add_op(get_r64_dest("RAX")).add_op(AgenOp("RDX + RBX", 8))
        tracker.track_instruction(inst)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker._dependencies.reg['A'], ['B', 'D'])

    def test_tainting_memory_access(self) -> None:
        """ Test that memory accesses are tainted correctly """
        tracker = taint_tracker.UnicornTaintTracker((0, 0), TD)

        # Initial dependency
        inst = Instruction("MOV").add_op(get_r64_dest("RAX")).add_op(get_r64_src("RBX"))
        tracker.track_instruction(inst)
        tracker._finalize_instruction()

        # Taint memory address
        inst = Instruction("MOV").add_op(get_r64_dest("RAX")).add_op(get_m64_src("RAX"))
        tracker.track_instruction(inst)
        tracker.track_memory_access(0x1100, 8, True)
        tracker.taint("mem")
        tracker._finalize_instruction()

        taint: InputTaint = tracker.get_taint(1)
        self.assertCountEqual(tracker._tainted_labels, {'B'})
        self.assertEqual(taint[0]['gpr'][1], True)  # RBX is tainted

    def test_tainting_pc(self) -> None:
        """ Test that the program counter is tainted correctly """
        tracker = taint_tracker.UnicornTaintTracker((0, 0), TD)

        # Initial dependency
        inst = Instruction("ADD").add_op(get_r64_src_dest("RAX")).add_op(get_r64_src("RBX")) \
            .add_op(FlagsOp(("w", "", "", "", "", "", "", "", "")))
        tracker.track_instruction(inst)
        tracker._finalize_instruction()

        # Taint PC
        jmp_instruction = Instruction("JC", is_control_flow=True)\
            .add_op(LabelOp(".bb0"))\
            .add_op(FlagsOp(("r", "", "", "", "", "", "", "", "")), True)\
            .add_op(RegisterOp("RIP", 64, True, True), True)
        tracker.track_instruction(jmp_instruction)
        tracker.taint("pc")
        tracker._finalize_instruction()

        taint: InputTaint = tracker.get_taint(1)
        self.assertEqual(tracker._tainted_labels, {'A', 'B', 'RIP'})
        self.assertEqual(taint[0]['gpr'][0], True)  # RAX
        self.assertEqual(taint[0]['gpr'][1], True)  # RBX

    def test_tainting_load_value(self) -> None:
        tracker = taint_tracker.UnicornTaintTracker((0, 0), TD)

        # Initial dependency
        inst = Instruction("MOV").add_op(get_r64_dest("RAX")).add_op(get_r64_src("RBX"))
        tracker.track_instruction(inst)
        tracker._finalize_instruction()

        # Taint load value
        inst = Instruction("MOV").add_op(get_r64_dest("RAX")).add_op(get_m64_src("RAX"))
        tracker.track_instruction(inst)
        tracker.track_memory_access(0x1100, 8, is_write=False)
        tracker.taint("mem")
        tracker.taint("ld_val")
        tracker._finalize_instruction()

        taint: InputTaint = tracker.get_taint(1)
        self.assertEqual(tracker._tainted_labels, {'B', '0x1100'})
        self.assertEqual(taint[0]['gpr'][1], True)
        self.assertEqual(taint[0]['main'][0x100 // 8], True)

    def test_label_to_taint(self) -> None:
        tracker = taint_tracker.UnicornTaintTracker((0, 0), TD)
        tracker._tainted_labels = {'0x1000', '0x1040', '0x1640', 'D', 'SI', '8', '14', 'DF', 'RIP'}
        taint: InputTaint = tracker.get_taint(1)

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
