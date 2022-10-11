"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import sys
import tempfile
import os
from typing import List
from pathlib import Path

sys.path.insert(0, '..')

import x86.x86_model as x86_model
import model as core_model

from interfaces import Instruction, RegisterOperand, MemoryOperand, InputTaint, LabelOperand, \
    FlagsOperand, TestCase, Input, CTrace
from isa_loader import InstructionSet
from x86.x86_generator import X86RandomGenerator
from copy import deepcopy

from config import CONF
from service import LOGGER

test_path = Path(__file__).resolve()
test_dir = test_path.parent

ASM_THREE_LOADS = """
.intel_syntax noprefix
.test_case_enter:
MOV RAX, qword ptr [R14]
MOV RAX, qword ptr [R14 + 512]
MOV RAX, qword ptr [R14 + 1050]
.test_case_exit:
"""

ASM_BRANCH_AND_LOAD = """
.intel_syntax noprefix
.test_case_enter:
XOR rax, rax
JNZ .l1
.l0:
MOV RAX, qword ptr [R14]
.l1:
NOP
.test_case_exit:
"""

ASM_STORE_AND_LOAD = """
.intel_syntax noprefix
.test_case_enter:
MOV qword ptr [R14], 2
MOV RAX, qword ptr [R14]
MOV RAX, qword ptr [R14 + RAX]
.test_case_exit:
"""

ASM_FENCE = """
.intel_syntax noprefix
.test_case_enter:
XOR rax, rax
JZ .l1
.l0:
MOV RAX, qword ptr [R14]
LFENCE
MOV RAX, qword ptr [R14 + 2]
.l1:
NOP
.test_case_exit:
"""

ASM_FAULTY_ACCESS = """
.intel_syntax noprefix
.test_case_enter:
MOV RAX, qword ptr [R14 + RCX]
MOV RAX, qword ptr [R14 + RAX]
MOV RBX, qword ptr [R14 + RBX]
.test_case_exit:
"""

ASM_DIV_ZERO = """
.intel_syntax noprefix
.test_case_enter:
DIV EBX
MOV rax, qword ptr [R14 + RAX]
.test_case_exit:
"""


class X86ModelTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # make sure that the change in the configuration does not impact the other tests
        cls.prev_conf = deepcopy(CONF)
        CONF.instruction_set = "x86-64"
        CONF.model = 'x86-unicorn'
        CONF.input_gen_seed = 10  # default
        CONF.setattr_internal("_no_generation", True)

    @classmethod
    def tearDownClass(cls):
        global CONF
        CONF = cls.prev_conf

    @staticmethod
    def load_tc(asm_str: str):
        min_x86_path = test_dir / "min_x86.json"
        instruction_set = InstructionSet(min_x86_path.absolute().as_posix())
        generator = X86RandomGenerator(instruction_set)

        asm_file = tempfile.NamedTemporaryFile(delete=False)
        with open(asm_file.name, "w") as f:
            f.write(asm_str)
        tc: TestCase = generator.parse_existing_test_case(asm_file.name)
        asm_file.close()
        os.unlink(asm_file.name)
        return tc

    def get_traces(self, model, asm_str, inputs):
        tc = self.load_tc(asm_str)
        model.load_test_case(tc)
        ctraces: List[CTrace] = model.trace_test_case(inputs, 1)
        return ctraces

    def test_l1d_seq(self):
        model = x86_model.X86UnicornSeq(0x1000000, 0x8000)
        model.tracer = core_model.L1DTracer()
        ctraces = self.get_traces(model, ASM_THREE_LOADS, [Input()])
        expected_trace = (1 << 63) + (1 << 55) + (1 << 47)
        self.assertEqual(ctraces, [expected_trace])

    def test_pc_seq(self):
        code_base = 0x8000
        model = x86_model.X86UnicornSeq(0x1000000, code_base)
        model.tracer = core_model.PCTracer()
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [Input()])
        expected_trace = hash(
            tuple([code_base + 0x0, code_base + 0x3, code_base + 0x5, code_base + 0x8]))
        self.assertEqual(ctraces, [expected_trace])

    def test_mem_seq(self):
        mem_base = 0x1000000
        model = x86_model.X86UnicornSeq(mem_base, 0x8000)
        model.tracer = core_model.MemoryTracer()
        ctraces = self.get_traces(model, ASM_THREE_LOADS, [Input()])
        expected_trace = hash(tuple([mem_base + 0, mem_base + 512, mem_base + 1050]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_seq(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = x86_model.X86UnicornSeq(mem_base, code_base)
        model.tracer = core_model.CTTracer()
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [Input()])
        expected_trace = hash(
            tuple(
                [code_base + 0x0, code_base + 0x3, code_base + 0x5, mem_base + 0, code_base + 0x8]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ctr_seq(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = x86_model.X86UnicornSeq(mem_base, code_base)
        model.tracer = core_model.CTRTracer()
        input_ = Input()
        for i in range(0, 7):
            input_[input_.register_start + i] = 2
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [input_])
        # print(model.tracer.get_contract_trace_full())
        expected_trace = hash(
            tuple([
                2, 2, 2, 2, 2, 2, 2, code_base + 0x0, code_base + 0x3, code_base + 0x5,
                mem_base + 0, code_base + 0x8
            ]))
        self.assertEqual(ctraces, [expected_trace])

    def test_arch_seq(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = x86_model.X86UnicornSeq(mem_base, code_base)
        model.tracer = core_model.ArchTracer()
        input_ = Input()
        input_[0] = 1
        for i in range(0, 7):
            input_[input_.register_start + i] = 2
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [input_])
        expected_trace = hash(
            tuple([
                2, 2, 2, 2, 2, 2, 2, code_base + 0x0, code_base + 0x3, code_base + 0x5, 1,
                mem_base + 0, code_base + 0x8
            ]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_cond(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = x86_model.X86UnicornCond(mem_base, code_base)
        model.tracer = core_model.CTTracer()
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [Input()])
        expected_trace = hash(
            tuple([
                code_base + 0x0, code_base + 0x3, code_base + 0x8, code_base + 0x5, mem_base + 0,
                code_base + 0x8
            ]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_bpas(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = x86_model.X86UnicornBpas(mem_base, code_base)
        model.tracer = core_model.CTTracer()
        input_ = Input()
        input_[0] = 1
        ctraces = self.get_traces(model, ASM_STORE_AND_LOAD, [input_])
        expected_trace = hash(
            tuple([
                code_base, mem_base, code_base + 7, mem_base, code_base + 10, mem_base + 1,
                code_base + 7, mem_base, code_base + 10, mem_base + 2
            ]))
        self.assertEqual(ctraces, [expected_trace])

    def test_rollback_on_fence(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = x86_model.X86UnicornCond(mem_base, code_base)
        model.tracer = core_model.MemoryTracer()
        ctraces = self.get_traces(model, ASM_FENCE, [Input()])
        expected_trace = hash(tuple([mem_base + 0]))
        self.assertEqual(ctraces, [expected_trace])

    def test_fault_handling(self):
        mbase, cbase = 0x1000000, 0x8000
        model = x86_model.X86UnicornSeq(mbase, cbase)
        model.tracer = core_model.CTTracer()
        # Note that this test sets up a R/W protection to trigger a fault
        # and enables handling of page faults (errno=12,13) to catch them on the contract level
        model.rw_protect = True
        model.handled_faults.extend([12, 13])
        input_ = Input()
        input_[0] = 1
        input_[input_.register_start + 2] = 4096
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_])
        expected_trace = hash(tuple([cbase, mbase + 4096]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_nullinj(self):
        mbase, cbase = 0x1000000, 0x8000
        model = x86_model.X86UnicornNull(mbase, cbase)
        model.tracer = core_model.CTTracer()
        model.rw_protect = True
        model.handled_faults.extend([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[input_.register_start + i] = 2
        input_[input_.register_start + 2] = 4096
        input_[0] = 1
        input_[4096 // 8] = 3
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_])
        expected_trace = hash(tuple([
            cbase, mbase + 4096,  # fault
            cbase, mbase + 4096,  # speculative injection
            cbase + 4,  # speculatively start executing the next instr
            cbase + 4, mbase + 0,  # re-execute the instruction after setting the permissions
            cbase + 8, mbase + 2,  # speculatively execute the last instruction and rollback
            cbase, mbase + 4096, cbase + 4, mbase + 3, cbase + 8, mbase + 2,  # after rollback
            ]))   # yapf: disable
        # on newer versions of Unicorn, the instruction may
        # not be re-executed after changing permissions
        # hence, an alternative trace would be
        expected_trace2 = hash(
            tuple([
                cbase, mbase + 4096, cbase, mbase + 4096, cbase + 4, mbase + 0, cbase + 8,
                mbase + 2, cbase, mbase + 4096, cbase + 4, mbase + 3, cbase + 8, mbase + 2
            ]))
        self.assertIn(ctraces[0], [expected_trace, expected_trace2])

    def test_ct_nullinj_term(self):
        mbase, cbase = 0x1000000, 0x8000
        model = x86_model.X86UnicornNullTerminating(mbase, cbase)
        model.tracer = core_model.CTTracer()
        model.rw_protect = True
        model.handled_faults.extend([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[input_.register_start + i] = 2
        input_[input_.register_start + 2] = 4096
        input_[0] = 1
        input_[4096 // 8] = 3
        # LOGGER.dbg_model = True
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_])
        # LOGGER.dbg_model = False
        # print(model.tracer.get_contract_trace_full(), mbase, cbase)
        expected_trace = hash(tuple([
            cbase, mbase + 4096,  # fault
            cbase, mbase + 4096,  # speculative injection
            cbase + 4,  # speculatively start executing the next instr
            cbase + 4, mbase + 0,  # re-execute the instruction after setting the permissions
            cbase + 8, mbase + 2,  # speculatively execute the last instruction and rollback
            # terminate after rollback
            ]))   # yapf: disable
        # on newer versions of Unicorn, the instruction may
        # not be re-executed after changing permissions
        # hence, an alternative trace would be
        expected_trace2 = hash(
            tuple([
                cbase, mbase + 4096, cbase, mbase + 4096, cbase + 4, mbase + 0, cbase + 8, mbase + 2
            ]))
        self.assertIn(ctraces[0], [expected_trace, expected_trace2])

    def test_ct_ooo(self):
        mbase, cbase = 0x1000000, 0x8000
        model = x86_model.X86UnicornOOO(mbase, cbase)
        model.tracer = core_model.CTTracer()
        model.rw_protect = True
        model.handled_faults.extend([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[input_.register_start + i] = 2
        input_[input_.register_start + 2] = 4096
        input_[0] = 1
        input_[4096 // 8] = 3
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_])
        expected_trace = hash(tuple([
            cbase, mbase + 4096,  # faulty load
            cbase + 7,  # next load is dependent - do not execute the mem access
            cbase + 11, mbase + 2,  # speculatively execute the last instruction and rollback
            # terminate after rollback
            ]))   # yapf: disable
        self.assertEqual(ctraces[0], expected_trace)

    def test_ct_div_zero(self):
        mbase, cbase = 0x1000000, 0x8000
        model = x86_model.X86UnicornDivZero(mbase, cbase)
        model.tracer = core_model.CTTracer()
        model.rw_protect = True
        model.handled_faults.append(21)
        input_ = Input()
        input_[input_.register_start] = 2  # rax
        input_[input_.register_start + 1] = 0  # rbx
        input_[input_.register_start + 3] = 0  # rdx
        ctraces = self.get_traces(model, ASM_DIV_ZERO, [input_])
        expected_trace = hash(tuple([cbase, cbase + 2, mbase + 0]))
        self.assertEqual(ctraces[0], expected_trace)

    @unittest.skip("not implemented")
    def test_ct_div_overflow(self):
        # TBD
        pass

    def test_ct_meltdown(self):
        mbase, cbase = 0x1000000, 0x8000
        model = x86_model.X86Meltdown(mbase, cbase)
        model.tracer = core_model.CTTracer()
        model.rw_protect = True
        model.handled_faults.extend([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[input_.register_start + i] = 2
        input_[input_.register_start + 2] = 4096
        input_[0] = 1
        input_[4096 // 8] = 3
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_])
        expected_trace = hash(tuple([
            cbase, mbase + 4096,  # fault
            cbase, mbase + 4096,  # speculative injection
            cbase + 4, mbase + 3,  # next instruction
            cbase + 8, mbase + 2,  # speculatively execute the last instruction and rollback
            # terminate after rollback
            ]))   # yapf: disable
        self.assertEqual(ctraces[0], expected_trace)

    def test_ct_skip_fault(self):
        mbase, cbase = 0x1000000, 0x8000
        model = x86_model.X86FaultSkip(mbase, cbase)
        model.tracer = core_model.CTTracer()
        model.rw_protect = True
        model.handled_faults.extend([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[input_.register_start + i] = 2
        input_[input_.register_start + 2] = 4096
        input_[0] = 1
        input_[4096 // 8] = 3
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_])
        expected_trace = hash(tuple([
            cbase, mbase + 4096,  # fault
            cbase + 4, mbase + 2,  # next instruction
            cbase + 8, mbase + 2,  # speculatively execute the last instruction and rollback
            # terminate after rollback
            ]))   # yapf: disable
        self.assertEqual(ctraces[0], expected_trace)

    @unittest.skip("not implemented")
    def test_ct_gp_ooo(self):
        # TBD
        pass


class X86TaintTrackerTest(unittest.TestCase):

    def test_dependency_tracking(self):
        tracker = x86_model.X86TaintTracker([])

        # reg -> reg
        tracker.start_instruction(Instruction("ADD")
                                  .add_op(RegisterOperand("RAX", 64, True, True))
                                  .add_op(RegisterOperand("RBX", 64, True, False)))  # yapf: disable
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.src_regs, ["A", "B"])
        self.assertCountEqual(tracker.dest_regs, ["A"])
        self.assertCountEqual(tracker.reg_dependencies['A'], ['A', 'B'])

        # chain of dependencies
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RCX", 64, False, True))
                                  .add_op(RegisterOperand("RAX", 64, True, False)))  # yapf: disable
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.reg_dependencies['A'], ['A', 'B'])
        self.assertCountEqual(tracker.reg_dependencies['C'], ['A', 'B', 'C'])

        # memory -> reg
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RDX", 64, False, True))
                                  .add_op(MemoryOperand("RCX", 64, True, False)))  # yapf: disable
        tracker.track_memory_access(0x87, 8, False)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.reg_dependencies['D'], ['0x80', '0x88', 'D'])

        # reg -> mem
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(MemoryOperand("RAX", 64, False, True))
                                  .add_op(RegisterOperand("RSI", 64, True, False)))  # yapf: disable
        tracker.track_memory_access(0x80, 8, True)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.mem_dependencies['0x80'], ['0x80', 'SI'])

        # store -> load
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RDI", 64, False, True))
                                  .add_op(MemoryOperand("RAX", 64, True, False)))  # yapf: disable
        tracker.track_memory_access(0x80, 8, False)
        tracker._finalize_instruction()
        self.assertCountEqual(tracker.reg_dependencies['DI'], ['SI', 'DI', '0x80'])

    def test_tainting(self):
        tracker = x86_model.X86TaintTracker([])

        # Initial dependency
        tracker.start_instruction(Instruction("ADD")
                                  .add_op(RegisterOperand("RAX", 64, True, True))
                                  .add_op(RegisterOperand("RBX", 64, True, False)))  # yapf: disable
        tracker._finalize_instruction()
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(MemoryOperand("RAX", 64, False, True))
                                  .add_op(RegisterOperand("RAX", 64, True, False)))  # yapf: disable
        tracker.track_memory_access(0x80, 8, True)
        tracker._finalize_instruction()

        # Taint memory address
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RBX", 64, True, False))
                                  .add_op(MemoryOperand("RCX + 8 -16", 64, False, True))
                                  )  # yapf: disable
        tracker.track_memory_access(0x80, 8, False)
        tracker.taint_memory_access_address()
        taint: InputTaint = tracker.get_taint()
        reg_offset = taint.register_start

        self.assertCountEqual(tracker.mem_dependencies['0x80'], ['A', 'B', '0x80'])
        self.assertCountEqual(tracker.tainted_labels, {'C'})
        self.assertEqual(taint[reg_offset + 2], True)  # RCX

        # Taint PC
        tracker.tainted_labels = set()
        tracker.start_instruction(Instruction("CMPC")
                                  .add_op(RegisterOperand("RAX", 64, True, False))
                                  .add_op(RegisterOperand("RDX", 64, True, False))
                                  .add_op(FlagsOperand(["w", "", "", "", "", "", "", "", ""]), True)
                                  )  # yapf: disable
        tracker._finalize_instruction()
        jmp_instruction = Instruction("JC")\
            .add_op(LabelOperand(".bb0"))\
            .add_op(FlagsOperand(["r", "", "", "", "", "", "", "", ""]), True)\
            .add_op(RegisterOperand("RIP", 64, True, True), True)
        jmp_instruction.control_flow = True
        tracker.start_instruction(jmp_instruction)
        tracker.taint_pc()
        taint: InputTaint = tracker.get_taint()
        self.assertEqual(taint[reg_offset], True)  # RAX - through flags
        self.assertEqual(taint[reg_offset + 1], True)  # RBX - through flags + register
        self.assertEqual(taint[reg_offset + 3], True)  # RDX - through flags

        # Taint load value
        tracker.tainted_labels = set()
        tracker.start_instruction(Instruction("MOV")
                                  .add_op(RegisterOperand("RBX", 64, False, True))
                                  .add_op(MemoryOperand("RCX", 64, True, False))
                                  )  # yapf: disable
        tracker.track_memory_access(0x80, 8, is_write=False)
        tracker.taint_memory_load()
        taint: InputTaint = tracker.get_taint()
        # 0x80 -> A -> [A, B]
        self.assertEqual(taint[reg_offset + 0], True)
        self.assertEqual(taint[reg_offset + 1], True)

    def test_label_to_taint(self):
        tracker = x86_model.X86TaintTracker([])
        tracker.tainted_labels = {'0x0', '0x40', '0x640', 'D', 'SI', '8', '14', 'DF', 'RIP'}
        taint: InputTaint = tracker.get_taint()
        register_start = taint.register_start
        taint_size = taint.size

        expected = [False for i in range(taint_size)]
        expected[0] = True  # 0x0
        expected[8] = True  # 0x40
        expected[200] = True  # 640
        expected[register_start + 3] = True  # D
        expected[register_start + 4] = True  # SI
        expected[register_start + 6] = True  # DF - flags
        # 8, 14, RIP - not a part of the input

        self.assertListEqual(list(taint), expected)


if __name__ == '__main__':
    unittest.main()
