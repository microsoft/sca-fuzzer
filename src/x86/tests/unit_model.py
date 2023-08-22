"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import tempfile
import os
from typing import List
from pathlib import Path
from copy import deepcopy

import src.x86.x86_model as x86_model
import src.model as core_model

from src.interfaces import Instruction, RegisterOperand, MemoryOperand, InputTaint, LabelOperand, \
    FlagsOperand, TestCase, Input, CTrace, PageTableModifier
from src.isa_loader import InstructionSet
from src.x86.x86_generator import X86RandomGenerator
from src.config import CONF

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

ASM_DOUBLE_BRANCH = """
.intel_syntax noprefix
.test_case_enter:
XOR rax, rax
JNZ .l1
.l0:
MOV RAX, qword ptr [R14]
JMP .l3
.l1:
XOR rbx, rbx
JNZ .l3
.l2:
MOV RBX, qword ptr [R14]
.l3:
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

ASM_FAULTY_ACCESS_FENCE = """
.intel_syntax noprefix
.test_case_enter:
MOV RAX, qword ptr [R14 + RCX]
MOV RAX, qword ptr [R14 + RAX]
LFENCE
MOV RBX, qword ptr [R14 + RBX]
.test_case_exit:
"""

ASM_BRANCH_AND_FAULT = """
.intel_syntax noprefix
.test_case_enter:
XOR rax, rax
JZ .l1
.l0:
MOV RAX, qword ptr [R14 + RCX]
MOV RAX, qword ptr [R14 + RAX]
.l1:
NOP
.test_case_exit:
"""

ASM_FAULT_AND_BRANCH = """
.intel_syntax noprefix
.test_case_enter:
MOV RAX, qword ptr [R14 + RCX]
XOR rbx, rbx
JZ .l1
.l0:
MOV RAX, qword ptr [R14 + RAX]
.l1:
NOP
.test_case_exit:
"""

ASM_DIV_ZERO = """
.intel_syntax noprefix
.test_case_enter:
DIV EBX
MOV rax, qword ptr [R14 + RAX]
.test_case_exit:
"""

ASM_DIV_ZERO_FENCE = """
.intel_syntax noprefix
.test_case_enter:
DIV EBX
LFENCE
MOV rax, qword ptr [R14 + RAX]
.test_case_exit:
"""

ASM_DIV_ZERO2 = """
.intel_syntax noprefix
.test_case_enter:
DIV RBX
MOV rax, qword ptr [R14 + RAX]
MOV rax, qword ptr [R14 + RAX]
.test_case_exit:
"""

PF_MASK = 0xfffffffffffffffe


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
        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)

        asm_file = tempfile.NamedTemporaryFile(delete=False)
        with open(asm_file.name, "w") as f:
            f.write(asm_str)
        tc: TestCase = generator.load(asm_file.name)
        asm_file.close()
        os.unlink(asm_file.name)
        return tc

    def get_traces(self, model, asm_str, inputs, nesting=1, pte_mask: int = 0xffffffffffffffff):
        tc = self.load_tc(asm_str)
        tc.faulty_pte = PageTableModifier(0, pte_mask)
        model.load_test_case(tc)
        ctraces: List[CTrace] = model.trace_test_case(inputs, nesting)
        return ctraces

    def test_gpr_tracer(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = x86_model.X86UnicornSeq(mem_base, code_base)
        model.tracer = core_model.GPRTracer()
        input_ = Input()
        input_[0]['main'][0] = 0
        input_[0]['main'][1] = 1
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        _ = self.get_traces(model, ASM_STORE_AND_LOAD, [input_])
        full_trace = model.tracer.get_contract_trace_full()
        expected_trace = [1 << 48, 2, 2, 2, 2, 2]
        self.assertEqual(full_trace, expected_trace)

    def test_l1d_seq(self):
        model = x86_model.X86UnicornSeq(0x1000000, 0x8000)
        model.tracer = core_model.L1DTracer()
        ctraces = self.get_traces(model, ASM_THREE_LOADS, [Input()])
        expected_trace = (1 << 63) + (1 << 55) + (1 << 47)
        self.assertEqual(ctraces, [expected_trace])

    def test_pc_seq(self):
        model = x86_model.X86UnicornSeq(0x1000000, 0x8000)
        model.tracer = core_model.PCTracer()
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [Input()])
        expected_trace = hash(tuple([0x0, 0x3, 0x5, 0x8]))
        self.assertEqual(ctraces, [expected_trace])

    def test_mem_seq(self):
        model = x86_model.X86UnicornSeq(0x1000000, 0x8000)
        model.tracer = core_model.MemoryTracer()
        ctraces = self.get_traces(model, ASM_THREE_LOADS, [Input()])
        expected_trace = hash(tuple([0, 512, 1050]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_seq(self):
        model = x86_model.X86UnicornSeq(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [Input()])
        expected_trace = hash(tuple([0x0, 0x3, 0x5, 0, 0x8]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ctr_seq(self):
        model = x86_model.X86UnicornSeq(0x1000000, 0x8000)
        model.tracer = core_model.CTRTracer()
        input_ = Input()
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [input_])
        expected_trace = hash(
            tuple([2, 2, 2, 2, 2, 2, 2, model.stack_base - model.sandbox_base, 0x0, 3, 5, 0, 8]))
        self.assertEqual(ctraces, [expected_trace])

    def test_arch_seq(self):
        model = x86_model.X86UnicornSeq(0x1000000, 0x8000)
        model.tracer = core_model.ArchTracer()
        input_ = Input()
        input_[0]['main'][0] = 1
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [input_])
        expected_trace = hash(
            tuple([2, 2, 2, 2, 2, 2, 2, model.stack_base - model.sandbox_base, 0x0, 3, 5, 1, 0, 8]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_cond(self):
        model = x86_model.X86UnicornCond(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [Input()])
        expected_trace = hash(tuple([0x0, 0x3, 0x8, 0x5, 0, 0x8]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_cond_double(self):
        model = x86_model.X86UnicornCond(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        ctraces = self.get_traces(model, ASM_DOUBLE_BRANCH, [Input()], nesting=2)
        expected_trace = hash(
            tuple([
                0,  # XOR rax, rax
                3,  # JNZ .l1
                10,  # XOR rbx, rbx
                13,  # JNZ .l3
                18,  # NOP, rollback inner speculation
                15,
                0,  # MOV RBX, qword ptr [R14]
                18,  # NOP, rollback outer speculation
                5,
                0,  # MOV RAX, qword ptr [R14]
                8,  # JMP .l3
                18,  # NOP
            ]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_bpas(self):
        model = x86_model.X86UnicornBpas(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        input_ = Input()
        input_['main'][0] = 1
        ctraces = self.get_traces(model, ASM_STORE_AND_LOAD, [input_])
        expected_trace = hash(tuple([0, 0, 7, 0, 10, 1, 7, 0, 10, 2]))
        self.assertEqual(ctraces, [expected_trace])

    def test_rollback_on_fence(self):
        model = x86_model.X86UnicornCond(0x1000000, 0x8000)
        model.tracer = core_model.MemoryTracer()
        ctraces = self.get_traces(model, ASM_FENCE, [Input()])
        expected_trace = hash(tuple([0]))
        self.assertEqual(ctraces, [expected_trace])

    def test_fault_handling(self):
        model = x86_model.X86UnicornSeq(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.handled_faults.update([12, 13])
        input_ = Input()
        input_[0]['main'][0] = 1
        input_[0]['gpr'][2] = 4096
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_], pte_mask=PF_MASK)
        expected_trace = hash(tuple([0, 4096, 4088]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_nullinj(self):
        model = x86_model.X86UnicornNullAssist(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.rw_protect = True
        model.handled_faults.update([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        input_[0]['gpr'][2] = 4096
        input_[0]['faulty'][0] = 3
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_], pte_mask=PF_MASK)
        expected_trace = hash(tuple([
            0, 4096, 4088,  # fault
            0, 4096,  # speculative injection
            4,  # speculatively start executing the next instr
            4, 0,  # re-execute the instruction after setting the permissions
            8, 2,  # speculatively execute the last instruction and rollback
            0, 4096, 4, 3, 8, 2,  # after rollback
        ]))   # yapf: disable
        # on newer versions of Unicorn, the instruction may
        # not be re-executed after changing permissions
        # hence, an alternative trace would be
        expected_trace2 = hash(tuple([0, 4096, 4088, 0, 4096, 4, 0, 8, 2, 0, 4096, 4, 3, 8, 2]))
        self.assertIn(ctraces[0], [expected_trace, expected_trace2])

    def test_ct_nullinj_term(self):
        model = x86_model.X86UnicornNull(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.handled_faults.update([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        input_[0]['gpr'][2] = 4096
        input_[0]['main'][0] = 1
        input_[0]['faulty'][0] = 3
        # model.LOG.dbg_model = not model.LOG.dbg_model
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_], pte_mask=PF_MASK)
        # model.LOG.dbg_model = not model.LOG.dbg_model
        # print(model.tracer.get_contract_trace_full(), mbase, cbase)
        expected_trace = hash(tuple([
            0, 4096, 4088,  # fault
            0, 4096,  # speculative injection
            4,  # speculatively start executing the next instr
            4, 0,  # re-execute the instruction after setting the permissions
            8, 2,  # speculatively execute the last instruction and rollback
            # terminate after rollback
        ]))   # yapf: disable
        # on newer versions of Unicorn, the instruction may
        # not be re-executed after changing permissions
        # hence, an alternative trace would be
        expected_trace2 = hash(tuple([0, 4096, 4088, 0, 4096, 4, 0, 8, 2]))
        self.assertIn(ctraces[0], [expected_trace, expected_trace2])

    def test_ct_deh(self):
        model = x86_model.X86UnicornDEH(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.handled_faults.update([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        input_[0]['gpr'][2] = 4096
        input_[0]['main'][0] = 1
        input_[0]['faulty'][0] = 3
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_], pte_mask=PF_MASK)
        expected_trace = hash(tuple([
            0, 4096, 4088,  # faulty load
            4,  # next load is dependent - do not execute the mem access
            8, 2,  # speculatively execute the last instruction and rollback
            # terminate after rollback
        ]))   # yapf: disable
        self.assertEqual(ctraces[0], expected_trace)

    def test_ct_div_zero(self):
        model = x86_model.X86UnicornDivZero(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.handled_faults.add(21)
        input_ = Input()
        input_[0]['gpr'][0] = 2  # rax
        input_[0]['gpr'][1] = 0  # rbx
        input_[0]['gpr'][3] = 0  # rdx
        ctraces = self.get_traces(model, ASM_DIV_ZERO, [input_])
        expected_trace = hash(tuple([0, 4088, 2, 0]))
        self.assertEqual(ctraces[0], expected_trace)

    def test_ct_div_zero_fence(self):
        model = x86_model.X86UnicornDivZero(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.rw_protect = True
        model.handled_faults.add(21)
        input_ = Input()
        input_[0]['gpr'][0] = 2  # rax
        input_[0]['gpr'][1] = 0  # rbx
        input_[0]['gpr'][3] = 0  # rdx
        ctraces = self.get_traces(model, ASM_DIV_ZERO_FENCE, [input_])
        expected_trace = hash(tuple([0, 4088, 2]))
        self.assertEqual(ctraces[0], expected_trace)

    def test_ct_meltdown(self):
        model = x86_model.X86Meltdown(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.handled_faults.update([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        input_[0]['gpr'][2] = 4096
        input_[0]['faulty'][0] = 3
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_], pte_mask=PF_MASK)
        expected_trace = hash(tuple([
            0, 4096, 4088,  # fault
            0, 4096,  # speculative injection
            4, 3,  # next instruction
            8, 2,  # speculatively execute the last instruction and rollback
            # terminate after rollback
        ]))   # yapf: disable
        self.assertEqual(ctraces[0], expected_trace)

    def test_ct_meltdown_fence(self):
        model = x86_model.X86Meltdown(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.handled_faults.update([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        input_[0]['gpr'][2] = 4096
        input_[0]['faulty'][0] = 3
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS_FENCE, [input_], pte_mask=PF_MASK)
        expected_trace = hash(
            tuple([
                0, 4096, 4088,  # fault
                0, 4096,  # speculative injection
                4, 3,  # next instruction
                8,  # now at fence, initiating a rollback
                # next instruction is not executed: speculation ended,
                # handling of exceptions not modeled
            ]))   # yapf: disable
        self.assertEqual(ctraces[0], expected_trace)

    def test_ct_meltdown_double(self):
        model = x86_model.X86Meltdown(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.handled_faults.update([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        input_[0]['gpr'][2] = 4096
        input_[0]['faulty'][0] = 4097
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_], nesting=2, pte_mask=PF_MASK)
        expected_trace = hash(
            tuple([
                0, 4096, 4088,  # fault
                0, 4096,  # speculative injection
                4, 4097,  # second fault
                # no second speculative injection, fault just ignored
                8, 2  # speculatively execute the last instruction and rollback
                # terminate after rollback
            ]))   # yapf: disable
        self.assertEqual(ctraces[0], expected_trace)

    def test_ct_branch_meltdown(self):
        model = x86_model.X86CondMeltdown(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.handled_faults.update([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        input_[0]['gpr'][2] = 4096
        input_[0]['faulty'][0] = 3
        ctraces = self.get_traces(
            model, ASM_BRANCH_AND_FAULT, [input_], nesting=2, pte_mask=PF_MASK)
        expected_trace = hash(tuple([
            0,
            3,  # speculatively do not jump
            5, 4096, 4088,  # fault while speculating
            5, 4096,  # speculative injection
            9, 3,  # leak [4096]
            13,  # last instruction of speculation caused by exception, rollback
            13,  # execution of correct branch
        ]))   # yapf: disable
        self.assertEqual(ctraces[0], expected_trace)

    def test_ct_meltdown_branch(self):
        model = x86_model.X86CondMeltdown(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.handled_faults.update([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        input_[0]['gpr'][2] = 4096
        input_[0]['faulty'][0] = 3
        # model.LOG.dbg_model = True
        ctraces = self.get_traces(
            model, ASM_FAULT_AND_BRANCH, [input_], nesting=2, pte_mask=PF_MASK)
        expected_trace_tmp = [
            0,
            4096,
            4088,  # faulty access
            0,
            4096,  # speculative injection
            4,  # xor
            7,  # speculatively do not jump
            9,
            3,  # leak [4096]
            13,  # end of branch speculation, rollback
            13,  # execution of correct branch
            # end of speculation after exception, rollback and terminate
        ]
        expected_trace = hash(tuple(expected_trace_tmp))
        # print(expected_trace_tmp)
        # print(model.tracer.get_contract_trace_full())
        # model.LOG.dbg_model = False
        self.assertEqual(ctraces[0], expected_trace)

    def test_ct_skip_fault(self):
        model = x86_model.X86FaultSkip(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.handled_faults.update([12, 13])
        input_ = Input()
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        input_[0]['gpr'][2] = 4096
        input_[0]['faulty'][0] = 3
        ctraces = self.get_traces(model, ASM_FAULTY_ACCESS, [input_], pte_mask=PF_MASK)
        expected_trace = hash(tuple([
            0, 4096, 4088,  # fault
            4, 2,  # next instruction
            8, 2,  # speculatively execute the last instruction and rollback
            # terminate after rollback
        ]))   # yapf: disable
        self.assertEqual(ctraces[0], expected_trace)

    def test_ct_vsops(self):
        model = x86_model.x86UnicornVspecOpsDIV(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.handled_faults.add(21)
        input_ = Input()
        input_[0]['gpr'][0] = 0  # rax
        input_[0]['gpr'][1] = 0  # rbx
        input_[0]['gpr'][3] = 0  # rdx
        input_[0]['main'][0] = 0

        ctraces = self.get_traces(model, ASM_DIV_ZERO2, [input_])
        hash_of_operands = hash((
            (0x0, 35, 0),  # rax
            (0x0, 37, 0),  # rbx
            (0x0, 40, 0),  # rdx
            (0x3, 112, 0x1000000)  # r14
        ))
        hash_of_input = hash(((0, 0, hash(input_)),))
        expected_trace_full = tuple([
            0x0, 0xff8,  # fault
            0x3, hash_of_operands,  # first mem access exposes the hash of the div operands
            0x7, hash_of_input  # next mem access exposes the hash of the whole input
            # terminate after rollback
        ])  # yapf: disable
        self.assertEqual(ctraces[0], hash(expected_trace_full))

    def test_ct_vsall(self):
        model = x86_model.x86UnicornVspecAllDIV(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        model.handled_faults.add(21)
        input_ = Input()
        input_[0]['gpr'][0] = 2  # rax
        input_[0]['gpr'][1] = 0  # rbx
        input_[0]['gpr'][3] = 0  # rdx

        ctraces = self.get_traces(model, ASM_DIV_ZERO, [input_])
        hash_of_input = hash(((0, 0, hash(input_)),))
        expected_trace_full = tuple([
            0x0, 0xff8,  # fault
            0x2, hash_of_input,  # mem access exposes the input hash
            # terminate after rollback
        ])  # yapf: disable
        self.assertEqual(ctraces[0], hash(expected_trace_full))


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

        self.assertCountEqual(tracker.mem_dependencies['0x80'], ['A', 'B', '0x80'])
        self.assertCountEqual(tracker.tainted_labels, {'C'})
        self.assertEqual(taint[0]['gpr'][2], True)  # RCX

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
        self.assertEqual(taint[0]['gpr'][0], True)  # RAX - through flags
        self.assertEqual(taint[0]['gpr'][1], True)  # RBX - through flags + register
        self.assertEqual(taint[0]['gpr'][3], True)  # RDX - through flags

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
        self.assertEqual(taint[0]['gpr'][0], True)
        self.assertEqual(taint[0]['gpr'][1], True)

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
