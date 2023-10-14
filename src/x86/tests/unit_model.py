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
    FlagsOperand, TestCase, Input, CTrace
from src.isa_loader import InstructionSet
from src.x86.x86_generator import X86RandomGenerator
from src.x86.x86_asm_parser import X86AsmParser
from src.config import CONF

test_path = Path(__file__).resolve()
test_dir = test_path.parent

ASM_HEADER = """
.intel_syntax noprefix
.test_case_enter:
.section .data.main
"""

ASM_THREE_LOADS = ASM_HEADER + """
MOV RAX, qword ptr [R14]
MOV RAX, qword ptr [R14 + 512]
MOV RAX, qword ptr [R14 + 1050]
.test_case_exit:
"""

ASM_BRANCH_AND_LOAD = ASM_HEADER + """
XOR rax, rax
JNZ .l1
.l0:
MOV RAX, qword ptr [R14]
.l1:
.test_case_exit:
"""

ASM_DOUBLE_BRANCH = ASM_HEADER + """
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
.test_case_exit:
"""

ASM_STORE_AND_LOAD = ASM_HEADER + """
MOV qword ptr [R14], 2
MOV RAX, qword ptr [R14]
MOV RAX, qword ptr [R14 + RAX]
.test_case_exit:
"""

ASM_FENCE = ASM_HEADER + """
XOR rax, rax
JZ .l1
.l0:
MOV RAX, qword ptr [R14]
LFENCE
MOV RAX, qword ptr [R14 + 2]
.l1:
.test_case_exit:
"""

ASM_FAULTY_ACCESS = ASM_HEADER + """
MOV RAX, qword ptr [R14 + RCX]
MOV RAX, qword ptr [R14 + RAX]
MOV RBX, qword ptr [R14 + RBX]
.test_case_exit:
"""

ASM_BRANCH_AND_FAULT = ASM_HEADER + """
XOR rax, rax
JZ .l1
.l0:
MOV RAX, qword ptr [R14 + RCX]
MOV RAX, qword ptr [R14 + RAX]
.l1:
NOP
.test_case_exit:
"""

ASM_FAULT_AND_BRANCH = ASM_HEADER + """
MOV RAX, qword ptr [R14 + RCX]
XOR rbx, rbx
JZ .l1
.l0:
MOV RAX, qword ptr [R14 + RAX]
.l1:
NOP
.test_case_exit:
"""

ASM_DIV_ZERO = ASM_HEADER + """
DIV EBX
MOV rax, qword ptr [R14 + RAX]
.test_case_exit:
"""

ASM_DIV_ZERO2 = ASM_HEADER + """
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
        CONF._no_generation = True

    @classmethod
    def tearDownClass(cls):
        global CONF
        CONF = cls.prev_conf

    @staticmethod
    def load_tc(asm_str: str):
        min_x86_path = test_dir / "min_x86.json"
        instruction_set = InstructionSet(min_x86_path.absolute().as_posix())

        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)
        parser = X86AsmParser(generator)

        asm_file = tempfile.NamedTemporaryFile(delete=False)
        with open(asm_file.name, "w") as f:
            f.write(asm_str)
        tc: TestCase = parser.parse_file(asm_file.name)
        asm_file.close()
        os.unlink(asm_file.name)
        return tc

    def get_traces(self, model, asm_str, inputs, nesting=1, pte_mask: int = 0):
        tc = self.load_tc(asm_str)
        tc.actors["main"].data_properties = pte_mask
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

    def test_ct_seq(self):
        model = x86_model.X86UnicornSeq(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [Input()])
        expected_trace = hash(tuple([0x0, 0x5, 0x8, 0xa, 0, 0xd]))
        # print([hex(x - model.code_start) for x in model.tracer.get_contract_trace_full()])
        self.assertEqual(ctraces, [expected_trace])

    def test_ctr_seq(self):
        model = x86_model.X86UnicornSeq(0x1000000, 0x8000)
        model.tracer = core_model.CTRTracer()
        input_ = Input()
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [input_])
        # print([hex(x - model.code_start) for x in model.tracer.get_contract_trace_full()])
        expected_trace = hash(
            tuple([
                2, 2, 2, 2, 2, 2, 2, model.stack_base - model.sandbox_base, 0x0, 0x5, 0x8, 0xa, 0,
                0xd
            ]))
        self.assertEqual(ctraces, [expected_trace])

    def test_arch_seq(self):
        model = x86_model.X86UnicornSeq(0x1000000, 0x8000)
        model.tracer = core_model.ArchTracer()
        input_ = Input()
        input_[0]['main'][0] = 1
        for i in range(0, 7):
            input_[0]['gpr'][i] = 2
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [input_])
        # print([hex(x - model.code_start) for x in model.tracer.get_contract_trace_full()])
        expected_trace = hash(
            tuple([
                2, 2, 2, 2, 2, 2, 2, model.stack_base - model.sandbox_base, 0x0, 0x5, 0x8, 0xa, 1,
                0, 0xd
            ]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_cond(self):
        model = x86_model.X86UnicornCond(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [Input()])
        # print([hex(x - model.code_start) for x in model.tracer.get_contract_trace_full()])
        expected_trace = hash(tuple([0x0, 0x5, 0x8, 0xd, 0xa, 0, 0xd]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_cond_double(self):
        model = x86_model.X86UnicornCond(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        ctraces = self.get_traces(model, ASM_DOUBLE_BRANCH, [Input()], nesting=2)
        # print([hex(x - model.code_start) for x in model.tracer.get_contract_trace_full()])
        expected_trace = hash(
            tuple([
                0x0,
                0x5,  # XOR rax, rax
                0x8,  # JNZ .l1
                0xf,  # XOR rbx, rbx
                0x12,  # JNZ .l3
                0x17,
                # rollback inner speculation
                0x14,
                0,  # MOV RBX, qword ptr [R14]
                0x17,
                # rollback outer speculation
                0xa,
                0,  # MOV RAX, qword ptr [R14]
                0xd,  # JMP .l3
                0x17,
            ]))
        self.assertEqual(ctraces, [expected_trace])

    @unittest.skip("under construction")
    def test_ct_bpas(self):
        model = x86_model.X86UnicornBpas(0x1000000, 0x8000)
        model.tracer = core_model.CTTracer()
        input_ = Input()
        input_['main'][0] = 1
        ctraces = self.get_traces(model, ASM_STORE_AND_LOAD, [input_])
        expected_trace = hash(tuple([0, 0, 7, 0, 10, 1, 14, 7, 0, 10, 2, 14]))
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
        expected_trace = hash(tuple([0x0, 0x5, 4096, 4088]))
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
        # print([hex(x - model.code_start) for x in model.tracer.get_contract_trace_full()])
        expected_trace = hash(tuple([
            0x0,
            0x5, 4096, 4088,  # fault
            0x5, 4096,  # speculative injection
            0x9,  # speculatively start executing the next instr
            0x9, 0,  # re-execute the instruction after setting the permissions
            0xd, 2, 0x11,  # speculatively execute the last instruction and rollback
            0x5, 4096, 0x9, 3, 0xd, 2,  # after rollback
            0x11,
            # terminate after rollback
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
        # print([hex(x - model.code_start) for x in model.tracer.get_contract_trace_full()])
        # model.LOG.dbg_model = not model.LOG.dbg_model
        expected_trace = hash(tuple([
            0x0,
            0x5, 4096, 4088,  # fault
            0x5, 4096,  # speculative injection
            0x9,  # speculatively start executing the next instr
            0x9, 0,  # re-execute the instruction after setting the permissions
            0xd, 2, 0x11,  # speculatively execute the last instruction and rollback
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
        # print([hex(x - model.code_start) for x in model.tracer.get_contract_trace_full()])
        expected_trace = hash(tuple([
            0x0,
            0x5, 4096, 4088,  # faulty load
            0x9,  # next load is dependent - do not execute the mem access
            0xd, 2, 0x11,  # speculatively execute the last instruction and rollback
            # terminate after rollback
        ]))   # yapf: disable
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
            0x0,
            0x5, 4096, 4088,  # faulty load
            0x5, 4096,  # speculative injection
            0x9, 3,  # next load is dependent - do not execute the mem access
            0xd, 2,  # speculatively execute the last instruction and rollback
            0x11,
            # terminate after rollback
        ]))   # yapf: disable
        self.assertEqual(ctraces[0], expected_trace)

    @unittest.skip("under construction")
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
                8, 2, 12,  # speculatively execute the last instruction and rollback
                # terminate after rollback
            ]))   # yapf: disable
        self.assertEqual(ctraces[0], expected_trace)

    @unittest.skip("under construction")
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
            13, 14,  # last instruction of speculation caused by exception, rollback
            13, 14,  # execution of correct branch
        ]))   # yapf: disable
        self.assertEqual(ctraces[0], expected_trace)

    @unittest.skip("under construction")
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
            13,
            14,  # end of branch speculation, rollback
            13,
            14,  # execution of correct branch
            # end of speculation after exception, rollback and terminate
        ]
        expected_trace = hash(tuple(expected_trace_tmp))
        # print(expected_trace_tmp)
        # print(model.tracer.get_contract_trace_full())
        # model.LOG.dbg_model = False
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
        # print([hex(x - model.code_start) for x in model.tracer.get_contract_trace_full()])
        hash_of_operands = hash((
            (0x5, 35, 0),  # rax
            (0x5, 37, 0),  # rbx
            (0x5, 40, 0),  # rdx
            (0x8, 112, 0x1000000)  # r14
        ))
        hash_of_input = hash(((0, 0, hash(input_)),))
        expected_trace_full = tuple([
            0x0,
            0x5, 0xff8,  # fault
            0x8, hash_of_operands,  # first mem access exposes the hash of the div operands
            0xc, hash_of_input,  # next mem access exposes the hash of the whole input
            0x10,  # terminate after rollback
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
        # print([hex(x - model.code_start) for x in model.tracer.get_contract_trace_full()])
        hash_of_input = hash(((0, 0, hash(input_)),))
        expected_trace_full = tuple([
            0x0,
            0x5, 0xff8,  # fault
            0x7, hash_of_input, 0xb,  # mem access exposes the input hash
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
