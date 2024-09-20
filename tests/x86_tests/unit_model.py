"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=too-many-arguments
# pylint: disable=too-few-public-methods

import unittest
import tempfile
import os
from typing import List
from pathlib import Path
from copy import deepcopy

import src.x86.x86_model as x86_model
import src.model as core_model

from src.interfaces import TestCase, Input, CTrace
from src.isa_loader import InstructionSet
from src.x86.x86_generator import X86RandomGenerator
from src.x86.x86_asm_parser import X86AsmParser
from src.config import CONF

test_path = Path(__file__).resolve()
test_dir = test_path.parent

# base addresses for calculating expected contract traces
PC0 = 0x8
MEM_BASE = 0x1000000
CODE_BASE = 0x8000
MAIN_OFFSET = 0x1000
FAULTY_OFFSET = 0x2000

MEM_DEFAULT_VALUE = 1
REG_DEFAULT_VALUE = 2
MEM_FAULTY_DEFAULT_VALUE = 3
RSP_DEFAULT_VALUE = FAULTY_OFFSET - 8


class _Inst:
    """ Instruction with its size and memory address """
    text: str
    size: int
    mem_address: int
    mem_value: int
    pc_offset: int

    def __init__(self, text: str, size: int, mem_address: int, mem_value: int):
        self.text = text
        self.size = size
        self.mem_address = mem_address
        self.mem_value = mem_value
        self.pc_offset = 0


class _InstList:
    """ List of instructions with their memory addresses """
    instructions: List[_Inst]

    def __init__(self, instructions: List[_Inst]):
        # measurement_end macro is inserted automatically at the end
        instructions.append(_Inst(".macro.measurement_end:", 0, 0, 0))

        # set the pc_offset for each instruction
        self.set_offsets(instructions)
        self.instructions = instructions

    def __iter__(self):
        return iter(self.instructions)

    def __getitem__(self, index):
        return self.instructions[index]

    @staticmethod
    def set_offsets(instructions: List[_Inst]):
        """ Set the pc_offset for each instruction in a list """
        pc = PC0
        for inst in instructions:
            inst.pc_offset = pc
            pc += inst.size


ASM_HEADER = """
.intel_syntax noprefix
.test_case_enter:
.section .data.main
"""

ASM_BRANCH_AND_LOAD = _InstList([
    _Inst("xor rax, rax", 3, 0, 0),
    _Inst("jnz .l1", 2, 0, 0),
    _Inst(".l0:", 0, 0, 0),
    _Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
    _Inst(".l1:", 0, 0, 0),
])

ASM_DOUBLE_BRANCH = _InstList([
    _Inst("xor rax, rax", 3, 0, 0),
    _Inst("jnz .l1", 2, 0, 0),
    _Inst(".l0:", 0, 0, 0),
    _Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
    _Inst("jmp .l3", 2, 0, 0),
    _Inst(".l1:", 0, 0, 0),
    _Inst("xor rbx, rbx", 3, 0, 0),
    _Inst("jnz .l3", 2, 0, 0),
    _Inst(".l2:", 0, 0, 0),
    _Inst("mov rbx, qword ptr [r14]", 3, MAIN_OFFSET + 0, 2),
    _Inst(".l3:", 0, 0, 0),
])

ASM_STORE_AND_LOAD = _InstList([
    _Inst("mov qword ptr [r14], 42", 3, MAIN_OFFSET + 0, 42),
    _Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 42),
])

ASM_STORE_AND_LOAD_AND_LOAD = _InstList([
    _Inst("mov qword ptr [r14], 42", 7, MAIN_OFFSET + 0, 42),
    _Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 42),
    _Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + 42, 0),
])

ASM_FENCE = _InstList([
    _Inst("xor rax, rax", 3, 0, 0),
    _Inst("jz .l1", 2, 0, 0),
    _Inst(".l0:", 0, 0, 0),
    _Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
    _Inst("lfence", 2, 0, 0),
    _Inst("mov rax, qword ptr [r14 + 2]", 5, MAIN_OFFSET + 2, 2),
    _Inst(".l1:", 0, 0, 0),
])

ASM_FAULTY_ACCESS = _InstList([
    _Inst("mov rax, qword ptr [r14 + 0x1000]", 7, FAULTY_OFFSET, 0),
    _Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + 3, 0),
    _Inst("mov rbx, qword ptr [r14 + rbx]", 4, MAIN_OFFSET + REG_DEFAULT_VALUE, 0),
])

ASM_DIV_ZERO = _InstList([
    _Inst("div rbx", 3, 0, 0),
    _Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + 0, 0),
])

ASM_DIV_ZERO2 = _InstList([
    _Inst("div rbx", 3, 0, 0),
    _Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + 0, 0),
    _Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + 0, 0),
])

PF_MASK = 0xfffffffffffffffe


class X86ModelTest(unittest.TestCase):  # pylint: disable=too-many-public-methods
    """
    A suite of tests for the x86 Unicorn-based models
    """

    @classmethod
    def setUpClass(cls):
        # make sure that the change in the configuration does not impact the other tests
        cls.prev_conf = deepcopy(CONF)
        CONF.instruction_set = "x86-64"
        CONF.model = 'x86-unicorn'
        CONF.input_gen_seed = 10  # default
        CONF._no_generation = True  # pylint: disable=protected-access

    @classmethod
    def tearDownClass(cls):
        global CONF  # pylint: disable=global-statement
        CONF = cls.prev_conf

    @staticmethod
    def _init_model(model_class, tracer_class, arch_mode=False) -> x86_model.X86UnicornSeq:
        """ Initialize a model with the given tracer and return it """
        tracer = tracer_class()
        return model_class(MEM_BASE, CODE_BASE, tracer, arch_mode)

    @staticmethod
    def load_tc(asm_str: str):
        """ Load a test case from an assembly string """
        min_x86_path = test_dir / "min_x86.json"
        instruction_set = InstructionSet(min_x86_path.absolute().as_posix())

        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)
        parser = X86AsmParser(generator)

        asm_file = tempfile.NamedTemporaryFile(delete=False)
        with open(asm_file.name, "w", encoding="utf-8") as f:
            f.write(asm_str)
        tc: TestCase = parser.parse_file(asm_file.name)
        asm_file.close()
        os.unlink(asm_file.name)
        return tc

    def _get_traces(self,
                    model: x86_model.UnicornModel,
                    instr_list: _InstList,
                    inputs: List[Input],
                    nesting: int = 1,
                    pte_mask: int = 0) -> List[CTrace]:
        asm_str = ASM_HEADER + "\n".join([x.text for x in instr_list]) + "\n.test_case_exit:\n"
        tc = self.load_tc(asm_str)
        tc.actors["main"].data_properties = pte_mask
        model.load_test_case(tc)
        ctraces = model.trace_test_case(inputs, nesting)
        return ctraces

    @staticmethod
    def _get_default_ct_trace() -> List[int]:
        trace = []
        return trace

    @staticmethod
    def _get_default_input():
        input_ = Input()
        input_[0]['main'][0] = MEM_DEFAULT_VALUE
        input_[0]['main'][1] = MEM_DEFAULT_VALUE
        input_[0]['faulty'][0] = MEM_FAULTY_DEFAULT_VALUE
        input_[0]['faulty'][1] = MEM_FAULTY_DEFAULT_VALUE
        for i in range(0, 7):
            input_[0]['gpr'][i] = REG_DEFAULT_VALUE
        return input_

    def test_l1d_seq(self):
        """ Test L1DTracer with X86UnicornSeq """
        model = self._init_model(x86_model.X86UnicornSeq, core_model.L1DTracer)
        instructions = ASM_BRANCH_AND_LOAD
        ctraces = self._get_traces(model, instructions, [Input()])
        expected_trace = [(1 << 63)]
        self.assertEqual(ctraces[0].raw, expected_trace)

    def test_ct_seq(self):
        """ Test CTTracer with X86UnicornSeq """
        model = self._init_model(x86_model.X86UnicornSeq, core_model.CTTracer)
        instructions = ASM_BRANCH_AND_LOAD
        input_ = self._get_default_input()
        ctraces = self._get_traces(model, instructions, [input_])
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[3].pc_offset)
        expected_trace.append(instructions[3].mem_address)
        expected_trace.append(instructions[5].pc_offset)

        # print([hex(x - model.layout.code_start) for x in model.tracer.get_contract_trace_full()])
        self.assertEqual(ctraces[0].raw, expected_trace)

    def test_ct_arch_mode(self):
        """ Test CTTracer with X86UnicornSeq in the architectural mode """
        model = self._init_model(x86_model.X86UnicornSeq, core_model.CTTracer, True)
        instructions = ASM_STORE_AND_LOAD
        input_ = self._get_default_input()
        _ = self._get_traces(model, instructions, [input_])
        full_trace = model.tracer.get_contract_trace_full()

        expected_trace = [
            instructions[1].mem_value,
            REG_DEFAULT_VALUE,
            REG_DEFAULT_VALUE,
            REG_DEFAULT_VALUE,
            REG_DEFAULT_VALUE,
            REG_DEFAULT_VALUE,
        ]
        self.assertEqual(full_trace, expected_trace)

    def test_arch_seq(self):
        """ Test ArchTracer with X86UnicornSeq """
        model = self._init_model(x86_model.X86UnicornSeq, core_model.ArchTracer)
        instructions = ASM_BRANCH_AND_LOAD
        input_ = self._get_default_input()
        ctraces = self._get_traces(model, instructions, [input_])
        expected_trace = self._get_default_ct_trace()

        expected_trace = [
            REG_DEFAULT_VALUE, REG_DEFAULT_VALUE, REG_DEFAULT_VALUE, REG_DEFAULT_VALUE,
            REG_DEFAULT_VALUE, REG_DEFAULT_VALUE, REG_DEFAULT_VALUE, RSP_DEFAULT_VALUE
        ] + expected_trace

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[3].pc_offset)
        expected_trace.append(instructions[3].mem_value)
        expected_trace.append(instructions[3].mem_address)
        expected_trace.append(instructions[5].pc_offset)

        self.assertEqual(ctraces[0].raw, expected_trace)

    def test_ct_cond(self):
        """ Test CTTracer with X86UnicornCond """
        model = self._init_model(x86_model.X86UnicornCond, core_model.CTTracer)
        instructions = ASM_BRANCH_AND_LOAD
        input_ = self._get_default_input()
        ctraces = self._get_traces(model, instructions, [input_])
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[5].pc_offset)
        expected_trace.append(instructions[3].pc_offset)
        expected_trace.append(instructions[3].mem_address)
        expected_trace.append(instructions[5].pc_offset)

        self.assertEqual(ctraces[0].raw, expected_trace)

    def test_ct_cond_double(self):
        """ Test CTTracer with X86UnicornCond, with nested misprediction """
        model = self._init_model(x86_model.X86UnicornCond, core_model.CTTracer)
        instructions = ASM_DOUBLE_BRANCH
        input_ = self._get_default_input()
        ctraces = self._get_traces(model, instructions, [input_], nesting=2)
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[5].pc_offset)
        expected_trace.append(instructions[7].pc_offset)
        expected_trace.append(instructions[10].pc_offset)
        expected_trace.append(instructions[9].pc_offset)
        expected_trace.append(instructions[9].mem_address)
        expected_trace.append(instructions[10].pc_offset)
        expected_trace.append(instructions[3].pc_offset)
        expected_trace.append(instructions[3].mem_address)
        expected_trace.append(instructions[4].pc_offset)
        expected_trace.append(instructions[10].pc_offset)

        self.assertEqual(ctraces[0].raw, expected_trace)

    def test_ct_bpas(self):
        """ Test CTTracer with X86UnicornBpas """
        model = self._init_model(x86_model.X86UnicornBpas, core_model.CTTracer)
        instructions = ASM_STORE_AND_LOAD_AND_LOAD
        input_ = self._get_default_input()
        ctraces = self._get_traces(model, instructions, [input_])
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)

        # speculative
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[1].mem_address)
        rax = MEM_DEFAULT_VALUE
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(MAIN_OFFSET + rax)
        expected_trace.append(instructions[3].pc_offset)

        # after rollback
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[1].mem_address)
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(instructions[2].mem_address)
        expected_trace.append(instructions[3].pc_offset)

        self.assertEqual(ctraces[0].raw, expected_trace)

    def test_rollback_on_fence(self):
        """ Test the rollback mechanism on a fence instruction """
        model = self._init_model(x86_model.X86UnicornCond, core_model.CTTracer)
        instructions = ASM_FENCE
        input_ = self._get_default_input()
        ctraces = self._get_traces(model, instructions, [input_])
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[3].pc_offset)
        expected_trace.append(instructions[3].mem_address)
        expected_trace.append(instructions[4].pc_offset)
        expected_trace.append(instructions[7].pc_offset)

        self.assertEqual(ctraces[0].raw, expected_trace)

    def test_fault_handling(self):
        """ Test the fault handling mechanism """
        model = self._init_model(x86_model.X86UnicornSeq, core_model.CTTracer)
        model.handled_faults.update([12, 13])
        instructions = ASM_FAULTY_ACCESS
        input_ = self._get_default_input()
        ctraces = self._get_traces(model, instructions, [input_], pte_mask=PF_MASK)
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)

        self.assertEqual(ctraces[0].raw, expected_trace)

    def test_ct_deh(self):
        """ Test X86UnicornDEH with CTTracer """
        model = self._init_model(x86_model.X86UnicornDEH, core_model.CTTracer)
        model.handled_faults.update([12, 13])
        instructions = ASM_FAULTY_ACCESS
        input_ = self._get_default_input()
        ctraces = self._get_traces(model, instructions, [input_], pte_mask=PF_MASK)
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(instructions[2].mem_address)
        expected_trace.append(instructions[3].pc_offset)

        self.assertEqual(ctraces[0].raw, expected_trace)

    def test_ct_nullinj_assist(self):
        """ Test X86UnicornNullAssist with CTTracer """
        model = self._init_model(x86_model.X86UnicornNullAssist, core_model.CTTracer)
        model.handled_faults.update([12, 13])
        instructions = ASM_FAULTY_ACCESS
        input_ = self._get_default_input()
        ctraces = self._get_traces(model, instructions, [input_], pte_mask=PF_MASK)
        expected_trace = self._get_default_ct_trace()

        # fault
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)

        # re-execute with changed permissions and inject zero into rax
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        rax = 0

        # execute with speculative rax
        expected_trace.append(instructions[1].pc_offset)  # traced twice due to a quirk in Unicorn
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(MAIN_OFFSET + rax)
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(instructions[2].mem_address)
        expected_trace.append(instructions[3].pc_offset)

        # rollback and re-execute without a fault
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[1].mem_address)
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(instructions[2].mem_address)
        expected_trace.append(instructions[3].pc_offset)

        self.assertEqual(ctraces[0].raw, expected_trace)

    def test_ct_nullinj_term(self):
        """ Test X86UnicornNull with CTTracer """
        model = self._init_model(x86_model.X86UnicornNull, core_model.CTTracer)
        model.handled_faults.update([12, 13])
        instructions = ASM_FAULTY_ACCESS
        input_ = self._get_default_input()
        ctraces = self._get_traces(model, instructions, [input_], pte_mask=PF_MASK)
        expected_trace = self._get_default_ct_trace()

        # fault
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)

        # re-execute with changed permissions and inject zero into rax
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        rax = 0

        # execute with speculative rax
        expected_trace.append(instructions[1].pc_offset)  # traced twice due to a quirk in Unicorn
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(MAIN_OFFSET + rax)
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(instructions[2].mem_address)
        expected_trace.append(instructions[3].pc_offset)

        self.assertEqual(ctraces[0].raw, expected_trace)

    def test_ct_meltdown(self):
        """ Test X86Meltdown with CTTracer """
        model = self._init_model(x86_model.X86Meltdown, core_model.CTTracer)
        model.handled_faults.update([12, 13])
        instructions = ASM_FAULTY_ACCESS
        input_ = self._get_default_input()
        ctraces = self._get_traces(model, instructions, [input_], pte_mask=PF_MASK)
        expected_trace = self._get_default_ct_trace()

        # fault
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)

        # re-execute with changed permissions and inject zero into rax
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        rax = MEM_FAULTY_DEFAULT_VALUE

        # execute with speculative rax
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(MAIN_OFFSET + rax)
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(instructions[2].mem_address)
        expected_trace.append(instructions[3].pc_offset)

        self.assertEqual(ctraces[0].raw, expected_trace)

    @unittest.skip("Not maintained")
    def test_ct_vsops(self):
        """ Test x86UnicornVspecOpsDIV with CTTracer """
        pass

    @unittest.skip("Not maintained")
    def test_ct_vsall(self):
        """ Test x86UnicornVspecAllDIV with CTTracer """
        pass


if __name__ == '__main__':
    unittest.main()
