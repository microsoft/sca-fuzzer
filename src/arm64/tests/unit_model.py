"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import unittest
import tempfile
import sys
import os
import unicorn.arm64_const as ucc
from copy import deepcopy
from typing import List
from pathlib import Path

sys.path.insert(0, '..')
import model as core_model
import arm64.arm64_model as arm64_model
from arm64.arm64_generator import ARMRandomGenerator
from isa_loader import InstructionSet
from interfaces import TestCase, Input, CTrace
from config import CONF
from service import LOGGER

test_path = Path(__file__).resolve()
test_dir = test_path.parent

ASM_THREE_LOADS = """
.test_case_enter:
LDR x0, [x30], #128
LDR x0, [x30], #120
LDR x0, [x30], #0
.test_case_exit:
"""

ASM_BRANCH_AND_LOAD = """
.test_case_enter:
MOV x1, #0
CMP x0, x1
B.EQ .l1
.l0:
LDR x0, [x30], #0
.l1:
.test_case_exit:
"""

ASM_STORE_AND_LOAD = """
.test_case_enter:
STR x0, [x30], #0
LDR x1, [x30], #0
ADD x30, x30, x1
LDR x1, [x30], #0
.test_case_exit:
"""

ASM_FENCE = """
.test_case_enter:
STR x0, [x30], #0
LDR x1, [x30], #0
ADD x30, x30, x1
DSB SY
LDR x1, [x30], #0
.test_case_exit:
"""


def tc_from_str(isa: InstructionSet, string: str):
    generator = ARMRandomGenerator(isa, CONF.program_generator_seed)
    asm_file = tempfile.NamedTemporaryFile(delete=False)
    with open(asm_file.name, "w") as f:
        f.write(string)
    tc: TestCase = generator.parse_existing_test_case(asm_file.name)
    asm_file.close()
    os.unlink(asm_file.name)
    return tc


def tc_from_bin(bin_contents):
    bin_file = tempfile.NamedTemporaryFile(delete=False)
    with open(bin_file.name, "wb") as f:
        f.write(bin_contents)
    tc = TestCase()
    tc.bin_path = bin_file.name
    return tc, bin_file


class ARMModelTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # make sure that the change in the configuration does not impact the other tests
        cls.prev_conf = deepcopy(CONF)
        CONF.instruction_set = "arm64"
        CONF.input_gen_seed = 10  # default
        CONF.setattr_internal("_no_generation", True)
        json_path = test_dir / 'min_arm64.json'
        cls.default_isa = InstructionSet(json_path.absolute().as_posix())

    @classmethod
    def tearDownClass(cls):
        global CONF
        CONF = cls.prev_conf

    def get_traces(self, model, asm_str, inputs) -> List[CTrace]:
        tc = tc_from_str(self.default_isa, asm_str)
        model.load_test_case(tc)
        ctraces = model.trace_test_case(inputs, 1)
        return ctraces

    def test_tc_loading(self):
        bin_contents = b'\x00\x01\x02\x03'
        tc, bin_file = tc_from_bin(bin_contents)

        model = arm64_model.ARM64UnicornSeq(0x10000, 0x20000)
        model.load_test_case(tc)

        # check that an emulator is created
        self.assertTrue(model.emulator)

        # check that the binary is loaded
        self.assertEqual(model.emulator.mem_read(0x20000, 4), bin_contents)

        bin_file.close()
        os.unlink(bin_file.name)

    def test_input_loading(self):
        asm = ".test_case_enter:\nADD x10, x10, x10\n.test_case_exit:"
        tc = tc_from_str(self.default_isa, asm)
        reg_values = [0, 1, 2, 3, 4, 5, 6]
        input_ = Input()
        input_[input_.register_start:input_.data_size - 1] = reg_values

        model = arm64_model.ARM64UnicornSeq(0x10000, 0x20000)
        model.tracer = core_model.L1DTracer()
        model.load_test_case(tc)
        _ = model.trace_test_case([input_], 1)

        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X30), 0x10000)
        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X0), reg_values[0])
        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X1), reg_values[1])
        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X2), reg_values[2])
        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X3), reg_values[3])
        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X4), reg_values[4])
        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X5), reg_values[5])
        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_NZCV), reg_values[6] << 28)

    def test_l1d_seq(self):
        model = arm64_model.ARM64UnicornSeq(0x1000000, 0x8000)
        model.tracer = core_model.L1DTracer()
        ctraces = self.get_traces(model, ASM_THREE_LOADS, [Input()])
        expected_trace = (1 << 63) + (1 << 61) + (1 << 60)
        self.assertEqual(ctraces, [expected_trace])

    def test_mem_seq(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = arm64_model.ARM64UnicornSeq(mem_base, code_base)
        model.tracer = core_model.MemoryTracer()
        ctraces = self.get_traces(model, ASM_THREE_LOADS, [Input()])
        expected_trace = hash(tuple([mem_base + 0, mem_base + 128, mem_base + 248]))
        self.assertEqual(ctraces, [expected_trace])

    def test_pc_seq(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = arm64_model.ARM64UnicornSeq(mem_base, code_base)
        model.tracer = core_model.PCTracer()
        # LOGGER.dbg_model = True
        input_ = Input()
        input_[input_.register_start] = 0
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [input_])
        expected_trace = hash(tuple([code_base + 0x0, code_base + 0x4, code_base + 0x8]))
        # print(model.tracer.get_contract_trace_full(), mem_base, code_base)
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_seq(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = arm64_model.ARM64UnicornSeq(mem_base, code_base)
        model.tracer = core_model.CTTracer()
        input_ = Input()
        input_[input_.register_start] = 1
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [input_])
        expected_trace = hash(
            tuple([code_base + 0x0, code_base + 0x4, code_base + 0x8, code_base + 0xc, mem_base]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ctr_seq(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = arm64_model.ARM64UnicornSeq(mem_base, code_base)
        model.tracer = core_model.CTRTracer()
        input_ = Input()
        for i in range(0, 7):
            input_[input_.register_start + i] = 2
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [input_])
        expected_trace = hash(
            tuple([
                2, 2, 2, 2, 2, 2, 2 << 28, code_base + 0x0, code_base + 0x4, code_base + 0x8,
                code_base + 0xc, mem_base
            ]))
        self.assertEqual(ctraces, [expected_trace])

    def test_arch_seq(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = arm64_model.ARM64UnicornSeq(mem_base, code_base)
        model.tracer = core_model.ArchTracer()
        input_ = Input()
        input_[0] = 1
        for i in range(0, 7):
            input_[input_.register_start + i] = 2
        ctraces = self.get_traces(model, ASM_BRANCH_AND_LOAD, [input_])
        expected_trace = hash(
            tuple([
                2, 2, 2, 2, 2, 2, 2 << 28, code_base + 0x0, code_base + 0x4, code_base + 0x8,
                code_base + 0xc, 1, mem_base
            ]))
        self.assertEqual(ctraces, [expected_trace])

    def test_ct_bpas(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = arm64_model.ARM64UnicornBpas(mem_base, code_base)
        model.tracer = core_model.CTTracer()
        input_ = Input()
        input_[0] = 1
        input_[input_.register_start] = 2
        ctraces = self.get_traces(model, ASM_STORE_AND_LOAD, [input_])
        expected_trace = hash(
            tuple([
                code_base, mem_base, code_base + 4, mem_base, code_base + 8, code_base + 12,
                mem_base + 1, code_base + 4, mem_base, code_base + 8, code_base + 12, mem_base + 2
            ]))
        self.assertEqual(ctraces, [expected_trace])

    def test_rollback_on_fence(self):
        mem_base, code_base = 0x1000000, 0x8000
        model = arm64_model.ARM64UnicornBpas(mem_base, code_base)
        model.tracer = core_model.CTTracer()
        input_ = Input()
        input_[0] = 1
        input_[input_.register_start] = 2
        ctraces = self.get_traces(model, ASM_FENCE, [input_])
        expected_trace = hash(
            tuple([
                code_base, mem_base, code_base + 4, mem_base, code_base + 8, code_base + 12,
                code_base + 4, mem_base, code_base + 8, code_base + 12, code_base + 16, mem_base + 2
            ]))
        self.assertEqual(ctraces, [expected_trace])
