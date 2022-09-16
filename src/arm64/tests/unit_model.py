"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import unittest
import tempfile
import sys
import os
import unicorn.arm64_const as ucc

sys.path.insert(0, '..')
from model import L1DTracer
from arm64.arm64_model import ARM64UnicornSeq
from arm64.arm64_generator import ARMRandomGenerator
from isa_loader import InstructionSet
from interfaces import TestCase, Input
from config import CONF

CONF.instruction_set = "arm64"


def tc_from_str(isa: InstructionSet, string: str):
    generator = ARMRandomGenerator(isa)
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
    def __init__(self, methodName: str = ...) -> None:
        self.default_isa = InstructionSet('isa_spec/base.json', CONF.instruction_categories)
        super().__init__(methodName)

    def test_tc_loading(self):
        bin_contents = b'\x00\x01\x02\x03'
        tc, bin_file = tc_from_bin(bin_contents)

        model = ARM64UnicornSeq(0x10000, 0x20000)
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

        model = ARM64UnicornSeq(0x10000, 0x20000)
        model.tracer = L1DTracer()
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

    def test_tracing(self):
        asm = """
.test_case_enter:
ADD x0, x0, x30
LDRH w1, [x0], #0
.test_case_exit:
"""
        tc = tc_from_str(self.default_isa, asm)
        input_ = Input()
        input_[16] = 42  # sandbox base + 128
        input_[input_.register_start] = 128  # x0
        input_[input_.data_size - 1] = 0  # flags

        model = ARM64UnicornSeq(0x10000, 0x20000)
        model.tracer = L1DTracer()
        model.load_test_case(tc)
        traces = model.trace_test_case([input_], 1)

        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X30), 0x10000)
        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_X0), 0x10080)
        self.assertEqual(model.emulator.reg_read(ucc.UC_ARM64_REG_W1), 42)
        self.assertEqual(traces[0], 1 << 61)
