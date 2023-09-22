"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import os
import tempfile
import subprocess
from pathlib import Path

from src.x86.x86_executor import X86IntelExecutor
from src.x86.x86_generator import X86RandomGenerator
from src.x86.x86_asm_parser import X86AsmParser
from src.isa_loader import InstructionSet
from src.interfaces import TestCase, Input
from src.config import CONF

test_path = Path(__file__).resolve()
test_dir = test_path.parent


class ExecutorTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tc: TestCase = TestCase(0)
        asm_file = tempfile.NamedTemporaryFile(delete=False)

        with open(asm_file.name, "w") as f:
            f.write(".intel_syntax noprefix\n"
                    ".test_case_enter:\n"
                    ".section .data.0_host\n"
                    "mov rax, qword ptr [r14 + 0x200]\n"
                    ".test_case_exit:\n")

        min_x86_path = test_dir / "min_x86.json"
        instruction_set = InstructionSet(min_x86_path.absolute().as_posix())
        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)
        parser = X86AsmParser(generator)

        cls.tc = parser.parse_file(asm_file.name)
        asm_file.close()
        os.unlink(asm_file.name)

    def test_init(self):
        # check if the executor kernel module is properly loaded and can be initialized
        executor = X86IntelExecutor()
        self.assertTrue(executor)

    def test_load(self):
        executor = X86IntelExecutor()
        executor.load_test_case(self.tc)
        out = subprocess.check_output(
            "cat /sys/x86_executor/test_case > tmp.o ;"
            " objdump -D -b binary -m i386:x86-64 tmp.o",
            shell=True).decode()
        self.assertIn("mov    0x200(%r14),%rax", out)
        self.assertNotIn("(bad)", out)

    def test_trace(self):
        executor = X86IntelExecutor()
        executor.load_test_case(self.tc)

        inputs = [Input(), Input()]  # single zero-initialized inputs
        traces = executor.trace_test_case(inputs, 2)
        self.assertEqual(len(traces), 2)

    def test_big_batch(self):
        executor = X86IntelExecutor()
        executor.load_test_case(self.tc)

        inputs = [Input() for _ in range(0, 300)]
        traces = executor.trace_test_case(inputs, 2)
        self.assertEqual(len(traces), 300)
