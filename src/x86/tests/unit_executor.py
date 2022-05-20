"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import sys
import os
import tempfile
import subprocess

sys.path.insert(0, '..')
from executor import X86IntelExecutor
from generator import X86Generator
from interfaces import TestCase, Input


class ExecutorTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tc: TestCase = TestCase()
        asm_file = tempfile.NamedTemporaryFile(delete=False)
        bin_file = tempfile.NamedTemporaryFile(delete=False)

        with open(asm_file.name, "w") as f:
            f.write("movq %r14, %rax; add $512, %rax; movq (%rax), %rax\n")
            # f.write("nop")

        try:
            X86Generator.assemble(asm_file.name, bin_file.name)
        except Exception:
            asm_file.close()
            bin_file.close()
            os.unlink(asm_file.name)
            os.unlink(bin_file.name)
            return

        asm_file.close()
        os.unlink(asm_file.name)

        cls.tc.bin_path = bin_file.name
        cls.bin_file = bin_file

    @classmethod
    def tearDownClass(cls):
        cls.bin_file.close()
        os.unlink(cls.bin_file.name)

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
        self.assertIn("add    $0x200,%rax", out)
        self.assertNotIn("(bad)", out)

    def test_trace(self):
        executor = X86IntelExecutor()
        executor.load_test_case(self.tc)

        inputs = [Input(), Input()]  # single zero-initialized inputs
        traces = executor.trace_test_case(inputs, 2)

        self.assertEqual(traces, [9259400833873739776, 9259400833873739776])

    def test_big_batch(self):
        executor = X86IntelExecutor()
        executor.load_test_case(self.tc)

        inputs = [Input() for _ in range(0, 300)]
        traces = executor.trace_test_case(inputs, 2)

        self.assertEqual(traces[0], 9259400833873739776)
        self.assertEqual(traces[299], 9259400833873739776)


if __name__ == '__main__':
    unittest.main()
