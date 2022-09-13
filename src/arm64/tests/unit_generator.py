"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import tempfile
import sys
import subprocess
import os

sys.path.insert(0, '..')
from arm64.arm64_generator import ARMRandomGenerator, ARMPrinter, OT
from factory import get_generator
from isa_loader import InstructionSet
from interfaces import TestCase
from config import CONF

CONF.instruction_set = "arm64"

PARSING_TEST_CASE = """
ISB  // instrumentation
.test_case_enter:

.function_main:
.bb_main.entry:
B .bb_main.0
.bb_main.0:

  // line with a comment

ADC W11, W20, W10  // register operands
AND X13, X13, #0b1111111000000     // immediate operand
ADD X13, X13, X30 // instrumentation
LDRH W23, [X13], #-115 // memory operand

B.NE .bb_main.1
B .bb_main.exit
  .bb_main.1:
    ADC W1, W2, W3  // indentation
    AND X30, X30, #0b1111111000000
    ADD X30, X30, X30
        LDRH W28, [ X30],     #-143    // extra spaces

.bb_main.exit:
.test_case_exit:
ISB  // instrumentation
"""


class ARMRandomGeneratorTest(unittest.TestCase):

    def test_configuration(self):
        instruction_set = InstructionSet('isa_spec/base.json', CONF.instruction_categories)
        gen = get_generator(instruction_set)
        self.assertEqual(gen.__class__, ARMRandomGenerator)

    def test_create_test_case(self):
        instruction_set = InstructionSet('isa_spec/base.json', CONF.instruction_categories)
        self.assertNotEqual(len(instruction_set.instructions), 0)

        generator = ARMRandomGenerator(instruction_set)

        asm_file = tempfile.NamedTemporaryFile(delete=False)
        name = asm_file.name
        # name = "tmp.asm"
        tc: TestCase = generator.create_test_case(name)
        size = len([i for bb in tc.functions for i in bb])
        self.assertNotEqual(size, 0)

        # get a list of relative instruction addresses
        dump = subprocess.run(
            f"aarch64-linux-gnu-objdump -D -b binary -m aarch64 {tc.bin_path} "
            "| awk '/ [0-9a-f]+:/{print $1, $3}'",
            shell=True,
            check=True,
            capture_output=True)
        for line in dump.stdout.decode().split("\n"):
            if not line:
                continue
            addr, name = line.split(": ")
            if "b." in name:
                name = "b."
            mapped_name = tc.address_map[int(addr, 16)].name
            if mapped_name != "UNMAPPED":
                self.assertEqual(name.upper(), mapped_name)

        asm_file.close()
        os.unlink(asm_file.name)

    def test_arm_parse_asm(self):
        gpr_blocklist_old = CONF.register_blocklist
        instruction_blocklist_old = CONF.instruction_blocklist
        CONF.register_blocklist = []
        CONF.instruction_blocklist = []
        instruction_set = InstructionSet('isa_spec/base.json')
        CONF.register_blocklist = gpr_blocklist_old
        CONF.instruction_blocklist = instruction_blocklist_old

        generator = ARMRandomGenerator(instruction_set)
        asm_file = tempfile.NamedTemporaryFile(delete=False)
        with open(asm_file.name, "w") as f:
            f.write(PARSING_TEST_CASE)
        tc: TestCase = generator.parse_existing_test_case(asm_file.name)
        asm_file.close()
        os.unlink(asm_file.name)

        self.assertEqual(len(tc.functions), 1)

        main = tc.functions[0]
        self.assertEqual(main.name, ".function_main")
        self.assertEqual(len(main), 4)
        main_iter = iter(main)

        entry = next(main_iter)
        bb0 = next(main_iter)
        bb1 = next(main_iter)
        exit_ = next(main_iter)

        self.assertEqual(entry.successors[0], bb0)
        self.assertEqual(bb0.successors[0], bb1)
        self.assertEqual(bb0.successors[1], exit_)
        self.assertEqual(bb1.successors[0], exit_)

        inst = bb0.get_first()
        self.assertEqual(inst.name, "ADC")
        self.assertEqual(len(inst.operands), 3)
        self.assertEqual(inst.operands[0].value, "W11")
        self.assertEqual(inst.operands[0].type, OT.REG)
        self.assertEqual(inst.operands[0].width, 32)
        self.assertEqual(inst.operands[1].value, "W20")
        self.assertEqual(inst.operands[2].value, "W10")

    def test_arm_all_instructions(self):
        instruction_set = InstructionSet('isa_spec/base.json', CONF.instruction_blocklist)
        generator = ARMRandomGenerator(instruction_set)
        func = generator.generate_function("function_main")
        printer = ARMPrinter()
        all_instructions = []

        # try generating instruction strings
        for bb in func:
            for instruction_spec in generator.non_control_flow_instructions:
                # fill up with random operand, following the spec
                inst = generator.generate_instruction(instruction_spec)
                bb.insert_after(bb.get_last(), inst)
                # print(inst)

            for instr in bb:
                instr_str = printer.instruction_to_str(instr)
                self.assertTrue(instr_str, f'Instruction {instr} was not generated.')
                all_instructions.append(instr_str + "\n")

        asm_file = tempfile.NamedTemporaryFile("w", delete=False)
        bin_file = tempfile.NamedTemporaryFile("w", delete=False)
        for i in all_instructions:
            asm_file.write(i)
            # print(i)

        # check if the generated instructions are valid
        assembly_failed = False
        try:
            generator.assemble(asm_file.name, bin_file.name)
        except subprocess.CalledProcessError:
            assembly_failed = True
        else:
            bin_file.close()
            os.unlink(bin_file.name)

        asm_file.close()
        os.unlink(asm_file.name)

        if assembly_failed:
            self.fail("Generated invalid instruction(s)")


if __name__ == '__main__':
    unittest.main()
