"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import unittest
import tempfile
import subprocess
import os
from pathlib import Path
from copy import deepcopy

from src.x86.x86_generator import X86RandomGenerator, X86Printer, X86PatchUndefinedFlagsPass, \
    X86Generator
from src.x86.x86_asm_parser import X86AsmParser
from src.x86.x86_target_desc import X86TargetDesc
from src.factory import get_program_generator
from src.isa_loader import InstructionSet
from src.interfaces import TestCase, Function, BasicBlock, ActorMode, Symbol
from src.config import CONF

CONF.instruction_set = "x86-64"
test_path = Path(__file__).resolve()
test_dir = test_path.parent

ASM_OPCODE = """
.intel_syntax noprefix
.test_case_enter:
.section .data.main
.byte 0x90
.test_case_exit:
"""


class X86RandomGeneratorTest(unittest.TestCase):

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

    def test_x86_configuration(self):
        CONF.generator = "random"
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(),
                                         CONF.instruction_categories)
        gen = get_program_generator(instruction_set, CONF.program_generator_seed)
        self.assertEqual(gen.__class__, X86RandomGenerator)

    def test_x86_all_instructions(self):
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(),
                                         CONF.instruction_categories)
        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)
        tc = TestCase(0)
        func = generator.generate_function(".function_0", tc.get_actor_by_name("main"), tc)
        printer = X86Printer(X86TargetDesc())
        all_instructions = ['.intel_syntax noprefix\n']

        # try generating instruction strings
        for bb in func:
            for instruction_spec in generator.non_control_flow_instructions:
                # fill up with random operand, following the spec
                inst = generator.generate_instruction(instruction_spec)
                bb.insert_after(bb.get_last(), inst)

            for instr in bb:
                instr_str = printer.instruction_to_str(instr)
                self.assertTrue(instr_str, f'Instruction {instr} was not generated.')
                all_instructions.append(instr_str + "\n")

        asm_file = tempfile.NamedTemporaryFile("w", delete=False)
        bin_file = tempfile.NamedTemporaryFile("w", delete=False)
        obj_file = tempfile.NamedTemporaryFile("w", delete=False)
        for i in all_instructions:
            asm_file.write(i)

        # check if the generated instructions are valid
        assembly_failed = False
        try:
            generator.assemble(asm_file.name, obj_file.name, bin_file.name)
        except subprocess.CalledProcessError:
            assembly_failed = True
        else:
            obj_file.close()
            os.unlink(obj_file.name)
            bin_file.close()
            os.unlink(bin_file.name)
        asm_file.close()
        os.unlink(asm_file.name)

        if assembly_failed:
            self.fail("Generated invalid instruction(s)")

    def test_create_test_case(self):
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(),
                                         CONF.instruction_categories)
        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)

        asm_file = tempfile.NamedTemporaryFile(delete=False)
        name = asm_file.name
        # name = "tmp.asm"
        tc: TestCase = generator.create_test_case(name)
        size = len([i for bb in tc.functions for i in bb])
        self.assertNotEqual(size, 0)

        dump = subprocess.run(
            f"objdump --no-show-raw-insn -D -M intel -m i386:x86-64 {tc.bin_path} "
            "| awk '/ [0-9a-f]+:/{print $1, $2, $3}'",
            shell=True,
            check=True,
            capture_output=True).stdout.decode().split("\n")
        for line in dump:
            words = line.split(" ")
            if len(words) < 2:
                continue
            pc = int(words[0][:-1], 16)
            inst_obj = tc.address_map[0][pc]
            if inst_obj.name == "unmapped" or '.byte' in inst_obj.name:
                continue
            disasm_name = words[1].lower()
            if disasm_name in X86Generator.asm_synonyms:
                disasm_name = X86Generator.asm_synonyms[disasm_name]
            self.assertIn(disasm_name, inst_obj.name)

        asm_file.close()
        os.unlink(asm_file.name)

    def test_x86_asm_parsing_basic(self):
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix())
        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)
        parser = X86AsmParser(generator)
        tc: TestCase = parser.parse_file((test_dir / "asm/asm_basic.asm").absolute().as_posix())
        self.assertEqual(len(tc.functions), 2)

        main = tc.functions[0]
        self.assertEqual(main.name, ".function_0")

        self.assertEqual(len(main), 3)

        bb0 = main[1]
        bb1 = main[2]
        exit_ = main.exit

        self.assertEqual(bb0.successors[0], bb1)
        self.assertEqual(bb1.successors[0], exit_)

        self.assertEqual(tc.functions[1].name, ".function_end")

    def test_x86_asm_parsing_opcode(self):

        tc = self.load_tc(ASM_OPCODE)

        main_iter = iter(tc.functions[0])
        bb0 = next(main_iter)
        insts = list(bb0)
        self.assertEqual(insts[0].name, "macro")
        self.assertEqual(insts[1].name, "opcode")

    def test_x86_asm_parsing_section(self):
        prev_actors = deepcopy(CONF._actors)
        CONF._actors["guest_1"] = deepcopy(CONF._actor_default)
        CONF._actors["guest_1"]["name"] = "guest_1"
        CONF._actors["guest_1"]["mode"] = "guest"
        CONF._actors["guest_1"]["privilege_level"] = "kernel"

        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix())
        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)
        parser = X86AsmParser(generator)
        tc: TestCase = parser.parse_file(
            (test_dir / "asm/asm_multiactor.asm").absolute().as_posix())

        self.assertEqual(tc.n_actors(), 2)
        self.assertEqual(tc.get_actor_by_name("main").mode, ActorMode.HOST)
        self.assertEqual(tc.get_actor_by_name("main").get_id(), 0)
        self.assertEqual(tc.get_actor_by_name("guest_1").mode, ActorMode.GUEST)
        self.assertEqual(tc.get_actor_by_name("guest_1").get_id(), 1)

        self.assertEqual(len(tc.functions), 4)
        f1 = tc.functions[0]
        f2 = tc.functions[1]
        f3 = tc.functions[2]

        self.assertEqual(f1.name, ".function_0")
        self.assertEqual(f1.owner.get_id(), 0)
        self.assertEqual(len(f1[0]), 3)

        self.assertEqual(f2.name, ".function_1")
        self.assertEqual(f2.owner.get_id(), 1)
        self.assertEqual(len(f2[0]), 1)

        self.assertEqual(f3.name, ".function_2")
        self.assertEqual(f3.owner.get_id(), 0)
        self.assertEqual(len(f3[0]), 1)

        CONF._actors = prev_actors

    def test_x86_asm_parsing_symbols(self):
        prev_actors = deepcopy(CONF._actors)
        CONF._actors["guest_1"] = deepcopy(CONF._actor_default)
        CONF._actors["guest_1"]["name"] = "guest_1"
        CONF._actors["guest_1"]["mode"] = "guest"
        CONF._actors["guest_1"]["privilege_level"] = "kernel"

        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix())
        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)
        parser = X86AsmParser(generator)
        tc: TestCase = parser.parse_file((test_dir / "asm/asm_symbol.asm").absolute().as_posix())

        self.assertEqual(tc.symbol_table[0], Symbol(0, 0, 0, 0))  # function_0
        self.assertEqual(tc.symbol_table[1], Symbol(0, 0, 1, 0))
        self.assertEqual(tc.symbol_table[2], Symbol(0, 9, 2, 0))
        self.assertEqual(tc.symbol_table[3], Symbol(0, 20, 0, 1))  # function_1
        self.assertEqual(tc.symbol_table[4], Symbol(1, 0, 0, 2))  # function_2

        CONF._actors = prev_actors

    def test_x86_undef_flag_patch(self):
        instruction_set = InstructionSet((test_dir / "min_x86.json").absolute().as_posix(),
                                         CONF.instruction_categories + ["BASE-FLAGOP"])
        undef_instr_spec = list(filter(lambda x: x.name == 'bsf', instruction_set.instructions))[0]
        read_instr_spec = list(filter(lambda x: x.name == 'lahf', instruction_set.instructions))[0]

        generator = X86RandomGenerator(instruction_set, CONF.program_generator_seed)
        undef_instr = generator.generate_instruction(undef_instr_spec)
        read_instr = generator.generate_instruction(read_instr_spec)

        test_case = TestCase(0)
        test_case.functions = [Function(".function_0", test_case.get_actor_by_name("main"))]
        bb = BasicBlock(".bb0")
        test_case.functions[0].append(bb)
        bb.insert_after(bb.get_last(), undef_instr)
        bb.insert_after(bb.get_last(), read_instr)

        X86PatchUndefinedFlagsPass(instruction_set, generator).run_on_test_case(test_case)
        self.assertEqual(len(bb), 3)
