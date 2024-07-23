"""
File: Parsing of assembly files into our internal representation (TestCase).
      This file contains x86-specific code.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import re
import os
from typing import List, Dict

from .x86_generator import X86Generator
from ..asm_parser import AsmParserGeneric, parser_assert
from ..interfaces import OT, Instruction, InstructionSpec, LabelOperand, Operand, RegisterOperand, \
    MemoryOperand, ImmediateOperand, AgenOperand

PATTERN_CONST_INT = re.compile("^-?[0-9]+$")
PATTERN_CONST_HEX = re.compile("^-?0x[0-9abcdef]+$")
PATTERN_CONST_BIN = re.compile("^-?0b[01]+$")
PATTERN_CONST_SUM = re.compile("^-?[0-9]+ *[+-] *[0-9]+$")


class X86AsmParser(AsmParserGeneric):
    generator: X86Generator

    asm_prefixes = ["lock", "rex", "rep", "repe", "repne"]
    asm_synonyms = {
        "je": "jz",
        "jne": "jnz",
        "jnae": "jb",
        "jc": "jb",
        "jae": "jnb",
        "jnc": "jnb",
        "jna": "jbe",
        "ja": "jnbe",
        "jnge": "jl",
        "jge": "jnl",
        "jng": "jle",
        "jg": "jnle",
        "jpe": "jp",
        "jpo": "jnp",
        "cmove": "cmovz",
        "cmovne": "cmovnz",
        "cmovnae": "cmovb",
        "cmovc": "cmovb",
        "cmovae": "cmovnb",
        "cmovnc": "cmovnb",
        "cmovna": "cmovbe",
        "cmova": "cmovnbe",
        "cmovnge": "cmovl",
        "cmovge": "cmovnl",
        "cmovng": "cmovle",
        "cmovg": "cmovnle",
        "cmovpe": "cmovp",
        "cmovpo": "cmovnp",
        "sete": "setz",
        "setne": "setnz",
        "setnae": "setb",
        "setc": "setb",
        "setae": "setnb",
        "setnc": "setnb",
        "setna": "setbe",
        "seta": "setnbe",
        "setnge": "setl",
        "setge": "setnl",
        "setng": "setle",
        "setg": "setnle",
        "setpe": "setp",
        "setpo": "setnp",
        "movabs": "mov",
        "repe": "repz",
        "repne": "repnz",
        "repnz": "repne",
        "repz": "repe",
    }
    memory_sizes = {
        "byte": 8,
        "word": 16,
        "dword": 32,
        "qword": 64,
        "tbyte": 80,
        "xmmword": 128,
        "ymmword": 256,
        "zmmword": 512
    }

    def parse_line(self, line: str, line_num: int,
                   instruction_map: Dict[str, List[InstructionSpec]]) -> Instruction:
        line = line.lower()

        # get name and possible specs
        words = line.split()
        name = ""
        specs: List[InstructionSpec] = []
        for word in words:
            if word in self.asm_prefixes:
                name += word + " "
                continue

            # fix jump name
            if word in self.asm_synonyms:
                key = name + self.asm_synonyms[word]
            else:
                key = name + word
            specs = instruction_map.get(key, [])
            name += word
            break
        parser_assert(specs != [], line_num, f"Unknown instruction {line}")

        # instrumentation?
        is_instrumentation = "instrumentation" in line
        is_noremove = "noremove" in line

        # remove comments
        if "#" in line:
            line = line.split("#")[0].strip()

        # extract operands
        operands_raw = line.removeprefix(name).split(",")
        if operands_raw == [""]:  # no operands
            operands_raw = []
        else:  # clean the operands
            operands_raw = [o.strip() for o in operands_raw]

        # find a matching spec
        matching_specs = []
        for spec_candidate in specs:
            if len(spec_candidate.operands) != len(operands_raw):
                continue

            match = True
            for op_id, op_raw in enumerate(operands_raw):
                op_spec = spec_candidate.operands[op_id]
                if op_raw[0] == ".":  # match label
                    if op_spec.type != OT.LABEL:
                        match = False
                        break
                    continue
                elif "[" in op_raw:  # match address
                    if op_spec.type not in [OT.AGEN, OT.MEM]:
                        match = False
                        break
                    access_size = op_raw.split()[0]  # match address size
                    if access_size == "ptr":
                        # out internal convention is that "ptr" prefix matches any size
                        continue

                    parser_assert(access_size in self.memory_sizes, line_num,
                                  f"Pointer size must be declared explicitly in {line}")
                    if op_spec.width != self.memory_sizes[access_size]:
                        match = False
                        break
                    continue
                # match immediate value
                elif PATTERN_CONST_BIN.match(op_raw) or \
                        PATTERN_CONST_HEX.match(op_raw) or \
                        PATTERN_CONST_INT.match(op_raw) or \
                        PATTERN_CONST_SUM.match(op_raw):
                    if op_spec.type != OT.IMM:
                        match = False
                        break
                    continue
                elif op_spec.type == OT.REG:
                    if op_raw not in op_spec.values:
                        match = False
                        break
                    continue
                else:
                    match = False
            if match:
                matching_specs.append(spec_candidate)
        parser_assert(
            len(matching_specs) != 0, line_num, f"Could not find a matching spec for {line}")

        # we might find several matches if the instruction has a magic operand value
        if len(matching_specs) > 1:
            magic_value_specs = list(filter(lambda x: (x.has_magic_value), matching_specs))
            if magic_value_specs:
                matching_specs = magic_value_specs

        # at this point we should have only one spec, but even if we don't, all of them should
        # be equivalent. Just pick the first
        spec: InstructionSpec = matching_specs[0]

        # generate a corresponding Instruction
        inst = Instruction.from_spec(spec, is_instrumentation)
        inst.is_noremove = is_noremove
        op: Operand
        for op_id, op_raw in enumerate(operands_raw):
            op_spec = spec.operands[op_id]
            if op_spec.type == OT.REG:
                op = RegisterOperand(op_raw, op_spec.width, op_spec.src, op_spec.dest)
            elif op_spec.type == OT.MEM:
                address_match = re.search(r'\[(.*)\]', op_raw)
                parser_assert(address_match is not None, line_num, "Invalid memory address")
                address = address_match.group(1)  # type: ignore
                op = MemoryOperand(address, op_spec.width, op_spec.src, op_spec.dest)
            elif op_spec.type == OT.IMM:
                op = ImmediateOperand(op_raw, op_spec.width)
            elif op_spec.type == OT.LABEL:
                assert spec.control_flow or spec.name == "macro"
                op = LabelOperand(op_raw)
            else:  # AGEN
                address_match = re.search(r'\[(.*)\]', op_raw)
                parser_assert(address_match is not None, line_num, "Invalid memory address")
                address = address_match.group(1)  # type: ignore
                op = AgenOperand(address, op_spec.width)
            inst.operands.append(op)

        for op_spec in spec.implicit_operands:
            op = self.generator.generate_operand(op_spec, inst)
            inst.implicit_operands.append(op)

        return inst

    def _patch_asm(self, asm_file: str, patched_asm_file: str):
        """
        Make sure that all function labels are exposed by adding a global label
          also, add NOP at the end of each function to make size calculations easier
          also, insert .function_0 at the beginning of the file if it is missing
          also, .test_case_exit must be within the .data.main section and contain a single NOP
        """

        def is_instruction(line: str) -> bool:
            return line != '' and line[0] != '#' \
                and (line[0] != '.' or line[:4] == ".bcd"
                     or line[:5] in [".byte", ".long", ".quad"] or line[:6] == '.macro'
                     or line[6:] in [".value", ".2byte", ".4byte", ".8byte"])

        main_function_label = ""
        enter_found = False
        has_measurement_start = False
        has_measurement_end = False
        prev_line = ""
        with open(asm_file, "r") as f:
            with open(patched_asm_file, "w") as patched:
                for line in f:
                    line = line.strip().lower()
                    if line.startswith(".macro.measurement_start"):
                        has_measurement_start = True
                    elif line.startswith(".macro.measurement_end"):
                        has_measurement_end = True

                    if not enter_found:
                        if line == ".test_case_enter:":
                            enter_found = True
                        patched.write(line + "\n")
                        continue
                    if ".test_case_exit:" in line:
                        if not main_function_label:
                            patched.write(".function_0:\n")
                            main_function_label = ".function_0"
                        if ".data.main" not in prev_line or "measurement_end" in prev_line:
                            patched.write(".section .data.main\n")
                        patched.write(".test_case_exit:" + "nop" + "\n")
                        continue

                    if line.startswith(".function_") and not main_function_label:
                        main_function_label = line[:-1]
                    elif not main_function_label and is_instruction(line):
                        patched.write(".function_0:\n")
                        main_function_label = ".function_0"

                    patched.write(line + "\n")
                    prev_line = line

        macro_placeholder = " nop qword ptr [rax + 0xff]"

        # add jump placeholders after macros
        with open(patched_asm_file, "r") as f:
            with open(patched_asm_file + ".tmp", "w") as patched:
                for line in f:
                    line = line.lower()
                    if line.startswith(".macro") and "nop" not in line:
                        patched.write(line[:-1] + macro_placeholder + "\n")
                    else:
                        patched.write(line)
        os.rename(patched_asm_file + ".tmp", patched_asm_file)

        # add .macro.measurement_start after .function_0
        if not has_measurement_start:
            with open(patched_asm_file, "r") as f:
                with open(patched_asm_file + ".tmp", "w") as patched:
                    for line in f:
                        line = line.lower()
                        patched.write(line)
                        if line.startswith(main_function_label):
                            patched.write(".macro.measurement_start:" + macro_placeholder + "\n")
            os.rename(patched_asm_file + ".tmp", patched_asm_file)

        # add .macro.measurement_end before .test_case_exit
        if not has_measurement_end:
            with open(patched_asm_file, "r") as f:
                with open(patched_asm_file + ".tmp", "w") as patched:
                    prev_line = ""
                    for line in f:
                        line = line.lower()
                        if line.startswith(".test_case_exit:"):
                            if prev_line.startswith(".section"):
                                patched.write(".function_end:\n")
                            patched.write(".macro.measurement_end:" + macro_placeholder + "\n")
                        patched.write(line)
                        prev_line = line
            os.rename(patched_asm_file + ".tmp", patched_asm_file)
