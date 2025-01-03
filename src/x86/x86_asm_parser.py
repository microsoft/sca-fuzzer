"""
File: Parsing of assembly files into our internal representation (TestCaseCode).
      This file contains x86-specific code.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import re
import os
from typing import TYPE_CHECKING, List, Dict, Final

from ..asm_parser import AsmParser, asm_parser_assert, AsmParserError
from ..instruction_spec import OT, InstructionSpec, OperandSpec
from ..tc_components.instruction import Instruction, Operand, RegisterOp, MemoryOp, \
    ImmediateOp, LabelOp, AgenOp, AnyOperand

if TYPE_CHECKING:
    from ..isa_spec import InstructionSet
    from ..target_desc import TargetDesc

# ==================================================================================================
# Private: Parser of assembly lines in Intel syntax
# ==================================================================================================
_PATTERN_CONST_INT = re.compile("^-?[0-9]+$")
_PATTERN_CONST_HEX = re.compile("^-?0x[0-9abcdef]+$")
_PATTERN_CONST_BIN = re.compile("^-?0b[01]+$")
_PATTERN_CONST_SUM = re.compile("^-?[0-9]+ *[+-] *[0-9]+$")

_ASM_PREFIXES = ["lock", "rex", "rep", "repe", "repne"]
_ASM_SYNONYMS = {
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
_MEMORY_SIZES = {
    "byte": 8,
    "word": 16,
    "dword": 32,
    "qword": 64,
    "tbyte": 80,
    "xmmword": 128,
    "ymmword": 256,
    "zmmword": 512
}


class _X86IntelLineParser:

    _instruction_map: Final[Dict[str, List[InstructionSpec]]]
    _curr_ln: int = -1

    def __init__(self, isa_spec: InstructionSet) -> None:
        instruction_map: Dict[str, List[InstructionSpec]] = {}
        for spec in isa_spec.instructions_unfiltered:
            if spec.name in instruction_map:
                instruction_map[spec.name].append(spec)
            else:
                instruction_map[spec.name] = [spec]

            # add an entry for direct opcodes
            opcode_spec = InstructionSpec("opcode", "opcode")
            instruction_map["opcode"] = [opcode_spec]

            # entry for macros
            macro_spec = InstructionSpec("macro", "macro")
            macro_spec.operands = [
                OperandSpec([], OT.LABEL, False, False),
                OperandSpec([], OT.LABEL, False, False)
            ]
            instruction_map["macro"] = [macro_spec]

        self._instruction_map = instruction_map

    def parse_line(self, line: str, line_num: int) -> Instruction:
        """
        Parse a single assembly line with an instruction in Intel syntax and
        return the corresponding Instruction object
        """
        self._curr_ln = line_num

        # Identify the line type
        line = line.lower()
        is_instrumentation = "instrumentation" in line
        is_noremove = "noremove" in line

        # Remove comments
        if "#" in line:
            line = line.split("#")[0].strip()

        # Get instruction name and operands
        name = self._get_instruction_name(line)
        operands_raw = self._get_instruction_operands(line, name)

        # Find a matching spec
        spec = self._find_matching_spec(line, operands_raw)

        # generate a corresponding Instruction
        inst = self._create_instruction(spec, operands_raw, is_instrumentation, is_noremove)
        inst.assign_line_num(line_num)

        return inst

    # ----------------------------------------------------------------------------------------------
    # Private: Breaking down the assembly line
    def _get_instruction_name(self, line: str) -> str:
        """ Get the name of the instruction from an assembly line, including prefixes """
        name = ""
        for word in line.split():
            if word in _ASM_PREFIXES:
                name += word + " "
                continue
            name += word
            break
        return name

    def _get_instruction_operands(self, line: str, name: str) -> List[str]:
        """ Get the list of operand strings from an assembly line """
        operands_raw = line.removeprefix(name).split(",")
        if operands_raw == [""]:  # no operands
            return []
        operands_raw = [o.strip() for o in operands_raw]  # remove spaces
        return operands_raw

    # ----------------------------------------------------------------------------------------------
    # Private: Finding a matching instruction spec
    def _find_matching_spec(self, line: str, operands_raw: List[str]) -> InstructionSpec:
        """ Find the InstructionSpec that matches the given assembly line """

        # Get candidate specs
        specs = self._get_initial_candidate_specs(line)
        if len(specs) == 0:
            raise AsmParserError(self._curr_ln, f"Unknown instruction {line}")

        # find a matching spec
        matching_specs: List[InstructionSpec] = []
        for spec_candidate in specs:
            if self._check_if_spec_matches(spec_candidate, operands_raw):
                matching_specs.append(spec_candidate)
        if len(matching_specs) == 0:
            raise AsmParserError(self._curr_ln, f"Could not find a matching spec for {line}")

        # we might find several matches if the instruction has a magic operand value
        if len(matching_specs) > 1:
            magic_value_specs = list(filter(lambda x: (x.has_magic_value), matching_specs))
            if magic_value_specs:
                matching_specs = magic_value_specs

        # at this point we should have only one spec, but even if we don't, all of them should
        # be equivalent. Just pick the first
        return matching_specs[0]

    def _check_if_spec_matches(self, spec: InstructionSpec, operands_raw: List[str]) -> bool:
        """ Check if the given spec matches the given list of operand strings """
        # pylint: disable=too-many-return-statements  # justified for selectors

        if len(spec.operands) != len(operands_raw):
            return False

        for op_id, op_raw in enumerate(operands_raw):
            op_spec = spec.operands[op_id]

            # match label
            if op_raw[0] == ".":
                if op_spec.type != OT.LABEL:
                    return False
                continue

            # match address
            if "[" in op_raw:
                if op_spec.type not in [OT.AGEN, OT.MEM]:
                    return False

                access_size = op_raw.split()[0]  # match address size
                if access_size == "ptr":
                    # out internal convention is that "ptr" prefix matches any size
                    continue

                asm_parser_assert(access_size in _MEMORY_SIZES, self._curr_ln,
                                  f"Pointer size must be declared explicitly: {op_raw}")
                if op_spec.width != _MEMORY_SIZES[access_size]:
                    return False
                continue

            # match immediate value
            if _PATTERN_CONST_BIN.match(op_raw) or \
                    _PATTERN_CONST_HEX.match(op_raw) or \
                    _PATTERN_CONST_INT.match(op_raw) or \
                    _PATTERN_CONST_SUM.match(op_raw):
                if op_spec.type != OT.IMM:
                    return False
                continue

            # match register
            if op_spec.type == OT.REG:
                if op_raw not in op_spec.values:
                    return False
                continue
            return False
        return True

    def _get_initial_candidate_specs(self, line: str) -> List[InstructionSpec]:
        """ Get the list of candidate specs for an instruction with the given name  """
        key = ""
        for word in line.split():
            # include prefixes in the key
            if word in _ASM_PREFIXES:
                key += word + " "
                continue

            # fix jump name
            if word in _ASM_SYNONYMS:
                key += _ASM_SYNONYMS[word]
            else:
                key += word
            return self._instruction_map.get(key, [])
        return []

    # ----------------------------------------------------------------------------------------------
    # Private: Creating an Instruction object for the line
    def _create_instruction(self, spec: InstructionSpec, operands_raw: List[str],
                            is_instrumentation: bool, is_noremove: bool) -> Instruction:
        """
        Create an Instruction object and its operands based on the assembly line
        and the spec that describes the instruction
        """
        # create the instruction with no operands
        inst = Instruction.from_spec(
            spec, is_instrumentation=is_instrumentation, is_noremove=is_noremove)

        # create operands
        op: AnyOperand
        for op_id, op_raw in enumerate(operands_raw):
            op_spec = spec.operands[op_id]
            if op_spec.type == OT.REG:
                op = RegisterOp(op_raw, op_spec.width, op_spec.src, op_spec.dest)
            elif op_spec.type == OT.MEM:
                address_match = re.search(r'\[(.*)\]', op_raw)
                asm_parser_assert(address_match is not None, self._curr_ln,
                                  "Invalid memory address")
                address = address_match.group(1)  # type: ignore
                op = MemoryOp(address, op_spec.width, op_spec.src, op_spec.dest)
            elif op_spec.type == OT.IMM:
                op = ImmediateOp(op_raw, op_spec.width)
            elif op_spec.type == OT.LABEL:
                assert spec.is_control_flow or spec.name == "macro"
                op = LabelOp(op_raw)
            else:  # AGEN
                address_match = re.search(r'\[(.*)\]', op_raw)
                asm_parser_assert(address_match is not None, self._curr_ln,
                                  "Invalid memory address")
                address = address_match.group(1)  # type: ignore
                op = AgenOp(address, op_spec.width)
            inst.operands.append(op)

        # add implicit operands
        for op_spec in spec.implicit_operands:
            # implicit operands should always have fixed spec, hence it's safe to use
            # the from_fixed_spec constructor
            op = Operand.from_fixed_spec(op_spec)
            inst.implicit_operands.append(op)

        return inst


# ==================================================================================================
# Private: Patching of assembly files
# ==================================================================================================
class _X86AsmPatcher:
    _main_function_label: str = ""
    _MACRO_PLACEHOLDER: Final[str] = " nop qword ptr [rax + 0xff]"

    def patch_asm(self, asm_file: str, patched_asm_file: str) -> None:
        """
        Ensure that the assembly file is in the correct format for parsing:
        - all function labels are exposed by adding a global label
        - NOP is added at the end of each function to make size calculations easier
        - .function_0 is inserted at the beginning of the file if it is missing
        - .test_case_exit is within the .data.main section and contains a single NOP
        """
        self._main_function_label = ""
        self._pre_clean(asm_file, patched_asm_file)

        # apply the patches
        self._add_exit_section(patched_asm_file)
        self._add_default_main(patched_asm_file)
        self._add_macro_placeholders(patched_asm_file)
        self._add_default_measurements(patched_asm_file)

    def _is_instruction(self, line: str) -> bool:
        return line != '' and line[0] != '#' \
            and (line[0] != '.' or line[:4] == ".bcd"
                 or line[:5] in [".byte", ".long", ".quad"] or line[:6] == '.macro'
                 or line[6:] in [".value", ".2byte", ".4byte", ".8byte"])

    def _pre_clean(self, asm_file: str, patched_asm_file: str) -> None:
        with open(asm_file, "r") as f:
            with open(patched_asm_file, "w") as patched:
                for line in f:
                    line = line.strip().lower()
                    patched.write(line + "\n")

    def _add_exit_section(self, patched_asm_file: str) -> None:
        prev_line = ""
        with open(patched_asm_file, "r") as f:
            with open(patched_asm_file + ".tmp", "w") as patched:
                for line in f:
                    line = line[:-1]
                    if ".test_case_exit:" in line:
                        if ".data.main" not in prev_line or "measurement_end" in prev_line:
                            patched.write(".section .data.main\n")
                        patched.write(".test_case_exit:" + "nop" + "\n")
                        continue
                    patched.write(line + "\n")
                    prev_line = line
        os.rename(patched_asm_file + ".tmp", patched_asm_file)

    def _add_default_main(self, patched_asm_file: str) -> None:
        main_function_label = ""
        with open(patched_asm_file, "r") as f:
            with open(patched_asm_file + ".tmp", "w") as patched:
                for line in f:
                    line = line[:-1]

                    # if we already have a main function, just copy the rest of the file
                    if main_function_label:
                        patched.write(line + "\n")
                        continue

                    # reached the end of the file
                    if ".test_case_exit:" in line:
                        main_function_label = ".function_0"
                        patched.write(".function_0:\n")
                        patched.write(line + "\n")
                        continue

                    # found the main function
                    if line.startswith(".function_"):
                        main_function_label = line[:-1]
                        patched.write(line + "\n")
                        continue

                    # found an instruction before the main function
                    if self._is_instruction(line):
                        patched.write(".function_0:\n")
                        main_function_label = ".function_0"
                        patched.write(line + "\n")
                        continue

                    # copy non-instruction lines
                    patched.write(line + "\n")

        self._main_function_label = main_function_label
        os.rename(patched_asm_file + ".tmp", patched_asm_file)

    def _add_macro_placeholders(self, patched_asm_file: str) -> None:
        """ add NOP placeholders after macros """

        with open(patched_asm_file, "r") as f:
            with open(patched_asm_file + ".tmp", "w") as patched:
                for line in f:
                    line = line.lower()
                    if line.startswith(".macro"):
                        if "nop" not in line:
                            patched.write(line[:-1] + self._MACRO_PLACEHOLDER + "\n")
                        else:
                            assert self._MACRO_PLACEHOLDER in line, \
                                "Unexpected NOP placeholder: " + line
                            patched.write(line)
                    else:
                        patched.write(line)
        os.rename(patched_asm_file + ".tmp", patched_asm_file)

    def _add_default_measurements(self, patched_asm_file: str) -> None:
        # identify if the file already has the measurement macros;
        # this information is used by multiple patching steps
        has_measurement_start = False
        has_measurement_end = False
        with open(patched_asm_file, "r") as f:
            for line in f:
                line = line.lower()
                if line.startswith(".macro.measurement_start"):
                    has_measurement_start = True
                elif line.startswith(".macro.measurement_end"):
                    has_measurement_end = True

        # add .macro.measurement_start after .function_0
        if not has_measurement_start:
            with open(patched_asm_file, "r") as f:
                with open(patched_asm_file + ".tmp", "w") as patched:
                    for line in f:
                        line = line.lower()
                        patched.write(line)
                        if line.startswith(self._main_function_label):
                            patched.write(".macro.measurement_start:" + self._MACRO_PLACEHOLDER
                                          + "\n")
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
                            patched.write(".macro.measurement_end:" + self._MACRO_PLACEHOLDER
                                          + "\n")
                        patched.write(line)
                        prev_line = line
            os.rename(patched_asm_file + ".tmp", patched_asm_file)


# ==================================================================================================
# Public Interface: Parser of X86 assembly files
# ==================================================================================================
class X86AsmParser(AsmParser):
    """ Implementation of the AsmParser interface for X86 assembly files """

    def __init__(self, isa_spec: InstructionSet, target_desc: TargetDesc) -> None:
        super().__init__(isa_spec, target_desc)
        self._line_parser = _X86IntelLineParser(isa_spec)
        self._asm_patcher = _X86AsmPatcher()

    def _patch_asm(self, asm_file: str, patched_asm_file: str) -> None:
        return self._asm_patcher.patch_asm(asm_file, patched_asm_file)

    def _parse_line(self, line: str, line_num: int) -> Instruction:
        return self._line_parser.parse_line(line, line_num)
