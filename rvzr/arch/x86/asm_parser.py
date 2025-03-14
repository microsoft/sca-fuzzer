"""
File: Parsing of assembly files into our internal representation (TestCaseCode).
      This file contains x86-specific code.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import re
from typing import TYPE_CHECKING, List

from rvzr.asm_parser import AsmParser, AsmLineParser, asm_parser_assert
from rvzr.instruction_spec import OT, InstructionSpec

if TYPE_CHECKING:
    from rvzr.isa_spec import InstructionSet
    from rvzr.target_desc import TargetDesc

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


class _X86IntelLineParser(AsmLineParser):
    _curr_ln: int

    def __init__(self, isa_spec: InstructionSet, target_desc: TargetDesc) -> None:
        super().__init__(isa_spec, target_desc)
        self._comment_char = "#"

    # ----------------------------------------------------------------------------------------------
    # Implementation of ISA-specific hooks
    def _tokenize(self, line: str) -> List[str]:
        return []  # no need to tokenize in this implementation

    def _get_instruction_name(self, line: str, _: List[str]) -> str:
        """ Get the name of the instruction from an assembly line, including prefixes """
        name = ""
        for word in line.split():
            if word in _ASM_PREFIXES:
                name += word + " "
                continue
            name += word
            break
        return name

    def _get_instruction_operands(self, line: str, name: str, tokens: List[str]) -> List[str]:
        """ Get the list of operand strings from an assembly line """
        operands_raw = line.removeprefix(name).split(",")
        if operands_raw == [""]:  # no operands
            return []
        operands_raw = [o.strip() for o in operands_raw]  # remove spaces
        return operands_raw

    def _get_initial_candidate_specs(self, line: str, _: str) -> List[InstructionSpec]:
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


# ==================================================================================================
# Public Interface: Parser of X86 assembly files
# ==================================================================================================
class X86AsmParser(AsmParser):
    """ Implementation of the AsmParser interface for X86 assembly files """

    def __init__(self, isa_spec: InstructionSet, target_desc: TargetDesc) -> None:
        super().__init__(isa_spec, target_desc)
        self._line_parser = _X86IntelLineParser(isa_spec, target_desc)
        self._asm_patcher.set_macro_placeholder(" nop qword ptr [rax + 0xff]")
