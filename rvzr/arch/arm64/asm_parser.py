"""
File: Parsing of assembly files into our internal representation (TestCaseCode).
      This file contains arm64-specific code.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# FIXME: this implementation is quite brittle; rewrite it using a proper parser (keystone ?)

from __future__ import annotations
import re
from typing import TYPE_CHECKING, List

from rvzr.asm_parser import AsmParser, AsmLineParser, AsmParserError
from rvzr.instruction_spec import OT, InstructionSpec

from .target_desc import ARM64TargetDesc

if TYPE_CHECKING:
    from rvzr.isa_spec import InstructionSet
    from rvzr.target_desc import TargetDesc


# ==================================================================================================
# Private: Parser of assembly lines in ARM64 syntax
# ==================================================================================================
class _ARM646LineParser(AsmLineParser):
    """ Parser of assembly lines in ARM64 syntax """
    _target_desc: ARM64TargetDesc
    _curr_ln: int

    def __init__(self, isa_spec: InstructionSet, target_desc: ARM64TargetDesc) -> None:
        super().__init__(isa_spec, target_desc)
        self._comment_char = "//"
        self._re_tokenize = re.compile(
            r"^([^ .]+\.?)([^ ]+)? ([^ ,]+)(,[^,]+)?(,[^,]+)?(,[^,]+)?( //.*)?")
        self._re_tokenize_nops = re.compile(r"^([^ .]+\.?)([^ ]+)?")
        self._condition_code = list(target_desc.branch_conditions.keys())

    # ----------------------------------------------------------------------------------------------
    # Implementation of ISA-specific hooks
    def _tokenize(self, line: str) -> List[str]:
        matches = self._re_tokenize.findall(line)
        if matches == []:
            matches = self._re_tokenize_nops.findall(line)
        if not matches:
            raise AsmParserError(self._curr_ln, "Could not tokenize the line")
        tokens = [t.removeprefix(",") for t in matches[0] if t]
        # print(tokens)

        # the regex above splits memory address operands into multiple tokens
        # we need to merge them back
        tokens_merged = []
        mem_started = False
        mem_token = ""
        for token in tokens:
            if not token:
                continue
            if token[0] == "[" and token[-1] == "]":
                tokens_merged.append(token)
                continue
            if token[0] == "[":
                mem_started = True
                mem_token = token
                continue
            if token[-1] == "]":
                tokens_merged.append(mem_token + "," + token)
                mem_started = False
                mem_token = ""
                continue
            if mem_started:
                mem_token += "," + token
                continue
            tokens_merged.append(token)

        # print(tokens_merged)
        return tokens_merged

    def _get_instruction_name(self, line: str, tokens: List[str]) -> str:
        return tokens[0]

    def _get_instruction_operands(self, _: str, __: str, tokens: List[str]) -> List[str]:
        """ Get the list of operand strings from the tokens """
        return tokens[1:]

    def _get_initial_candidate_specs(self, _: str, name: str) -> List[InstructionSpec]:
        """ Get the list of candidate specs for an instruction with the given name  """
        return self._instruction_map.get(name, [])

    def _check_if_spec_matches(self, spec: InstructionSpec, operands_raw: List[str]) -> bool:
        """ Check if the given spec matches the given list of operand strings """
        # pylint: disable=too-many-return-statements  # justified for selectors
        # pylint: disable=too-many-branches  # justified for selectors
        # print(spec.name, operands_raw, spec.operands)

        if len(spec.operands) != len(operands_raw):
            return False

        for op_id, op_raw in enumerate(operands_raw):
            op_spec = spec.operands[op_id]

            # match condition
            if op_spec.type == OT.COND:
                if op_raw not in self._condition_code:
                    return False
                continue

            # match label
            if op_raw[0] == ".":
                if op_spec.type != OT.LABEL:
                    return False
                continue

            # match address
            if "[" in op_raw:
                if op_spec.type not in [OT.AGEN, OT.MEM]:
                    return False
                continue

            # match immediate value
            if op_raw[0] == "#":
                if op_spec.type != OT.IMM:
                    return False
                continue

            # match register
            if op_spec.type == OT.REG:
                if op_raw not in op_spec.values:
                    return False
                continue

            # match keyword immediate
            if op_raw in ["sy", "ld", "st"]:
                if op_spec.type != OT.IMM:
                    return False
                continue

            # no match
            return False
        return True


# ==================================================================================================
# Public Interface: Parser of X86 assembly files
# ==================================================================================================
class ARM64AsmParser(AsmParser):
    """ Implementation of the AsmParser interface for X86 assembly files """

    def __init__(self, isa_spec: InstructionSet, target_desc: TargetDesc) -> None:
        super().__init__(isa_spec, target_desc)
        assert isinstance(target_desc, ARM64TargetDesc)
        self._line_parser = _ARM646LineParser(isa_spec, target_desc)
        self._asm_patcher.set_macro_placeholder("nop; nop; nop")
