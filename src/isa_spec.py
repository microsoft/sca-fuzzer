"""
File:

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import json
from copy import deepcopy
from typing import Dict, List, Optional, Any
from typing_extensions import get_args

from .instruction_spec import OT, XOT, OperandSpec, InstructionSpec
from .config import CONF

_OT_STR_TO_ENUM = {
    "REG": OT.REG,
    "MEM": OT.MEM,
    "IMM": OT.IMM,
    "LABEL": OT.LABEL,
    "AGEN": OT.AGEN,
    "FLAGS": OT.FLAGS,
    "COND": OT.COND,
}

FP_XOT = ["f64", "f32"]


class InstructionSet:
    """
    Class representing an instruction set of a given architecture.
    Contains a list of InstructionSpec objects as well as type-based lists of instructions.
    """

    instructions: List[InstructionSpec]
    instructions_unfiltered: List[InstructionSpec]

    has_unconditional_branch: bool = False
    has_conditional_branch: bool = False
    has_indirect_branch: bool = False
    has_reads: bool = False
    has_writes: bool = False

    control_flow_specs: List[InstructionSpec]
    non_control_flow_specs: List[InstructionSpec]
    non_memory_access_specs: List[InstructionSpec]
    load_instruction: List[InstructionSpec]
    store_instructions: List[InstructionSpec]
    cond_branches: List[InstructionSpec]

    def __init__(self, filename: str, include_categories: Optional[List[str]] = None):
        self.instructions = []
        _read_json_spec(self, filename)
        self.instructions_unfiltered = deepcopy(self.instructions)
        _reduce(self, include_categories)
        _set_isa_properties(self)
        _dedup(self)
        _set_categories(self)

    def get_return_spec(self) -> InstructionSpec:
        """ Return the instruction spec for the RET instruction on the given architecture """
        assert CONF.instruction_set == "x86-64", "Only x86-64 is supported"
        return InstructionSpec("ret", "BASE-RET", is_control_flow=True)

    def get_unconditional_jump_spec(self) -> InstructionSpec:
        """
        Return the instruction spec for the unconditional jump instruction
        on the given architecture
        """
        assert CONF.instruction_set == "x86-64", "Only x86-64 is supported"
        spec = InstructionSpec("jmp", "BASE-UNCOND_BR", is_control_flow=True)
        spec.operands.append(OperandSpec([], OT.LABEL, src=True, dest=False, width=64))
        return spec


# ==================================================================================================
# Local service functions that post-process the instruction set
# ==================================================================================================
def _read_json_spec(isa: InstructionSet, filename: str) -> None:
    with open(filename, "r") as f:
        root = json.load(f)
    for instruction_node in root:
        instruction = InstructionSpec(instruction_node["name"], instruction_node["category"],
                                      instruction_node["is_control_flow"])

        for op_node in instruction_node["operands"]:
            op = _parse_json_operand(op_node, instruction)
            instruction.operands.append(op)
            if op.has_magic_value:
                instruction.has_magic_value = True

        for op_node in instruction_node["implicit_operands"]:
            op = _parse_json_operand(op_node, instruction)
            instruction.implicit_operands.append(op)

        isa.instructions.append(instruction)


def _parse_json_operand(op: Dict[str, Any], parent: InstructionSpec) -> OperandSpec:
    op_type = _OT_STR_TO_ENUM[op["type_"]]
    op_values = op.get("values", [])
    if op_type == OT.REG:
        op_values = sorted(op_values)

    spec = OperandSpec(
        values=op_values,
        type_=op_type,
        src=op["src"],
        dest=op["dest"],
        width=op["width"],
        is_signed=op.get("is_signed", True),
        xtype=op.get("xtype", None),
    )

    if op_type == OT.MEM:
        parent.has_mem_operand = True
        if spec.dest:
            parent.has_write = True

    return spec


def _reduce(isa: InstructionSet, include_categories: Optional[List[str]]) -> None:
    """ Remove unsupported instructions and operand values """

    def is_supported(spec: InstructionSpec) -> bool:
        # pylint: disable=too-many-return-statements
        # This is justified as it is a filtering function

        if not CONF.is_generation_enabled():
            # if we use an existing test case, then instruction filtering is irrelevant
            return True

        # allowlist has priority over blocklist
        if spec.name in CONF.instruction_allowlist:
            return True

        if include_categories and spec.category not in include_categories:
            return False

        if spec.name in CONF.instruction_blocklist:
            return False

        for operand in spec.operands:
            if operand.type == OT.MEM and operand.values \
                    and operand.values[0] in register_blocklist:
                return False

        # FP SIMD is not supported
        for operand in spec.operands:
            if operand.type != OT.REG or operand.xtype is None:
                continue
            assert operand.xtype in get_args(XOT), f"Unknown xtype value: {operand.xtype}"
            if operand.xtype in FP_XOT:
                return False

        for implicit_operand in spec.implicit_operands:
            assert implicit_operand.type != OT.LABEL  # I know no such instructions
            if implicit_operand.type == OT.MEM \
                    and implicit_operand.values[0] in register_blocklist:
                return False

            if implicit_operand.type == OT.REG \
                    and implicit_operand.values[0] in register_blocklist:
                assert len(implicit_operand.values) == 1
                return False
        return True

    register_blocklist = set(CONF.register_blocklist) - set(CONF.register_allowlist)

    # Remove unsupported instructions
    skip_list = []
    for s in isa.instructions:
        if not is_supported(s):
            skip_list.append(s)
    for s in skip_list:
        isa.instructions.remove(s)

    # Remove unsupported operand values from operand specs;
    # If all operand values are unsupported, remove the instruction
    skip_list = []
    for s in isa.instructions:
        operands = list(s.operands)  # make a copy
        for op_id, op in enumerate(operands):
            # filtering applies only to registers
            if op.type != OT.REG:
                continue

            # identify supported registers
            op_values = sorted(list(set(op.values) - register_blocklist))

            # FIXME: temporary disabled generation of higher reg. bytes for x86
            for i, reg in enumerate(op_values):
                if reg[-1] == 'h':
                    op_values[i] = reg.replace('h', 'l')

            # no supported values -> skip this instruction
            if not op_values:
                skip_list.append(s)
                break

            # otherwise, update the operand
            s.operands[op_id] = OperandSpec(op_values, op.type, op.src, op.dest, op.width,
                                            op.is_signed, op.has_magic_value, op.xtype)
    for s in skip_list:
        isa.instructions.remove(s)


def _set_isa_properties(isa: InstructionSet) -> None:
    """
    Set properties of the instruction set that are used in the generation process.
    """
    for inst in isa.instructions:
        if inst.is_control_flow:
            if inst.category == "BASE-UNCOND_BR":
                isa.has_unconditional_branch = True
            else:
                isa.has_conditional_branch = True
        elif inst.has_mem_operand:
            if inst.has_write:
                isa.has_writes = True
            else:
                isa.has_reads = True


def _dedup(isa: InstructionSet) -> None:
    """
    Instruction set spec may contain several copies of the same instruction.
    Remove them.
    """
    skip_list = set()
    n_instructions = len(isa.instructions)
    for i in range(n_instructions):
        for j in range(i + 1, n_instructions):
            inst1 = isa.instructions[i]
            inst2 = isa.instructions[j]
            if inst1.name == inst2.name and len(inst1.operands) == len(inst2.operands):
                match = True
                for k, op1 in enumerate(inst1.operands):
                    op2 = inst2.operands[k]

                    if op1.type != op2.type:
                        match = False
                        continue

                    if op1.values != op2.values:
                        match = False
                        continue

                    if op1.width != op2.width and op1.type != OT.IMM:
                        match = False
                        continue

                    # assert op1.src == op2.src
                    # assert op1.dest == op2.dest

                if match:
                    skip_list.add(inst1)

    for s in skip_list:
        isa.instructions.remove(s)


def _set_categories(isa: InstructionSet) -> None:
    isa.control_flow_specs = [i for i in isa.instructions if i.is_control_flow]
    assert isa.control_flow_specs or CONF.max_successors_per_bb <= 1, \
           "The instruction set is insufficient to generate a test case"

    isa.non_control_flow_specs = [i for i in isa.instructions if not i.is_control_flow]
    assert isa.non_control_flow_specs, \
        "The instruction set is insufficient to generate a test case"

    isa.non_memory_access_specs = \
        [i for i in isa.non_control_flow_specs if not i.has_mem_operand]
    if CONF.avg_mem_accesses != 0:
        memory_access_instructions = \
            [i for i in isa.non_control_flow_specs if i.has_mem_operand]
        isa.load_instruction = [i for i in memory_access_instructions if not i.has_write]
        isa.store_instructions = [i for i in memory_access_instructions if i.has_write]
        assert isa.load_instruction or isa.store_instructions, \
               "The instruction set does not have memory accesses while `avg_mem_accesses > 0`"
    else:
        isa.load_instruction = []
        isa.store_instructions = []

    uncond_name = isa.get_unconditional_jump_spec().name.lower()
    isa.cond_branches = \
        [i for i in isa.control_flow_specs if i.name.lower() != uncond_name]
