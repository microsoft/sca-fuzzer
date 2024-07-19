"""
File:

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import json
from typing import Dict, List
from copy import deepcopy
from .interfaces import OT, InstructionSetAbstract, OperandSpec, InstructionSpec
from .config import CONF


class InstructionSet(InstructionSetAbstract):
    ot_str_to_enum = {
        "REG": OT.REG,
        "MEM": OT.MEM,
        "IMM": OT.IMM,
        "LABEL": OT.LABEL,
        "AGEN": OT.AGEN,
        "FLAGS": OT.FLAGS,
        "COND": OT.COND,
    }
    instructions: List[InstructionSpec]
    instruction_unfiltered: List[InstructionSpec]

    def __init__(self, filename: str, include_categories=None):
        self.instructions: List[InstructionSpec] = []
        self.init_from_file(filename)
        self.instruction_unfiltered = deepcopy(self.instructions)
        self.reduce(include_categories)
        self.dedup()

    def init_from_file(self, filename: str):
        with open(filename, "r") as f:
            root = json.load(f)
        for instruction_node in root:
            instruction = InstructionSpec()
            instruction.name = instruction_node["name"]
            instruction.category = instruction_node["category"]
            instruction.control_flow = instruction_node["control_flow"]

            for op_node in instruction_node["operands"]:
                op = self.parse_operand(op_node, instruction)
                instruction.operands.append(op)
                if op.magic_value:
                    instruction.has_magic_value = True

            for op_node in instruction_node["implicit_operands"]:
                op = self.parse_operand(op_node, instruction)
                instruction.implicit_operands.append(op)

            self.instructions.append(instruction)

    def parse_operand(self, op: Dict, parent: InstructionSpec) -> OperandSpec:
        op_type = self.ot_str_to_enum[op["type_"]]
        op_values = op.get("values", [])
        if op_type == "REG":
            op_values = sorted(op_values)
        spec = OperandSpec(op_values, op_type, op["src"], op["dest"])
        spec.width = op["width"]
        spec.signed = op.get("signed", True)

        if op_type == OT.MEM:
            parent.has_mem_operand = True
            if spec.dest:
                parent.has_write = True

        return spec

    def reduce(self, include_categories):
        """ Remove unsupported instructions and operand values """

        def is_supported(spec: InstructionSpec):
            if CONF._no_generation:
                # if we use an existing test case, then instruction filtering is irrelevant
                return True

            # allowlist has priority over blocklists
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

        skip_list = []
        register_blocklist = set(CONF.register_blocklist) - set(CONF.register_allowlist)

        for s in self.instructions:
            # Unsupported instructions
            if not is_supported(s):
                skip_list.append(s)
                continue

            skip_pending = False
            for op in s.operands:
                if op.type == OT.REG:
                    choices = sorted(list(set(op.values) - register_blocklist))
                    if not choices:
                        skip_pending = True
                        break
                    op.values = choices

                    # FIXME: temporary disabled generation of higher reg. bytes for x86
                    for i, reg in enumerate(op.values):
                        if reg[-1] == 'h':
                            op.values[i] = reg.replace(
                                'h',
                                'l',
                            )

            if skip_pending:
                skip_list.append(s)

        # remove the unsupported
        for s in skip_list:
            self.instructions.remove(s)

        # set parameters
        for inst in self.instructions:
            if inst.control_flow:
                if inst.category == "BASE-UNCOND_BR":
                    self.has_unconditional_branch = True
                else:
                    self.has_conditional_branch = True
            elif inst.has_mem_operand:
                if inst.has_write:
                    self.has_writes = True
                else:
                    self.has_reads = True

    def dedup(self):
        """
        Instruction set spec may contain several copies of the same instruction.
        Remove them.
        """
        skip_list = set()
        for i in range(len(self.instructions)):
            for j in range(i + 1, len(self.instructions)):
                inst1 = self.instructions[i]
                inst2 = self.instructions[j]
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
            self.instructions.remove(s)
