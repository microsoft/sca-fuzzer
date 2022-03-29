"""
File:
- Parser of XML ISA descriptions
- Data structures for the parsed data

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import xml.etree.ElementTree as ET
from interfaces import List, OT, InstructionSetAbstract
from config import CONF


class OperandSpec:
    values: List[str]
    type: OT
    width: int
    src: bool
    dest: bool

    # certain operand values have special handling (e.g., separate opcode when RAX is a destination)
    # magic_value attribute indicates a specification for this special value
    magic_value: bool = False

    def __init__(self, values: List[str], type_: OT, src: str, dest: str):
        self.values = values
        self.type = type_
        self.src = True if src == "1" else False
        self.dest = True if dest == "1" else False
        self.width = 0

    def __str__(self):
        return f"{self.values}"


class InstructionSpec:
    name: str
    operands: List[OperandSpec]
    implicit_operands: List[OperandSpec]
    category: str
    control_flow = False

    zeroing = False
    rnsae = False
    sae = False

    has_mem_operand = False
    has_write = False
    has_magic_value: bool = False

    def __init__(self):
        self.operands = []
        self.implicit_operands = []

    def __str__(self):
        ops = ""
        for o in self.operands:
            ops += str(o) + " "
        return f"{self.name} {ops}"


class InstructionSet(InstructionSetAbstract):
    all: List[InstructionSpec]
    control_flow: List[InstructionSpec]

    def __init__(self, filename: str, include_categories=None):
        self.all = []
        self.control_flow = []
        self.init_from_file(filename)
        self.reduce(include_categories)
        self.dedup()
        super().__init__(filename, include_categories)

    def init_from_file(self, filename: str):
        parser = ET.ElementTree()
        root = parser.parse(filename)
        for instruction_node in root.iter('instruction'):
            self.instruction = InstructionSpec()
            self.instruction.name = instruction_node.attrib['asm']
            self.instruction.category = instruction_node.attrib['category']

            self.instruction.zeroing = instruction_node.attrib.get('zeroing', '') == '1'
            self.instruction.rnsae = instruction_node.attrib.get('roundc', '') == '1'
            self.instruction.sae = instruction_node.attrib.get('sae', '') == '1'

            for op_node in instruction_node.iter('op'):
                op_type = op_node.attrib['type']
                if op_type == 'reg':
                    parsed_op = self.parse_reg_operand(op_node)
                    if op_node.text == "RIP":  # FIXME: x86-specific
                        self.instruction.control_flow = True
                elif op_type == 'mem':
                    parsed_op = self.parse_mem_operand(op_node)
                    self.instruction.has_mem_operand = True
                    if parsed_op.dest:
                        self.instruction.has_write = True
                elif op_type == 'agen':
                    op_node.text = instruction_node.attrib['agen']
                    parsed_op = self.parse_agen_operand(op_node)
                elif op_type == 'imm':
                    parsed_op = self.parse_imm_operand(op_node)
                elif op_type == 'relbr':
                    parsed_op = self.parse_label_operand(op_node)
                    self.instruction.control_flow = True
                elif op_type == 'flags':
                    parsed_op = self.parse_flags_operand(op_node)
                else:
                    raise Exception("Unknown operand type " + op_type)

                if op_node.attrib.get('implicit', '0') == '1':
                    parsed_op.magic_value = True
                    self.instruction.has_magic_value = True

                if op_node.attrib.get('suppressed', '0') == '1':
                    self.instruction.implicit_operands.append(parsed_op)
                else:
                    self.instruction.operands.append(parsed_op)

            self.all.append(self.instruction)

    def reduce(self, include_categories):
        """ Remove unsupported instructions and operand choices """

        def is_supported(spec: InstructionSpec):
            if CONF._no_generation:
                # if we use an existing test case, then instruction filterring is irrelevant
                return True

            if include_categories and spec.category not in include_categories:
                return False

            if spec.sae or spec.rnsae or spec.zeroing:
                return False

            if spec.name in CONF.instruction_blocklist:
                return False

            for operand in spec.operands:
                if operand.type == OT.MEM and operand.values \
                        and operand.values[0] in CONF.gpr_blocklist:
                    return False

            for implicit_operand in spec.implicit_operands:
                assert implicit_operand.type != OT.LABEL  # I know no such instructions
                if implicit_operand.type == OT.MEM and \
                        implicit_operand.values[0] in CONF.gpr_blocklist:
                    return False

                if implicit_operand.type == OT.REG and \
                        implicit_operand.values[0] in CONF.gpr_blocklist:
                    assert len(implicit_operand.values) == 1
                    return False
            return True

        skip_list = []
        for s in self.all:
            # Unsupported instructions
            if not is_supported(s):
                skip_list.append(s)
                continue

            # Control-flow instructions go into a separate category
            if s.control_flow:
                skip_list.append(s)
                self.control_flow.append(s)

            skip_pending = False
            for op in s.operands:
                if op.type == OT.REG:
                    choices = list(set(op.values) - set(CONF.gpr_blocklist))
                    if not choices:
                        skip_pending = True
                        break
                    op.values = choices

                    # FIXME: temporary disabled generation of higher reg. bytes
                    for i, reg in enumerate(op.values):
                        if reg[-1] == 'H':
                            op.values[i] = reg.replace('H', 'L', )

            if skip_pending:
                skip_list.append(s)

        # remove the unsupported
        for s in skip_list:
            self.all.remove(s)

        # set parameters
        for inst in self.all + self.control_flow:
            if inst.control_flow:
                if inst.category == "UNCOND_BR":
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
        for i in range(len(self.all)):
            for j in range(i + 1, len(self.all)):
                inst1 = self.all[i]
                inst2 = self.all[j]
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
            self.all.remove(s)

    def parse_reg_operand(self, op):
        registers = op.text.split(',')
        spec = OperandSpec(registers, OT.REG,
                           op.attrib.get('r', "0"),
                           op.attrib.get('w', "0"))
        spec.width = int(op.attrib.get('width'))
        return spec

    @staticmethod
    def parse_mem_operand(op):
        width = int(op.attrib['width'])

        # asserts are for unsupported instructions
        assert op.attrib.get('VSIB', '0') == '0'  # asm += '[' + op.attrib.get('VSIB') + '0]'
        assert op.attrib.get('memory-suffix', '') == ''

        choices = []
        if op.attrib.get('base', ''):
            choices = [op.attrib.get('base', '')]

        spec = OperandSpec(choices, OT.MEM,
                           op.attrib.get('r', "0"),
                           op.attrib.get('w', "0"))
        spec.width = width
        return spec

    @staticmethod
    def parse_agen_operand(op):
        spec = OperandSpec([], OT.AGEN, "1", "0")
        spec.width = int(op.attrib.get('width'))
        return spec

    @staticmethod
    def parse_imm_operand(op):
        if op.attrib.get('implicit', '0') == '1':
            value = [op.text]
        else:
            value = []
        spec = OperandSpec(value, OT.IMM, "1", "0")
        spec.width = int(op.attrib['width'])
        return spec

    @staticmethod
    def parse_label_operand(_):
        return OperandSpec([], OT.LABEL, "1", "0")

    @staticmethod
    def parse_flags_operand(op):
        # TODO: this is x86-specific. Has to be decoupled from the generic data types
        flags = [
            op.attrib.get("flag_CF", ""),
            op.attrib.get("flag_PF", ""),
            op.attrib.get("flag_AF", ""),
            op.attrib.get("flag_ZF", ""),
            op.attrib.get("flag_SF", ""),
            op.attrib.get("flag_TF", ""),
            op.attrib.get("flag_IF", ""),
            op.attrib.get("flag_DF", ""),
            op.attrib.get("flag_OF", ""),
        ]
        return OperandSpec(flags, OT.FLAGS,
                           op.attrib.get('r', "0"),
                           op.attrib.get('w', "0"))
