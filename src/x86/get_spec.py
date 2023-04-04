"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import json
import subprocess
from typing import List
from xml.etree import ElementTree as ET


class OperandSpec:
    values: List[str]
    type_: str
    width: int
    comment: str
    src: bool = False
    dest: bool = False
    magic: bool = False

    def to_json(self) -> str:
        return json.dumps(self, default=vars)


class InstructionSpec:
    name: str
    category: str = ""
    control_flow: bool = False
    operands: List[OperandSpec]
    implicit_operands: List[OperandSpec]

    def __init__(self) -> None:
        self.operands = []
        self.implicit_operands = []

    def __str__(self) -> str:
        return f"{self.name} {self.control_flow} {self.category} " \
               f"{len(self.operands)} {len(self.implicit_operands)}"

    def to_json(self) -> str:
        s = "{"
        s += f'"name": "{self.name}", "category": "{self.category}", '
        s += f'"control_flow": {str(self.control_flow).lower()},\n'
        s += '  "operands": [\n    '
        s += ',\n    '.join([o.to_json() for o in self.operands])
        s += '\n  ],\n'
        if self.implicit_operands:
            s += '  "implicit_operands": [\n    '
            s += ',\n    '.join([o.to_json() for o in self.implicit_operands])
            s += '\n  ]'
        else:
            s += '  "implicit_operands": []'
        s += "\n}"
        return s


class ParseFailed(Exception):
    pass


class X86Transformer:
    tree: ET.Element
    instructions: List[InstructionSpec]
    current_spec: InstructionSpec
    reg_sizes = {
        "RAX": 64,
        "RBX": 64,
        "RCX": 64,
        "RDX": 64,
        "EAX": 32,
        "EBX": 32,
        "ECX": 32,
        "EDX": 32,
        "AX": 16,
        "DX": 16,
        "AL": 8,
        "AH": 8,
        "TMM0": 0,
        "MXCSR": 32,
        'ES': 16,
        'SS': 16,
        'DS': 16,
        'FS': 16,
        'GS': 16,
    }
    not_control_flow = ["INT", "INT1", "INT3", "INTO"]
    """ a list of instructions that have RIP as an operand but should
    not be considered as control-flow instructions by the generator"""

    def __init__(self) -> None:
        self.instructions = []

    def load_files(self, filename: str):
        parser = ET.ElementTree()
        tree = parser.parse(filename)
        if not tree:
            print("No input. Exiting")
            exit(1)
        self.tree = tree

    def parse_tree(self, extensions: List[str]):
        for instruction_node in self.tree.iter('instruction'):
            if instruction_node.attrib.get('sae', '') == '1' or \
               instruction_node.attrib.get('roundc', '') == '1' or \
               instruction_node.attrib.get('zeroing', '') == '1':
                continue

            if extensions and instruction_node.attrib['extension'] not in extensions:
                continue

            self.instruction = InstructionSpec()
            self.instruction.category = instruction_node.attrib['extension'] \
                + "-" \
                + instruction_node.attrib['category']

            # clean up the name
            name = instruction_node.attrib['asm']
            name = name.removeprefix("{load} ")
            name = name.removeprefix("{store} ")
            name = name.removeprefix("{disp32} ")
            self.instruction.name = name

            try:
                for op_node in instruction_node.iter('operand'):
                    op_type = op_node.attrib['type']
                    if op_type == 'reg':
                        parsed_op = self.parse_reg_operand(op_node)
                        if op_node.text == "RIP" and name not in self.not_control_flow:
                            self.instruction.control_flow = True
                    elif op_type == 'mem':
                        parsed_op = self.parse_mem_operand(op_node)
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
                        parsed_op.magic = True

                    if op_node.attrib.get('suppressed', '0') == '1':
                        self.instruction.implicit_operands.append(parsed_op)
                    else:
                        self.instruction.operands.append(parsed_op)

            except ParseFailed:
                continue

            self.instructions.append(self.instruction)

    def save(self, filename: str):
        json_str = "[\n" + ",\n".join([i.to_json() for i in self.instructions]) + "\n]"
        # print(json_str)
        with open(filename, "w+") as f:
            f.write(json_str)

    def parse_reg_operand(self, op):
        spec = OperandSpec()
        spec.type_ = "REG"
        spec.values = op.text.split(',')
        spec.src = True if op.attrib.get('r', "0") == "1" else False
        spec.dest = True if op.attrib.get('w', "0") == "1" else False
        spec.width = int(op.attrib.get('width', 0))
        if spec.width == 0:
            if spec.values[0] in self.reg_sizes:
                spec.width = self.reg_sizes[spec.values[0]]
            else:
                raise ParseFailed()
        return spec

    @staticmethod
    def parse_mem_operand(op):
        # asserts are for unsupported instructions
        if op.attrib.get('VSIB', '0') != '0':
            raise ParseFailed()
        # assert op.attrib.get('VSIB', '0') == '0'  # asm += '[' + op.attrib.get('VSIB') + '0]'
        if op.attrib.get('memory-suffix', '') != '':
            raise ParseFailed()

        choices = []
        if op.attrib.get('base', ''):
            choices = [op.attrib.get('base', '')]

        spec = OperandSpec()
        spec.type_ = "MEM"
        spec.values = choices
        spec.src = True if op.attrib.get('r', "0") == "1" else False
        spec.dest = True if op.attrib.get('w', "0") == "1" else False
        spec.width = int(op.attrib.get('width'))
        return spec

    @staticmethod
    def parse_agen_operand(op):
        spec = OperandSpec()
        spec.type_ = "AGEN"
        spec.values = []
        spec.src = True
        spec.dest = False
        spec.width = 64
        return spec

    @staticmethod
    def parse_imm_operand(op):
        spec = OperandSpec()
        spec.type_ = "IMM"
        if op.attrib.get('implicit', '0') == '1':
            spec.values = [op.text]
        else:
            spec.values = []
        spec.src = True
        spec.dest = False
        spec.width = int(op.attrib.get('width'))
        return spec

    @staticmethod
    def parse_label_operand(_):
        spec = OperandSpec()
        spec.type_ = "LABEL"
        spec.values = []
        spec.src = True
        spec.dest = False
        spec.width = 0
        return spec

    @staticmethod
    def parse_flags_operand(op):
        spec = OperandSpec()
        spec.type_ = "FLAGS"
        spec.values = [
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
        spec.src = False
        spec.dest = False
        spec.width = 0
        return spec

    def add_missing(self, extensions):
        """ adds the instructions specs that are missing from the XML file we use """
        if not extensions or "CLFSH" in extensions:
            for width in [8, 16, 32, 64]:
                inst = InstructionSpec()
                inst.name = "CLFLUSH"
                inst.category = "CLFSH-MISC"
                inst.control_flow = False
                op = OperandSpec()
                op.type_ = "MEM"
                op.values = []
                op.src = True
                op.dest = False
                op.width = width
                inst.operands = [op]
                self.instructions.append(inst)

        if not extensions or "CLFLUSHOPT" in extensions:
            for width in [8, 16, 32, 64]:
                inst = InstructionSpec()
                inst.name = "CLFLUSHOPT"
                inst.category = "CLFLUSHOPT-CLFLUSHOPT"
                inst.control_flow = False
                op = OperandSpec()
                op.type_ = "MEM"
                op.values = []
                op.src = True
                op.dest = False
                op.width = width
                inst.operands = [op]
                self.instructions.append(inst)

        if not extensions or "BASE" in extensions:
            inst = InstructionSpec()
            inst.name = "INT1"
            inst.category = "BASE-INTERRUPT"
            inst.control_flow = False
            op1 = OperandSpec()
            op1.type_, op1.src, op1.dest, op1.width = "REG", False, True, 64
            op1.values = ["RIP"]
            op2 = OperandSpec()
            op2.type_, op2.src, op2.dest, op2.width = "FLAGS", False, False, 0
            op2.values = ["", "", "", "", "", "w", "w", "", ""]
            inst.implicit_operands = [op1, op2]
            self.instructions.append(inst)


class Downloader:
    def __init__(self, extensions: List[str], out_file: str) -> None:
        self.extensions = extensions
        self.out_file = out_file

    def run(self):
        subprocess.run(
            "wget "
            "https://github.com/microsoft/sca-fuzzer/releases/download/v1.2/x86_instructions.xml",
            shell=True,
            check=True)

        try:
            transformer = X86Transformer()
            transformer.load_files("x86_instructions.xml")
            transformer.parse_tree(self.extensions)
            transformer.add_missing(self.extensions)
            print(f"Produced base.json with {len(transformer.instructions)} instructions")
            transformer.save(self.out_file)
        finally:
            subprocess.run("rm x86_instructions.xml", shell=True, check=True)
