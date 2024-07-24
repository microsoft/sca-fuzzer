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
    signed: bool = True
    comment: str
    src: bool = False
    dest: bool = False
    magic: bool = False

    def to_json(self) -> str:
        values_lower = []
        for v in self.values:
            values_lower.append(v.lower())
        self.values = values_lower
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
        s += f'"name": "{self.name.lower()}", "category": "{self.category}", '
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
        "rax": 64,
        "rbx": 64,
        "rcx": 64,
        "rdx": 64,
        "r11": 64,
        "eax": 32,
        "ebx": 32,
        "ecx": 32,
        "edx": 32,
        "ax": 16,
        "dx": 16,
        "al": 8,
        "ah": 8,
        "cl": 8,
        "tmm0": 0,
        "mxcsr": 32,
        'es': 16,
        'ss': 16,
        'ds': 16,
        'fs': 16,
        'gs': 16,
        'cr0': 64,
        'cr3': 64,
        'cr4': 64,
        'cr8': 64,
        'xcr0': 64,
        'dr0': 64,
        'dr1': 64,
        'dr2': 64,
        'dr3': 64,
        'dr6': 64,
        'dr7': 64,
        'gdtr': 80,
        'ldtr': 96,
        'idtr': 80,
        'tr': 16,
        'msrs': 64,
        'x87control': 16,
        'tsc': 64,
        "tscaux": 64,
    }
    not_control_flow = ["int", "int1", "int3", "into"]
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
            name = name.lower()
            self.instruction.name = name

            try:
                for op_node in instruction_node.iter('operand'):
                    op_type = op_node.attrib['type']
                    if op_type == 'reg':
                        parsed_op = self.parse_reg_operand(op_node)
                        text = getattr(op_node, 'text', '').lower()
                        if text == "rip" and name not in self.not_control_flow:
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
        spec.values = op.text.lower().split(',')
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
        if op.attrib.get('s', '1') == '0':
            spec.signed = False
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
                inst.name = "clflush"
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
                inst.name = "clflushopt"
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
            inst.name = "int1"
            inst.category = "BASE-INTERRUPT"
            inst.control_flow = False
            op1 = OperandSpec()
            op1.type_, op1.src, op1.dest, op1.width = "REG", False, True, 64
            op1.values = ["rip"]
            op2 = OperandSpec()
            op2.type_, op2.src, op2.dest, op2.width = "FLAGS", False, False, 0
            op2.values = ["", "", "", "", "", "w", "w", "", ""]
            inst.implicit_operands = [op1, op2]
            self.instructions.append(inst)

        if not extensions or "MPX" in extensions:
            for name in ["bndcl", "bndcu"]:
                inst = InstructionSpec()
                inst.name = name
                inst.category = "MPX-MPX"
                inst.control_flow = False
                op1 = OperandSpec()
                op1.type_, op1.src, op1.dest, op1.width = "REG", True, False, 128
                op1.values = ["bnd0", "bnd1", "bnd2", "bnd3"]
                op2 = OperandSpec()
                op2.type_, op2.src, op2.dest, op2.width = "MEM", True, False, 64
                op2.values = []
                inst.operands = [op1, op2]
                self.instructions.append(inst)


SAFE_EXTENSIONS = [
    "BASE",
    "SSE",
    "SSE2",
    "SSE3",
    "SSE4",
    "SSE4a",
    "CLFLUSHOPT",
    "CLFSH",
    "MPX",
    "SSE",
    "RDTSCP",
    "LONGMODE",
]

ALL_EXTENSIONS = SAFE_EXTENSIONS + [
    "VTX",
    "SVM",
    "SMX",
    "WBNOINVD",
    "XSAVE",
    "XSAVEOPT",
    "XSAVES",
    "SGX",
    "ENQCMD",
    "INVPCID",
    "KEYLOCKER",
    "MONITOR",
    "PAUSE",
    "RDRAND",
    "RDSEED",
    "RDWRFSGS",
    "HRESET",
    "SYSRET",
    "SMAP",
    "AMD_INVLPGB",
    "SNP",
]


class Downloader:

    def __init__(self, extensions: List[str], out_file: str) -> None:
        if "ALL_SUPPORTED" in extensions:
            extensions.extend(SAFE_EXTENSIONS)
            extensions = list(set(extensions))
        elif "ALL_AND_UNSAFE" in extensions:
            extensions.extend(ALL_EXTENSIONS)
            extensions = list(set(extensions))
        self.extensions = extensions
        self.out_file = out_file

    def run(self):
        subprocess.run(
            "curl -L -o x86_instructions.xml "
            "https://github.com/microsoft/sca-fuzzer/releases/download/v1.2.4/x86_instructions.xml",
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
