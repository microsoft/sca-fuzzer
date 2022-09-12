#!/usr/bin/env python3
"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import os
import glob
import re
import json
import subprocess
from typing import List, Optional
from xml.etree import ElementTree as ET


class OperandSpec:
    values: List[str]
    type_: str
    width: int
    comment: str
    src: bool = False
    dest: bool = False

    def to_json(self) -> str:
        return json.dumps(self, default=vars)


class InstructionSpec:
    name: str
    category: str = ""
    control_flow: bool = False
    operands: List[OperandSpec]
    implicit_operands: List[OperandSpec]
    datasize: int = 0

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


class ARMTransformer:
    tree: ET.ElementTree
    instructions: List[InstructionSpec]
    current_spec: InstructionSpec

    def __init__(self) -> None:
        self.instructions = []

    def load_files(self, files: List[str]):
        # get the data from all files
        tree = ET.parse("_root.xml")
        root = tree.getroot()
        for filename in files:
            data = ET.parse(filename).getroot()
            root.append(data)
        if not tree:
            print("No input. Exiting")
            exit(1)
        self.tree = tree

    def parse_tree(self):
        for instruction_node in self.tree.iter('instructionsection'):
            if instruction_node.attrib['type'] != "instruction":
                continue

            # remove those instruction types/forms that are not yet supported
            docvars = instruction_node.find("docvars")
            if not docvars:
                continue  # empty spec?
            address_form = ""
            category = ""
            for op_node in docvars.iter("docvar"):
                if op_node.attrib["key"] == "instr-class":
                    category = op_node.attrib["value"]
                elif op_node.attrib["key"] == "address-form":
                    address_form = op_node.attrib["value"]
            if category != "general":
                continue

            flags_op = self.get_flags_from_asl(instruction_node)

            # get all asm variants of the instructions
            for variant in instruction_node.findall("classes/iclass/encoding"):
                self.current_spec = InstructionSpec()

                # instruction info
                docvars = variant.find("docvars")
                assert docvars
                for op_node in docvars.iter("docvar"):
                    if op_node.attrib["key"] == "instr-class":
                        self.current_spec.category = op_node.attrib["value"]
                    elif op_node.attrib["key"] == "branch-offset":
                        self.current_spec.control_flow = True
                    elif op_node.attrib["key"] == "address-form":
                        address_form = op_node.attrib["value"]
                    elif op_node.attrib["key"] == "datatype":
                        self.current_spec.datasize = int(op_node.attrib["value"])

                if address_form not in ["literal", "base-register", "post-indexed", ""]:
                    continue

                self.current_spec.name = variant.find("asmtemplate/text").text.split(" ")[0]

                # implicit PC operand
                if self.current_spec.control_flow:
                    op_pc = OperandSpec()
                    op_pc.values = ["PC"]
                    op_pc.type_ = "REG"
                    op_pc.width = 64
                    op_pc.src = True
                    op_pc.dest = False
                    self.current_spec.implicit_operands.append(op_pc)

                # implicit flags operand
                if flags_op:
                    self.current_spec.implicit_operands.append(flags_op)

                # explicit operands
                op_type_hint = ""
                optional_depth = 0
                try:
                    for op_node in variant.find("asmtemplate").iter():
                        if op_node.tag == "a" and optional_depth == 0:
                            hover_text = op_node.attrib["hover"].lower().strip()
                            op = self.parse_hover_text(hover_text, op_type_hint)
                            self.current_spec.operands.append(op)

                        text = op_node.text
                        if text:
                            op_type_hint, modifier = self.parse_asm_template_text(text)
                            optional_depth += modifier

                except ParseFailed:
                    continue

                self.instructions.append(self.current_spec)

    def save(self, filename: str):
        json_str = "[\n" + ",\n".join([i.to_json() for i in self.instructions]) + "\n]"
        # print(json_str)
        with open(filename, "w+") as f:
            f.write(json_str)

    def get_flags_from_asl(self, element: ET.Element) -> Optional[OperandSpec]:
        """ look through the ASL code of the instruction to find if it reads/writes the flags """
        flag_values = {k: [False, False] for k in ["N", "Z", "C", "V", ""]}
        uses_flags = False
        for line in element.find("ps_section/ps/pstext").itertext():
            match = re.search(r"(=?) *PSTATE\.<?([NZCV,]+)>? *(=?)", line)
            if match:
                affected_flags = match.group(2).split(",")
                is_read = (match.group(1) == "=")
                is_write = (match.group(3) == "=")
                if not is_read and not is_write:
                    continue

                uses_flags = True
                for f in affected_flags:
                    flag_values[f][0] |= is_read
                    flag_values[f][1] |= is_write
        if uses_flags:
            flag_op = OperandSpec()
            flag_op.type_ = "FLAGS"
            flag_op.width = 0
            flag_op.src = False
            flag_op.dest = False
            flag_op.values = []

            # the loop maps ARM flags to x86 eflags, which is the basis for out flags data structure
            for f in ["C", "", "", "Z", "N", "", "", "", "V"]:
                if flag_values[f][0] and flag_values[f][1]:
                    flag_op.values.append("r/w")
                elif flag_values[f][0] and not flag_values[f][1]:
                    flag_op.values.append("r")
                elif not flag_values[f][0] and flag_values[f][1]:
                    flag_op.values.append("w")
                else:
                    flag_op.values.append("")
        else:
            flag_op = None
        return flag_op

    def parse_asm_template_text(self, text: str):
        op_type_hint = ""
        optional_depth = 0
        for word in text.split(" "):
            if not word:
                continue

            if word == self.current_spec.name:
                continue

            # operand name
            if word[0] == "<":
                assert word[-1] == ">"
                continue

            # indexing modes - not yet supported
            if "!" in word:
                raise ParseFailed()

            # multivariant operands - not yet supported
            if "|" in word or "(" in word:
                raise ParseFailed()

            # optional value
            if "{" in word:
                optional_depth += 1
                continue

            if "}" in word:
                optional_depth -= 1
                continue

            # immediate value
            if word == "#":
                op_type_hint = "IMM"
                continue

            # memory address - start
            if word == "[":
                op_type_hint = "MEM"
                continue

            # memory address - end
            if word == "]":
                op_type_hint = ""
                continue

            if word == "LSL":
                op_type_hint = "LSL"
                continue

            if word in [",", "],"]:
                op_type_hint = ""
                continue
            assert False, f"Unknown keyword: {word} in {self.current_spec.name}"

        return op_type_hint, optional_depth

    def parse_hover_text(self, text: str, type_hint: str) -> OperandSpec:
        text = text.removeprefix("first ")
        text = text.removeprefix("second ")
        text = text.removeprefix("third ")

        op = OperandSpec()
        op.dest = ("destination" in text)
        op.src = ("source" in text)
        op.comment = text

        if "MEM" == type_hint:
            return self.parse_mem_operand(op, text)

        if "IMM" == type_hint:
            op.type_ = "IMM"
            op.src = True
            op.dest = False

            range_match = re.search(r"\[-?\d+-\d+\]", text)
            if range_match:
                op.values = [range_match.group(0)]
                op.width = 0
            elif "bit " in text:
                if "five" in text and "positive" in text:
                    op.values = ["[0-31]"]
                    op.width = 5
                else:
                    assert False, f"{self.current_spec.name} {text}"
            elif "bitmask immediate" in text:
                op.values = ["bitmask"]
                op.width = self.current_spec.datasize
            else:
                assert False, f"{self.current_spec.name} {text}"
            assert "register" not in text and "label" not in text, \
                f"{self.current_spec.name} {text}"
            return op

        if "register" in text:
            return self.parse_reg_operand(op, text, type_hint)

        if "label" in text:
            op.type_ = "LABEL"
            op.values = []
            op.width = 0
            op.src = True
            return op

        if "standard condition" in text:
            return self.parse_cond_operand(op, text)

        raise ParseFailed()

    def parse_cond_operand(self, op, text: str):
        op.type_ = "COND"
        op.values = []
        op.width = 0
        if "except" not in text:
            return op

        raise ParseFailed()

    def parse_mem_operand(self, op, text: str):
        op.type_ = "MEM"
        op.width = 32 if "32-bit" in text else 64
        assert "base" in text or "address" in text, f"{self.current_spec.name} {text}"
        assert op.width == 32 or "64-bit" in text or "-bit" not in text, \
            f"{self.current_spec.name} {text}"

        if op.dest or op.src:
            return op

        if self.current_spec.name[:3] == "LDR":
            op.src = True
            return op

        if self.current_spec.name[:3] == "STR":
            op.dest = True
            return op

        raise ParseFailed()

    def parse_reg_operand(self, op, text: str, type_hint):
        if "to be branched" in text:
            raise ParseFailed()

        op.type_ = "REG"
        op.width = 32 if "32-bit" in text else 64
        op.values = ["GPR"]
        if " wsp" in text or " sp" in text:
            op.values.append("SP")
        if "zr" in text:
            op.values.append("ZR")
        assert type_hint == "", f"{self.current_spec.name} {text}"
        assert "general-purpose" in text, f"{self.current_spec.name} {text}"
        assert op.width == 32 or "64-bit" in text or "-bit" not in text, \
            f"{self.current_spec.name} {text}"

        if op.dest or op.src:
            return op

        op.dest = ("stored" in text)
        op.src = ("loaded" in text)
        if op.dest or op.src:
            return op

        op.dest = ("output" in text)
        op.src = ("input" in text)
        if op.dest or op.src:
            return op

        if "tested" in text:
            op.src = True
            return op

        if self.current_spec.name[:3] == "LDR":
            op.dest = True
            return op

        if self.current_spec.name[:3] == "STR":
            op.src = True
            return op

        raise ParseFailed()


def main():
    subprocess.run(
        "wget "
        "https://developer.arm.com/-/media/developer/products/architecture/armv9-a-architecture/2022-03/ISA_A64_xml_A_profile-2022-03.tar.gz",
        shell=True,
        check=True)
    subprocess.run("mkdir -p all", shell=True, check=True)
    subprocess.run("mkdir -p instructions", shell=True, check=True)
    subprocess.run("tar xf ISA_A64_xml_A_profile-2022-03.tar.gz -C all", shell=True, check=True)
    subprocess.run(
        "mv all/ISA_A64_xml_A_profile-2022-03/*.xml instructions/", shell=True, check=True)
    subprocess.run("rm ISA_A64_xml_A_profile-2022-03.tar.gz*", shell=True, check=True)
    os.remove("instructions/encodingindex.xml")
    os.remove("instructions/onebigfile.xml")
    subprocess.run("rm -r all", shell=True, check=True)

    files = glob.glob("instructions/*.xml")

    transformer = ARMTransformer()
    transformer.load_files(files)
    transformer.parse_tree()
    print(f"Produced base.json with {len(transformer.instructions)} instructions")
    transformer.save("base.json")
    subprocess.run("rm -r instructions", shell=True, check=True)


if __name__ == "__main__":
    main()
