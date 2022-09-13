"""
File:

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List
from interfaces import Instruction
from generator import TargetDesc
from model import UnicornTargetDesc

from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, \
    UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_NZCV

from config import CONF


class ARMTargetDesc(TargetDesc):
    branch_conditions = {
        "EQ": ["", "", "", "r", "", "", "", "", ""],
        "NE": ["", "", "", "r", "", "", "", "", ""],
        "CS": ["r", "", "", "", "", "", "", "", ""],
        "CC": ["r", "", "", "", "", "", "", "", ""],
        "MI": ["", "", "", "", "r", "", "", "", ""],
        "PL": ["", "", "", "", "r", "", "", "", ""],
        "VS": ["", "", "", "", "", "", "", "", "r"],
        "VC": ["", "", "", "", "", "", "", "", "r"],
        "HI": ["r", "", "", "r", "", "", "", "", ""],
        "LS": ["r", "", "", "r", "", "", "", "", ""],
        "GE": ["", "", "", "", "r", "", "", "", "r"],
        "LT": ["", "", "", "", "r", "", "", "", "r"],
        "GT": ["", "", "", "r", "r", "", "", "", "r"],
        "LE": ["", "", "", "r", "r", "", "", "", "r"],
        "AL": ["", "", "", "", "", "", "", "", ""]
    }

    def __init__(self):
        super().__init__()
        self.registers = {}
        self.registers[32] = ["W" + str(i) for i in range(0, 31)]
        self.registers[32].append("WSP")
        self.registers[32].append("WZR")
        self.registers[64] = ["X" + str(i) for i in range(0, 31)]
        self.registers[64].append("SP")
        self.registers[64].append("XZR")

        self.register_sizes = {}
        for k, v in self.registers.items():
            for reg in v:
                self.register_sizes[reg] = k

        # remove blocked registers
        filtered_decoding = {}
        for size, registers in self.registers.items():
            filtered_decoding[size] = []
            for register in registers:
                if register not in CONF.register_blocklist:
                    filtered_decoding[size].append(register)
        self.registers = filtered_decoding

    @staticmethod
    def is_unconditional_branch(inst: Instruction) -> bool:
        return inst.name in ["B"]

    @staticmethod
    def is_call(inst: Instruction) -> bool:
        return inst.name in ["BL"]


class ARM64UnicornTargetDesc(UnicornTargetDesc):
    registers: List[int] = [
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4,
        UC_ARM64_REG_X5, UC_ARM64_REG_NZCV
    ]
    barriers: List[str] = [
        'DMB', 'DSB',
        'LDAR', 'STLR', 'LDAXR', 'STLXR'  # One-way barrier
    ]
    flags_register: int = UC_ARM64_REG_NZCV