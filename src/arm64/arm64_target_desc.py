"""
File:

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List
from interfaces import Instruction, TargetDesc
from model import UnicornTargetDesc

import unicorn.arm64_const as ucc
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

    gpr_normalized = {
        "PC": "RIP",
        "SP_EL0": "SP", "SP_EL1": "SP", "SP_EL2": "SP", "SP_EL3": "SP",
        "X0": "0", "W0": "0",
        "X1": "1", "W1": "1",
        "X2": "2", "W2": "2",
        "X3": "3", "W3": "3",
        "X4": "4", "W4": "4",
        "X5": "5", "W5": "5",
        "X6": "6", "W6": "6",
        "X7": "7", "W7": "7",
        "X8": "8", "W8": "8",
        "X9": "9", "W9": "9",
        "X10": "10", "W10": "10",
        "X11": "11", "W11": "11",
        "X12": "12", "W12": "12",
        "X13": "13", "W13": "13",
        "X14": "14", "W14": "14",
        "X15": "15", "W15": "15",
        "X16": "16", "W16": "16",
        "X17": "17", "W17": "17",
        "X18": "18", "W18": "18",
        "X19": "19", "W19": "19",
        "X20": "20", "W20": "20",
        "X21": "21", "W21": "21",
        "X22": "22", "W22": "22",
        "X23": "23", "W23": "23",
        "X24": "24", "W24": "24",
        "X25": "25", "W25": "25",
        "X26": "26", "W26": "26",
        "X27": "27", "W27": "27",
        "X28": "28", "W28": "28",
        "X29": "29", "W29": "29",
        "X30": "30", "W30": "30"
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
        ucc.UC_ARM64_REG_X0, ucc.UC_ARM64_REG_X1, ucc.UC_ARM64_REG_X2,
        ucc.UC_ARM64_REG_X3, ucc.UC_ARM64_REG_X4, ucc.UC_ARM64_REG_X5,
        ucc.UC_ARM64_REG_NZCV
    ]
    barriers: List[str] = [
        'DMB', 'DSB',
        'LDAR', 'STLR', 'LDAXR', 'STLXR'  # One-way barrier
    ]
    flags_register: int = ucc.UC_ARM64_REG_NZCV

    reg_str_to_constant = {
        "X0": ucc.UC_ARM64_REG_X0,
        "X1": ucc.UC_ARM64_REG_X1,
        "X2": ucc.UC_ARM64_REG_X2,
        "X3": ucc.UC_ARM64_REG_X3,
        "X4": ucc.UC_ARM64_REG_X4,
        "X5": ucc.UC_ARM64_REG_X5,
        "X6": ucc.UC_ARM64_REG_X6,
        "X7": ucc.UC_ARM64_REG_X7,
        "X8": ucc.UC_ARM64_REG_X8,
        "X9": ucc.UC_ARM64_REG_X9,
        "X10": ucc.UC_ARM64_REG_X10,
        "X11": ucc.UC_ARM64_REG_X11,
        "X12": ucc.UC_ARM64_REG_X12,
        "X13": ucc.UC_ARM64_REG_X13,
        "X14": ucc.UC_ARM64_REG_X14,
        "X15": ucc.UC_ARM64_REG_X15,
        "X16": ucc.UC_ARM64_REG_X16,
        "X17": ucc.UC_ARM64_REG_X17,
        "X18": ucc.UC_ARM64_REG_X18,
        "X19": ucc.UC_ARM64_REG_X19,
        "X20": ucc.UC_ARM64_REG_X20,
        "X21": ucc.UC_ARM64_REG_X21,
        "X22": ucc.UC_ARM64_REG_X22,
        "X23": ucc.UC_ARM64_REG_X23,
        "X24": ucc.UC_ARM64_REG_X24,
        "X25": ucc.UC_ARM64_REG_X25,
        "X26": ucc.UC_ARM64_REG_X26,
        "X27": ucc.UC_ARM64_REG_X27,
        "X28": ucc.UC_ARM64_REG_X28,
        "X29": ucc.UC_ARM64_REG_X29,
        "X30": ucc.UC_ARM64_REG_X30
    }

    reg_decode = {
        "RIP": ucc.UC_ARM64_REG_PC,
        "SP": ucc.UC_ARM64_REG_SP,
        "0": ucc.UC_ARM64_REG_X0,
        "1": ucc.UC_ARM64_REG_X1,
        "2": ucc.UC_ARM64_REG_X2,
        "3": ucc.UC_ARM64_REG_X3,
        "4": ucc.UC_ARM64_REG_X4,
        "5": ucc.UC_ARM64_REG_X5,
        "6": ucc.UC_ARM64_REG_X6,
        "7": ucc.UC_ARM64_REG_X7,
        "8": ucc.UC_ARM64_REG_X8,
        "9": ucc.UC_ARM64_REG_X9,
        "10": ucc.UC_ARM64_REG_X10,
        "11": ucc.UC_ARM64_REG_X11,
        "12": ucc.UC_ARM64_REG_X12,
        "13": ucc.UC_ARM64_REG_X13,
        "14": ucc.UC_ARM64_REG_X14,
        "15": ucc.UC_ARM64_REG_X15,
        "16": ucc.UC_ARM64_REG_X16,
        "17": ucc.UC_ARM64_REG_X17,
        "18": ucc.UC_ARM64_REG_X18,
        "19": ucc.UC_ARM64_REG_X19,
        "20": ucc.UC_ARM64_REG_X20,
        "21": ucc.UC_ARM64_REG_X21,
        "22": ucc.UC_ARM64_REG_X22,
        "23": ucc.UC_ARM64_REG_X23,
        "24": ucc.UC_ARM64_REG_X24,
        "25": ucc.UC_ARM64_REG_X25,
        "26": ucc.UC_ARM64_REG_X26,
        "27": ucc.UC_ARM64_REG_X27,
        "28": ucc.UC_ARM64_REG_X28,
        "29": ucc.UC_ARM64_REG_X29,
        "30": ucc.UC_ARM64_REG_X30,
        "FLAGS": ucc.UC_ARM64_REG_NZCV,
        "CF": ucc.UC_ARM64_REG_NZCV,
        "PF": ucc.UC_ARM64_REG_NZCV,
        "AF": ucc.UC_ARM64_REG_NZCV,
        "ZF": ucc.UC_ARM64_REG_NZCV,
        "SF": ucc.UC_ARM64_REG_NZCV,
        "TF": ucc.UC_ARM64_REG_NZCV,
        "IF": ucc.UC_ARM64_REG_NZCV,
        "DF": ucc.UC_ARM64_REG_NZCV,
        "OF": ucc.UC_ARM64_REG_NZCV,
        "AC": ucc.UC_ARM64_REG_NZCV,
    }
