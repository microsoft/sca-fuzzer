"""
File: Register ID to/from Register Name mappings for DynamoRIO.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from typing import Dict, Final, List
from .shared_types import *


# Map regiter names back to registers.
REVERSE_REGS: Dict[RegName, RegId] = {}

# Map register id to register names, taken from the DynamoRIO headers.
REGS: List[RegName] = []

# Register used for AVX instruction size
OPMASKS: Final[List[RegName]] = ["K0",
    "K1",
    "K2",
    "K3",
    "K4",
    "K5",
    "K6",
    "K7"]

def init_reg_map():
    """
    Initialize the value of the register maps.
    """
    global REGS
    global REVERSE_REGS

    REGS.extend([ "NULL",
        "RAX",
        "RCX",
        "RDX",
        "RBX",
        "RSP",
        "RBP",
        "RSI",
        "RDI",
        "R8",
        "R9",
        "R10",
        "R11",
        "R12",
        "R13",
        "R14",
        "R15",
        "EAX",
        "ECX",
        "EDX",
        "EBX",
        "ESP",
        "EBP",
        "ESI",
        "EDI",
        "R8D",
        "R9D",
        "R10D",
        "R11D",
        "R12D",
        "R13D",
        "R14D",
        "R15D",
        "AX",
        "CX",
        "DX",
        "BX",
        "SP",
        "BP",
        "SI",
        "DI",
        "R8W",
        "R9W",
        "R10W",
        "R11W",
        "R12W",
        "R13W",
        "R14W",
        "R15W",
        "AL",
        "CL",
        "DL",
        "BL",
        "AH",
        "CH",
        "DH",
        "BH",
        "R8L",
        "R9L",
        "R10L",
        "R11L",
        "R12L",
        "R13L",
        "R14L",
        "R15L",
        "SPL",
        "BPL",
        "SIL",
        "DIL",
        "MM0",
        "MM1",
        "MM2",
        "MM3",
        "MM4",
        "MM5",
        "MM6",
        "MM7",
        "XMM0",
        "XMM1",
        "XMM2",
        "XMM3",
        "XMM4",
        "XMM5",
        "XMM6",
        "XMM7",
        "XMM8",
        "XMM9",
        "XMM10",
        "XMM11",
        "XMM12",
        "XMM13",
        "XMM14",
        "XMM15",
        "XMM16",
        "XMM17",
        "XMM18",
        "XMM19",
        "XMM20",
        "XMM21",
        "XMM22",
        "XMM23",
        "XMM24",
        "XMM25",
        "XMM26",
        "XMM27",
        "XMM28",
        "XMM29",
        "XMM30",
        "XMM31",
    ])
    REGS.extend(["RESERVED_XMM"]*32)
    REGS.extend([
        "ST0",
        "ST1",
        "ST2",
        "ST3",
        "ST4",
        "ST5",
        "ST6",
        "ST7",
        "DR_SEG_ES",
        "DR_SEG_CS",
        "DR_SEG_SS",
        "DR_SEG_DS",
        "DR_SEG_FS",
        "DR_SEG_GS",
        "DR0",
        "DR1",
        "DR2",
        "DR3",
        "DR4",
        "DR5",
        "DR6",
        "DR7",
        "DR8",
        "DR9",
        "DR10",
        "DR11",
        "DR12",
        "DR13",
        "DR14",
        "DR15",
        "CR0",
        "CR1",
        "CR2",
        "CR3",
        "CR4",
        "CR5",
        "CR6",
        "CR7",
        "CR8",
        "CR9",
        "CR10",
        "CR11",
        "CR12",
        "CR13",
        "CR14",
        "CR15",
        "INVALID",
        "YMM0",
        "YMM1",
        "YMM2",
        "YMM3",
        "YMM4",
        "YMM5",
        "YMM6",
        "YMM7",
        "YMM8",
        "YMM9",
        "YMM10",
        "YMM11",
        "YMM12",
        "YMM13",
        "YMM14",
        "YMM15",
        "YMM16",
        "YMM17",
        "YMM18",
        "YMM19",
        "YMM20",
        "YMM21",
        "YMM22",
        "YMM23",
        "YMM24",
        "YMM25",
        "YMM26",
        "YMM27",
        "YMM28",
        "YMM29",
        "YMM30",
        "YMM31",
    ])
    REGS.extend(["RESERVED_YMM"]*32)
    REGS.extend(["ZMM0",
        "ZMM1",
        "ZMM2",
        "ZMM3",
        "ZMM4",
        "ZMM5",
        "ZMM6",
        "ZMM7",
        "ZMM8",
        "ZMM9",
        "ZMM10",
        "ZMM11",
        "ZMM12",
        "ZMM13",
        "ZMM14",
        "ZMM15",
        "ZMM16",
        "ZMM17",
        "ZMM18",
        "ZMM19",
        "ZMM20",
        "ZMM21",
        "ZMM22",
        "ZMM23",
        "ZMM24",
        "ZMM25",
        "ZMM26",
        "ZMM27",
        "ZMM28",
        "ZMM29",
        "ZMM30",
        "ZMM31",
    ])
    REGS.extend(["RESERVED_ZMM"]*32)
    REGS.extend(["K0",
        "K1",
        "K2",
        "K3",
        "K4",
        "K5",
        "K6",
        "K7"])
    REGS.extend(["RESERVED_OPMASK"]*8)
    REGS.extend([
        "BND0",
        "BND1",
        "BND2",
        "BND3",
        ])

    # Map each name back to an ID.
    for idx, val in enumerate(REGS):
        REVERSE_REGS[val] = idx


def strip_alias(reg_name: RegName):
    """
    Reduce different names that represent portions of the same register to a single name.
    """
    if reg_name in ["RAX", "EAX", "AX", "AL"]:
        return "RAX"
    elif reg_name in ["RBX", "EBX", "BX", "BL"]:
        return "RBX"
    elif reg_name in ["RCX", "ECX", "CX", "CL"]:
        return "RCX"
    elif reg_name in ["RDX", "EDX", "DX", "DL"]:
        return "RDX"
    elif reg_name in ["RDI", "EDI", "DI", "DIL"]:
        return "RDI"
    elif reg_name in ["RSI", "ESI", "SI", "SIL"]:
        return "RSI"
    elif reg_name in ["RSP", "ESP", "SP", "SPL"]:
        return "RSP"
    elif reg_name in ["RBP", "EBP", "BP", "BPL"]:
        return "RBP"
    elif reg_name in ["R8", "R8D", "R8W", "R8L"]:
        return "R8"
    elif reg_name in ["R9", "R9D", "R9W", "R9L"]:
        return "R9"
    elif reg_name in ["R10", "R10D", "R10W", "R10L"]:
        return "R10"
    elif reg_name in ["R11", "R11D", "R11W", "R11L"]:
        return "R11"

    return reg_name


def reg_id_to_stripped_name(reg_idx: RegId):
    """
    Get the name for a reg id after stripping the alias, treating registers that alias as
    the same register.
    """
    return strip_alias(REGS[reg_idx])
