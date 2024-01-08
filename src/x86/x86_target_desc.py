"""
File: x86-specific constants and lists

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List
import unicorn.x86_const as ucc  # type: ignore

from ..interfaces import Instruction, TargetDesc, MacroSpec
from ..model import UnicornTargetDesc
from ..config import CONF


class X86TargetDesc(TargetDesc):
    register_sizes = {
        "RAX": 64, "RBX": 64, "RCX": 64, "RDX": 64, "RSI": 64, "RDI": 64, "RSP": 64, "RBP": 64,
        "R8": 64, "R9": 64, "R10": 64, "R11": 64, "R12": 64, "R13": 64, "R14": 64, "R15": 64,
        "EAX": 32, "EBX": 32, "ECX": 32, "EDX": 32, "ESI": 32, "EDI": 32, "R8D": 32, "R9D": 32,
        "R10D": 32, "R11D": 32, "R12D": 32, "R13D": 32, "R14D": 32, "R15D": 32,
        "AX": 16, "BX": 16, "CX": 16, "DX": 16, "SI": 16, "DI": 16, "R8W": 16, "R9W": 16,
        "R10W": 16, "R11W": 16, "R12W": 16, "R13W": 16, "R14W": 16, "R15W": 16,
        "AL": 8, "BL": 8, "CL": 8, "DL": 8, "SIL": 8, "DIL": 8, "R8B": 8, "R9B": 8,
        "R10B": 8, "R11B": 8, "R12B": 8, "R13B": 8, "R14B": 8, "R15B": 8,
        "AH": 8, "Bh": 8, "CH": 8, "DH": 8,
    }  # yapf: disable
    reg_normalized = {
        "RAX": "A", "EAX": "A", "AX": "A", "AL": "A", "AH": "A",
        "RBX": "B", "EBX": "B", "BX": "B", "BL": "B", "BH": "B",
        "RCX": "C", "ECX": "C", "CX": "C", "CL": "C", "CH": "C",
        "RDX": "D", "EDX": "D", "DX": "D", "DL": "D", "DH": "D",
        "RSI": "SI", "ESI": "SI", "SI": "SI", "SIL": "SI",
        "RDI": "DI", "EDI": "DI", "DI": "DI", "DIL": "DI",
        "R8": "8", "R8D": "8", "R8W": "8", "R8B": "8",
        "R9": "9", "R9D": "9", "R9W": "9", "R9B": "9",
        "R10": "10", "R10D": "10", "R10W": "10", "R10B": "10",
        "R11": "11", "R11D": "11", "R11W": "11", "R11B": "11",
        "R12": "12", "R12D": "12", "R12W": "12", "R12B": "12",
        "R13": "13", "R13D": "13", "R13W": "13", "R13B": "13",
        "R14": "14", "R14D": "14", "R14W": "14", "R14B": "14",
        "R15": "15", "R15D": "15", "R15W": "15", "R15B": "15",
        "FLAGS": "FLAGS",
        "RIP": "RIP",
        "RSP": "RSP",
        "CF": "CF", "PF": "PF", "AF": "AF", "ZF": "ZF", "SF": "SF", "TF": "TF", "IF": "IF",
        "DF": "DF", "OF": "OF", "AC": "AC",
        "BND0": "BND0", "BND1": "BND1", "BND2": "BND2", "BND3": "BND3",
        "XMM0": "XMM0",
        "XMM1": "XMM1",
        "XMM2": "XMM2",
        "XMM3": "XMM3",
        "XMM4": "XMM4",
        "XMM5": "XMM5",
        "XMM6": "XMM6",
        "XMM7": "XMM7",
        "XMM8": "XMM8",
        "XMM9": "XMM9",
        "XMM10": "XMM10",
        "XMM11": "XMM11",
        "XMM12": "XMM12",
        "XMM13": "XMM13",
        "XMM14": "XMM14",
        "XMM15": "XMM15"
    }  # yapf: disable
    reg_denormalized = {
        "A": {64: "RAX", 32: "EAX", 16: "AX", 8: "AL"},
        "B": {64: "RBX", 32: "EBX", 16: "BX", 8: "BL"},
        "C": {64: "RCX", 32: "ECX", 16: "CX", 8: "CL"},
        "D": {64: "RDX", 32: "EDX", 16: "DX", 8: "DL"},
        "SI": {64: "RSI", 32: "ESI", 16: "SI", 8: "SIL"},
        "DI": {64: "RDI", 32: "EDI", 16: "DI", 8: "DIL"},
        "8": {64: "R8", 32: "R8D", 16: "R8W", 8: "R8B"},
        "9": {64: "R9", 32: "R9D", 16: "R9W", 8: "R9B"},
        "10": {64: "R10", 32: "R10D", 16: "R10W", 8: "R10B"},
        "11": {64: "R11", 32: "R11D", 16: "R11W", 8: "R11B"},
        "12": {64: "R12", 32: "R12D", 16: "R12W", 8: "R12B"},
        "13": {64: "R13", 32: "R13D", 16: "R13W", 8: "R13B"},
        "14": {64: "R14", 32: "R14D", 16: "R14W", 8: "R14B"},
        "15": {64: "R15", 32: "R15D", 16: "R15W", 8: "R15B"},
        "RIP": {64: "RIP", 32: "RIP", 16: "RIP", 8: "RIP"},
        "RSP": {64: "RSP", 32: "RSP", 16: "RSP", 8: "RSP"},
        "XMM0": {128: "XMM0"},
        "XMM1": {128: "XMM1"},
        "XMM2": {128: "XMM2"},
        "XMM3": {128: "XMM3"},
        "XMM4": {128: "XMM4"},
        "XMM5": {128: "XMM5"},
        "XMM6": {128: "XMM6"},
        "XMM7": {128: "XMM7"},
        "XMM8": {128: "XMM8"},
        "XMM9": {128: "XMM9"},
        "XMM10": {128: "XMM10"},
        "XMM11": {128: "XMM11"},
        "XMM12": {128: "XMM12"},
        "XMM13": {128: "XMM13"},
        "XMM14": {128: "XMM14"},
        "XMM15": {128: "XMM15"}
    }  # yapf: disable
    registers = {
        8: ["AL", "BL", "CL", "DL", "SIL", "DIL", "R8B", "R9B", "R10B", "R11B", "R12B", "R13B",
            "R14B", "R15B"],
        16: ["AX", "BX", "CX", "DX", "SI", "DI", "R8W", "R9W", "R10W", "R11W", "R12W", "R13W",
             "R14W", "R15W"],
        32: ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "R8D", "R9D", "R10D", "R11D", "R12D",
             "R13D", "R14D", "R15D"],
        64: ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13",
             "R14", "R15", "RSP", "RBP"],
        128: ["BND0", "BND1", "BND2", "BND3",
              "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5",
              "XMM6", "XMM7", "XMM8", "XMM9", "XMM10", "XMM11", "XMM12", "XMM13", "XMM14", "XMM15"]
    }  # yapf: disable
    simd_registers = {
        64: [f"MM{i}" for i in range(0, 8)],
        128: [f"XMM{i}" for i in range(0, 32)],
        256: [f"YMM{i}" for i in range(0, 32)],
        512: [f"ZMM{i}" for i in range(0, 32)],
    }  # yapf: disable

    pte_bits = {
        # NAME: (position, default value)
        "present": (0, True),  # is present
        "writable": (1, True),  # writeable
        "user": (2, False),  # userspace addressable
        "write-through": (3, False),  # page write through
        "cache-disable": (4, False),  # page cache disabled
        "accessed": (5, True),  # was accessed
        "dirty": (6, True),  # was written to
        # "pkey_bit0": (59, False),  # Protection Keys, bit 1/4
        # "pkey_bit1": (60, False),  # Protection Keys, bit 2/4
        # "pkey_bit2": (61, False),  # Protection Keys, bit 3/4
        # "pkey_bit3": (62, False),  # Protection Keys, bit 4/4
        "non_executable": (63, False),  # No execute: only valid after cpuid check
    }

    epte_bits = {
        # NAME: (position, default value)
        "present": (0, True),  # is present
        "writable": (1, True),  # writeable
        "executable": (2, True),  # executable
        "accessed": (8, True),  # was accessed
        "dirty": (9, True),  # was written to
        "user": (10, False),  # userspace addressable
    }

    # FIXME: macro IDs should not be hardcoded but rather received from the executor
    # or at least we need a test that will check that the IDs match
    macro_specs = {
        # macros with negative IDs are used for generation
        # and are not supposed to reach the final binary
        "random_instructions": MacroSpec(-1, "random_instructions", ("int", "int", "", "")),

        # macros with positive IDs are used for execution and can be interpreted by executor/model
        "function": MacroSpec(0, "function", ("", "", "", "")),
        "measurement_start": MacroSpec(1, "measurement_start", ("", "", "", "")),
        "measurement_end": MacroSpec(2, "measurement_end", ("", "", "", "")),
        "switch": MacroSpec(4, "switch", ("actor_id", "function_id", "", "")),
        "set_k2u_target": MacroSpec(5, "set_k2u_target", ("actor_id", "function_id", "", "")),
        "switch_k2u": MacroSpec(6, "switch_k2u", ("actor_id", "", "", "")),
        "set_u2k_target": MacroSpec(7, "set_u2k_target", ("actor_id", "function_id", "", "")),
        "switch_u2k": MacroSpec(8, "switch_u2k", ("actor_id", "", "", "")),
        "set_h2g_target": MacroSpec(9, "set_h2g_target", ("actor_id", "function_id", "", "")),
        "switch_h2g": MacroSpec(10, "switch_h2g", ("actor_id", "", "", "")),
        "set_g2h_target": MacroSpec(11, "set_g2h_target", ("actor_id", "function_id", "", "")),
        "switch_g2h": MacroSpec(12, "switch_g2h", ("actor_id", "", "", "")),
    }

    def __init__(self):
        super().__init__()
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
        return inst.category == "BASE-UNCOND_BR"

    @staticmethod
    def is_call(inst: Instruction) -> bool:
        return inst.category == "BASE-CALL"


class X86UnicornTargetDesc(UnicornTargetDesc):
    reg_str_to_constant = {
        "AL": ucc.UC_X86_REG_AL,
        "BL": ucc.UC_X86_REG_BL,
        "CL": ucc.UC_X86_REG_CL,
        "DL": ucc.UC_X86_REG_DL,
        "DIL": ucc.UC_X86_REG_DIL,
        "SIL": ucc.UC_X86_REG_SIL,
        "SPL": ucc.UC_X86_REG_SPL,
        "BPL": ucc.UC_X86_REG_BPL,
        "AH": ucc.UC_X86_REG_AH,
        "BH": ucc.UC_X86_REG_BH,
        "CH": ucc.UC_X86_REG_CH,
        "DH": ucc.UC_X86_REG_DH,
        "AX": ucc.UC_X86_REG_AX,
        "BX": ucc.UC_X86_REG_BX,
        "CX": ucc.UC_X86_REG_CX,
        "DX": ucc.UC_X86_REG_DX,
        "DI": ucc.UC_X86_REG_DI,
        "SI": ucc.UC_X86_REG_SI,
        "SP": ucc.UC_X86_REG_SP,
        "BP": ucc.UC_X86_REG_BP,
        "EAX": ucc.UC_X86_REG_EAX,
        "EBX": ucc.UC_X86_REG_EBX,
        "ECX": ucc.UC_X86_REG_ECX,
        "EDX": ucc.UC_X86_REG_EDX,
        "EDI": ucc.UC_X86_REG_EDI,
        "ESI": ucc.UC_X86_REG_ESI,
        "ESP": ucc.UC_X86_REG_ESP,
        "EBP": ucc.UC_X86_REG_EBP,
        "RAX": ucc.UC_X86_REG_RAX,
        "RBX": ucc.UC_X86_REG_RBX,
        "RCX": ucc.UC_X86_REG_RCX,
        "RDX": ucc.UC_X86_REG_RDX,
        "RDI": ucc.UC_X86_REG_RDI,
        "RSI": ucc.UC_X86_REG_RSI,
        "RSP": ucc.UC_X86_REG_RSP,
        "RBP": ucc.UC_X86_REG_RBP,
        "XMM0": ucc.UC_X86_REG_XMM0,
        "XMM1": ucc.UC_X86_REG_XMM1,
        "XMM2": ucc.UC_X86_REG_XMM2,
        "XMM3": ucc.UC_X86_REG_XMM3,
        "XMM4": ucc.UC_X86_REG_XMM4,
        "XMM5": ucc.UC_X86_REG_XMM5,
        "XMM6": ucc.UC_X86_REG_XMM6,
        "XMM7": ucc.UC_X86_REG_XMM7,
        "XMM8": ucc.UC_X86_REG_XMM8,
        "XMM9": ucc.UC_X86_REG_XMM9,
        "XMM10": ucc.UC_X86_REG_XMM10,
        "XMM11": ucc.UC_X86_REG_XMM11,
        "XMM12": ucc.UC_X86_REG_XMM12,
        "XMM14": ucc.UC_X86_REG_XMM14,
        "XMM15": ucc.UC_X86_REG_XMM15,
    }

    reg_decode = {
        "A": ucc.UC_X86_REG_RAX,
        "B": ucc.UC_X86_REG_RBX,
        "C": ucc.UC_X86_REG_RCX,
        "D": ucc.UC_X86_REG_RDX,
        "DI": ucc.UC_X86_REG_RDI,
        "SI": ucc.UC_X86_REG_RSI,
        "SP": ucc.UC_X86_REG_RSP,
        "BP": ucc.UC_X86_REG_RBP,
        "8": ucc.UC_X86_REG_R8,
        "9": ucc.UC_X86_REG_R9,
        "10": ucc.UC_X86_REG_R10,
        "11": ucc.UC_X86_REG_R11,
        "12": ucc.UC_X86_REG_R12,
        "13": ucc.UC_X86_REG_R13,
        "14": ucc.UC_X86_REG_R14,
        "15": ucc.UC_X86_REG_R15,
        "FLAGS": ucc.UC_X86_REG_EFLAGS,
        "CF": ucc.UC_X86_REG_EFLAGS,
        "PF": ucc.UC_X86_REG_EFLAGS,
        "AF": ucc.UC_X86_REG_EFLAGS,
        "ZF": ucc.UC_X86_REG_EFLAGS,
        "SF": ucc.UC_X86_REG_EFLAGS,
        "TF": ucc.UC_X86_REG_EFLAGS,
        "IF": ucc.UC_X86_REG_EFLAGS,
        "DF": ucc.UC_X86_REG_EFLAGS,
        "OF": ucc.UC_X86_REG_EFLAGS,
        "AC": ucc.UC_X86_REG_EFLAGS,
        "XMM0": ucc.UC_X86_REG_XMM0,
        "XMM1": ucc.UC_X86_REG_XMM1,
        "XMM2": ucc.UC_X86_REG_XMM2,
        "XMM3": ucc.UC_X86_REG_XMM3,
        "XMM4": ucc.UC_X86_REG_XMM4,
        "XMM5": ucc.UC_X86_REG_XMM5,
        "XMM6": ucc.UC_X86_REG_XMM6,
        "XMM7": ucc.UC_X86_REG_XMM7,
        "XMM8": ucc.UC_X86_REG_XMM8,
        "XMM9": ucc.UC_X86_REG_XMM9,
        "XMM10": ucc.UC_X86_REG_XMM10,
        "XMM11": ucc.UC_X86_REG_XMM11,
        "XMM12": ucc.UC_X86_REG_XMM12,
        "XMM14": ucc.UC_X86_REG_XMM14,
        "XMM15": ucc.UC_X86_REG_XMM15,
        "RIP": -1,
        "RSP": -1,
    }

    registers: List[int] = [
        ucc.UC_X86_REG_RAX, ucc.UC_X86_REG_RBX, ucc.UC_X86_REG_RCX, ucc.UC_X86_REG_RDX,
        ucc.UC_X86_REG_RSI, ucc.UC_X86_REG_RDI, ucc.UC_X86_REG_EFLAGS, ucc.UC_X86_REG_RSP
    ]
    simd128_registers: List[int] = [
        ucc.UC_X86_REG_XMM0, ucc.UC_X86_REG_XMM1, ucc.UC_X86_REG_XMM2, ucc.UC_X86_REG_XMM3,
        ucc.UC_X86_REG_XMM4, ucc.UC_X86_REG_XMM5, ucc.UC_X86_REG_XMM6, ucc.UC_X86_REG_XMM7,
        ucc.UC_X86_REG_XMM8, ucc.UC_X86_REG_XMM9, ucc.UC_X86_REG_XMM10, ucc.UC_X86_REG_XMM11,
        ucc.UC_X86_REG_XMM12, ucc.UC_X86_REG_XMM13, ucc.UC_X86_REG_XMM14, ucc.UC_X86_REG_XMM15
    ]
    barriers: List[str] = ['MFENCE', 'LFENCE']
    flags_register: int = ucc.UC_X86_REG_EFLAGS
    pc_register: int = ucc.UC_X86_REG_RIP
    actor_base_register: int = ucc.UC_X86_REG_R14
    sp_register: int = ucc.UC_X86_REG_RSP
