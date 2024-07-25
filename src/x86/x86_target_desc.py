"""
File: x86-specific constants and lists

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List
import re
import unicorn.x86_const as ucc  # type: ignore

from ..interfaces import Instruction, TargetDesc, MacroSpec, CPUDesc
from ..model import UnicornTargetDesc
from ..config import CONF


class X86TargetDesc(TargetDesc):
    register_sizes = {
        "xmm0": 128, "xmm1": 128, "xmm2": 128, "xmm3": 128, "xmm4": 128, "xmm5": 128, "xmm6": 128,
        "xmm7": 128, "xmm8": 128, "xmm9": 128, "xmm10": 128, "xmm11": 128, "xmm12": 128,
        "xmm13": 128, "xmm14": 128, "xmm15": 128,

        "rax": 64, "rbx": 64, "rcx": 64, "rdx": 64, "rsi": 64, "rdi": 64, "rsp": 64, "rbp": 64,
        "r8": 64, "r9": 64, "r10": 64, "r11": 64, "r12": 64, "r13": 64, "r14": 64, "r15": 64,

        "eax": 32, "ebx": 32, "ecx": 32, "edx": 32, "esi": 32, "edi": 32, "r8d": 32, "r9d": 32,
        "r10d": 32, "r11d": 32, "r12d": 32, "r13d": 32, "r14d": 32, "r15d": 32,

        "ax": 16, "bx": 16, "cx": 16, "dx": 16, "si": 16, "di": 16, "r8w": 16, "r9w": 16,
        "r10w": 16, "r11w": 16, "r12w": 16, "r13w": 16, "r14w": 16, "r15w": 16,

        "al": 8, "bl": 8, "cl": 8, "dl": 8, "sil": 8, "dil": 8, "r8b": 8, "r9b": 8,
        "r10b": 8, "r11b": 8, "r12b": 8, "r13b": 8, "r14b": 8, "r15b": 8,
        "ah": 8, "bh": 8, "ch": 8, "dh": 8,
    }  # yapf: disable
    reg_normalized = {
        "rax": "A", "eax": "A", "ax": "A", "al": "A", "ah": "A",
        "rbx": "B", "ebx": "B", "bx": "B", "bl": "B", "bh": "B",
        "rcx": "C", "ecx": "C", "cx": "C", "cl": "C", "ch": "C",
        "rdx": "D", "edx": "D", "dx": "D", "dl": "D", "dh": "D",
        "rsi": "SI", "esi": "SI", "si": "SI", "sil": "SI",
        "rdi": "DI", "edi": "DI", "di": "DI", "dil": "DI",
        "r8": "8", "r8d": "8", "r8w": "8", "r8b": "8",
        "r9": "9", "r9d": "9", "r9w": "9", "r9b": "9",
        "r10": "10", "r10d": "10", "r10w": "10", "r10b": "10",
        "r11": "11", "r11d": "11", "r11w": "11", "r11b": "11",
        "r12": "12", "r12d": "12", "r12w": "12", "r12b": "12",
        "r13": "13", "r13d": "13", "r13w": "13", "r13b": "13",
        "r14": "14", "r14d": "14", "r14w": "14", "r14b": "14",
        "r15": "15", "r15d": "15", "r15w": "15", "r15b": "15",
        "FLAGS": "FLAGS",
        "rip": "RIP",
        "rsp": "RSP",
        "CF": "CF", "PF": "PF", "AF": "AF", "ZF": "ZF", "SF": "SF", "TF": "TF", "IF": "IF",
        "DF": "DF", "OF": "OF", "AC": "AC",
        "bnd0": "BND0", "bnd1": "BND1", "bnd2": "BND2", "bnd3": "BND3",
        "xmm0": "XMM0",
        "xmm1": "XMM1",
        "xmm2": "XMM2",
        "xmm3": "XMM3",
        "xmm4": "XMM4",
        "xmm5": "XMM5",
        "xmm6": "XMM6",
        "xmm7": "XMM7",
        "xmm8": "XMM8",
        "xmm9": "XMM9",
        "xmm10": "XMM10",
        "xmm11": "XMM11",
        "xmm12": "XMM12",
        "xmm13": "XMM13",
        "xmm14": "XMM14",
        "xmm15": "XMM15",
        "cr0": "CR0",
        "cr2": "CR2",
        "cr3": "CR3",
        "cr4": "CR4",
        "cr8": "CR8",
        "xcr0": "XCR0",
        "dr0": "DR0",
        "dr1": "DR1",
        "dr2": "DR2",
        "dr3": "DR3",
        "dr6": "DR6",
        "dr7": "DR7",
        "gdtr": "GDTR",
        "idtr": "IDTR",
        "ldtr": "LDTR",
        "tr": "TR",
        "gs": "GS",
        "fs": "FS",
        "es": "ES",
        "ds": "DS",
        "cs": "CS",
        "ss": "SS",
        "fsbase": "FSBASE",
        "gsbase": "GSBASE",
        "msrs": "MSRS",
        "x87control": "X87CONTROL",
        "tsc": "TSC",
        "tscaux": "TSCAUX",
    }  # yapf: disable
    reg_denormalized = {
        "A": {64: "rax", 32: "eax", 16: "ax", 8: "al"},
        "B": {64: "rbx", 32: "ebx", 16: "bx", 8: "bl"},
        "C": {64: "rcx", 32: "ecx", 16: "cx", 8: "cl"},
        "D": {64: "rdx", 32: "edx", 16: "dx", 8: "dl"},
        "SI": {64: "rsi", 32: "esi", 16: "si", 8: "sil"},
        "DI": {64: "rdi", 32: "edi", 16: "di", 8: "dil"},
        "8": {64: "r8", 32: "r8d", 16: "r8w", 8: "r8b"},
        "9": {64: "r9", 32: "r9d", 16: "r9w", 8: "r9b"},
        "10": {64: "r10", 32: "r10d", 16: "r10w", 8: "r10b"},
        "11": {64: "r11", 32: "r11d", 16: "r11w", 8: "r11b"},
        "12": {64: "r12", 32: "r12d", 16: "r12w", 8: "r12b"},
        "13": {64: "r13", 32: "r13d", 16: "r13w", 8: "r13b"},
        "14": {64: "r14", 32: "r14d", 16: "r14w", 8: "r14b"},
        "15": {64: "r15", 32: "r15d", 16: "r15w", 8: "r15b"},
        "RIP": {64: "rip", 32: "rip", 16: "rip", 8: "rip"},
        "RSP": {64: "rsp", 32: "rsp", 16: "rsp", 8: "rsp"},
        "XMM0": {128: "xmm0"},
        "XMM1": {128: "xmm1"},
        "XMM2": {128: "xmm2"},
        "XMM3": {128: "xmm3"},
        "XMM4": {128: "xmm4"},
        "XMM5": {128: "xmm5"},
        "XMM6": {128: "xmm6"},
        "XMM7": {128: "xmm7"},
        "XMM8": {128: "xmm8"},
        "XMM9": {128: "xmm9"},
        "XMM10": {128: "xmm10"},
        "XMM11": {128: "xmm11"},
        "XMM12": {128: "xmm12"},
        "XMM13": {128: "xmm13"},
        "XMM14": {128: "xmm14"},
        "XMM15": {128: "xmm15"}
    }  # yapf: disable
    registers = {
        8: ["al", "bl", "cl", "dl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b",
            "r14b", "r15b"],
        16: ["ax", "bx", "cx", "dx", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w",
             "r14w", "r15w"],
        32: ["eax", "ebx", "ecx", "edx", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d",
             "r13d", "r14d", "r15d"],
        64: ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
             "r14", "r15", "rsp", "rbp"],
        128: ["bnd0", "bnd1", "bnd2", "bnd3",
              "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
              "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"]
    }  # yapf: disable
    simd_registers = {
        64: [f"mm{i}" for i in range(0, 8)],
        128: [f"xmm{i}" for i in range(0, 32)],
        256: [f"ymm{i}" for i in range(0, 32)],
        512: [f"zmm{i}" for i in range(0, 32)],
    }  # yapf: disable

    pte_bits = {
        # NAME: (position, default value)
        "present": (0, True),
        "writable": (1, True),
        "user": (2, False),
        "write-through": (3, False),
        "cache-disable": (4, False),
        "accessed": (5, True),
        "dirty": (6, True),
        "reserved_bit": (51, False),
        "non_executable": (63, True),
    }

    epte_bits_intel = {
        # NAME: (position, default value)
        "present": (0, True),
        "writable": (1, True),
        "executable": (2, False),
        "accessed": (8, True),
        "dirty": (9, True),
        "user": (10, False),
        "reserved_bit": (51, False),
    }

    npte_bits_amd = {
        # NAME: (position, default value)
        "present": (0, True),
        "writable": (1, True),
        "user": (2, True),
        "accessed": (5, True),
        "dirty": (6, True),
        "reserved_bit": (51, False),
        "non_executable": (63, True),
    }

    # FIXME: macro IDs should not be hardcoded but rather received from the executor
    # or at least we need a test that will check that the IDs match
    macro_specs = {
        # macros with negative IDs are used for generation
        # and are not supposed to reach the final binary
        "random_instructions":
            MacroSpec(-1, "random_instructions", ("int", "int", "", "")),

        # macros with positive IDs are used for execution and can be interpreted by executor/model
        "function":
            MacroSpec(0, "function", ("", "", "", "")),
        "measurement_start":
            MacroSpec(1, "measurement_start", ("", "", "", "")),
        "measurement_end":
            MacroSpec(2, "measurement_end", ("", "", "", "")),
        "fault_handler":
            MacroSpec(3, "fault_handler", ("", "", "", "")),
        "switch":
            MacroSpec(4, "switch", ("actor_id", "function_id", "", "")),
        "set_k2u_target":
            MacroSpec(5, "set_k2u_target", ("actor_id", "function_id", "", "")),
        "switch_k2u":
            MacroSpec(6, "switch_k2u", ("actor_id", "", "", "")),
        "set_u2k_target":
            MacroSpec(7, "set_u2k_target", ("actor_id", "function_id", "", "")),
        "switch_u2k":
            MacroSpec(8, "switch_u2k", ("actor_id", "", "", "")),
        "set_h2g_target":
            MacroSpec(9, "set_h2g_target", ("actor_id", "function_id", "", "")),
        "switch_h2g":
            MacroSpec(10, "switch_h2g", ("actor_id", "", "", "")),
        "set_g2h_target":
            MacroSpec(11, "set_g2h_target", ("actor_id", "function_id", "", "")),
        "switch_g2h":
            MacroSpec(12, "switch_g2h", ("actor_id", "", "", "")),
        "landing_k2u":
            MacroSpec(13, "landing_k2u", ("", "", "", "")),
        "landing_u2k":
            MacroSpec(14, "landing_u2k", ("", "", "", "")),
        "landing_h2g":
            MacroSpec(15, "landing_h2g", ("", "", "", "")),
        "landing_g2h":
            MacroSpec(16, "landing_g2h", ("", "", "", "")),
        "set_data_permissions":
            MacroSpec(18, "set_data_permissions", ("actor_id", "int", "int", ""))
    }

    def __init__(self):
        super().__init__()
        # remove blocked registers
        filtered_decoding = {}
        for size, registers in self.registers.items():
            filtered_decoding[size] = []
            for register in registers:
                if register not in CONF.register_blocklist or register in CONF.register_allowlist:
                    filtered_decoding[size].append(register)
        self.registers = filtered_decoding

        # identify the CPU model we are running on
        with open("/proc/cpuinfo", "r") as f:
            cpuinfo = f.read()
            if 'Intel' in cpuinfo:
                vendor = 'Intel'
            elif 'AMD' in cpuinfo:
                vendor = 'AMD'
            else:
                vendor = 'Unknown'

            family_match = re.search(r"cpu family\s+:\s+(.*)", cpuinfo)
            assert family_match, "Failed to find family in /proc/cpuinfo"
            family = family_match.group(1)

            model_match = re.search(r"model\s+:\s+(.*)", cpuinfo)
            assert model_match, "Failed to find model name in /proc/cpuinfo"
            model = model_match.group(1)

            stepping_match = re.search(r"stepping\s+:\s+(.*)", cpuinfo)
            assert stepping_match, "Failed to find stepping in /proc/cpuinfo"
            stepping = stepping_match.group(1)

        self.cpu_desc = CPUDesc(vendor, model, family, stepping)

        # select EPT/NPT bits based on the CPU vendor
        self.epte_bits = self.epte_bits_intel if vendor == 'Intel' else self.npte_bits_amd

    @staticmethod
    def is_unconditional_branch(inst: Instruction) -> bool:
        return inst.category == "BASE-UNCOND_BR"

    @staticmethod
    def is_call(inst: Instruction) -> bool:
        return inst.category == "BASE-CALL"


class X86UnicornTargetDesc(UnicornTargetDesc):
    reg_str_to_constant = {
        "al": ucc.UC_X86_REG_AL,
        "bl": ucc.UC_X86_REG_BL,
        "cl": ucc.UC_X86_REG_CL,
        "dl": ucc.UC_X86_REG_DL,
        "dil": ucc.UC_X86_REG_DIL,
        "sil": ucc.UC_X86_REG_SIL,
        "spl": ucc.UC_X86_REG_SPL,
        "bpl": ucc.UC_X86_REG_BPL,
        "ah": ucc.UC_X86_REG_AH,
        "bh": ucc.UC_X86_REG_BH,
        "ch": ucc.UC_X86_REG_CH,
        "dh": ucc.UC_X86_REG_DH,
        "ax": ucc.UC_X86_REG_AX,
        "bx": ucc.UC_X86_REG_BX,
        "cx": ucc.UC_X86_REG_CX,
        "dx": ucc.UC_X86_REG_DX,
        "di": ucc.UC_X86_REG_DI,
        "si": ucc.UC_X86_REG_SI,
        "sp": ucc.UC_X86_REG_SP,
        "bp": ucc.UC_X86_REG_BP,
        "eax": ucc.UC_X86_REG_EAX,
        "ebx": ucc.UC_X86_REG_EBX,
        "ecx": ucc.UC_X86_REG_ECX,
        "edx": ucc.UC_X86_REG_EDX,
        "edi": ucc.UC_X86_REG_EDI,
        "esi": ucc.UC_X86_REG_ESI,
        "esp": ucc.UC_X86_REG_ESP,
        "ebp": ucc.UC_X86_REG_EBP,
        "rax": ucc.UC_X86_REG_RAX,
        "rbx": ucc.UC_X86_REG_RBX,
        "rcx": ucc.UC_X86_REG_RCX,
        "rdx": ucc.UC_X86_REG_RDX,
        "rdi": ucc.UC_X86_REG_RDI,
        "rsi": ucc.UC_X86_REG_RSI,
        "rsp": ucc.UC_X86_REG_RSP,
        "rbp": ucc.UC_X86_REG_RBP,
        "xmm0": ucc.UC_X86_REG_XMM0,
        "xmm1": ucc.UC_X86_REG_XMM1,
        "xmm2": ucc.UC_X86_REG_XMM2,
        "xmm3": ucc.UC_X86_REG_XMM3,
        "xmm4": ucc.UC_X86_REG_XMM4,
        "xmm5": ucc.UC_X86_REG_XMM5,
        "xmm6": ucc.UC_X86_REG_XMM6,
        "xmm7": ucc.UC_X86_REG_XMM7,
        "xmm8": ucc.UC_X86_REG_XMM8,
        "xmm9": ucc.UC_X86_REG_XMM9,
        "xmm10": ucc.UC_X86_REG_XMM10,
        "xmm11": ucc.UC_X86_REG_XMM11,
        "xmm12": ucc.UC_X86_REG_XMM12,
        "xmm14": ucc.UC_X86_REG_XMM14,
        "xmm15": ucc.UC_X86_REG_XMM15,
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
        "CR0": -1,
        "CR2": -1,
        "CR3": -1,
        "CR4": -1,
        "CR8": -1,
        "XCR0": -1,
        "DR0": -1,
        "DR1": -1,
        "DR2": -1,
        "DR3": -1,
        "DR6": -1,
        "DR7": -1,
        "GDTR": -1,
        "IDTR": -1,
        "LDTR": -1,
        "TR": -1,
        "FSBASE": -1,
        "GSBASE": -1,
        "MSRS": -1,
        "X87CONTROL": -1,
        "TSC": -1,
        "TSCAUX": -1,
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
    barriers: List[str] = ['mfence', 'lfence']
    flags_register: int = ucc.UC_X86_REG_EFLAGS
    pc_register: int = ucc.UC_X86_REG_RIP
    actor_base_register: int = ucc.UC_X86_REG_R14
    sp_register: int = ucc.UC_X86_REG_RSP
