"""
File: x86-specific model implementation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import re
import numpy as np
from typing import Tuple, Dict, List, Set
import copy

import unicorn.x86_const as ucc  # type: ignore
from unicorn import Uc, UC_MEM_WRITE, UC_ARCH_X86, UC_MODE_64, UC_PROT_READ, UC_PROT_NONE

from interfaces import Input, FlagsOperand, RegisterOperand, MemoryOperand, TestCase
from model import UnicornModel, UnicornSpec, UnicornSeq, UnicornBpas, BaseTaintTracker
from x86.x86_target_desc import X86UnicornTargetDesc, X86TargetDesc
from service import UnreachableCode

FLAGS_CF = 0b000000000001
FLAGS_PF = 0b000000000100
FLAGS_AF = 0b000000010000
FLAGS_ZF = 0b000001000000
FLAGS_SF = 0b000010000000
FLAGS_OF = 0b100000000000


class X86UnicornModel(UnicornModel):
    """
    Base class that serves as main interface.
    Loads inputs and executes the test case on x86
    """

    def __init__(self, sandbox_base, code_start):
        self.target_desc = X86UnicornTargetDesc()
        self.architecture = (UC_ARCH_X86, UC_MODE_64)
        self.rw_fault_mask = (1 << X86TargetDesc.pte_bits["PRESENT"][0]) + \
            (1 << X86TargetDesc.pte_bits["ACCESSED"][0])
        self.rw_fault_mask_unset = (1 << X86TargetDesc.pte_bits["USER"][0])
        self.write_fault_mask = (1 << X86TargetDesc.pte_bits["RW"][0]) + \
            (1 << X86TargetDesc.pte_bits["DIRTY"][0])

        self.flags_id = ucc.UC_X86_REG_EFLAGS

        super().__init__(sandbox_base, code_start)

    def load_test_case(self, test_case: TestCase) -> None:
        # check which permissions have to be set on the pages
        self.rw_protect = bool((0xffffffffffffffff ^ test_case.faulty_pte.mask_clear)
                               & self.rw_fault_mask)
        self.rw_protect |= bool(test_case.faulty_pte.mask_set & self.rw_fault_mask_unset)
        self.write_protect = bool((0xffffffffffffffff ^ test_case.faulty_pte.mask_clear)
                                  & self.write_fault_mask)
        return super().load_test_case(test_case)

    def _load_input(self, input_: Input):
        """
        Set registers and stack before starting the emulation
        """
        # Set memory:
        # - initialize overflows with zeroes
        self.emulator.mem_write(self.lower_overflow_base, self.overflow_region_values)
        self.emulator.mem_write(self.upper_overflow_base, self.overflow_region_values)

        # - sandbox pages
        self.emulator.mem_write(self.sandbox_base, input_.get_memory().tobytes())

        # Set values in registers
        regs = self.target_desc.registers
        flags = self.target_desc.flags_register
        reg_init_address = self.sandbox_base + self.MAIN_REGION_SIZE + self.FAULTY_REGION_SIZE
        for i, value in enumerate(input_.get_registers()):
            if regs[i] == flags:
                value = (value & np.uint64(2263)) | np.uint64(2)  # type: ignore
            self.emulator.reg_write(regs[i], value)

            # executor uses the lower bytes of the upper_overflow_region to initialize registers
            # we need to match it in the model
            self.emulator.mem_write(reg_init_address, value.tobytes())
            reg_init_address += 8
        self.emulator.mem_write(reg_init_address,
                                self.stack_base.to_bytes(8, byteorder='little', signed=False))

        if self.rw_protect:
            self.emulator.mem_protect(self.sandbox_base + self.MAIN_REGION_SIZE,
                                      self.FAULTY_REGION_SIZE, UC_PROT_NONE)
        elif self.write_protect:
            self.emulator.mem_protect(self.sandbox_base + self.MAIN_REGION_SIZE,
                                      self.FAULTY_REGION_SIZE, UC_PROT_READ)

        self.emulator.reg_write(ucc.UC_X86_REG_RSP, self.stack_base)
        self.emulator.reg_write(ucc.UC_X86_REG_RBP, self.stack_base)
        self.emulator.reg_write(ucc.UC_X86_REG_R14, self.sandbox_base)

    def print_state(self, oneline: bool = False):

        def compressed(val: int):
            if val >= self.sandbox_base and val <= self.sandbox_base + 12288:
                return f"+0x{val - self.sandbox_base:<15x}"
            elif val >= self.sandbox_base - self.OVERFLOW_REGION_SIZE and val < self.sandbox_base:
                return f"+0x{val - self.sandbox_base:<15x}"
            else:
                return f"0x{val:<15x}"

        emulator = self.emulator
        rax = compressed(emulator.reg_read(ucc.UC_X86_REG_RAX))
        rbx = compressed(emulator.reg_read(ucc.UC_X86_REG_RBX))
        rcx = compressed(emulator.reg_read(ucc.UC_X86_REG_RCX))
        rdx = compressed(emulator.reg_read(ucc.UC_X86_REG_RDX))
        rsi = compressed(emulator.reg_read(ucc.UC_X86_REG_RSI))
        rdi = compressed(emulator.reg_read(ucc.UC_X86_REG_RDI))

        if not oneline:
            print("\n\nRegisters:")
            print(f"RAX: {rax}")
            print(f"RBX: {rbx}")
            print(f"RCX: {rcx}")
            print(f"RDX: {rdx}")
            print(f"RSI: {rsi}")
            print(f"RDI: {rdi}")
        else:
            print(f"  rax={rax} "
                  f"rbx={rbx} "
                  f"rcx={rcx} \n"
                  f"  rdx={rdx} "
                  f"rsi={rsi} "
                  f"rdi={rdi} \n"
                  f"  fl={emulator.reg_read(ucc.UC_X86_REG_EFLAGS):012b}")


# ==================================================================================================
# Implementation of Execution Clauses
# ==================================================================================================
class X86UnicornSeq(UnicornSeq, X86UnicornModel):
    pass


class X86UnicornSpec(UnicornSpec, X86UnicornModel):
    pass


class X86UnicornCond(X86UnicornSpec):
    """
    Contract for conditional branch mispredicitons.
    Forces all cond. branches to speculatively go into a wrong target
    """

    jumps = {
        # c - the byte code of the instruction
        # f - the value of EFLAGS
        0x70: lambda c, f, r: (c[1:], f & FLAGS_OF != 0, False),  # JO
        0x71: lambda c, f, r: (c[1:], f & FLAGS_OF == 0, False),  # JNO
        0x72: lambda c, f, r: (c[1:], f & FLAGS_CF != 0, False),  # JB
        0x73: lambda c, f, r: (c[1:], f & FLAGS_CF == 0, False),  # JAE
        0x74: lambda c, f, r: (c[1:], f & FLAGS_ZF != 0, False),  # JZ
        0x75: lambda c, f, r: (c[1:], f & FLAGS_ZF == 0, False),  # JNZ
        0x76: lambda c, f, r: (c[1:], f & FLAGS_CF != 0 or f & FLAGS_ZF != 0, False),  # JNA
        0x77: lambda c, f, r: (c[1:], f & FLAGS_CF == 0 and f & FLAGS_ZF == 0, False),  # JNBE
        0x78: lambda c, f, r: (c[1:], f & FLAGS_SF != 0, False),  # JS
        0x79: lambda c, f, r: (c[1:], f & FLAGS_SF == 0, False),  # JNS
        0x7A: lambda c, f, r: (c[1:], f & FLAGS_PF != 0, False),  # JP
        0x7B: lambda c, f, r: (c[1:], f & FLAGS_PF == 0, False),  # JPO
        0x7C: lambda c, f, r: (c[1:], (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),  # JNGE
        0x7D: lambda c, f, r: (c[1:], (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),  # JNL
        0x7E: lambda c, f, r:
        (c[1:], f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),
        0x7F: lambda c, f, r:
        (c[1:], f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),
        0xE0: lambda c, f, r: (c[1:], r != 1 and (f & FLAGS_ZF == 0), True),  # LOOPNE
        0xE1: lambda c, f, r: (c[1:], r != 1 and (f & FLAGS_ZF != 0), True),  # LOOPE
        0xE2: lambda c, f, r: (c[1:], r != 1, True),  # LOOP
        0xE3: lambda c, f, r: (c[1:], r == 0, False),  # J*CXZ
        0x0F: lambda c, f, r:
        X86UnicornCond.multibyte_jmp.get(c[1], (lambda _, __, ___: ([0], False, False)))(c, f, r)
    }  # yapf: disable

    multibyte_jmp: Dict = {
        0x80: lambda c, f, r: (c[2:], f & FLAGS_OF != 0, False),  # JO
        0x81: lambda c, f, r: (c[2:], f & FLAGS_OF == 0, False),  # JNO
        0x82: lambda c, f, r: (c[2:], f & FLAGS_CF != 0, False),  # JB
        0x83: lambda c, f, r: (c[2:], f & FLAGS_CF == 0, False),  # JAE
        0x84: lambda c, f, r: (c[2:], f & FLAGS_ZF != 0, False),  # JE
        0x85: lambda c, f, r: (c[2:], f & FLAGS_ZF == 0, False),  # JNE
        0x86: lambda c, f, r: (c[2:], f & FLAGS_CF != 0 or f & FLAGS_ZF != 0, False),  # JBE
        0x87: lambda c, f, r: (c[2:], f & FLAGS_CF == 0 and f & FLAGS_ZF == 0, False),  # JA
        0x88: lambda c, f, r: (c[2:], f & FLAGS_SF != 0, False),  # JS
        0x89: lambda c, f, r: (c[2:], f & FLAGS_SF == 0, False),  # JNS
        0x8A: lambda c, f, r: (c[2:], f & FLAGS_PF != 0, False),  # JP
        0x8B: lambda c, f, r: (c[2:], f & FLAGS_PF == 0, False),  # JPO
        0x8C: lambda c, f, r: (c[2:], (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),  # JNGE
        0x8D: lambda c, f, r: (c[2:], (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),  # JNL
        0x8E: lambda c, f, r:
        (c[2:], f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),
        0x8F: lambda c, f, r:
        (c[2:], f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),
    }  # yapf: disable

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model: UnicornModel) -> None:
        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return

        # if the instruction is undefined, Unicorn will return a huge value as size
        # skip those
        if size > 15:  # 15 bytes is max instr size on Intel
            return

        # decode the instruction
        code = emulator.mem_read(address, size)
        flags = emulator.reg_read(ucc.UC_X86_REG_EFLAGS)
        rcx = emulator.reg_read(ucc.UC_X86_REG_RCX)
        target, will_jump, is_loop = X86UnicornCond.decode(code, flags, rcx)

        # not a a cond. jump? ignore
        if not target:
            return

        # LOOP instructions must also decrement RCX
        if is_loop:
            emulator.reg_write(ucc.UC_X86_REG_RCX, rcx - 1)

        # Take a checkpoint
        next_instr = address + size + target if will_jump else address + size
        model.checkpoint(emulator, next_instr)

        # Simulate misprediction
        if will_jump:
            emulator.reg_write(ucc.UC_X86_REG_RIP, address + size)
        else:
            emulator.reg_write(ucc.UC_X86_REG_RIP, address + size + target)

    @staticmethod
    def decode(code: bytearray, flags: int, rcx: int) -> Tuple[int, bool, bool]:
        """
        Decodes the instruction encoded in `code` and, if it's a conditional jump,
        returns its expected target, whether it will jump to the target (based
        on the `flags` value), and whether it is a LOOP instruction
        """
        calculate_target = X86UnicornCond.jumps.get(code[0], (lambda _, __, ___:
                                                              ([0], False, False)))
        target, will_jump, is_loop = calculate_target(code, flags, rcx)
        if len(target) == 1:
            return target[0], will_jump, is_loop
        return int.from_bytes(target, byteorder='little'), will_jump, is_loop

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model):
        pass  # cond does not need to speculate mem accesses


class X86UnicornBpas(UnicornBpas, X86UnicornModel):
    pass


class X86UnicornNull(X86UnicornSpec):
    instruction_address: int

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, _, model):
        assert isinstance(model, X86UnicornNull)

        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return

        # applicable only to loads
        if access == UC_MEM_WRITE:
            return

        # make sure we do not repeat the same injection all over again
        if model.instruction_address == model.latest_rollback_address:
            return

        # store a checkpoint
        model.checkpoint(emulator, model.instruction_address)
        model.store_logs[-1].append((address, emulator.mem_read(address, 8)))

        # emulate zero-injection by writing zero to the target address of the load
        zero_value = bytes([0 for _ in range(size)])
        emulator.mem_write(address, zero_value)

    @staticmethod
    def speculate_instruction(emulator: Uc, address, _, model) -> None:
        assert isinstance(model, X86UnicornNull)
        model.instruction_address = address


class X86UnicornCondBpas(X86UnicornSpec):

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model: UnicornSpec):
        X86UnicornBpas.speculate_mem_access(emulator, access, address, size, value, model)

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        X86UnicornCond.speculate_instruction(emulator, address, size, model)
        X86UnicornBpas.speculate_instruction(emulator, address, size, model)


# ==================================================================================================
# Taint tracker
# ==================================================================================================
class X86TaintTracker(BaseTaintTracker):
    # ISA-specific fields
    _registers = [
        ucc.UC_X86_REG_RAX, ucc.UC_X86_REG_RBX, ucc.UC_X86_REG_RCX, ucc.UC_X86_REG_RDX,
        ucc.UC_X86_REG_RSI, ucc.UC_X86_REG_RDI, ucc.UC_X86_REG_EFLAGS
    ]

    def __init__(self, initial_observations, sandbox_base=0):
        super().__init__(initial_observations, sandbox_base=sandbox_base)

        # ISA-specific field setup
        self.target_desc = X86TargetDesc()
        self.unicorn_target_desc = X86UnicornTargetDesc()
