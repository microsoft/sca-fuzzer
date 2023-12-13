"""
File:

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import numpy as np
import unicorn as uni
from unicorn import Uc
import unicorn.arm64_const as ucc
from typing import Tuple
from model import UnicornModel, UnicornSeq, UnicornSpec, UnicornBpas, BaseTaintTracker
from interfaces import Input
from arm64.arm64_target_desc import ARMTargetDesc, ARM64UnicornTargetDesc

REG64_MASK = np.uint64(pow(2, 64) - 1)  # type: ignore


class ARM64UnicornModel(UnicornModel):
    """
    Base class that serves as main interface.
    Load inputs and executes the test case on AARCH64
    """

    def __init__(self, sandbox_base, code_start):
        self.target_desc = ARM64UnicornTargetDesc()
        self.architecture = (uni.UC_ARCH_ARM64, uni.UC_MODE_ARM)
        super().__init__(sandbox_base, code_start)

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
                value = (value << np.uint64(28)) % REG64_MASK   # type: ignore
            self.emulator.reg_write(regs[i], value)

            # executor uses the lower bytes of the upper_overflow_region to initialize registers
            # we need to match it in the model
            self.emulator.mem_write(reg_init_address, value.tobytes())
            reg_init_address += 8
        self.emulator.mem_write(reg_init_address,
                                self.stack_base.to_bytes(8, byteorder='little', signed=False))

        # initialize machine registers
        self.emulator.reg_write(ucc.UC_ARM64_REG_SP, self.stack_base)
        self.emulator.reg_write(ucc.UC_ARM64_REG_X30, self.sandbox_base)

    def print_state(self, oneline: bool = False):

        def compressed(val: int):
            if val >= self.sandbox_base and val <= self.sandbox_base + 12288:
                return f"+0x{val - self.sandbox_base:<15x}"
            elif val >= self.sandbox_base - self.OVERFLOW_REGION_SIZE and val < self.sandbox_base:
                return f"+0x{val - self.sandbox_base:<15x}"
            else:
                return f"0x{val:<16x}"

        emulator = self.emulator
        x0 = compressed(emulator.reg_read(ucc.UC_ARM64_REG_X0))
        x1 = compressed(emulator.reg_read(ucc.UC_ARM64_REG_X1))
        x2 = compressed(emulator.reg_read(ucc.UC_ARM64_REG_X2))
        x3 = compressed(emulator.reg_read(ucc.UC_ARM64_REG_X3))
        x4 = compressed(emulator.reg_read(ucc.UC_ARM64_REG_X4))
        x5 = compressed(emulator.reg_read(ucc.UC_ARM64_REG_X5))

        if not oneline:
            print("\n\nRegisters:")
            print(f"X0: {x0}")
            print(f"X1: {x1}")
            print(f"X2: {x2}")
            print(f"X3: {x3}")
            print(f"X4: {x4}")
            print(f"X5: {x5}")
        else:
            print(f"  x0={x0} "
                  f"x1={x1} "
                  f"x2={x2} \n"
                  f"  x3={x3} "
                  f"x4={x4} "
                  f"x5={x5} \n"
                  f"  nzcv={emulator.reg_read(ucc.UC_ARM64_REG_NZCV)>>28:0b}")


class ARMTaintTracker(BaseTaintTracker):
    # ISA-specific fields
    _registers = [
        ucc.UC_ARM64_REG_X0, ucc.UC_ARM64_REG_X1, ucc.UC_ARM64_REG_X2,
        ucc.UC_ARM64_REG_X3, ucc.UC_ARM64_REG_X4, ucc.UC_ARM64_REG_X5,
        ucc.UC_ARM64_REG_NZCV
    ]

    def __init__(self, initial_observations, sandbox_base=0):
        super().__init__(initial_observations, sandbox_base=sandbox_base)

        # ISA-specific field setup
        self.target_desc = ARMTargetDesc()
        self.unicorn_target_desc = ARM64UnicornTargetDesc()


# ==================================================================================================
# Implementation of Execution Clauses
# ==================================================================================================
class ARM64UnicornSeq(UnicornSeq, ARM64UnicornModel):
    pass


class ARM64UnicornSpec(UnicornSpec, ARM64UnicornModel):
    pass


class ARM64UnicornBpas(UnicornBpas, ARM64UnicornModel):
    pass

def twos_complement(n: int, nbits: int) -> int:
    n &= (1 << nbits) - 1
    sign_bit = 1 << (nbits - 1)
    if n & sign_bit:
        return n - 2 * sign_bit
    else:
        return n

# flag values taken from unicorn/qemu/target/arm/cpu.h
FLAG_N = 1 << 31
FLAG_Z = 1 << 30
FLAG_C = 1 << 29
FLAG_V = 1 << 28

class ARM64UnicornCond(ARM64UnicornSpec):
    """
    Contract for conditional branch mispredictions.
    Forces all cond. branches to speculatively go into a wrong target
    """

    @staticmethod
    def decode(reg_read, code: bytearray, flags: int) -> Tuple[int, bool]:
        instruction = int.from_bytes(code, byteorder='little')
        first_byte = instruction >> 24
        if first_byte == 0x54 and instruction & 0x10 == 0:
            # B.cond instruction
            target = twos_complement(instruction >> 5, 19)
            condition = instruction & 0xf
            n = (flags & FLAG_N) != 0
            z = (flags & FLAG_Z) != 0
            c = (flags & FLAG_C) != 0
            v = (flags & FLAG_V) != 0
            # table here is useful: https://community.arm.com/arm-community-blogs/b/architectures-and-processors-blog/posts/condition-codes-1-condition-flags-and-codes
            will_jump = [
                z, # 0 = b.eq "equal"
                not z, # 1 = b.ne "not equal"
                c, # 2 = b.cs "carry set"
                not c, # 3 = b.cc "carry clear"
                n, # 4 = b.mi "minus"
                not n, # 5 = b.pl "plus"
                v, # 6 = b.vs "overflow set"
                not v, # 7 = b.vc "overflow clear"
                c and not z, # 8 = b.hi "higher than"
                not c or z, # 9 = b.ls "lower or same"
                n == v, # a = b.ge "greater than or equal"
                n != v, # b = b.lt "less than"
                not z and n == v, # c = b.gt "greater than"
                z or n != v, # d = b.le "less than or equal"
                True, # e = b.al "always"
                False, # f = b.nv "never"
            ][condition]
            return (target, will_jump)
        if 0xb4 <= first_byte <= 0xb7 or 0x34 <= first_byte <= 0x37:
            # CBZ/CBNZ/TBZ/TBNZ
            register_index = instruction & 0x1f
            is_32bit = first_byte >> 4 == 0x3
            if register_index <= 28:
                register_value = reg_read(ucc.UC_ARM64_REG_X0 + register_index)
            elif register_index <= 30:
                # for some reason UC_ARM64_REG_X29 != UC_ARM64_REG_X0 + 29
                register_value = reg_read(ucc.UC_ARM64_REG_X29 + (register_index - 29))
            elif register_index == 31:
                # xzr "zero register"
                register_value = 0
            if is_32bit:
                register_value &= 0xffff_ffff
            if first_byte & 0xf <= 0x5:
                # CBZ/CBNZ
                target = twos_complement(instruction >> 5, 19)
                if first_byte & 0xf == 4:
                    # CBZ
                    will_jump = register_value == 0
                else:
                    # CBNZ
                    will_jump = register_value != 0
            else:
                target = twos_complement(instruction >> 5, 14)
                bit_number = (instruction >> 19) & 0x1f
                if not is_32bit:
                    bit_number += 32
                bit = register_value & (1 << bit_number)
                if first_byte & 0xf == 6:
                    # TBZ
                    will_jump = bit == 0
                else:
                    # TBNZ
                    will_jump = bit != 0
            return (target, will_jump)
        return (0, False)

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model: UnicornModel) -> None:
        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return

        # decode the instruction
        code = emulator.mem_read(address, size)
        flags = emulator.reg_read(ucc.UC_ARM64_REG_NZCV)
        target, will_jump = ARM64UnicornCond.decode(emulator.reg_read, code, flags)

        # not a a cond. jump? ignore
        if not target:
            return
        # multiply by size of instruction
        target *= 4

        # Take a checkpoint
        next_instr = address + target if will_jump else address + size
        model.checkpoint(emulator, next_instr)

        # Simulate misprediction
        if will_jump:
            emulator.reg_write(ucc.UC_ARM64_REG_PC, address + size)
        else:
            emulator.reg_write(ucc.UC_ARM64_REG_PC, address + target)

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model):
        pass  # cond does not need to speculate mem accesses

class ARM64UnicornCondBpas(ARM64UnicornSpec):
    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model: UnicornSpec):
        ARM64UnicornBpas.speculate_mem_access(emulator, access, address, size, value, model)

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        ARM64UnicornCond.speculate_instruction(emulator, address, size, model)
        ARM64UnicornBpas.speculate_instruction(emulator, address, size, model)
