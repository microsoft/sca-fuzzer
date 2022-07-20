"""
File: x86-specific model implementation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import re
import copy
import numpy as np
from typing import List, Tuple, Dict, Optional, Set

import unicorn.x86_const as ucc
from unicorn import Uc, UcError, UC_MEM_WRITE, UC_ARCH_X86, UC_MODE_64, \
    UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_CODE

from interfaces import TestCase, InputTaint, Instruction, RegisterOperand, FlagsOperand, \
    MemoryOperand, Input
from model import UnicornModel, UnicornSpec, UnicornSeq, TaintTrackerInterface, UnicornTargetDesc
from x86.x86_generator import X86TargetDesc
from service import LOGGER

FLAGS_CF = 0b000000000001
FLAGS_PF = 0b000000000100
FLAGS_AF = 0b000000010000
FLAGS_ZF = 0b000001000000
FLAGS_SF = 0b000010000000
FLAGS_OF = 0b100000000000


class X86UnicornTargetDesc(UnicornTargetDesc):
    registers: List[int] = [
        ucc.UC_X86_REG_RAX, ucc.UC_X86_REG_RBX, ucc.UC_X86_REG_RCX, ucc.UC_X86_REG_RDX,
        ucc.UC_X86_REG_RSI, ucc.UC_X86_REG_RDI, ucc.UC_X86_REG_EFLAGS
    ]
    barriers: List[str] = ['MFENCE', 'LFENCE']
    flags_register: int = ucc.UC_X86_REG_EFLAGS


class X86UnicornModel(UnicornModel):
    """
    Base class that serves as main interface.
    Load inputs and executes the test case on x86
    """

    def __init__(self, sandbox_base, code_start):
        self.target_desc = X86UnicornTargetDesc()
        super().__init__(sandbox_base, code_start)

    def load_test_case(self, test_case: TestCase) -> None:
        self.test_case = test_case

        # create and read a binary
        with open(test_case.bin_path, 'rb') as f:
            code = f.read()
        self.code_end = self.code_start + len(code)

        # initialize emulator in x86-64 mode
        emulator = Uc(UC_ARCH_X86, UC_MODE_64)

        try:
            # allocate memory
            emulator.mem_map(self.code_start, self.CODE_SIZE)
            sandbox_size = \
                self.OVERFLOW_REGION_SIZE * 2 + self.MAIN_REGION_SIZE + self.FAULTY_REGION_SIZE
            emulator.mem_map(self.sandbox_base - self.OVERFLOW_REGION_SIZE, sandbox_size)

            # write machine code to be emulated to memory
            emulator.mem_write(self.code_start, code)

            # set up callbacks
            emulator.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.trace_mem_access, self)
            emulator.hook_add(UC_HOOK_CODE, self.instruction_hook, self)

            self.emulator = emulator

        except UcError as e:
            LOGGER.error("[X86UnicornModel:load_test_case] %s" % e)

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
            print(f"rax={rax} "
                  f"rbx={rbx} "
                  f"rcx={rcx} "
                  f"rdx={rdx} "
                  f"rsi={rsi} "
                  f"rdi={rdi} "
                  f"fl={emulator.reg_read(ucc.UC_X86_REG_EFLAGS):012b}")


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


class X86UnicornBpas(X86UnicornSpec):

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model):
        """
        Since Unicorn does not have post-instruction hooks,
        I have to implement it in a dirty way:
        Save the information about the store here, but execute all the
        contract logic in a hook before the next instruction (see trace_instruction)
        """
        if access == UC_MEM_WRITE:
            rip = emulator.reg_read(ucc.UC_X86_REG_RIP)
            opcode = emulator.mem_read(rip, 1)[0]
            if opcode not in [0xE8, 0xFF, 0x9A]:  # ignore CALL instructions
                model.previous_store = (address, size, emulator.mem_read(address, size), value)

    @staticmethod
    def speculate_instruction(emulator: Uc, address, _, model) -> None:
        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return

        if model.previous_store[0]:
            store_addr = model.previous_store[0]
            old_value = bytes(model.previous_store[2])
            new_is_signed = model.previous_store[3] < 0
            new_value = (model.previous_store[3]). \
                to_bytes(model.previous_store[1], byteorder='little', signed=new_is_signed)

            # store a checkpoint
            model.checkpoint(emulator, address)

            # cancel the previous store but preserve its value
            emulator.mem_write(store_addr, old_value)
            model.store_logs[-1].append((store_addr, new_value))
        model.previous_store = (0, 0, 0, 0)


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
    def speculate_mem_access(emulator, access, address, size, value, model):
        X86UnicornBpas.speculate_mem_access(emulator, access, address, size, value, model)

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        X86UnicornCond.speculate_instruction(emulator, address, size, model)
        X86UnicornBpas.speculate_instruction(emulator, address, size, model)


# ==================================================================================================
# Taint tracker
# ==================================================================================================
class X86TaintTracker(TaintTrackerInterface):
    strict_undefined: bool = True
    _instruction: Optional[Instruction] = None
    sandbox_base: int = 0

    src_regs: List[str]
    dest_regs: List[str]
    reg_dependencies: Dict[str, Set]

    src_flags: List[str]
    dest_flags: List[str]
    flag_dependencies: Dict[str, Set]

    src_mems: List[str]
    dest_mems: List[str]
    mem_dependencies: Dict[str, Set]

    mem_address_regs: List[str]

    tainted_labels: Set[str]
    pending_taint: List[str]

    _reg_decode = {
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
        "RIP": -1,
        "RSP": -1,
    }
    _registers = [
        ucc.UC_X86_REG_RAX, ucc.UC_X86_REG_RBX, ucc.UC_X86_REG_RCX, ucc.UC_X86_REG_RDX,
        ucc.UC_X86_REG_RSI, ucc.UC_X86_REG_RDI, ucc.UC_X86_REG_EFLAGS
    ]

    def __init__(self, initial_observations, sandbox_base=0):
        self.initial_observations = initial_observations
        self.sandbox_base = sandbox_base
        self.flag_dependencies = {}
        self.reg_dependencies = {}
        self.mem_dependencies = {}
        self.tainted_labels = set(self.initial_observations)
        self.checkpoints = []

    def start_instruction(self, instruction):
        """ Collect source and target registers/flags """
        if self._instruction:
            self._finalize_instruction()  # finalize the previous instruction

        self._instruction = instruction
        self.src_regs = []
        self.src_flags = []
        self.src_mems = []
        self.dest_regs = []
        self.dest_flags = []
        self.dest_mems = []
        self.pending_taint = []
        self.mem_address_regs = []

        for op in instruction.operands + instruction.implicit_operands:
            if isinstance(op, RegisterOperand):
                value = X86TargetDesc.gpr_normalized[op.value]
                if op.src:
                    self.src_regs.append(value)
                if op.dest:
                    self.dest_regs.append(value)
            elif isinstance(op, FlagsOperand):
                self.src_flags = op.get_read_flags()
                if self.strict_undefined:
                    self.src_flags.extend(op.get_undef_flags())
                self.dest_flags = op.get_write_flags()
            elif isinstance(op, MemoryOperand):
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in X86TargetDesc.gpr_normalized:
                        self.mem_address_regs.append(X86TargetDesc.gpr_normalized[sub_op])

    def _finalize_instruction(self):
        """Propagate dependencies from source operands to destinations """
        # print("-----------------------------------------------")
        # print(self._instruction)
        # print(f"Src:  {self.src_regs}, {self.src_flags}, {self.src_mems}, "
        #   f"Mem regs: {self.mem_address_regs}")
        # print(f"Dest: {self.dest_regs}, {self.dest_flags}, {self.dest_mems}")

        # Compute source label
        src_labels = set()
        for reg in self.src_regs:
            src_labels.update(self.reg_dependencies.get(reg, {reg}))
        for flag in self.src_flags:
            src_labels.update(self.flag_dependencies.get(flag, {flag}))
        for addr in self.src_mems:
            src_labels.update(self.mem_dependencies.get(addr, {addr}))

        # print(src_labels)

        # Propagate label to all targets
        uniq_labels = src_labels
        for reg in self.dest_regs:
            if reg in self.reg_dependencies:
                self.reg_dependencies[reg].update(uniq_labels)
            else:
                self.reg_dependencies[reg] = copy.copy(uniq_labels)
                self.reg_dependencies[reg].add(reg)

        for flg in self.dest_flags:
            if flg in self.flag_dependencies:
                self.flag_dependencies[flg].update(uniq_labels)
            else:
                self.flag_dependencies[flg] = copy.copy(uniq_labels)
                self.flag_dependencies[flg].add(flg)

        for mem in self.dest_mems:
            if mem in self.mem_dependencies:
                self.mem_dependencies[mem].update(uniq_labels)
            else:
                self.mem_dependencies[mem] = copy.copy(uniq_labels)
                self.mem_dependencies[mem].add(mem)

        # Update taints
        for label in self.pending_taint:
            if label.startswith("0x"):
                self.tainted_labels.update(self.mem_dependencies.get(label, {label}))
            else:
                self.tainted_labels.update(self.reg_dependencies.get(label, {label}))

        self._instruction = None

    def track_memory_access(self, address: int, size: int, is_write: bool):
        """ Tracking concrete memory accesses """
        # mask the address - we taint at the granularity of 8 bytes
        address -= self.sandbox_base
        masked_start_addr = address & 0xffff_ffff_ffff_fff8
        end_addr = address + (size - 1)
        masked_end_addr = end_addr & 0xffff_ffff_ffff_fff8

        # add all addresses to tracking
        track_list = self.dest_mems if is_write else self.src_mems
        for i in range(masked_start_addr, masked_end_addr + 1, 8):
            track_list.append(hex(i))

    def taint_pc(self):
        if self._instruction and self._instruction.control_flow:
            self.pending_taint.append("RIP")

    def taint_memory_access_address(self):
        for reg in self.mem_address_regs:
            self.pending_taint.append(reg)

    def taint_memory_load(self):
        for addr in self.src_mems:
            self.pending_taint.append(addr)

    def taint_memory_store(self):
        for addr in self.dest_mems:
            self.pending_taint.append(addr)

    def checkpoint(self):
        if self._instruction:
            self._finalize_instruction()
        self.checkpoints.append(
            (copy.deepcopy(self.flag_dependencies), copy.deepcopy(self.reg_dependencies),
             copy.deepcopy(self.mem_dependencies)))

    def rollback(self):
        assert self.checkpoints, "There are no more checkpoints"
        if self._instruction:
            self._finalize_instruction()
        t = self.checkpoints.pop()
        self.flag_dependencies = copy.deepcopy(t[0])
        self.reg_dependencies = copy.deepcopy(t[1])
        self.mem_dependencies = copy.deepcopy(t[2])

    def get_taint(self) -> InputTaint:
        if self._instruction:
            self._finalize_instruction()

        taint = InputTaint()
        tainted_positions = []
        register_start = taint.register_start

        for label in self.tainted_labels:
            input_offset = -1  # the location of the label within the Input array
            if label.startswith('0x'):
                # memory address
                # we taint the 64-bits block that contains the address
                input_offset = (int(label, 16)) // 8
            else:
                reg = self._reg_decode[label]
                if reg in self._registers:
                    input_offset = register_start + \
                          self._registers.index(self._reg_decode[label])
            if input_offset >= 0:
                tainted_positions.append(input_offset)

        tainted_positions = list(dict.fromkeys(tainted_positions))
        tainted_positions.sort()
        for i in range(taint.size):
            if i in tainted_positions:
                taint[i] = True
            else:
                taint[i] = False

        # print(self.tainted_labels)
        # for i, t in enumerate(taint):
        # if t:
        # print(i)

        return taint
