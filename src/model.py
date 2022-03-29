"""
File: Model Interface and its implementations

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC

import numpy as np
import unicorn as uni
from unicorn import Uc, UcError, UC_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RBP, \
    UC_X86_REG_RIP, \
    UC_X86_REG_EFLAGS, UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, \
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, \
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15
from typing import List, Tuple, Dict, Optional

from interfaces import CTrace, Input, TestCase, Model, InputTaint, Instruction
from config import CONF
from dependency_tracking import DependencyTracker

FLAGS_CF = 0b000000000001
FLAGS_PF = 0b000000000100
FLAGS_AF = 0b000000010000
FLAGS_ZF = 0b000001000000
FLAGS_SF = 0b000010000000
FLAGS_OF = 0b100000000000


# ==================================================================================================
# Abstract Interfaces
# ==================================================================================================
class X86UnicornTracer(ABC):
    trace: List[int]
    full_execution_trace: List[Tuple[bool, int]]

    def __init__(self):
        super().__init__()
        self.trace = []

    def reset_trace(self, emulator) -> None:
        self.trace = []
        self.full_execution_trace = []

    def get_trace(self) -> CTrace:
        return hash(tuple(self.trace))

    def get_full_execution_trace(self):
        return self.full_execution_trace

    def add_mem_address_to_trace(self, address, model):
        self.trace.append(address)
        if model.dependency_tracker is not None:
            # Update the tracking with the address labels
            model.dependency_tracker.observe_instruction("OPS")

    def add_pc_to_trace(self, address, model):
        self.trace.append(address)
        if model.dependency_tracker is not None:
            model.dependency_tracker.observe_instruction("PC")

    def observe_mem_access(self, access, address: int, size: int, value: int, model) -> None:
        if not model.in_speculation:
            self.full_execution_trace.append((False, address - model.sandbox_base))
            if model.debug:
                if access == uni.UC_MEM_READ:
                    val = int.from_bytes(model.emulator.mem_read(address, size), byteorder='little')
                    print(f"  > read: +0x{address - model.sandbox_base:x} = 0x{val:x}")
                else:
                    print(f"  > write: +0x{address - model.sandbox_base:x} = 0x{value:x}")

    def observe_instruction(self, address: int, size: int, model) -> None:
        if not model.in_speculation:
            self.full_execution_trace.append((True, address - model.code_base))
            if model.debug:
                print(f"{address - model.code_base:2x}: ", end="")
                model.print_state(oneline=True)


class X86UnicornModel(Model):
    """
    Base class for all Unicorn-based models.
    Serves as an adapter between Unicorn and our fuzzer.
    """
    CODE_SIZE = 4 * 1024
    WORKING_MEMORY_SIZE = 1024 * 1024
    MAIN_REGION_SIZE = CONF.input_main_region_size * 8
    ASSIST_REGION_SIZE = CONF.input_assist_region_size * 8
    OVERFLOW_REGION_SIZE = 4096

    test_case: TestCase
    code: bytes
    emulator: Uc
    in_speculation: bool = False
    speculation_window: int = 0
    checkpoints: List
    store_logs: List
    previous_store: Tuple[int, int, int, int]
    tracer: X86UnicornTracer
    nesting: int = 0
    debug: bool = False
    dependency_tracker: Optional[DependencyTracker] = None

    def __init__(self, sandbox_base, code_base):
        super().__init__(sandbox_base, code_base)
        self.code_base: int = code_base
        self.sandbox_base: int = sandbox_base
        self.lower_overflow_base = self.sandbox_base - self.OVERFLOW_REGION_SIZE
        self.upper_overflow_base = \
            self.sandbox_base + self.MAIN_REGION_SIZE + self.ASSIST_REGION_SIZE
        self.stack_base = sandbox_base + self.MAIN_REGION_SIZE - 8
        self.overflow_region_values = bytes(self.OVERFLOW_REGION_SIZE)

    def load_test_case(self, test_case: TestCase) -> None:
        self.test_case = test_case

        # create and read a binary
        with open(test_case.bin_path, 'rb') as f:
            self.code = f.read()

        # initialize emulator in x86-64 mode
        emulator = Uc(uni.UC_ARCH_X86, uni.UC_MODE_64)

        try:
            # allocate memory
            emulator.mem_map(self.code_base, self.CODE_SIZE)
            emulator.mem_map(self.sandbox_base - self.WORKING_MEMORY_SIZE // 2,
                             self.WORKING_MEMORY_SIZE)

            # write machine code to be emulated to memory
            emulator.mem_write(self.code_base, self.code)

            # set up callbacks
            emulator.hook_add(uni.UC_HOOK_MEM_READ | uni.UC_HOOK_MEM_WRITE, self.trace_mem_access,
                              self)
            emulator.hook_add(uni.UC_HOOK_CODE, self.instruction_hook, self)

            self.emulator = emulator

        except UcError as e:
            print("Model error [load_test_case]: %s" % e)
            raise e

    def trace_test_case(self, inputs: List[Input], nesting, dbg: bool = False) -> \
            Tuple[List[CTrace], List[InputTaint]]:
        self.nesting = nesting
        self.debug = dbg

        traces = []
        full_execution_traces = []
        taints = []
        for input_ in inputs:
            try:
                self.reset_model()
                self._load_input(input_)
                self.emulator.emu_start(
                    self.code_base,
                    self.code_base + len(self.code),
                    timeout=10 * uni.UC_SECOND_SCALE)
            except UcError as e:
                if not self.in_speculation:
                    self.print_state()
                    print("Model error [trace_test_case]: %s" % e)
                    raise e

            # if we use one of the SPEC contracts, we might have some residual simulations
            # that did not reach the spec. window by the end of simulation. Those need
            # to be rolled back
            while self.in_speculation:
                try:
                    self.rollback()
                except uni.UcError:
                    continue

            # store the results
            traces.append(self.tracer.get_trace())
            full_execution_traces.append(self.tracer.get_full_execution_trace())
            if self.dependency_tracker is not None:
                dependencies = self.dependency_tracker.get_observed_dependencies()
                taints.append(self.get_taint(dependencies))

        if self.coverage:
            self.coverage.model_hook(full_execution_traces)

        return traces, taints

    def reset_model(self):
        self.checkpoints = []
        self.in_speculation = False
        self.speculation_window = 0
        self.tracer.reset_trace(self.emulator)
        if self.dependency_tracker is not None:
            self.dependency_tracker.reset()

    def _load_input(self, input_: Input):
        # Set memory:
        # - initialize overflows with zeroes
        self.emulator.mem_write(self.lower_overflow_base, self.overflow_region_values)
        self.emulator.mem_write(self.upper_overflow_base, self.overflow_region_values)

        # - sandbox pages
        self.emulator.mem_write(self.sandbox_base, input_.tobytes())

        # Set values in registers
        registers = [
            UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI,
            UC_X86_REG_RDI, UC_X86_REG_EFLAGS
        ]
        for i, value in enumerate(input_.get_registers()):
            if registers[i] == UC_X86_REG_EFLAGS:
                value = (value & np.uint64(2263)) | np.uint64(2)  # type: ignore
            self.emulator.reg_write(registers[i], value)

        self.emulator.reg_write(UC_X86_REG_RSP, self.stack_base)
        self.emulator.reg_write(UC_X86_REG_RBP, self.stack_base)
        self.emulator.reg_write(UC_X86_REG_R14, self.sandbox_base)

    def get_taint(self, dependencies) -> InputTaint:

        def get_register(reg_):
            reg_dict = {
                "RAX": UC_X86_REG_RAX,
                "RBX": UC_X86_REG_RBX,
                "RCX": UC_X86_REG_RCX,
                "RDX": UC_X86_REG_RDX,
                "RDI": UC_X86_REG_RDI,
                "RSI": UC_X86_REG_RSI,
                "RSP": UC_X86_REG_RSP,
                "RBP": UC_X86_REG_RBP,
                "R8": UC_X86_REG_R8,
                "R9": UC_X86_REG_R9,
                "R10": UC_X86_REG_R10,
                "R11": UC_X86_REG_R11,
                "R12": UC_X86_REG_R12,
                "R13": UC_X86_REG_R13,
                "R14": UC_X86_REG_R14,
                "R15": UC_X86_REG_R15,
            }

            if reg_ in {"CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF", "AC"}:
                return UC_X86_REG_EFLAGS
            elif reg_ == "PC":
                return -1
            else:
                for j in {"A", "B", "C", "D"}:
                    if reg_ == f"R{j}X":
                        return reg_dict[f"R{j}X"]
                    elif reg_ == f"E{j}X":
                        return reg_dict[f"R{j}X"]
                    elif reg_ == f"{j}X":
                        return reg_dict[f"R{j}X"]
                    elif reg_ == f"{j}L":
                        return reg_dict[f"R{j}X"]
                    elif reg_ == f"{j}H":
                        return reg_dict[f"R{j}X"]

                for j in {"BP", "SI", "DI", "SP", "IP"}:
                    if reg_ == f"R{j}":
                        return reg_dict[f"R{j}"]
                    elif reg_ == f"E{j}":
                        return reg_dict[f"R{j}"]
                    elif reg_ == f"{j}":
                        return reg_dict[f"R{j}"]
                    elif reg_ == f"{j}L":
                        return reg_dict[f"R{j}"]

                for j in range(8, 16):
                    if reg_ == f"R{j}":
                        return reg_dict[f"R{j}"]
                    elif reg_ == f"R{j}D":
                        return reg_dict[f"R{j}"]
                    elif reg_ == f"R{j}W":
                        return reg_dict[f"R{j}"]
                    elif reg_ == f"R{j}B":
                        return reg_dict[f"R{j}"]

                print(f"Unsupported identifier {reg_}")
                exit(1)

        taint = InputTaint()
        tainted_positions = []
        for d in dependencies:
            pos = -1
            if type(d) is int:
                # memory address
                # we taint the 64-bits block that contains the address
                pos = (d - self.sandbox_base) // 8
            elif type(d) is str:
                # flag register
                registers = [
                    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI,
                    UC_X86_REG_RDI, UC_X86_REG_EFLAGS
                ]
                reg = get_register(d)
                if reg in registers:
                    pos = CONF.input_main_region_size + \
                          CONF.input_assist_region_size + \
                          registers.index(get_register(d))
            if pos != -1:
                tainted_positions.append(pos)

        tainted_positions = list(dict.fromkeys(tainted_positions))
        tainted_positions.sort()
        for i in range(CONF.input_main_region_size + CONF.input_assist_region_size +
                       CONF.input_register_region_size):
            if i in tainted_positions:
                taint[i] = True
            else:
                taint[i] = False
        return taint

    def print_state(self, oneline: bool = False):

        def compressed(val: int):
            if val < self.lower_overflow_base or \
                 val > self.upper_overflow_base + self.OVERFLOW_REGION_SIZE:
                return f"0x{val:<16x}"
            elif val >= self.sandbox_base:
                return f"+0x{val - self.sandbox_base:<15x}"
            else:
                return f"-0x{self.sandbox_base - val:<15x}"

        emulator = self.emulator
        rax = compressed(emulator.reg_read(UC_X86_REG_RAX))
        rbx = compressed(emulator.reg_read(UC_X86_REG_RBX))
        rcx = compressed(emulator.reg_read(UC_X86_REG_RCX))
        rdx = compressed(emulator.reg_read(UC_X86_REG_RDX))
        rsi = compressed(emulator.reg_read(UC_X86_REG_RSI))
        rdi = compressed(emulator.reg_read(UC_X86_REG_RDI))

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
                  f"fl={emulator.reg_read(UC_X86_REG_EFLAGS):012b}")

    @staticmethod
    def instruction_hook(emulator: Uc, address: int, size: int, model: X86UnicornModel) -> None:
        model.current_instruction = model.test_case.address_map[address - model.code_base]
        model.trace_instruction(emulator, address, size, model)

    @staticmethod
    def trace_instruction(emulator: Uc, address: int, size: int, model: X86UnicornModel) -> None:
        pass  # Implemented by subclasses

    @staticmethod
    def trace_mem_access(emulator: Uc, access: int, address: int, size: int, value: int,
                         model: X86UnicornModel) -> None:
        pass  # Implemented by subclasses

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model):
        pass  # Implemented by subclasses

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        pass  # Implemented by subclasses

    @staticmethod
    def checkpoint(emulator, next_instruction):
        pass  # Implemented by subclasses

    def rollback(self):
        pass  # Implemented by subclasses


# ==================================================================================================
# Implementation of Observation Clauses
# ==================================================================================================
class L1DTracer(X86UnicornTracer):

    def reset_trace(self, emulator):
        self.trace = [0, 0]
        self.full_execution_trace = []

    def add_mem_address_to_trace(self, address, model):
        page_offset = (address & 4032) >> 6  # 4032 = 0b111111000000
        cache_set_index = 9223372036854775808 >> page_offset
        # print(f"{cache_set_index:064b}")
        if model.in_speculation:
            self.trace[1] |= cache_set_index
        else:
            self.trace[0] |= cache_set_index
        if model.dependency_tracker is not None:
            model.dependency_tracker.observe_instruction("OPS")

    def observe_mem_access(self, access, address, size, value, model):
        self.add_mem_address_to_trace(address, model)
        super(L1DTracer, self).observe_mem_access(access, address, size, value, model)

    def observe_instruction(self, address: int, size: int, model):
        super(L1DTracer, self).observe_instruction(address, size, model)

    def get_trace(self) -> CTrace:
        if CONF.ignore_first_cache_line:
            self.trace[0] &= 9223372036854775807
            self.trace[1] &= 9223372036854775807
        return (self.trace[1] << 64) + self.trace[0]


class PCTracer(X86UnicornTracer):

    def observe_instruction(self, address: int, size: int, model):
        self.add_pc_to_trace(address, model)
        super(PCTracer, self).observe_instruction(address, size, model)


class MemoryTracer(X86UnicornTracer):

    def observe_mem_access(self, access, address, size, value, model):
        self.add_mem_address_to_trace(address, model)
        super(MemoryTracer, self).observe_mem_access(access, address, size, value, model)


class CTTracer(PCTracer):

    def observe_mem_access(self, access, address, size, value, model):
        self.add_mem_address_to_trace(address, model)
        super(CTTracer, self).observe_mem_access(access, address, size, value, model)


class CTNonSpecStoreTracer(PCTracer):

    def observe_mem_access(self, access, address, size, value, model):
        # trace all non-spec mem accesses and speculative loads
        if not model.in_speculation or access == uni.UC_MEM_READ:
            self.add_mem_address_to_trace(address, model)
        super(CTNonSpecStoreTracer, self).observe_mem_access(access, address, size, value, model)


class CTRTracer(CTTracer):

    def reset_trace(self, emulator):
        self.trace = [
            emulator.reg_read(UC_X86_REG_RAX),
            emulator.reg_read(UC_X86_REG_RBX),
            emulator.reg_read(UC_X86_REG_RCX),
            emulator.reg_read(UC_X86_REG_RDX),
            emulator.reg_read(UC_X86_REG_RSI),
            emulator.reg_read(UC_X86_REG_RDI),
            emulator.reg_read(UC_X86_REG_EFLAGS),
        ]
        self.full_execution_trace = []


class ArchTracer(CTRTracer):

    def observe_mem_access(self, access, address, size, value, model):
        if access == uni.UC_MEM_READ:
            val = int.from_bytes(model.emulator.mem_read(address, size), byteorder='little')
            self.trace.append(val)
            if model.dependency_tracker is not None:
                model.dependency_tracker.observe_memory_address(address, size)
        self.add_mem_address_to_trace(address, model)
        super(ArchTracer, self).observe_mem_access(access, address, size, value, model)


# ==================================================================================================
# Implementation of Execution Clauses
# ==================================================================================================
class X86UnicornSeq(X86UnicornModel):
    """
    A simple, in-order contract.
    The only thing it does is tracing.
    No manipulation of the control or data flow.
    """

    @staticmethod
    def trace_mem_access(emulator, access, address: int, size, value, model):
        # Dependency tracking: Track the memory access
        if model.dependency_tracker is not None:
            mode = "WRITE" if access == UC_MEM_WRITE else "READ"
            model.dependency_tracker.track_memory_access(address, size, mode)

        model.tracer.observe_mem_access(access, address, size, value, model)

    @staticmethod
    def trace_instruction(emulator, address, size, model) -> None:
        # Dependency tracking: Whenever we fetch a new instruction, we update the tracking data
        if model.dependency_tracker is not None:
            model.dependency_tracker.finalize_tracking()
            code = bytes(emulator.mem_read(address, size))
            model.dependency_tracker.initialize(code, model.current_instruction)

        model.tracer.observe_instruction(address, size, model)


class X86UnicornSpec(X86UnicornModel):
    """
    Intermediary class for all speculative contracts.
    Tracks speculative stores
    """

    def __init__(self, *args):
        self.checkpoints = []
        self.store_logs = []
        self.previous_store = (0, 0, 0, 0)
        self.latest_rollback_address = 0
        super(X86UnicornSpec, self).__init__(*args)

    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, model):
        # when in speculation, log all changes to memory
        if access == UC_MEM_WRITE and model.store_logs:
            model.store_logs[-1].append((address, emulator.mem_read(address, 8)))

        X86UnicornSeq.trace_mem_access(emulator, access, address, size, value, model)
        model.speculate_mem_access(emulator, access, address, size, value, model)

    @staticmethod
    def trace_instruction(emulator, address, size, model) -> None:
        if model.in_speculation:
            model.speculation_window += 1
            # rollback on a serializing instruction (lfence, sfence, mfence)
            if emulator.mem_read(address,
                                 size) in [b'\x0F\xAE\xE8', b'\x0F\xAE\xF8', b'\x0F\xAE\xF0']:
                emulator.emu_stop()

            # and on expired speculation window
            if model.speculation_window > CONF.max_speculation_window:
                emulator.emu_stop()

        X86UnicornSeq.trace_instruction(emulator, address, size, model)
        model.speculate_instruction(emulator, address, size, model)

    def checkpoint(self, emulator, next_instruction):
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        context = emulator.context_save()
        spec_window = self.speculation_window
        self.checkpoints.append((context, next_instruction, flags, spec_window))
        self.store_logs.append([])
        self.in_speculation = True
        if self.dependency_tracker is not None:
            self.dependency_tracker.checkpoint()

    def rollback(self):
        # restore register values
        state, next_instr, flags, spec_window = self.checkpoints.pop()
        if not self.checkpoints:
            self.in_speculation = False

        self.latest_rollback_address = next_instr

        # restore the speculation state
        self.emulator.context_restore(state)
        self.speculation_window = spec_window

        # rollback memory changes
        mem_changes = self.store_logs.pop()
        while mem_changes:
            addr, val = mem_changes.pop()
            self.emulator.mem_write(addr, bytes(val))

        # if there are any pending speculative store bypasses, cancel them
        self.previous_store = (0, 0, 0, 0)

        # restore the flags last, to avoid corruption by other operations
        self.emulator.reg_write(UC_X86_REG_EFLAGS, flags)

        # restore the dependency tracking
        if self.dependency_tracker is not None:
            self.dependency_tracker.rollback()

        # restart without misprediction
        self.emulator.emu_start(
            next_instr, self.code_base + len(self.code), timeout=10 * uni.UC_SECOND_SCALE)

    def reset_model(self):
        super().reset_model()
        self.latest_rollback_address = 0


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
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return

        # decode the instruction
        code = emulator.mem_read(address, size)
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        rcx = emulator.reg_read(UC_X86_REG_RCX)
        target, will_jump, is_loop = X86UnicornCond.decode(code, flags, rcx)

        # not a a cond. jump? ignore
        if not target:
            return

        # LOOP instructions must also decrement RCX
        if is_loop:
            emulator.reg_write(UC_X86_REG_RCX, rcx - 1)

        # Take a checkpoint
        next_instr = address + size + target if will_jump else address + size
        model.checkpoint(emulator, next_instr)

        # Simulate misprediction
        if will_jump:
            emulator.reg_write(UC_X86_REG_RIP, address + size)
        else:
            emulator.reg_write(UC_X86_REG_RIP, address + size + target)

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
            rip = emulator.reg_read(UC_X86_REG_RIP)
            opcode = emulator.mem_read(rip, 1)[0]
            if opcode not in [0xE8, 0xFF, 0x9A]:  # ignore CALL instructions
                model.previous_store = (address, size, emulator.mem_read(address, size), value)

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
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
    def speculate_mem_access(emulator, access, address, size, value, model):
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
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        model.instruction_address = address


class X86UnicornCondBpas(X86UnicornSpec):

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model):
        X86UnicornBpas.speculate_mem_access(emulator, access, address, size, value, model)

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        X86UnicornCond.speculate_instruction(emulator, address, size, model)
        X86UnicornBpas.speculate_instruction(emulator, address, size, model)


def get_model(bases: Tuple[int, int]) -> Model:
    if CONF.model == 'x86-unicorn':
        model: Model

        # functional part of the contract
        if "cond" in CONF.contract_execution_clause and "bpas" in CONF.contract_execution_clause:
            model = X86UnicornCondBpas(bases[0], bases[1])
        elif "cond" in CONF.contract_execution_clause:
            model = X86UnicornCond(bases[0], bases[1])
        elif "bpas" in CONF.contract_execution_clause:
            model = X86UnicornBpas(bases[0], bases[1])
        elif "null-injection" in CONF.contract_execution_clause:
            model = X86UnicornNull(bases[0], bases[1])
        elif "seq" in CONF.contract_execution_clause:
            model = X86UnicornSeq(bases[0], bases[1])
        else:
            print("Error: unknown value of `contract_execution_clause` configuration option")
            exit(1)

        # observational part of the contract
        if CONF.contract_observation_clause == "l1d":
            model.tracer = L1DTracer()
        elif CONF.contract_observation_clause == 'pc':
            model.tracer = PCTracer()
        elif CONF.contract_observation_clause == 'memory':
            model.tracer = MemoryTracer()
        elif CONF.contract_observation_clause == 'ct':
            model.tracer = CTTracer()
        elif CONF.contract_observation_clause == 'ct-nonspecstore':
            model.tracer = CTNonSpecStoreTracer()
        elif CONF.contract_observation_clause == 'ctr':
            model.tracer = CTRTracer()
        elif CONF.contract_observation_clause == 'arch':
            model.tracer = ArchTracer()
        else:
            print("Error: unknown value of `contract_observation_clause` configuration option")
            exit(1)

        if CONF.dependency_tracking:
            # 64-bits only
            if CONF.contract_observation_clause == 'ctr' or CONF.contract_observation_clause == 'arch':
                initial_observations = [
                    "RAX", "RBX", "RCX", "RDX", "CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF",
                    "OF", "AC"
                ]
                model.dependency_tracker = DependencyTracker(64, initial_observations)
            else:
                model.dependency_tracker = DependencyTracker(64)

        return model
    else:
        print("Error: unknown value of `model` configuration option")
        exit(1)
