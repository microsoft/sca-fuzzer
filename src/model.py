"""
File: Model Interface and its implementations

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC, abstractmethod

import numpy as np
import unicorn as uni
import copy
import re
from unicorn import Uc, UcError, UC_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RBP, \
    UC_X86_REG_RIP, \
    UC_X86_REG_EFLAGS, UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, \
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, \
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15
from typing import List, Tuple, Dict, Optional, Set

from interfaces import CTrace, Input, TestCase, Model, InputTaint, Instruction, RegisterOperand, \
    FlagsOperand, MemoryOperand, ExecutionTrace, TracedInstruction, TracedMemAccess
from generator import X86Registers
from config import CONF, ConfigException
from service import LOGGER

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
    execution_trace: ExecutionTrace
    instruction_id: int

    def __init__(self):
        super().__init__()
        self.trace = []

    def reset_trace(self, emulator) -> None:
        self.trace = []
        self.execution_trace = []

    def get_contract_trace(self) -> CTrace:
        return hash(tuple(self.trace))

    def get_execution_trace(self) -> ExecutionTrace:
        return self.execution_trace

    def add_mem_address_to_trace(self, address: int, model):
        self.trace.append(address)
        model.taint_tracker.taint_memory_access_address()

    def add_pc_to_trace(self, address, model):
        self.trace.append(address)
        model.taint_tracker.taint_pc()

    def observe_mem_access(self, access, address: int, size: int, value: int,
                           model: X86UnicornModel) -> None:
        if model.in_speculation:
            return

        normalized_address = address - model.sandbox_base
        is_store = (access != uni.UC_MEM_READ)
        val = value if is_store else int.from_bytes(
            model.emulator.mem_read(address, size), byteorder='little')
        LOGGER.dbg_model_mem_access(normalized_address, val, is_store)

        if model.execution_tracing_enabled:
            traced_instruction = self.execution_trace[self.instruction_id]
            traced_instruction.accesses.append(TracedMemAccess(normalized_address, val, is_store))

    def observe_instruction(self, address: int, size: int, model) -> None:
        if model.in_speculation:
            return
        normalized_address = address - model.code_start
        LOGGER.dbg_model_instruction(model.test_case.address_map[normalized_address].name,
                                     normalized_address, model)

        if model.execution_tracing_enabled:
            self.execution_trace.append(TracedInstruction(normalized_address, []))
            self.instruction_id = len(self.execution_trace) - 1


class X86UnicornModel(Model):
    """
    Base class for all Unicorn-based models.
    Serves as an adapter between Unicorn and our fuzzer.
    """
    CODE_SIZE = 4 * 1024
    WORKING_MEMORY_SIZE = 1024 * 1024
    MAIN_REGION_SIZE = CONF.input_main_region_size
    ASSIST_REGION_SIZE = CONF.input_assist_region_size
    OVERFLOW_REGION_SIZE = 4096

    emulator: Uc
    tracer: X86UnicornTracer
    taint_tracker: TaintTrackerInterface

    test_case: TestCase
    current_instruction: Instruction
    code_start: int
    code_end: int
    sandbox_base: int
    nesting: int = 0
    in_speculation: bool = False
    speculation_window: int = 0
    checkpoints: List
    store_logs: List
    previous_store: Tuple[int, int, int, int]

    # execution modes
    tainting_enabled: bool = False
    execution_tracing_enabled: bool = False

    def __init__(self, sandbox_base, code_start):
        super().__init__(sandbox_base, code_start)
        self.code_start = code_start
        self.sandbox_base = sandbox_base
        self.lower_overflow_base = self.sandbox_base - self.OVERFLOW_REGION_SIZE
        self.upper_overflow_base = \
            self.sandbox_base + self.MAIN_REGION_SIZE + self.ASSIST_REGION_SIZE
        self.stack_base = sandbox_base + self.MAIN_REGION_SIZE - 8
        self.overflow_region_values = bytes(self.OVERFLOW_REGION_SIZE)

        if CONF.contract_observation_clause == 'ctr' or CONF.contract_observation_clause == 'arch':
            self.initial_taints = [
                "A", "B", "C", "D", "SI", "DI", "RSP", "CF", "PF", "AF", "ZF", "SF", "TF", "IF",
                "DF", "OF", "AC"
            ]
        else:
            self.initial_taints = []

    def load_test_case(self, test_case: TestCase) -> None:
        self.test_case = test_case

        # create and read a binary
        with open(test_case.bin_path, 'rb') as f:
            code = f.read()
        self.code_end = self.code_start + len(code)

        # initialize emulator in x86-64 mode
        emulator = Uc(uni.UC_ARCH_X86, uni.UC_MODE_64)

        try:
            # allocate memory
            emulator.mem_map(self.code_start, self.CODE_SIZE)
            emulator.mem_map(self.sandbox_base - self.WORKING_MEMORY_SIZE // 2,
                             self.WORKING_MEMORY_SIZE)

            # write machine code to be emulated to memory
            emulator.mem_write(self.code_start, code)

            # set up callbacks
            emulator.hook_add(uni.UC_HOOK_MEM_READ | uni.UC_HOOK_MEM_WRITE, self.trace_mem_access,
                              self)
            emulator.hook_add(uni.UC_HOOK_CODE, self.instruction_hook, self)

            self.emulator = emulator

        except UcError as e:
            LOGGER.error("[X86UnicornModel:load_test_case] %s" % e)

    def _execute_test_case(self, inputs, nesting):
        self.nesting = nesting

        contract_traces: List[CTrace] = []
        execution_traces: List[ExecutionTrace] = []
        taints = []
        for input_ in inputs:
            self.reset_model()
            try:
                self._load_input(input_)
                self.emulator.emu_start(
                    self.code_start, self.code_end, timeout=10 * uni.UC_SECOND_SCALE)
            except UcError as e:
                if not self.in_speculation:
                    self.print_state()
                    LOGGER.error("[X86UnicornModel:trace_test_case] %s" % e)

            # if we use one of the SPEC contracts, we might have some residual simulations
            # that did not reach the spec. window by the end of simulation. Those need
            # to be rolled back
            while self.in_speculation:
                try:
                    self.rollback()
                except uni.UcError:
                    continue

            # store the results
            contract_traces.append(self.tracer.get_contract_trace())
            execution_traces.append(self.tracer.get_execution_trace())
            taints.append(self.taint_tracker.get_taint())

        self.coverage.model_hook(execution_traces)

        return contract_traces, taints

    def trace_test_case(self, inputs, nesting):
        self.execution_tracing_enabled = True
        ctraces, _ = self._execute_test_case(inputs, nesting)
        self.execution_tracing_enabled = False
        return ctraces

    def get_taints(self, inputs, nesting):
        self.tainting_enabled = True
        _, taints = self._execute_test_case(inputs, nesting)
        self.tainting_enabled = False
        return taints

    def reset_model(self):
        self.checkpoints = []
        self.in_speculation = False
        self.speculation_window = 0
        self.tracer.reset_trace(self.emulator)
        self.taint_tracker = TaintTracker(self.initial_taints, self.sandbox_base) \
            if self.tainting_enabled else DummyTaintTracker([])

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
        model.current_instruction = model.test_case.address_map[address - model.code_start]
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
# Tainting
# ==================================================================================================
class TaintTrackerInterface(ABC):

    def __init__(self, initial_observations, sandbox_base=0):
        pass

    def start_instruction(self, instruction: Instruction) -> None:
        pass

    def track_memory_access(self, address: int, size: int, is_write: bool) -> None:
        pass

    def taint_pc(self):
        pass

    def taint_memory_access_address(self):
        pass

    def taint_memory_load(self):
        pass

    def taint_memory_store(self):
        pass

    def checkpoint(self):
        pass

    def rollback(self):
        pass

    @abstractmethod
    def get_taint(self) -> InputTaint:
        pass


class DummyTaintTracker(TaintTrackerInterface):

    def get_taint(self) -> InputTaint:
        return InputTaint()


class TaintTracker(TaintTrackerInterface):
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
        "A": UC_X86_REG_RAX,
        "B": UC_X86_REG_RBX,
        "C": UC_X86_REG_RCX,
        "D": UC_X86_REG_RDX,
        "DI": UC_X86_REG_RDI,
        "SI": UC_X86_REG_RSI,
        "SP": UC_X86_REG_RSP,
        "BP": UC_X86_REG_RBP,
        "8": UC_X86_REG_R8,
        "9": UC_X86_REG_R9,
        "10": UC_X86_REG_R10,
        "11": UC_X86_REG_R11,
        "12": UC_X86_REG_R12,
        "13": UC_X86_REG_R13,
        "14": UC_X86_REG_R14,
        "15": UC_X86_REG_R15,
        "FLAGS": UC_X86_REG_EFLAGS,
        "CF": UC_X86_REG_EFLAGS,
        "PF": UC_X86_REG_EFLAGS,
        "AF": UC_X86_REG_EFLAGS,
        "ZF": UC_X86_REG_EFLAGS,
        "SF": UC_X86_REG_EFLAGS,
        "TF": UC_X86_REG_EFLAGS,
        "IF": UC_X86_REG_EFLAGS,
        "DF": UC_X86_REG_EFLAGS,
        "OF": UC_X86_REG_EFLAGS,
        "AC": UC_X86_REG_EFLAGS,
        "RIP": -1,
        "RSP": -1,
    }
    _registers = [
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI,
        UC_X86_REG_RDI, UC_X86_REG_EFLAGS
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
                value = X86Registers.gpr_normalized[op.value]
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
                    if sub_op and sub_op in X86Registers.gpr_normalized:
                        self.mem_address_regs.append(X86Registers.gpr_normalized[sub_op])

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

        # print(f"Dep: R{self.reg_dependencies}, F{self.flag_dependencies}, M{self.mem_dependencies}")
        # print(f"Taint: {self.tainted_labels}")

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


# ==================================================================================================
# Implementation of Observation Clauses
# ==================================================================================================
class L1DTracer(X86UnicornTracer):

    def reset_trace(self, emulator):
        self.trace = [0, 0]
        self.execution_trace = []

    def add_mem_address_to_trace(self, address, model):
        page_offset = (address & 0b111111000000) >> 6
        cache_set_index = 0x8000000000000000 >> page_offset
        # print(f"{cache_set_index:064b}")
        if model.in_speculation:
            self.trace[1] |= cache_set_index
        else:
            self.trace[0] |= cache_set_index
        model.taint_tracker.taint_memory_access_address()

    def observe_mem_access(self, access, address, size, value, model):
        self.add_mem_address_to_trace(address, model)
        super(L1DTracer, self).observe_mem_access(access, address, size, value, model)

    def observe_instruction(self, address: int, size: int, model):
        super(L1DTracer, self).observe_instruction(address, size, model)

    def get_contract_trace(self) -> CTrace:
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
        self.execution_trace = []


class ArchTracer(CTRTracer):

    def observe_mem_access(self, access, address, size, value, model: X86UnicornModel):
        if access == uni.UC_MEM_READ:
            val = int.from_bytes(model.emulator.mem_read(address, size), byteorder='little')
            self.trace.append(val)
            model.taint_tracker.taint_memory_load()
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
    def trace_instruction(emulator, address, size, model) -> None:
        model.taint_tracker.start_instruction(model.current_instruction)
        model.tracer.observe_instruction(address, size, model)

    @staticmethod
    def trace_mem_access(emulator, access, address: int, size, value, model):
        model.taint_tracker.track_memory_access(address, size, access == UC_MEM_WRITE)
        model.tracer.observe_mem_access(access, address, size, value, model)


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
            # rollback on a serializing instruction
            if model.current_instruction.name in ["LFENCE", "MFENCE"]:
                emulator.emu_stop()

            # and on expired speculation window
            if model.speculation_window > CONF.model_max_spec_window:
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
        self.taint_tracker.checkpoint()

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

        # restore the taint tracking
        self.taint_tracker.rollback()

        # restart without misprediction
        self.emulator.emu_start(next_instr, self.code_end, timeout=10 * uni.UC_SECOND_SCALE)

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
            ConfigException("unknown value of `contract_execution_clause` configuration option")
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
            ConfigException("unknown value of `contract_observation_clause` configuration option")
            exit(1)

        return model
    else:
        ConfigException("unknown value of `model` configuration option")
        exit(1)
