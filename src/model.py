"""
File: Model Interface and its implementations

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Tuple, Type

from unicorn import Uc, UcError, UC_MEM_WRITE, UC_MEM_READ, UC_SECOND_SCALE

from interfaces import CTrace, TestCase, Model, InputTaint, Instruction, ExecutionTrace, \
     TracedInstruction, TracedMemAccess, Input, Dict
from config import CONF
from service import LOGGER


# ==================================================================================================
# Abstract Interfaces
# ==================================================================================================
class UnicornTargetDesc(ABC):
    registers: List[int]
    barriers: List[str]
    flags_register: int
    reg_decode: Dict[str, int]


class UnicornTracer(ABC):
    """
    A simple tracer.
    Collect instructions as they are emulated. See :class:`TracedInstruction`
    """
    trace: List[int]
    execution_trace: ExecutionTrace
    instruction_id: int

    def __init__(self):
        super().__init__()
        self.trace = []

    def reset_trace(self, emulator, target_desc: UnicornTargetDesc) -> None:
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
                           model: UnicornModel) -> None:
        if model.in_speculation:
            return

        normalized_address = address - model.sandbox_base
        is_store = (access != UC_MEM_READ)
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
        if normalized_address in model.test_case.address_map:
            LOGGER.dbg_model_instruction(model.test_case.address_map[normalized_address].name,
                                         normalized_address, model)
        # TODO: handle keyerror

        if model.execution_tracing_enabled:
            self.execution_trace.append(TracedInstruction(normalized_address, []))
            self.instruction_id = len(self.execution_trace) - 1


class UnicornModel(Model, ABC):
    """
    Base class for all Unicorn-based models.
    Serves as an adapter between Unicorn and our fuzzer.
    """
    CODE_SIZE = 4 * 1024
    MAIN_REGION_SIZE = CONF.input_main_region_size
    FAULTY_REGION_SIZE = CONF.input_faulty_region_size
    OVERFLOW_REGION_SIZE = 4096

    emulator: Uc
    target_desc: UnicornTargetDesc
    tracer: UnicornTracer
    taint_tracker: TaintTrackerInterface
    taint_tracker_cls: Type[TaintTrackerInterface]

    test_case: TestCase
    current_instruction: Instruction
    code_start: int
    code_end: int
    sandbox_base: int
    main_region: int
    faulty_region: int
    nesting: int = 0
    in_speculation: bool = False
    speculation_window: int = 0
    checkpoints: List[Tuple[object, int, int, int]]
    ''' List of (context : UnicornContext, next_instruction, flags, spec_window)) '''

    store_logs: List[List[Tuple[int, bytes]]]
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
            self.sandbox_base + self.MAIN_REGION_SIZE + self.FAULTY_REGION_SIZE
        self.main_region = self.sandbox_base
        self.faulty_region = self.main_region + self.MAIN_REGION_SIZE
        self.stack_base = self.main_region + self.MAIN_REGION_SIZE - 8

        self.overflow_region_values = bytes(self.OVERFLOW_REGION_SIZE)

        if CONF.contract_observation_clause == 'ctr' or CONF.contract_observation_clause == 'arch':
            self.initial_taints = [
                "A", "B", "C", "D", "SI", "DI", "RSP", "CF", "PF", "AF", "ZF", "SF", "TF", "IF",
                "DF", "OF", "AC"
            ]
        else:
            self.initial_taints = []

    @abstractmethod
    def load_test_case(self, test_case: TestCase) -> None:
        """
        Instantiate emulator and load input in registers
        This is architecture specific.
        """
        pass

    @abstractmethod
    def _load_input(self, input_: Input):
        """
        Load registers with given input: this is architecture specific
        """
        pass

    def _execute_test_case(self, inputs, nesting):
        """
        Architecture independent code - it starts the emulator
        """
        self.nesting = nesting

        contract_traces: List[CTrace] = []
        execution_traces: List[ExecutionTrace] = []
        taints = []
        for input_ in inputs:
            self.reset_model()
            try:
                self._load_input(input_)
                self.emulator.emu_start(
                    self.code_start, self.code_end, timeout=10 * UC_SECOND_SCALE)
            except UcError as e:
                if not self.in_speculation:
                    self.print_state()
                    LOGGER.error("[UnicornModel:trace_test_case] %s" % e)

            # if we use one of the SPEC contracts, we might have some residual simulations
            # that did not reach the spec. window by the end of simulation. Those need
            # to be rolled back
            while self.in_speculation:
                try:
                    self.rollback()
                except UcError:
                    continue

            # store the results
            assert self.tracer
            contract_traces.append(self.tracer.get_contract_trace())
            execution_traces.append(self.tracer.get_execution_trace())
            taints.append(self.taint_tracker.get_taint())

        if self.coverage:
            self.coverage.model_hook(execution_traces)

        return contract_traces, taints

    def trace_test_case(self, inputs, nesting):
        """
        Enables tracing and starts the emulator
        """
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
        self.tracer.reset_trace(self.emulator, self.target_desc)
        if self.tainting_enabled:
            self.taint_tracker = self.taint_tracker_cls(self.initial_taints, self.sandbox_base)
        else:
            self.taint_tracker = DummyTaintTracker([])

    @abstractmethod
    def print_state(self, oneline: bool = False):
        pass

    @staticmethod
    def instruction_hook(emulator: Uc, address: int, size: int, model: UnicornModel) -> None:
        """
        Invoked when an instruction is executed.
        it records instruction
        """
        model.current_instruction = model.test_case.address_map[address - model.code_start]
        model.trace_instruction(emulator, address, size, model)

    @staticmethod
    @abstractmethod
    def trace_instruction(emulator: Uc, address: int, size: int, model: UnicornModel) -> None:
        pass

    @staticmethod
    @abstractmethod
    def trace_mem_access(emulator: Uc, access: int, address: int, size: int, value: int,
                         model: UnicornModel) -> None:
        pass

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model: UnicornModel) -> None:
        pass

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model: UnicornModel) -> None:
        pass

    def checkpoint(self, emulator: Uc, next_instruction: int):
        pass

    def rollback(self):
        pass


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


# ==================================================================================================
# Implementation of Observation Clauses
# ==================================================================================================
class L1DTracer(UnicornTracer):

    def reset_trace(self, _, __):
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


class PCTracer(UnicornTracer):
    """
    Program counter tracer
    """

    def observe_instruction(self, address: int, size: int, model):
        self.add_pc_to_trace(address, model)
        super(PCTracer, self).observe_instruction(address, size, model)


class MemoryTracer(UnicornTracer):

    def observe_mem_access(self, access, address, size, value, model):
        self.add_mem_address_to_trace(address, model)
        super(MemoryTracer, self).observe_mem_access(access, address, size, value, model)


class CTTracer(PCTracer):
    """
    Observe address of the memory access and of the program counter.
    """

    def observe_mem_access(self, access, address, size, value, model):
        self.add_mem_address_to_trace(address, model)
        super(CTTracer, self).observe_mem_access(access, address, size, value, model)


class CTNonSpecStoreTracer(PCTracer):
    """
    Observe address of memory access only if not in speculation or it is a read.
    """

    def observe_mem_access(self, access, address, size, value, model):
        # trace all non-spec mem accesses and speculative loads
        if not model.in_speculation or access == UC_MEM_READ:
            self.add_mem_address_to_trace(address, model)
        super(CTNonSpecStoreTracer, self).observe_mem_access(access, address, size, value, model)


class CTRTracer(CTTracer):
    """
    When execution starts we also observe registers state.
    """

    def reset_trace(self, emulator: Uc, target_desc: UnicornTargetDesc):
        self.trace = [emulator.reg_read(reg) for reg in target_desc.registers]
        self.execution_trace = []


class ArchTracer(CTRTracer):
    """
    Observe (also) the value loaded from memory
    """

    def observe_mem_access(self, access, address, size, value, model: UnicornModel):
        if access == UC_MEM_READ:
            val = int.from_bytes(model.emulator.mem_read(address, size), byteorder='little')
            self.trace.append(val)
            model.taint_tracker.taint_memory_load()
        self.add_mem_address_to_trace(address, model)
        super(ArchTracer, self).observe_mem_access(access, address, size, value, model)


# ==================================================================================================
# Implementation of Execution Clauses
# ==================================================================================================


class UnicornSeq(UnicornModel):
    """
    A simple, in-order contract.
    The only thing it does is tracing.
    No manipulation of the control or data flow.
    """

    @staticmethod
    def trace_instruction(_, address, size, model) -> None:
        model.taint_tracker.start_instruction(model.current_instruction)
        model.tracer.observe_instruction(address, size, model)

    @staticmethod
    def trace_mem_access(_, access, address: int, size, value, model):
        model.taint_tracker.track_memory_access(address, size, access == UC_MEM_WRITE)
        model.tracer.observe_mem_access(access, address, size, value, model)


class UnicornSpec(UnicornModel):
    """
    Intermediary class for all speculative contracts.
    """

    def __init__(self, *args):
        self.checkpoints = []
        self.store_logs = []
        self.previous_store = (0, 0, 0, 0)
        self.latest_rollback_address = 0
        super().__init__(*args)

    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, model) -> None:
        # when in speculation, log all changes to memory
        if access == UC_MEM_WRITE and model.store_logs:
            model.store_logs[-1].append((address, emulator.mem_read(address, 8)))

        UnicornSeq.trace_mem_access(emulator, access, address, size, value, model)
        model.speculate_mem_access(emulator, access, address, size, value, model)

    @staticmethod
    def trace_instruction(emulator, address, size, model: UnicornModel) -> None:
        if model.in_speculation:
            model.speculation_window += 1
            # rollback on a serializing instruction
            if model.current_instruction.name in model.target_desc.barriers:
                emulator.emu_stop()

            # and on expired speculation window
            if model.speculation_window > CONF.model_max_spec_window:
                emulator.emu_stop()

        UnicornSeq.trace_instruction(emulator, address, size, model)
        model.speculate_instruction(emulator, address, size, model)

    def checkpoint(self, emulator: Uc, next_instruction):
        flags = emulator.reg_read(self.target_desc.flags_register)
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
        self.emulator.reg_write(self.target_desc.flags_register, flags)

        # restore the taint tracking
        self.taint_tracker.rollback()

        # restart without misprediction
        self.emulator.emu_start(next_instr, self.code_end, timeout=10 * UC_SECOND_SCALE)

    def reset_model(self):
        super().reset_model()
        self.latest_rollback_address = 0
