"""
File:
    Leakage models, including:
      - Interfaces for models and service classes
        (UnicornModel, UnicornTracer, UnicornTargetDesc)
      - Core model (UnicornSeq), which implements in-order execution
        and tracing of test cases, as well as fault handling, actor management, and interpretation
        of macros
      - Checkpoint-rollback primitives for speculative contracts (UnicornSpec)
      - Tracing of test cases, otherwise known as observation clauses (PCTracer, CTTracer, etc.)
      - Taint-tracking for input boosting (BaseTaintTracker)
      - Macro interpreters (macro_switch, macro_measurement_start, etc.)

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, Set, Dict
from collections import defaultdict

import copy
import re

import unicorn as uc
from unicorn import Uc, UcError, UC_MEM_WRITE, UC_MEM_READ, UC_SECOND_SCALE, UC_HOOK_MEM_READ, \
    UC_HOOK_MEM_WRITE, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED

from .interfaces import CTrace, TestCase, Model, InputTaint, Instruction, ExecutionTrace, \
    TracedInstruction, TracedMemAccess, Input, Tracer, Actor, ActorMode, ActorPL, \
    RegisterOperand, FlagsOperand, MemoryOperand, TaintTrackerInterface, TargetDesc, \
    get_sandbox_addr, SANDBOX_DATA_SIZE, SANDBOX_CODE_SIZE, NotSupportedException, AgenOperand
from .config import CONF
from .util import Logger

# ==================================================================================================
# Custom Data Types and Constants
# ==================================================================================================
Checkpoint = Tuple[object, int, int, int]
""" context : UnicornContext, next_instruction, flags, spec_window) """

StoreLogEntry = Tuple[int, bytes]
""" store address, previous value """

UcPointer = int
""" pointer to a memory address within the Unicorn emulator instance """


class UnicornTargetDesc:
    registers: List[int]
    simd128_registers: List[int]
    barriers: List[str]
    flags_register: int
    pc_register: int
    actor_base_register: int
    sp_register: int
    reg_decode: Dict[str, int]
    reg_str_to_constant: Dict[str, int]


# ==================================================================================================
# Macro interpretation
# ==================================================================================================
class MacroInterpreter:
    next_switch_target: Tuple[int, int] = (0, 0)

    def __init__(self, model: UnicornSeq):
        pass

    def interpret(self, macro: Instruction, address: int):
        pass

    def load_test_case(self, test_case: TestCase):
        pass


# ==================================================================================================
# Observation Clauses
# ==================================================================================================
class UnicornTracer(Tracer):
    """
    A simple tracer.
    Collect instructions as they are emulated. See :class:`TracedInstruction`
    """
    trace: List[int]
    execution_trace: ExecutionTrace
    instruction_id: int
    enable_tracing: bool = False

    def __init__(self):
        super().__init__()
        self.trace = []
        self.LOG = Logger()

    def init_trace(self, emulator: Uc, uc_target_desc: UnicornTargetDesc) -> None:
        self.trace = []
        self.execution_trace = []

    def produce_trace(self, model: Model) -> CTrace:
        # make the trace reproducible by normalizing the addresses
        normalized_trace: List[int] = []
        for val in self.trace:
            if model.code_start <= val and val < model.code_end:
                normalized_trace.append(val - model.code_start)
            elif model.data_start < val and val < model.data_end:
                normalized_trace.append(val - model.sandbox_base)
            else:
                normalized_trace.append(val)

        return CTrace(normalized_trace)

    def get_contract_trace_full(self) -> List[int]:
        return self.trace

    def get_execution_trace(self) -> ExecutionTrace:
        return self.execution_trace

    def add_mem_address_to_trace(self, address: int, model: UnicornModel):
        if self.enable_tracing:
            self.trace.append(address)
            model.taint_tracker.taint_memory_access_address()

    def add_pc_to_trace(self, address: int, model: UnicornModel):
        if self.enable_tracing:
            self.trace.append(address)
            model.taint_tracker.taint_pc()

    def add_dependencies_to_trace(self, address: int, dependency_hash: int, model: UnicornModel):
        if self.enable_tracing:
            self.trace.append(dependency_hash)
            model.taint_tracker.taint_memory_access_address()

    def observe_mem_access(self, access, address: int, size: int, value: int,
                           model: UnicornModel) -> None:
        normalized_address = address - model.sandbox_base
        is_store = (access != UC_MEM_READ)
        self.LOG.dbg_model_mem_access(normalized_address, value, address, size, is_store, model)

        if model.in_speculation:
            return

        if model.execution_tracing_enabled:
            val = value if is_store else int.from_bytes(
                model.emulator.mem_read(address, size), byteorder='little')
            traced_instruction = self.execution_trace[self.instruction_id]
            traced_instruction.accesses.append(TracedMemAccess(normalized_address, val, is_store))

    def observe_instruction(self, address: int, size: int, model: UnicornModel) -> None:
        self.LOG.dbg_model_instruction(address, model)

        if model.in_speculation:
            return

        if model.execution_tracing_enabled:
            normalized_address = address - model.code_start
            self.execution_trace.append(TracedInstruction(normalized_address, []))
            self.instruction_id = len(self.execution_trace) - 1


class NoneTracer(UnicornTracer):

    def observe_mem_access(self, _, __, ___, ____, _____):
        pass

    def observe_instruction(self, _, __, ___):
        pass

    def produce_trace(self, _) -> CTrace:
        return CTrace.get_null()


class L1DTracer(UnicornTracer):
    """
    Memory address tracer that compresses the trace to imitate L1D cache observations.
    """

    def init_trace(self, _, __):
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

    def produce_trace(self, _) -> CTrace:
        """
        Return the collected trace. Since the trace is a single 64-bit value,
        we don't need hashing, and instead we assign the trace value to the hash.
        """
        trace = (self.trace[1] << 64) + self.trace[0]
        ctrace_obj = CTrace([trace])
        ctrace_obj.hash_ = trace
        return ctrace_obj


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


class TruncatedCTTracer(UnicornTracer):
    """
    Observe address of the memory access and of the program counter at cache line granularity.
    """

    def observe_mem_access(self, access, address, size, value, model):
        self.add_mem_address_to_trace((address >> 6) << 6, model)
        super(TruncatedCTTracer, self).observe_mem_access(access, address, size, value, model)

    def observe_instruction(self, address: int, size: int, model):
        self.add_pc_to_trace((address >> 6) << 6, model)
        super(TruncatedCTTracer, self).observe_instruction(address, size, model)


class TruncatedCTWithOverflowsTracer(UnicornTracer):
    """
    Observe address of the memory access and of the program counter at cache line granularity +
    observe cache line overflows.
    """

    def observe_mem_access(self, access, address, size, value, model) -> None:
        self.add_mem_address_to_trace((address >> 6) << 6, model)
        if (address + size) % 64 != (address % 64):  # add overflows to the trace
            self.add_mem_address_to_trace(((address + size) >> 6) << 6, model)
        return super().observe_mem_access(access, address, size, value, model)

    def observe_instruction(self, address: int, size: int, model) -> None:
        self.add_pc_to_trace((address >> 6) << 6, model)
        if (address + size) // 64 != (address // 64):  # add overflows to the trace
            self.add_pc_to_trace(((address + size) >> 6) << 6, model)
        return super().observe_instruction(address, size, model)


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

    def init_trace(self, emulator: Uc, uc_target_desc: UnicornTargetDesc):
        self.trace = [emulator.reg_read(reg) for reg in uc_target_desc.registers]  # type: ignore
        self.execution_trace = []


class ArchTracer(CTRTracer):
    """
    Observe (also) the value loaded from memory
    """

    def observe_mem_access(self, access, address, size, value, model: UnicornModel):
        if access == UC_MEM_READ:
            val = int.from_bytes(model.emulator.mem_read(address, size), byteorder='little')
            self.trace.append(val)
            model.taint_tracker.taint_loaded_value()
        super(ArchTracer, self).observe_mem_access(access, address, size, value, model)


# ==================================================================================================
# Model Implementation and Execution Clauses
# ==================================================================================================
class UnicornModel(Model, ABC):
    """
    Base class for all Unicorn-based models.
    Defines the interface for all models.
    """
    # service objects
    LOG: Logger
    emulator: Uc
    target_desc: TargetDesc
    uc_target_desc: UnicornTargetDesc
    tracer: UnicornTracer
    taint_tracker: TaintTrackerInterface
    original_tain_tracker: TaintTrackerInterface
    macro_interpreter: MacroInterpreter

    # checkpointing
    checkpoints: List[Checkpoint]
    store_logs: List[List[StoreLogEntry]]

    # speculation control
    in_speculation: bool = False
    nesting: int = 0
    speculation_window: int = 0
    previous_context = None

    # execution modes
    tainting_enabled: bool = False
    execution_tracing_enabled: bool = False

    def __init__(self,
                 sandbox_base: int,
                 code_start: int,
                 tracer: Tracer,
                 enable_mismatch_check_mode: bool = False):
        super().__init__(sandbox_base, code_start, tracer, enable_mismatch_check_mode)
        self.LOG = Logger()

    @staticmethod
    @abstractmethod
    def instruction_hook(emulator: Uc, address: int, size: int, model) -> None:
        """
        Invoked when an instruction is executed.
        it records instruction
        """
        pass

    @abstractmethod
    def _load_input(self, input_: Input):
        """
        Load registers and memory with given input: this is architecture specific
        """
        pass

    @abstractmethod
    def _execute_test_case(self, inputs: List[Input],
                           nesting: int) -> Tuple[List[CTrace], List[InputTaint]]:
        pass

    def trace_test_case(self, inputs, nesting) -> List[CTrace]:
        """
        Executes the test case with the inputs, and returns the corresponding contract traces
        """
        self.execution_tracing_enabled = True
        ctraces, _ = self._execute_test_case(inputs, nesting)
        self.execution_tracing_enabled = False
        return ctraces

    def trace_test_case_with_taints(self, inputs, nesting):
        self.tainting_enabled = True
        self.execution_tracing_enabled = True
        ctraces, taints = self._execute_test_case(inputs, nesting)
        self.tainting_enabled = False
        self.execution_tracing_enabled = False
        return ctraces, taints

    def dbg_get_trace_detailed(self, input_, nesting, raw: bool = False) -> List[str]:
        _, __ = self._execute_test_case([input_], nesting)
        trace = self.tracer.get_contract_trace_full()
        if raw:
            return [str(x) for x in trace]
        normalized_trace = []
        for val in trace:
            if self.code_start <= val and val < self.code_end:
                normalized_trace.append(f"pc:0x{val - self.code_start:x}")
            elif self.data_start < val and val < self.data_end:
                normalized_trace.append(f"mem:0x{val - self.sandbox_base:x}")
            else:
                normalized_trace.append(f"val:{val}")
        return normalized_trace

    @abstractmethod
    def reset_model(self):
        pass

    @abstractmethod
    def print_state(self, oneline: bool = False):
        pass

    @staticmethod
    @abstractmethod
    def trace_instruction(emulator: Uc, address: int, size: int, model) -> None:
        pass

    @staticmethod
    @abstractmethod
    def trace_mem_access(emulator: Uc, access: int, address: int, size: int, value: int,
                         model) -> None:
        pass

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model) -> None:
        pass

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        pass

    def post_execution_patch(self) -> None:
        pass

    def speculate_fault(self, errno: int) -> int:
        """
        return the address of the first speculative instruction
        return 0 if not speculation is triggered
        """
        return 0

    def checkpoint(self, emulator: Uc, next_instruction: int):
        pass

    def rollback(self) -> int:
        return 0

    @abstractmethod
    def emulate_vm_execution(self, address: int) -> None:
        """ Emulate the execution of an instruction in VM guest mode """
        # implemented by ISA-specific subclasses
        pass

    @abstractmethod
    def emulate_userspace_execution(self, address: int) -> None:
        """ Emulate the execution of an instruction in userspace mode """
        # implemented by ISA-specific subclasses
        pass


class UnicornSeq(UnicornModel):
    """
    The core model. Implements in-order execution and tracing of test cases.
    As well as that, this class implements:
     - fault handling
     - actor management
     - interpretation of macros

    This class does *not* implement speculative execution; refer to UnicornSpec for that.
    """
    # execution context
    actors_sorted: List[Actor]
    test_case: TestCase  # the test case being traced
    current_instruction: Instruction  # the instruction currently being executed
    current_actor: Actor  # the active actor
    local_coverage: Optional[Dict[str, int]]  # local coverage for the current test case
    initial_taints: List[str]  # initial taints for taint tracker

    # test case code
    code_start: UcPointer  # the lower bound of the code area
    code_end: UcPointer  # the upper bound of the code area
    exit_addr: UcPointer  # the address of the test case exit instruction
    fault_handler_addr: UcPointer  # the address of the fault handler

    # test case data
    main_area: UcPointer  # the base address of the main area
    faulty_area: UcPointer  # the base address of the faulty area
    reg_init_area: UcPointer  # the base address of the register initialization area
    stack_base: UcPointer  # the base address of the stack at the beginning of the test case

    # ISA-specific fields
    architecture: Tuple[int, int]  # (UC_ARCH, UC_MODE)
    flags_id: int  # the Unicorn constant corresponding to the flags register for the given ISA

    # fault handling
    handled_faults: Set[int]  # the set of fault types that do NOT terminate execution
    pending_fault_id: int = 0  # if a fault was triggered but not handled yet, its ID is stored here
    fault_mapping = {  # maps fault types to the corresponding Unicorn fault IDs
        "DE": [21],
        "DB": [10],
        "BP": [21],
        "BR": [13],
        "UD": [10],
        "PF": [12, 13],
        "GP": [6, 7],
        "assist": [12, 13],
    }
    had_arch_fault: bool = False

    def __init__(self,
                 sandbox_base: int,
                 code_start: int,
                 tracer: Tracer,
                 enable_mismatch_check_mode: bool = False):
        super().__init__(sandbox_base, code_start, tracer, enable_mismatch_check_mode)

        # sandbox
        self.underflow_pad_base = get_sandbox_addr(sandbox_base, "underflow_pad")
        self.main_area = get_sandbox_addr(sandbox_base, "main")
        self.faulty_area = get_sandbox_addr(sandbox_base, "faulty")
        self.reg_init_area = get_sandbox_addr(sandbox_base, "reg_init")
        self.stack_base = self.faulty_area - 8

        # taint tracking (actual values are set by ISA-specific subclasses)
        self.initial_taints = []

        # fault handling
        self.handled_faults = set()
        for fault in CONF._handled_faults:
            if fault in self.fault_mapping:
                self.handled_faults.update(self.fault_mapping[fault])
            else:
                raise NotSupportedException(f"Fault type {fault} is not supported")

    def reset_model(self):
        self.checkpoints = []
        self.in_speculation = False
        self.speculation_window = 0
        self.tracer.init_trace(self.emulator, self.uc_target_desc)
        if self.tainting_enabled:
            self.taint_tracker = self.original_tain_tracker
            self.taint_tracker.reset(self.initial_taints)
        else:
            self.taint_tracker = DummyTaintTracker([])
        self.pending_fault_id = 0
        self.had_arch_fault = False
        self.current_actor = self.test_case.actors["main"]

    def load_test_case(self, test_case: TestCase) -> None:
        """
        Instantiate emulator and copy the test case into the emulator's memory
        """
        self.test_case = test_case

        main_actor = test_case.actors["main"]
        assert main_actor.elf_section, f"Actor {main_actor.name} has no ELF section"
        actors = sorted(test_case.actors.values(), key=lambda a: (a.id_))
        self.actors_sorted = actors

        # read sections from the test case binary
        sections = []
        with open(test_case.obj_path, 'rb') as bin_file:
            for actor in actors:
                assert actor.elf_section, f"Actor {actor.name} has no ELF section"
                bin_file.seek(actor.elf_section.offset)
                sections.append(bin_file.read(actor.elf_section.size))

        # create a complete binary
        code = b''
        for section in sections:
            code += section
            padding = SANDBOX_CODE_SIZE - (len(section) % SANDBOX_CODE_SIZE)
            code += b'\x90' * padding  # fill with NOPs
        self.code_end = self.code_start + len(code)
        self.exit_addr = self.code_start + main_actor.elf_section.size - 1

        # sandbox data bounds
        self.data_start = get_sandbox_addr(self.sandbox_base, "start")
        self.data_end = self.sandbox_base + SANDBOX_DATA_SIZE * len(actors)

        # initialize emulator in x86-64 mode
        emulator = Uc(*self.architecture)

        try:
            # allocate memory
            emulator.mem_map(self.code_start, SANDBOX_CODE_SIZE * len(actors))
            emulator.mem_map(self.data_start, self.data_end - self.data_start)

            # write machine code to be emulated to memory
            emulator.mem_write(self.code_start, code)

            # set up callbacks
            emulator.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.trace_mem_access, self)
            emulator.hook_add(UC_HOOK_MEM_UNMAPPED, self.trace_mem_access, self)
            emulator.hook_add(UC_HOOK_CODE, self.instruction_hook, self)

            self.emulator = emulator

        except UcError as e:
            self.LOG.error("[UnicornModel:load_test_case] %s" % e)

        # set the fault handler address
        fh_id = self.target_desc.macro_specs["fault_handler"].type_
        for symbol in test_case.symbol_table:
            if symbol.type_ == fh_id:
                assert symbol.aid == 0, "Fault handler must be in the main actor"
                self.fault_handler_addr = symbol.offset + self.code_start
                break
        else:
            self.fault_handler_addr = self.exit_addr

        # load the test case into the macro interpreter
        self.macro_interpreter.load_test_case(test_case)

    def _execute_test_case(self, inputs: List[Input], nesting: int):
        """
        Execute the test case with the given inputs.

        The execution algorithm is as follows:
            - Load the inputs into registers and memory
            - Start emulation at self.code_start
            - For each instruction, call the tracers and emulate speculation according to
               the contract (implemented by UnicornTracer and by subclasses)
            - When a fault is triggered:
                a. If the fault ID is in self.handled_faults, jump to self.exit_addr
                a. Otherwise, throw an error
            - When a SWITCH macro is encountered, switch the active actor and jump to
               the corresponding function address
            - When self.exit_addr is reached:
                a. If self.is_speculating, rollback to the last checkpoint
                b. Otherwise, terminate execution
        """
        assert self.tracer
        self.nesting = nesting

        contract_traces: List[CTrace] = []
        execution_traces: List[ExecutionTrace] = []
        taints = []
        self.local_coverage = \
            defaultdict(int) if CONF.coverage_type == "model_instructions" else None

        for index, input_ in enumerate(inputs):
            self.LOG.dbg_model_header(index)

            self._load_input(input_)
            self.reset_model()
            start_address = self.code_start
            while True:
                self.pending_fault_id = 0

                # make sure that the actor is synchronized with the current address
                aid = (start_address - self.code_start) // SANDBOX_CODE_SIZE
                self.current_actor = self.test_case.get_actor_by_id(aid)

                # check if we're re-entering into the exit address
                if not self.in_speculation and self.exit_reached(start_address):
                    break

                # check if we've rolled back to the fault handler; if so, rollback again as
                # it indicates that rollback was supposed to terminate speculation
                if self.in_speculation and start_address == self.fault_handler_addr:
                    start_address = self.rollback()
                    continue

                # execute the test case
                try:
                    self.emulator.emu_start(
                        start_address, self.code_end, timeout=10 * UC_SECOND_SCALE)
                except UcError as e:
                    # the type annotation below is ignored because some
                    # of the packaged versions of Unicorn do not have
                    # complete type annotations
                    self.pending_fault_id = int(e.errno)  # type: ignore

                # handle faults
                if self.pending_fault_id:
                    if not self.previous_context:
                        self.LOG.error("Fault triggered without a previous context")

                    # workaround for a Unicorn bug: after catching an exception
                    # we need to restore some pre-exception context. otherwise,
                    # the emulator becomes corrupted
                    self.emulator.context_restore(self.previous_context)
                    # another workaround, specifically for flags
                    self.emulator.reg_write(self.flags_id, self.emulator.reg_read(self.flags_id))

                    start_address = self.handle_fault(self.pending_fault_id)
                    self.pending_fault_id = 0
                    if start_address and start_address != self.exit_addr:
                        continue

                # if we use one of the speculative contracts, we might have some residual simulation
                # that did not reach the spec. window by the end of simulation. Those need
                # to be rolled back
                if self.in_speculation:
                    start_address = self.rollback()
                    continue

                # otherwise, we're done with this execution
                break

            # Special Case: Execution in mismatch_check_mode
            # Instead of the contract trace, store the values of registers after execution
            if self.mismatch_check_mode:
                register_list = self.uc_target_desc.registers
                registers = register_list[:-2]  # exclude RSP and EFLAGS
                reg_values = [int(self.emulator.reg_read(reg)) for reg in registers]  # type: ignore
                self.tracer.trace = reg_values

            # store the results
            contract_traces.append(self.tracer.produce_trace(self))
            execution_traces.append(self.tracer.get_execution_trace())
            taints.append(self.taint_tracker.get_taint())

        # update coverage
        if self.local_coverage is not None:
            for inst_name in self.local_coverage.keys():
                self.instruction_coverage[inst_name] += 1

        return contract_traces, taints

    def exit_reached(self, address) -> bool:
        return address == self.exit_addr or \
            (self.current_actor.id_ == 0 and address > self.exit_addr)

    def handle_fault(self, errno: int) -> int:
        self.LOG.dbg_model_exception(errno, self.err_to_str(errno))

        # when a fault is triggered, CPU stores the PC and the fault type
        # on stack - this has to be mirrored at the contract level
        self.tracer.observe_mem_access(UC_MEM_WRITE, self.stack_base, 8, errno, self)

        next_addr = self.speculate_fault(errno)
        if next_addr:
            return next_addr

        # if we're speculating, rollback regardless of the fault type
        if self.in_speculation:
            return 0

        # error on nested non-speculative faults
        if self.had_arch_fault:
            self.print_state()
            self.LOG.error(f"Nested fault {errno} {self.err_to_str(errno)}", print_last_tb=True)
        self.had_arch_fault = True

        # an expected fault - terminate execution
        if errno in self.handled_faults:
            return self.fault_handler_addr

        # unexpected fault - throw an error
        self.print_state()
        self.LOG.error(f"Unexpected exception {errno} {self.err_to_str(errno)}", print_last_tb=True)

    @staticmethod
    def instruction_hook(emulator: Uc, address: int, size: int, model) -> None:
        # terminate execution if the exit instruction is reached
        if model.exit_reached(address):
            emulator.emu_stop()
            return

        # preserve context and trace the instruction
        model.previous_context = model.emulator.context_save()
        aid = model.current_actor.id_
        section_start = model.code_start + SANDBOX_CODE_SIZE * aid
        model.current_instruction = model.test_case.address_map[aid][address - section_start]
        model.trace_instruction(emulator, address, size, model)

        # collect coverage
        if model.local_coverage is not None:
            if not model.current_instruction.is_instrumentation:
                model.local_coverage[model.current_instruction.get_brief()] += 1

        # if the current instruction is a macro, interpret it
        if model.current_instruction.name == "macro":
            model.macro_interpreter.interpret(model.current_instruction, address)

        # emulate invalid opcode for certain instructions when executed in VM guest mode
        if model.current_actor.mode == ActorMode.GUEST:
            model.emulate_vm_execution(address)
        elif model.current_actor.privilege_level == ActorPL.USER:
            model.emulate_userspace_execution(address)

    @staticmethod
    def trace_instruction(emulator, address, size, model) -> None:
        model.taint_tracker.start_instruction(model.current_instruction)
        model.tracer.observe_instruction(address, size, model)
        # speculate_instruction is empty for seq, nonempty in subclasses
        model.speculate_instruction(emulator, address, size, model)
        model.post_execution_patch()

    @staticmethod
    def trace_mem_access(emulator, access, address: int, size, value, model):
        model.taint_tracker.track_memory_access(address, size, access == UC_MEM_WRITE)
        model.tracer.observe_mem_access(access, address, size, value, model)
        # speculate_mem_access is empty for seq, nonempty in subclasses
        model.speculate_mem_access(emulator, access, address, size, value, model)

        # emulate page faults
        if model.current_actor.privilege_level == ActorPL.USER:
            target_actor = (address - model.sandbox_base) // SANDBOX_DATA_SIZE
            if target_actor != model.current_actor.id_:
                model.pending_fault_id = 12
                model.emulator.emu_stop()

    @staticmethod
    def err_to_str(errno: int) -> str:
        if errno == uc.UC_ERR_OK:
            return "OK (UC_ERR_OK)"
        elif errno == uc.UC_ERR_NOMEM:
            return "No memory available or memory not present (UC_ERR_NOMEM)"
        elif errno == uc.UC_ERR_ARCH:
            return "Invalid/unsupported architecture (UC_ERR_ARCH)"
        elif errno == uc.UC_ERR_HANDLE:
            return "Invalid handle (UC_ERR_HANDLE)"
        elif errno == uc.UC_ERR_MODE:
            return "Invalid mode (UC_ERR_MODE)"
        elif errno == uc.UC_ERR_VERSION:
            return "Different API version between core & binding (UC_ERR_VERSION)"
        elif errno == uc.UC_ERR_READ_UNMAPPED:
            return "Invalid memory read (UC_ERR_READ_UNMAPPED)"
        elif errno == uc.UC_ERR_WRITE_UNMAPPED:
            return "Invalid memory write (UC_ERR_WRITE_UNMAPPED)"
        elif errno == uc.UC_ERR_FETCH_UNMAPPED:
            return "Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)"
        elif errno == uc.UC_ERR_HOOK:
            return "Invalid hook type (UC_ERR_HOOK)"
        elif errno == uc.UC_ERR_INSN_INVALID:
            return "Invalid instruction (UC_ERR_INSN_INVALID)"
        elif errno == uc.UC_ERR_MAP:
            return "Invalid memory mapping (UC_ERR_MAP)"
        elif errno == uc.UC_ERR_WRITE_PROT:
            return "Write to write-protected memory (UC_ERR_WRITE_PROT)"
        elif errno == uc.UC_ERR_READ_PROT:
            return "Read from non-readable memory (UC_ERR_READ_PROT)"
        elif errno == uc.UC_ERR_FETCH_PROT:
            return "Fetch from non-executable memory (UC_ERR_FETCH_PROT)"
        elif errno == uc.UC_ERR_ARG:
            return "Invalid argument (UC_ERR_ARG)"
        elif errno == uc.UC_ERR_READ_UNALIGNED:
            return "Read from unaligned memory (UC_ERR_READ_UNALIGNED)"
        elif errno == uc.UC_ERR_WRITE_UNALIGNED:
            return "Write to unaligned memory (UC_ERR_WRITE_UNALIGNED)"
        elif errno == uc.UC_ERR_FETCH_UNALIGNED:
            return "Fetch from unaligned memory (UC_ERR_FETCH_UNALIGNED)"
        elif errno == uc.UC_ERR_RESOURCE:
            return "Insufficient resource (UC_ERR_RESOURCE)"
        elif errno == uc.UC_ERR_EXCEPTION:
            return "Misc. CPU exception (UC_ERR_EXCEPTION)"
        else:
            return "Unknown error code"


class UnicornSpec(UnicornSeq):
    """
    Intermediary class for all speculative contracts.
    """

    def __init__(self, *args):
        self.checkpoints = []
        self.store_logs = []
        self.latest_rollback_address = 0
        super().__init__(*args)

    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, model: UnicornSpec) -> None:
        # when in speculation, log all changes to memory
        if access == UC_MEM_WRITE and model.store_logs:
            model.store_logs[-1].append((address, emulator.mem_read(address, 8)))

        UnicornSeq.trace_mem_access(emulator, access, address, size, value, model)

    @staticmethod
    def trace_instruction(emulator, address, size, model: UnicornSpec) -> None:
        if model.in_speculation:
            model.speculation_window += 1
            # rollback on a serializing instruction
            if model.current_instruction.name in model.uc_target_desc.barriers:
                emulator.emu_stop()

            # and on expired speculation window
            if model.speculation_window > CONF.model_max_spec_window:
                emulator.emu_stop()

        UnicornSeq.trace_instruction(emulator, address, size, model)

    def checkpoint(self, emulator: Uc, next_instruction):
        flags = emulator.reg_read(self.uc_target_desc.flags_register)
        context = emulator.context_save()
        spec_window = self.speculation_window
        self.checkpoints.append((context, next_instruction, flags, spec_window))
        self.store_logs.append([])
        self.in_speculation = True
        self.taint_tracker.checkpoint()

    def rollback(self) -> int:
        # restore register values
        state, next_instr, flags, spec_window = self.checkpoints.pop()
        if not self.checkpoints:
            self.in_speculation = False

        self.LOG.dbg_model_rollback(next_instr, self.code_start)
        self.latest_rollback_address = next_instr

        # restore the speculation state
        self.emulator.context_restore(state)
        self.speculation_window = spec_window

        # rollback memory changes
        mem_changes = self.store_logs.pop()
        while mem_changes:
            addr, val = mem_changes.pop()
            self.emulator.mem_write(addr, bytes(val))

        # restore the flags last, to avoid corruption by other operations
        self.emulator.reg_write(self.uc_target_desc.flags_register, flags)

        # restore the taint tracking
        self.taint_tracker.rollback()

        # restart without misprediction
        return next_instr

    def reset_model(self):
        super().reset_model()
        self.latest_rollback_address = 0


# ==================================================================================================
# Implementation of Tainting
# ==================================================================================================
class DummyTaintTracker(TaintTrackerInterface):

    def get_taint(self) -> InputTaint:
        return InputTaint()


class BaseTaintTracker(TaintTrackerInterface):
    """
    Base class for taint tracking that implements ISA-agnostic tracking.

    The algorithm is as follows:
    - start_instruction: get the static source and destination operands of the instruction
    - track_memory_access: get dynamic source and destination memory addresses
    - taint_*: collect the labels (register names or mem. addresses) that are
      exposed by this instruction in the contract trace
    - finalize_instruction:
      1. propagate the dependencies of the source operands to the destination operands
      2. update the list of tainted labels with the dependencies of the labels
         collected by taint_* methods
    - get_taint: produce an InputTaint object based on the all tainted labels
    """
    strict_undefined: bool = True
    _instruction: Optional[Instruction] = None
    sandbox_base: int = 0
    checkpoints: List[Tuple[Dict[str, Set[str]], Dict[str, Set[str]], Dict[str, Set[str]]]]

    src_regs: Set[str]
    dest_regs: Set[str]
    reg_deps: Dict[str, Set[str]]

    src_flags: Set[str]
    dest_flags: Set[str]
    flag_deps: Dict[str, Set[str]]

    src_mems: Set[str]
    dest_mems: Set[str]
    mem_deps: Dict[str, Set[str]]

    mem_address_regs: Set[str]

    tainted_labels: Set[str]
    pending_taint: Set[str]

    # ISA-specific fields
    uc_target_desc: UnicornTargetDesc
    target_desc: TargetDesc
    _registers: List[int]
    _simd_registers: List[int]

    def __init__(self, initial_observations, sandbox_base=0):
        self.sandbox_base = sandbox_base
        self.reset(initial_observations)
        assert CONF.instruction_set == "x86-64", "Taint tracking is only supported for x86_64"

    # ----------------------------------------------------------------------------------------------
    # State management methods
    def reset(self, initial_observations) -> None:
        """ Reset the taint tracker state """
        # print("=============")
        self.initial_observations = initial_observations
        self.flag_deps = {}
        self.reg_deps = {}
        self.mem_deps = {}
        self.tainted_labels = set(self.initial_observations)
        self.checkpoints = []

    def checkpoint(self) -> None:
        """ Save the current state of the taint tracker """
        if self._instruction:
            self._finalize_instruction()
        self.checkpoints.append((copy.deepcopy(self.flag_deps), copy.deepcopy(self.reg_deps),
                                 copy.deepcopy(self.mem_deps)))

    def rollback(self) -> None:
        """
        Restore the state of the taint tracker from the top-most checkpoint

        :raises AssertionError: if there are no more checkpoints
        """
        assert self.checkpoints, "There are no more checkpoints"
        if self._instruction:
            self._finalize_instruction()
        t = self.checkpoints.pop()
        self.flag_deps = copy.deepcopy(t[0])
        self.reg_deps = copy.deepcopy(t[1])
        self.mem_deps = copy.deepcopy(t[2])

    # ----------------------------------------------------------------------------------------------
    # Dependency propagation methods
    def start_instruction(self, instruction: Instruction) -> None:
        """
        Parse instruction and record its static source and destination operands.
        Static means the operands that we can identify without executing the instruction.
        The remaining dynamic operands are collected by track_* methods.

        :param instruction: the instruction to be parsed
        """
        # make sure that the previous instruction is finalized
        if self._instruction:
            self._finalize_instruction()

        # restart the tracking
        # print("-----------------------------------")
        self._instruction = instruction
        self.src_regs = set()
        self.src_flags = set()
        self.src_mems = set()
        self.dest_regs = set()
        self.dest_flags = set()
        self.dest_mems = set()
        self.pending_taint = set()
        self.mem_address_regs = set()

        # Parse the instruction operands
        for op in instruction.get_all_operands():
            if isinstance(op, RegisterOperand):
                # Registers: normalize the names and record them
                value = self.target_desc.reg_normalized[op.value]
                if op.src:
                    self.src_regs.add(value)
                if op.dest:
                    self.dest_regs.add(value)
            elif isinstance(op, FlagsOperand):
                # Flags: record the read and write flags; optionally, record the undefined flags
                self.src_flags = set(op.get_read_flags())
                if self.strict_undefined:
                    self.src_flags.update(op.get_undef_flags())
                self.dest_flags = set(op.get_write_flags())
            elif isinstance(op, MemoryOperand):
                # Memory: record the names of the address registers
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in self.target_desc.reg_normalized:
                        self.mem_address_regs.add(self.target_desc.reg_normalized[sub_op])
            elif isinstance(op, AgenOperand):
                # LEA operand: record the names of the address registers
                # Note that we record the names in self.src_regs, because it's not a memory access
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in self.target_desc.reg_normalized:
                        self.src_regs.add(self.target_desc.reg_normalized[sub_op])

        flag_op = instruction.get_flags_operand()
        if flag_op:
            for flag in flag_op.get_overwrite_flags():
                self.flag_deps[flag] = set()

    def track_memory_access(self, address: int, size: int, is_write: bool) -> None:
        """
        Add the address of the memory access to the list of current instruction dependencies

        :param address: the address of the memory access
        :param size: the size of the memory access
        :param is_write: True if the memory access is a write (store), False if it's a read (load)
        """
        # mask the address - we taint at the granularity of 8 bytes
        address -= self.sandbox_base
        masked_start_addr = address & 0xffff_ffff_ffff_fff8
        end_addr = address + (size - 1)
        masked_end_addr = end_addr & 0xffff_ffff_ffff_fff8

        # add all addresses to tracking
        track_list = self.dest_mems if is_write else self.src_mems
        for i in range(masked_start_addr, masked_end_addr + 1, 8):
            track_list.add(hex(i))

    def _finalize_instruction(self) -> None:
        """
        Propagate dependencies from source operands to destinations

        :raises AssertionError: if called before start_instruction
        """
        inst = self._instruction
        assert inst, "_finalize_instruction called before start_instruction"
        inst_name = inst.name.lower()

        # Get dependencies of the source operands
        src_dependencies = set()
        for reg in self.src_regs:
            src_dependencies.update(self.reg_deps.get(reg, {reg}))
        for flag in self.src_flags:
            src_dependencies.update(self.flag_deps.get(flag, {flag}))
        for addr in self.src_mems:
            src_dependencies.update(self.mem_deps.get(addr, {addr}))

        # Propagate source dependencies to destination operands
        for reg in self.dest_regs:
            if reg in self.reg_deps:
                self.reg_deps[reg].update(src_dependencies)
            else:
                self.reg_deps[reg] = copy.copy(src_dependencies)
                self.reg_deps[reg].add(reg)
        for flg in self.dest_flags:
            if flg in self.flag_deps:
                self.flag_deps[flg].update(src_dependencies)
            else:
                self.flag_deps[flg] = copy.copy(src_dependencies)
                self.flag_deps[flg].add(flg)
        for mem in self.dest_mems:
            if mem in self.mem_deps:
                self.mem_deps[mem].update(src_dependencies)
            else:
                self.mem_deps[mem] = copy.copy(src_dependencies)
                self.mem_deps[mem].add(mem)
        # print(self.dest_regs, self.src_regs)
        # print(self.dest_flags, self.src_flags)
        # print(self.dest_mems, self.src_mems)
        # print(self.reg_deps)
        # print(self.flag_deps)
        # print(self.mem_deps)

        # Workaround for REP instructions with implicit RCX dependency
        if "rep" in inst_name and "C" in self.src_regs and self.pending_taint:
            self.pending_taint.add('C')

        # Update taints
        # print(self.pending_taint)
        for label in self.pending_taint:
            if label.startswith("0x"):
                self.tainted_labels.update(self.mem_deps.get(label, {label}))
            else:
                self.tainted_labels.update(self.reg_deps.get(label, {label}))
        # print(self.tainted_labels)

        # Identify if the instruction overrides previous dependencies
        # (so far we consider only two such case: MOV and LEA)
        # FIXME: this is an x86-specific implementation and it should be moved to the x86 model
        override: bool = False
        if (inst_name.startswith("mov") or inst_name == "lea") and len(self.dest_regs) == 1:
            reg = inst.get_reg_operands()[0].value
            if self.target_desc.register_sizes.get(reg, 0) == 64:
                override = True

        # If the instruction overrides previous dependencies, remove them
        if override:
            assert len(self.dest_regs) == 1, "MOV instruction with multiple destinations"
            reg = self.dest_regs.pop()
            for dep in list(self.reg_deps[reg]):
                if dep not in src_dependencies:
                    self.reg_deps[reg].remove(dep)

        # Reset the instruction
        self._instruction = None

    # ----------------------------------------------------------------------------------------------
    # Tainting callbacks
    def taint_pc(self) -> None:
        """
        Taint the RIP register.

        This method is meant to be called by the tracer when it exposes a PC.
        """
        if self._instruction and self._instruction.control_flow:
            self.pending_taint.add("RIP")

    def taint_memory_access_address(self) -> None:
        """
        Taint the memory addresses accessed by the instruction.

        This method is meant to be called by the tracer when it exposes a memory address.
        """
        for reg in self.mem_address_regs:
            self.pending_taint.add(reg)

    def taint_loaded_value(self) -> None:
        """
        Taint the value loaded from memory.

        This method is meant to be called by the tracer when it exposes a loaded value.
        """
        for addr in self.src_mems:
            self.pending_taint.add(addr)

    # ----------------------------------------------------------------------------------------------
    # Taint output methods
    def get_taint(self) -> InputTaint:
        """
        Produce an InputTaint object based on the taints collected during
        the model execution.

        :return: an InputTaint object
        """

        if self._instruction:
            self._finalize_instruction()

        n_actors = len(CONF._actors)
        taint = InputTaint(n_actors)
        tainted_positions = []
        register_start = taint[0].dtype.fields['gpr'][1] // 8
        simd_start = taint[0].dtype.fields['simd'][1] // 8

        for label in self.tainted_labels:
            if label.startswith('0x'):
                # memory address
                # we taint the 64-bits block that contains the address
                input_offset = (int(label, 16)) // 8
                tainted_positions.append(input_offset)
            else:
                # uncomment if to create violations of vspec-ops-div
                # if not label == 'D':
                reg = self.uc_target_desc.reg_decode[label]
                if reg in self._registers:
                    input_offset = register_start + \
                        self._registers.index(self.uc_target_desc.reg_decode[label])
                    tainted_positions.append(input_offset)
                elif reg in self._simd_registers:
                    input_offset = simd_start + \
                        self._simd_registers.index(self.uc_target_desc.reg_decode[label]) * 2
                    tainted_positions.append(input_offset)
                    tainted_positions.append(input_offset + 1)
                # else:
                # print(f"Register {label} is not tracked")

        tainted_positions = list(dict.fromkeys(tainted_positions))
        tainted_positions.sort()

        for actor_id in range(0, n_actors):
            # create a view of the taint array as a 64-bit array
            # note that it *does not* copy the taint, only casts it into a different type
            linear_view = taint.linear_view(actor_id)
            actor_offset = actor_id * 0x4000 // 8

            for i in range(actor_offset, actor_offset + linear_view.size):
                if i in tainted_positions:
                    linear_view[i - actor_offset] = True

        return taint
