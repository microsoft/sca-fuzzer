"""
File: Collection of tracers for the Unicorn backend to the contract model.

      A tracer is a component that record certain events during the execution of a
      test case on the contract model. As such, the tracers implement
      observation clauses of different contracts.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC

from typing import List, TYPE_CHECKING
from unicorn import UC_MEM_READ
from ..traces import CTrace, CTraceEntry

if TYPE_CHECKING:
    from .model import UnicornModel
    from .taint_tracker import UnicornTaintTracker
    from ..target_desc import TargetDesc, UnicornTargetDesc


# ==================================================================================================
# Abstract Tracer Interface
# ==================================================================================================
class UnicornTracer(ABC):
    """
    Interface definition that must be implemented by all tracers
    as well as implementation of common functionality.
    """
    trace: List[CTraceEntry]
    enable_tracing: bool = False
    _model: UnicornModel
    _taint_tracker: UnicornTaintTracker
    _uc_target_desc: UnicornTargetDesc

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__()
        self.trace = []
        self._model = model
        self._taint_tracker = taint_tracker
        self._uc_target_desc = target_desc.uc_target_desc

    # ==============================================================================================
    # Public Interface
    def reset(self) -> None:
        """ Initialize/reset the state of the tracer """
        self.trace = []
        self.enable_tracing = False

    def get_trace(self) -> CTrace:
        """ Return the collected trace in a form of a CTrace object """

        # make the trace reproducible by normalizing the addresses
        normalized_trace: List[CTraceEntry] = []
        layout = self._model.layout
        for org_entry in self.trace:
            if org_entry.type_ == "pc":
                entry = CTraceEntry("pc", layout.code_addr_to_offset(org_entry.value))
            elif org_entry.type_ == "mem":
                entry = CTraceEntry("mem", layout.data_addr_to_offset(org_entry.value))
            else:
                entry = CTraceEntry(org_entry.type_, org_entry.value)
            normalized_trace.append(entry)
        return CTrace(normalized_trace)

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """
        Trace a memory access.
        The value may or may not be recorded on the trace, depending on the tracer implementation.
        :param access: type of access (UC_MEM_READ, UC_MEM_WRITE)
        :param address: address of the memory access
        :param size: size of the memory access
        :param value: value read or written
        """

    def observe_instruction(self, pc: int, size: int) -> None:
        """
        Trace an instruction.
        The value may or may not be recorded on the trace, depending on the tracer implementation.
        :param pc: program counter of the instruction
        :param size: size of the instruction
        """

    # ==============================================================================================
    # Private Methods

    def _add_mem_address_to_trace(self, address: int) -> None:
        """ Record the given memory address, if tracing is enabled """
        if self.enable_tracing:
            self.trace.append(CTraceEntry("mem", address))
            self._taint_tracker.taint("mem")

    def _add_pc_to_trace(self, address: int) -> None:
        """ Record the given program counter, if tracing is enabled """
        if self.enable_tracing:
            self.trace.append(CTraceEntry("pc", address))
            self._taint_tracker.taint("pc")

    def _add_dependencies_to_trace(self, dependency_hash: int) -> None:
        """ Record the given dependency hash, if tracing is enabled """
        if self.enable_tracing:
            self.trace.append(CTraceEntry("val", dependency_hash))
            self._taint_tracker.taint("mem")

    def _add_value_to_trace(self, val: int) -> None:
        """ Record the given untyped value, if tracing is enabled """
        if self.enable_tracing:
            self.trace.append(CTraceEntry("val", val))


# ==================================================================================================
# Concrete Tracers
# ==================================================================================================


class NoneTracer(UnicornTracer):
    """
    Tracer that does not record any information.
    Used as a placeholder when a test case has to be executed on the model without tracing.
    """

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        pass

    def observe_instruction(self, pc: int, size: int) -> None:
        pass

    def get_trace(self) -> CTrace:
        return CTrace.empty_trace()


class PCTracer(UnicornTracer):
    """
    Tracer that records the program counter of all instructions executed on the model.

    E.g., if the following program is executed:
        0x0: mov eax, 0x1
        0x4: mov ebx, 0x2
        0x8: mov ecx, 0x3

    The output trace will be [0x0, 0x4, 0x8]
    """

    def observe_instruction(self, pc: int, size: int) -> None:
        self._add_pc_to_trace(pc)
        super().observe_instruction(pc, size)


class MemoryTracer(UnicornTracer):
    """
    Tracer that records the memory addresses accessed by the model.

    E.g., if the following program is executed:
        0x0: mov eax, [0x100]
        0x4: mov ebx, [0x200]
        0x8: mov ecx, [0x300]

    The output trace will be [0x100, 0x200, 0x300]
    """

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        self._add_mem_address_to_trace(address)
        super().observe_mem_access(access, address, size, value)


class L1DTracer(MemoryTracer):
    """
    The same as MemoryTracer, but the traces will be marked as L1D traces; that is, when
    such traces are printed, they will be printed as L1D maps.
    """

    def get_trace(self) -> CTrace:
        trace = super().get_trace()
        trace.set_printed_as_l1d(True)
        return trace


class CTTracer(PCTracer):
    """
    Observe address of the memory access and of the program counter.
    """

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        self._add_mem_address_to_trace(address)
        super().observe_mem_access(access, address, size, value)


class TruncatedCTTracer(UnicornTracer):
    """
    Observe address of the memory access and of the program counter at cache line granularity.
    """

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        self._add_mem_address_to_trace((address >> 6) << 6)
        super().observe_mem_access(access, address, size, value)

    def observe_instruction(self, pc: int, size: int) -> None:
        self._add_pc_to_trace((pc >> 6) << 6)
        super().observe_instruction(pc, size)


class TruncatedCTWithOverflowsTracer(UnicornTracer):
    """
    Observe address of the memory access and of the program counter at cache line granularity +
    observe cache line overflows.
    """

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        self._add_mem_address_to_trace((address >> 6) << 6)
        if (address + size) % 64 != (address % 64):  # add overflows to the trace
            self._add_mem_address_to_trace(((address + size) >> 6) << 6)
        return super().observe_mem_access(access, address, size, value)

    def observe_instruction(self, pc: int, size: int) -> None:
        self._add_pc_to_trace((pc >> 6) << 6)
        if (pc + size) // 64 != (pc // 64):  # add overflows to the trace
            self._add_pc_to_trace(((pc + size) >> 6) << 6)
        return super().observe_instruction(pc, size)


class CTNonSpecStoreTracer(PCTracer):
    """
    Observe address of memory access only if not in speculation or it is a read.
    """

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        # trace all non-spec mem accesses and speculative loads
        if not self._model.speculator.in_speculation() or access == UC_MEM_READ:
            self._add_mem_address_to_trace(address)
        super().observe_mem_access(access, address, size, value)


class ArchTracer(CTTracer):
    """
    Similar to CTTracer, with additional exposure of:
     - Register state at the first memory access
     - The values loaded from memory

    The main use case of this tracer is to model the guarantees provided by secure speculation
    mechanisms, such as Speculative Taint Tracking (STT).
    """
    _started: bool = False

    def reset(self) -> None:
        super().reset()
        self._started = False

    def observe_instruction(self, pc: int, size: int) -> None:
        # The first instruction must exposes all register values
        if not self._started:
            self._started = True
            for reg in self._uc_target_desc.usable_registers[:-1]:  # exclude stack pointer
                val = self._model.emulator.reg_read(reg)
                assert isinstance(val, int), f"Expected int, got {type(val)}"
                self.trace.append(CTraceEntry("val", val))

        return super().observe_instruction(pc, size)

    def observe_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        if access == UC_MEM_READ:
            val = int.from_bytes(self._model.emulator.mem_read(address, size), byteorder='little')
            self._add_value_to_trace(val)
            self._taint_tracker.taint("ld_val")
        super().observe_mem_access(access, address, size, value)


# ==================================================================================================
# Actor-based Tracers
# ==================================================================================================
# class ActorNITracer(CTTracer):
#     """
#     The model that exposes all data that belongs to the actors with `observer` flag set
#     + sequential traces for the non-observer actors
#     """
#     observer_actor_ids: List[int]

#     def __init__(self, target_desc: TargetDesc, model: UnicornModel,
#                  taint_tracker: UnicornTaintTracker) -> None:
#         super().__init__(target_desc, model, taint_tracker)
#         n_observers = len([desc for desc in CONF.get_actors_conf().values() if desc['observer']])
#         if n_observers == len(CONF.get_actors_conf()):
#             raise ValueError("ActorNITracer requires at least 1 non-observer actor")
#         if n_observers == 0:
#             raise ValueError("ActorNITracer requires at least 1 observer actor")

#     def reset(self) -> None:
#         super().reset()

#         test_case = self._model.test_case
#         self.observer_actor_ids = [
#             actor.get_id() for actor in test_case.get_actors() if actor.observer
#         ]

#     def get_trace(self) -> CTrace:
#         self._add_observer_traces()
#         self._taint_tracker.taint_observers(self.observer_actor_ids)
#         return super().get_trace()

#     def _add_observer_traces(self, inputs: List[InputData], ctraces: List[CTrace]):
#         for input_id, input_ in enumerate(inputs):
#             fragment_hashes: List[CTraceEntry] = []
#             for actor_id in self.observer_actor_ids:
#                 input_fragment = input_[actor_id]
#                 data = input_fragment.tobytes()
#                 hash_ = xxhash.xxh64(data, seed=0).intdigest()
#                 fragment_hashes.append(CTraceEntry("val", hash_))
#             new_trace = ctraces[input_id].get_typed() + fragment_hashes
#             ctraces[input_id] = CTrace(new_trace)

#     def _taint_observers(self, taints: List[InputTaint]):
#         for taint in taints:
#             for actor_id in self.observer_actor_ids:
#                 # create a view of the taint array as a 64-bit array
#                 # note that it *does not* copy the taint, only casts it into a different type
#                 linear_view = taint.linear_view(actor_id)
#                 actor_offset = actor_id * 0x4000 // 8

#                 # taint the whole actor
#                 for i in range(actor_offset, actor_offset + linear_view.size):
#                     linear_view[i - actor_offset] = True
