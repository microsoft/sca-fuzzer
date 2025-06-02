"""
File: Abstract interface to be implemented by all speculators.
      For an implementation of concrete speculators, see speculators_*.py files.

      A speculator is a component that modifies the execution process of a test case when it
      runs on the contract model (e.g., it can emulate misprediction of branches).
      As such, speculators implement execution clauses of different contracts.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, List, Final, Tuple

from unicorn import UC_MEM_WRITE

from ..config import CONF

if TYPE_CHECKING:
    from unicorn import Uc
    from .model import UnicornModel
    from .taint_tracker import UnicornTaintTracker
    from ..target_desc import TargetDesc, UnicornTargetDesc

_UnicornContext = object
_InstrAddress = int
_Flags = int
_SpecWindow = int
_Checkpoint = Tuple[_UnicornContext, _InstrAddress, _Flags, _SpecWindow]

_MemoryAddress = int
_MemoryValue = bytes
_StoreLogEntry = Tuple[_MemoryAddress, _MemoryValue]


class UnicornSpeculator(ABC):
    """
    Interface definition that must be implemented by all speculators.
    as well as implementation of common functionality.
    """

    is_sequential: bool = False
    """ Flag indicating if the speculator does *not* actually implement speculation. """

    # checkpointing
    _checkpoints: List[_Checkpoint]
    _store_logs: List[List[_StoreLogEntry]]

    # speculation control
    _max_nesting: int = 0
    _speculation_window: int = 0
    _max_spec_window: int = 0
    _in_speculation: bool = False

    # connections to other modules
    _emulator: Uc
    _model: Final[UnicornModel]
    _target_desc: Final[TargetDesc]
    _uc_target_desc: Final[UnicornTargetDesc]
    _taint_tracker: UnicornTaintTracker

    def __init__(self, target_desc: TargetDesc, model: UnicornModel,
                 taint_tracker: UnicornTaintTracker) -> None:
        super().__init__()
        self._model = model
        self._taint_tracker = taint_tracker
        self._target_desc = target_desc
        self._uc_target_desc = target_desc.uc_target_desc
        self.reset()

    # ----------------------------------------------------------------------------------------------
    # Public Interface
    def in_speculation(self) -> bool:
        """ Return whether the model is currently in speculation. """
        return self._in_speculation

    def set_max_nesting(self, max_nesting: int) -> None:
        """ Set the maximum nesting level of the model. """
        self._max_nesting = max_nesting

    def nesting(self) -> int:
        """ Return the current nesting level of the model. """
        return len(self._checkpoints)

    def reset(self) -> None:
        """ Reset the speculator to its initial state. """
        self._emulator = self._model.emulator  # refresh the emulator reference
        self._checkpoints = []
        self._store_logs = []
        self._in_speculation = False
        self._speculation_window = 0
        self._max_spec_window = CONF.model_max_spec_window

    def rollback(self) -> int:
        """ Rollback the model and its service modules to the last checkpoint. """
        # restore register values
        state, next_instr, flags, spec_window = self._checkpoints.pop()
        if not self._checkpoints:
            self._in_speculation = False

        # restore the speculation state
        self._emulator.context_restore(state)
        self._speculation_window = spec_window

        # rollback memory changes
        mem_changes = self._store_logs.pop()
        while mem_changes:
            addr, val = mem_changes.pop()
            self._emulator.mem_write(addr, val)

        # restore the flags last, to avoid corruption by other operations
        self._emulator.reg_write(self._uc_target_desc.flags_register, flags)

        # restore the taint tracking
        self._taint_tracker.rollback()

        # restart without misprediction
        return next_instr

    def handle_instruction(self, address: int, size: int) -> None:
        """
        Hook function executed by the speculator on every instruction.
        Depending on the speculator (i.e., the subclass), it may implement different speculation
        mechanisms for some instructions (e.g., branch mispredictions).
        :param address: address of the current instruction
        :param size: size of the current instruction
        :return: None
        """

        if self._in_speculation:
            self._speculation_window += 1
            # rollback on a serializing instruction
            if self._model.state.current_instruction.name in self._uc_target_desc.barriers:
                self._emulator.emu_stop()

            # and on expired speculation window
            if self._speculation_window > self._max_spec_window:
                self._emulator.emu_stop()

        self._speculate_instruction(address, size)

    def handle_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        """
        Hook function executed by the speculator on every memory access.
        Depending on the speculator (i.e., the subclass), it may implement different speculation
        mechanisms for some memory accesses (e.g., store-to-load forwarding).
        :param access: type of the memory access (UC_MEM_READ or UC_MEM_WRITE)
        :param address: address of the memory access
        :param size: size of the memory access
        :param value: value of the memory access
        :return: None
        """
        # when in speculation, log all changes to memory
        if access == UC_MEM_WRITE and self._store_logs:
            prev_value = bytes(self._emulator.mem_read(address, 8))
            self._store_logs[-1].append((address, prev_value))

        self._speculate_mem_access(access, address, size, value)

    def handle_fault(self, errno: int) -> int:
        """
        Hook function executed by the speculator on every fault.
        Depending on the speculator (i.e., the subclass), it may implement different speculation
        mechanisms for some faults (e.g., Meltdown).
        :param errno: error number of the fault
        :return: address of the next speculative instruction; 0 if no speculation
        """
        return self._speculate_fault(errno)

    # ----------------------------------------------------------------------------------------------
    # Private Methods
    def _checkpoint(self, next_instruction_addr: int) -> None:
        """ Store a checkpoint for the current state of the model and its service modules. """
        flags: int = self._emulator.reg_read(self._uc_target_desc.flags_register)  # type: ignore
        context = self._emulator.context_save()
        spec_window = self._speculation_window
        self._checkpoints.append((context, next_instruction_addr, flags, spec_window))
        self._store_logs.append([])
        self._in_speculation = True
        self._taint_tracker.checkpoint()

    def _max_nesting_reached(self) -> bool:
        """ Check if the maximum nesting level has been reached. """
        return len(self._checkpoints) >= self._max_nesting

    def _speculate_instruction(self, address: int, size: int) -> None:
        pass

    def _speculate_mem_access(self, access: int, address: int, size: int, value: int) -> None:
        pass

    def _speculate_fault(self, _: int) -> int:
        """
        Implement speculation upon a fault. The default implementation does not speculate.
        :param errno: ID of the fault
        :return: the address of the first speculative instruction
                 OR zero if not speculation is triggered
        """
        return 0
