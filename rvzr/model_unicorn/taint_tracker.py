"""
File: Taint tracking implementation for the Unicorn model

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import copy
import re
from typing import List, Optional, Set, Dict, TYPE_CHECKING, Literal, Final
from typing_extensions import assert_never

from ..tc_components.instruction import Instruction, RegisterOp, FlagsOp, \
    MemoryOp, AgenOp, ImmediateOp, LabelOp, CondOp
from ..tc_components.test_case_data import InputTaint
from ..target_desc import TargetDesc
from ..sandbox import SandboxLayout, DataArea
from ..config import CONF

if TYPE_CHECKING:
    from ..target_desc import UnicornTargetDesc
    from ..sandbox import BaseAddrTuple, DataAddr

TAINTED_VALUE_TYPE = Literal["pc", "mem", "ld_val"]
_ARCH_INITIAL_OBSERVATIONS_X86_64 = [
    "A", "B", "C", "D", "SI", "DI", "RSP", "CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF",
    "AC"
]
_ARCH_INITIAL_OBSERVATIONS_ARM64 = ["R0", "R1", "R2", "R3", "R4", "R5", "N", "Z", "C", "V"]


# ==================================================================================================
# Public Interface: Taint Tracker
# ==================================================================================================
class UnicornTaintTracker:
    """
    Tracking of the input data that impacts contract traces.

    The algorithm is as follows:
    - start_instruction: get the static source and destination operands of the instruction
    - track_memory_access: get dynamic source and destination memory addresses
    - taint: collect the labels (register names or mem. addresses) that are
      exposed by this instruction in the contract trace
    - finalize_instruction:
      1. propagate the dependencies of the source operands to the destination operands
      2. update the list of tainted labels with the dependencies of the labels
         collected by taint_* methods
    - get_taint: produce an InputTaint object based on the all tainted labels
    """
    _enable_tracking: bool = True
    _tracking_in_progress: bool = False

    _initial_observations: List[str]
    _data_start: Final[DataAddr]
    _uc_target_desc: Final[UnicornTargetDesc]
    _target_desc: Final[TargetDesc]

    _checkpoints: List[_Dependencies]
    _tainted_labels: Set[str]
    _pending_taint: Set[str]

    _instruction: Optional[_TrackedInstruction] = None
    _dependencies: _Dependencies

    def __init__(self, bases: BaseAddrTuple, target_desc: TargetDesc):
        assert CONF.instruction_set in ["x86-64", "arm64"], \
               "Taint tracking is only supported for x86_64 and arm64"

        self._data_start = bases[0]
        self._target_desc = target_desc
        self._uc_target_desc = target_desc.uc_target_desc

        # Certain types of contracts have predefined observations
        if CONF.contract_observation_clause in ('ctr', 'arch'):
            if CONF.instruction_set == "x86-64":
                self._initial_observations = _ARCH_INITIAL_OBSERVATIONS_X86_64
            elif CONF.instruction_set == "arm64":
                self._initial_observations = _ARCH_INITIAL_OBSERVATIONS_ARM64
        else:
            self._initial_observations = []

        self.reset()
        self._tracking_in_progress = False

    # ----------------------------------------------------------------------------------------------
    # State management methods
    def set_enable_tracking(self, enable: bool) -> None:
        """ Enable or disable the taint tracking """
        assert self._tracking_in_progress is False, \
            "Cannot change tracking mode before get_taint() is called"
        self._enable_tracking = enable

    def reset(self) -> None:
        """ Reset the taint tracker to its initial state """
        self._checkpoints = []
        self._tainted_labels = set(self._initial_observations)
        self._pending_taint = set()
        self._instruction = None
        self._dependencies = _Dependencies()
        self._tracking_in_progress = True

    def checkpoint(self, include_current_inst: bool) -> None:
        """
        Save the current state of the taint tracker
        :param include_current_inst: if True, include the current instruction in the checkpoint
        """
        if not self._enable_tracking:
            return

        if include_current_inst and self._instruction is not None:
            self._finalize_instruction()
        self._checkpoints.append(copy.deepcopy(self._dependencies))

    def rollback(self) -> None:
        """
        Restore the state of the taint tracker from the top-most checkpoint
        :raises AssertionError: if there are no more checkpoints
        """
        if not self._enable_tracking:
            return

        assert self._checkpoints, "There are no more checkpoints"
        if self._instruction is not None:
            self._finalize_instruction()
        self._dependencies = copy.deepcopy(self._checkpoints.pop())

    # ----------------------------------------------------------------------------------------------
    # Dependency propagation methods
    def track_instruction(self, instruction: Instruction) -> None:
        """
        Parse instruction and record its static source and destination operands.
        Static means the operands that we can identify without executing the instruction.
        The remaining dynamic operands are collected by track_* methods.
        :param instruction: the instruction to be parsed
        """
        if not self._enable_tracking:
            return

        # make sure that the previous instruction is finalized
        if self._instruction:
            self._finalize_instruction()

        # restart the tracking
        # print("-----------------------------------")
        self._instruction = _TrackedInstruction(instruction)
        self._instruction.parse_static_operands(self._target_desc.reg_normalized)
        self._pending_taint = set()

        # overwrite stale flag dependencies
        # FIXME: this feels like it should be in _finalize_instruction?
        flag_op = self._instruction.inst.get_flags_operand()
        if flag_op:
            for flag_label in flag_op.get_flags_by_type('overwrite'):
                self._dependencies.flag[flag_label] = set()

    def track_memory_access(self, address: int, size: int, is_write: bool) -> None:
        """
        Add the address of the memory access to the list of current instruction dependencies
        :param address: the address of the memory access
        :param size: the size of the memory access
        :param is_write: True if the memory access is a write (store), False if it's a read (load)
        """
        if not self._enable_tracking:
            return

        assert self._instruction, "track_memory_access called before track_instruction"

        # mask the address - we taint at the granularity of 8 bytes
        address -= self._data_start
        masked_start_addr = address & 0xffff_ffff_ffff_fff8
        end_addr = address + (size - 1)
        masked_end_addr = end_addr & 0xffff_ffff_ffff_fff8

        # add all addresses to tracking
        for i in range(masked_start_addr, masked_end_addr + 1, 8):
            if is_write:
                self._instruction.dest_mems.add(hex(i))
            else:
                self._instruction.src_mems.add(hex(i))

    def _finalize_instruction(self) -> None:
        """
        Propagate dependencies and record the taints of the tracked instruction
        :raises AssertionError: if called before track_instruction
        """
        assert self._instruction, "_finalize_instruction called before track_instruction"
        inst = self._instruction.inst
        inst_name = inst.name.lower()

        # Extract dependencies of the tracked instruction
        self._dependencies.add_dependencies(self._instruction)

        # Workaround for REP instructions with implicit RCX dependency
        if self._pending_taint and "rep" in inst_name and "C" in self._instruction.src_regs:
            self._pending_taint.add('C')

        # Update taints
        # print(self._pending_taint)
        for label in self._pending_taint:
            if label.startswith("0x"):
                tainted_values = self._dependencies.mem.get(label, {label})
            else:
                tainted_values = self._dependencies.reg.get(label, {label})
            self._tainted_labels.update(tainted_values)
        # print(self._tainted_labels)

        # Clear the dependencies of the overwritten registers
        # NOTE: this must be done *after* the taint update, or the taints will be lost
        self._dependencies.remove_overwritten_dependencies(self._instruction, self._target_desc)

        # Reset the instruction
        self._instruction = None

    # ----------------------------------------------------------------------------------------------
    # Tainting callback
    def taint(self, value_type: TAINTED_VALUE_TYPE) -> None:
        """
        Taint the operands of a given type for the tracked instruction
        (tracked instruction is the last instruction on which track_instruction was called)

        :param value_type: the type of the value to be tainted
        """
        if not self._enable_tracking:
            return

        if not self._instruction:
            return

        # Taint the program counter
        if value_type == "pc":
            if self._instruction and self._instruction.inst.is_control_flow:
                self._pending_taint.add("RIP")
            return

        # Taint the memory addresses accessed by the instruction
        if value_type == "mem":
            for reg in self._instruction.mem_address_regs:
                self._pending_taint.add(reg)
            return

        # Taint the loaded value
        if value_type == "ld_val":
            for addr in self._instruction.src_mems:
                self._pending_taint.add(addr)
            return
        assert_never(value_type)

    def taint_actors(self, actor_ids: List[int]) -> None:
        """
        Taint all the memory addresses of the actors in the list
        :param actor_ids: the list of actor IDs
        """
        data_size_per_actor = SandboxLayout.data_size_per_actor()
        for actor_id in actor_ids:
            actor_offset = actor_id * data_size_per_actor
            for i in range(actor_offset, actor_offset + data_size_per_actor, 8):
                self._tainted_labels.add(hex(i))

    # ----------------------------------------------------------------------------------------------
    # Taint output
    def get_taint(self, n_actors: int) -> InputTaint:
        """
        Produce an InputTaint object based on the taints collected during
        the model execution.
        :param n_actors: the number of actors in the test case
        :return: an InputTaint object
        """
        # pylint: disable=too-many-locals
        # NOTE: justified, because we have many variable that define area boundaries

        if not self._enable_tracking:
            self._tracking_in_progress = False
            return InputTaint(n_actors)

        if self._instruction:
            self._finalize_instruction()

        taint = InputTaint(n_actors)
        tainted_sandbox_addresses: List[int] = []
        register_start = SandboxLayout.data_area_offset(DataArea.GPR)
        simd_start = SandboxLayout.data_area_offset(DataArea.SIMD)

        for label in self._tainted_labels:
            # Memory address
            if label.startswith('0x'):
                sandbox_address = int(label, 16)
                tainted_sandbox_addresses.append(sandbox_address)
                continue

            # Register
            reg = self._uc_target_desc.reg_norm_to_constant[label]
            registers = self._uc_target_desc.usable_registers
            if reg in registers:
                sandbox_address = register_start + registers.index(reg) * 8
                tainted_sandbox_addresses.append(sandbox_address)
                continue

            # SIMD register
            simd_registers = self._uc_target_desc.usable_simd128_registers
            if reg in simd_registers:
                sandbox_address = simd_start + simd_registers.index(reg) * 16
                tainted_sandbox_addresses.append(sandbox_address)
                tainted_sandbox_addresses.append(sandbox_address + 1)
            # else:
            # print(f"Register {label} is not tracked")

        tainted_sandbox_addresses.sort()
        taint_offsets = [
            InputTaint.taint_offset_from_sandbox_address(pos) for pos in tainted_sandbox_addresses
        ]

        for actor_id in range(0, n_actors):
            actor_area_start = actor_id * InputTaint.per_actor_taint_size
            actor_area_end = (actor_id + 1) * InputTaint.per_actor_taint_size
            actor_taints = [
                pos - actor_area_start
                for pos in taint_offsets
                if actor_area_start <= pos < actor_area_end
            ]
            taint.taint_actor_offsets(actor_id, actor_taints)

        self._tracking_in_progress = False
        return taint


# ==================================================================================================
# Private: Service Classes
# ==================================================================================================
class _TrackedInstruction:
    """
    A private data class that holds the source and destination operands of the tracked instruction
    """

    def __init__(self, instruction: Instruction) -> None:
        self.inst = instruction

        self.src_regs: Set[str] = set()
        self.dest_regs: Set[str] = set()

        self.src_flags: Set[str] = set()
        self.dest_flags: Set[str] = set()

        self.src_mems: Set[str] = set()
        self.dest_mems: Set[str] = set()

        self.mem_address_regs: Set[str] = set()

    def parse_static_operands(self, reg_normalizer: Dict[str, str]) -> None:
        """
        Set the source and destination operands of the instruction.
        :param reg_normalizer: a dictionary that maps register names to their normalized names
        :return: None
        """
        for op in self.inst.get_all_operands():
            # Registers: normalize the names and record them
            if isinstance(op, RegisterOp):
                value = reg_normalizer[op.value]
                if op.src:
                    self.src_regs.add(value)
                if op.dest:
                    self.dest_regs.add(value)
                continue

            # Flags: record the read and write flags; also record the undefined flags
            if isinstance(op, FlagsOp):
                self.src_flags = set(op.get_flags_by_type('read'))
                self.src_flags.update(op.get_flags_by_type('undef'))
                self.dest_flags = set(op.get_flags_by_type('write'))
                continue

            # Memory: record the names of the address registers
            if isinstance(op, MemoryOp):
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in reg_normalizer:
                        self.mem_address_regs.add(reg_normalizer[sub_op])
                continue

            if isinstance(op, AgenOp):
                # LEA operand: record the names of the address registers
                # Note that we record the names in self.src_regs, because it's not a memory access
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in reg_normalizer:
                        self.src_regs.add(reg_normalizer[sub_op])
                continue

            # Immediate, Label, and Condition: do nothing
            if isinstance(op, (ImmediateOp, LabelOp, CondOp)):
                continue

            assert_never(op)


class _Dependencies:
    """
    A private data class that tracks all dependencies collected by UnicornTaintTracker
    """
    _cached_src_dependencies: Optional[Set[str]]

    def __init__(self) -> None:
        self.reg: Dict[str, Set[str]] = {}
        self.flag: Dict[str, Set[str]] = {}
        self.mem: Dict[str, Set[str]] = {}

    def add_dependencies(self, tracked_inst: _TrackedInstruction) -> None:
        """
        Update the dependencies with the source and destination operands of the tracked instruction
        """

        # Get dependencies of the source operands
        src_dependencies = set()
        for reg in tracked_inst.src_regs:
            src_dependencies.update(self.reg.get(reg, {reg}))
        for flag in tracked_inst.src_flags:
            src_dependencies.update(self.flag.get(flag, {flag}))
        for addr in tracked_inst.src_mems:
            src_dependencies.update(self.mem.get(addr, {addr}))
        self._cached_src_dependencies = src_dependencies

        # Propagate source dependencies to destination operands
        for reg in tracked_inst.dest_regs:
            if reg in self.reg:
                self.reg[reg].update(src_dependencies)
            else:
                self.reg[reg] = copy.copy(src_dependencies)
                self.reg[reg].add(reg)
        for flg in tracked_inst.dest_flags:
            if flg in self.flag:
                self.flag[flg].update(src_dependencies)
            else:
                self.flag[flg] = copy.copy(src_dependencies)
                self.flag[flg].add(flg)
        for mem in tracked_inst.dest_mems:
            if mem in self.mem:
                self.mem[mem].update(src_dependencies)
            else:
                self.mem[mem] = copy.copy(src_dependencies)
                self.mem[mem].add(mem)

        # print(f"reg: dest={tracked_inst.dest_regs}, src={tracked_inst.src_regs}")
        # print(f"flag: dst={tracked_inst.dest_flags}, src={tracked_inst.src_flags}")
        # print(f"mem: dest={tracked_inst.dest_mems}, src={tracked_inst.src_mems}")
        # print(f"all reg={self.reg}")
        # print(f"all flg={self.flag}")
        # print(f"all mem={self.mem}")
        # print("----------------------")

    def remove_overwritten_dependencies(self, tracked_inst: _TrackedInstruction,
                                        target_desc: TargetDesc) -> None:
        """
        Remove the dependencies of the destination operands of the tracked instruction
        """
        assert self._cached_src_dependencies is not None, \
            "remove_overwritten_dependencies must be called after add_dependencies"
        src_dependencies = self._cached_src_dependencies
        self._cached_src_dependencies = None

        # Identify if the instruction overrides previous dependencies
        # (so far we consider only two such case: MOV and LEA)
        # FIXME: this is an x86-specific implementation and it should be moved to the x86 model
        override: bool = False
        inst_name = tracked_inst.inst.name.lower()
        if (inst_name.startswith("mov") or inst_name == "lea") \
           and len(tracked_inst.dest_regs) == 1:
            reg = tracked_inst.inst.get_reg_operands(True)[0].value
            if target_desc.register_sizes.get(reg, 0) == 64:
                override = True

        # If the instruction overrides previous dependencies, remove them
        if override:
            assert len(tracked_inst.dest_regs) == 1, "MOV instruction with multiple destinations"
            reg = tracked_inst.dest_regs.pop()
            for dep in list(self.reg[reg]):
                if dep not in src_dependencies:
                    self.reg[reg].remove(dep)
