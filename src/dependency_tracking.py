from __future__ import annotations

from typing import Dict, List
from interfaces import Instruction, RegisterOperand, FlagsOperand, MemoryOperand
from generator import X86Registers
import copy


def get_register_label(reg_tracking, reg: str) -> set:
    if reg not in reg_tracking.keys():
        return {reg}
    else:
        label = set()
        if reg not in reg_tracking.keys():
            label.add(reg)
        else:
            label = label.union(reg_tracking[reg])
        return label


def get_flag_label(flag_tracking, flag_name: str) -> set:
    if flag_name not in flag_tracking.keys():
        return {flag_name}
    else:
        return flag_tracking[flag_name]


def get_mem_label(mem_tracking, address: int) -> set:
    if address not in mem_tracking.keys():
        return {address}
    else:
        return mem_tracking[address]


class DependencyTracker:
    strict_undefined: bool = True

    src_regs: List[str]
    src_flags: List[str]
    src_mems: List[str]
    dest_regs: List[str]
    dest_flags: List[str]
    dest_mems: List[str]

    def __init__(self, code_biteness, initial_observations=None):
        if initial_observations is None:
            initial_observations = []
        self.initial_observations = initial_observations
        self.code_biteness = code_biteness

        self.reset()

    def reset(self):
        self.flag_tracking = {}
        self.reg_tracking = {}
        self.mem_tracking = {}
        self.observed_labels = set(self.initial_observations)
        self.checkpoints = []
        self.reset_instruction_tracking()

    def reset_instruction_tracking(self):
        self.src_regs = []
        self.src_flags = []
        self.src_mems = []
        self.dest_regs = []
        self.dest_flags = []
        self.dest_mems = []

    def initialize(self, instruction: Instruction):
        """ Collect source and target registers/flags """
        self.finalize_tracking()  # finalize the previous instruction
        self.reset_instruction_tracking()

        for op in instruction.operands + instruction.implicit_operands:
            if isinstance(op, RegisterOperand):
                value = X86Registers.gpr_normalized[op.value]
                if op.src:
                    self.src_regs.append(value)
                if op.dest:
                    self.dest_regs.append(value)
            if instruction.control_flow:
                self.dest_regs.append("RIP")
            if isinstance(op, FlagsOperand):
                self.src_flags = op.get_read_flags()
                if self.strict_undefined:
                    self.src_flags.extend(op.get_undef_flags())
                self.dest_flags = op.get_write_flags()

    def track_memory_access(self, address, size, is_write: bool):
        """ Tracking concrete memory accesses """
        if is_write:
            for i in range(0, size):
                self.dest_mems.append(address + i)
        else:
            for i in range(0, size):
                self.src_mems.append(address + i)

    def finalize_tracking(self):
        # Compute source label
        src_label = set()
        for reg in self.src_regs:
            src_label = src_label.union(get_register_label(self.reg_tracking, reg))
        for flag in self.src_flags:
            src_label = src_label.union(get_flag_label(self.flag_tracking, flag))
        for addr in self.src_mems:
            src_label = src_label.union(get_mem_label(self.mem_tracking, addr))

        # Propagate label to all targets
        for reg in self.dest_regs:
            self.reg_tracking[reg] = list(src_label)
        for flg in self.dest_flags:
            self.flag_tracking[flg] = list(src_label)
        for mem in self.dest_mems:
            self.mem_tracking[mem] = list(src_label)

    def observe_instruction(self, mode):
        if mode == "PC":
            # Add regLabel(PC) to the set of observed labels
            self.observed_labels = \
                self.observed_labels.union(get_register_label(self.reg_tracking, "RIP"))
        elif mode == "OPS":
            # For all registers r in the instruction operands
            # (i.e., all source registers), Add regLabel(r) to the set of observed labels
            for reg in self.src_regs:
                self.observed_labels = \
                    self.observed_labels.union(get_register_label(self.reg_tracking, reg))
        else:
            print(f"Invalid mode {mode}")
            exit(1)

    def observe_memory_address(self, address: int, size: int):
        # Add memLabel(address) to the set of observed labels
        if self.debug:
            print(f"ObservedLabels: {self.observed_labels}")
        for i in range(0, size):
            self.observed_labels = \
                self.observed_labels.union(get_mem_label(self.mem_tracking, address + i))
        if self.debug:
            print(f"ObserveMemoryAddress {address} {size} : {self.observed_labels}")
        # return a copy of the tracker state!
        return copy.deepcopy(self.flag_tracking), \
               copy.deepcopy(self.reg_tracking), \
               copy.deepcopy(self.mem_tracking), \
               copy.deepcopy(self.observed_labels)

    def restore_state(self, flag_tracking, reg_tracking, mem_tracking, observed_labels):
        self.flag_tracking = copy.deepcopy(flag_tracking)
        self.reg_tracking = copy.deepcopy(reg_tracking)
        self.mem_tracking = copy.deepcopy(mem_tracking)
        self.observed_labels = copy.deepcopy(observed_labels)

    def checkpoint(self):
        t = self.save_state()
        self.checkpoints.append(t)

    def rollback(self):
        assert self.checkpoints, "There are no more checkpoints"
        t = self.checkpoints.pop()
        self.restore_state(*t)

    def get_observed_dependencies(self):
        return copy.deepcopy(self.observed_labels)
