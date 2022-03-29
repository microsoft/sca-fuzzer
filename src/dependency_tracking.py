from __future__ import annotations

from iced_x86 import Register, OpAccess, FlowControl, MemorySize, UsedRegister, UsedMemory, \
     RflagsBits, Decoder
from typing import Dict, List
from interfaces import Instruction, RegisterOperand, FlagsOperand, MemoryOperand
from types import ModuleType
import copy


def create_enum_dict(module: ModuleType) -> Dict[int, str]:
    return {
        module.__dict__[key]: key
        for key in module.__dict__
        if isinstance(module.__dict__[key], int)
    }


REGISTER_TO_STRING: Dict[int, str] = create_enum_dict(Register)
OP_ACCESS_TO_STRING: Dict[int, str] = create_enum_dict(OpAccess)
FLOW_CONTROL_TO_STRING: Dict[int, str] = create_enum_dict(FlowControl)
MEMORY_SIZE_TO_STRING: Dict[int, str] = create_enum_dict(MemorySize)


def register_to_string(value: int) -> str:
    s = REGISTER_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*Register enum*/"
    return s


def op_access_to_string(value: int) -> str:
    s = OP_ACCESS_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*OpAccess enum*/"
    return s


def flow_control_to_string(value: int) -> str:
    s = FLOW_CONTROL_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*FlowControl enum*/"
    return s


def memory_size_to_string(value: int) -> str:
    s = MEMORY_SIZE_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*MemorySize enum*/"
    return s


def used_reg_to_string(reg_info: UsedRegister) -> str:
    return register_to_string(reg_info.register) + ":" + op_access_to_string(reg_info.access)


def used_mem_to_string(mem_info: UsedMemory) -> str:
    sb = "[" + register_to_string(mem_info.segment) + ":"
    need_plus = mem_info.base != Register.NONE
    if need_plus:
        sb += register_to_string(mem_info.base)
    if mem_info.index != Register.NONE:
        if need_plus:
            sb += "+"
        need_plus = True
        sb += register_to_string(mem_info.index)
        if mem_info.scale != 1:
            sb += "*" + str(mem_info.scale)
    if mem_info.displacement != 0 or not need_plus:
        if need_plus:
            sb += "+"
        sb += f"0x{mem_info.displacement:X}"
    sb += ";" + memory_size_to_string(mem_info.memory_size) + ";" + op_access_to_string(
        mem_info.access) + "]"
    return sb


def get_register_label(reg_tracking, register_name: str) -> set:
    if register_name not in reg_tracking.keys():
        return {register_name}
    else:
        label = set()
        for reg in register_deps(register_name):
            if reg not in reg_tracking.keys():
                label.add(reg)
            else:
                label = label.union(reg_tracking[reg])
        return label
        # return regTracking[register_name]


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


def register_deps(reg: str) -> set:
    if reg == "PC":
        return {reg}
    for i in {"A", "B", "C", "D"}:
        if reg == f"R{i}X":
            return {f"{i}L", f"{i}H", f"{i}X", f"E{i}X", f"R{i}X"}
        elif reg == f"E{i}X":
            return {f"{i}L", f"{i}H", f"{i}X", f"E{i}X"}
        elif reg == f"{i}X":
            return {f"{i}L", f"{i}H", f"{i}X"}
        elif reg == f"{i}L":
            return {f"{i}L"}
        elif reg == f"{i}H":
            return {f"{i}H"}

    for i in {"BP", "SI", "DI", "SP", "IP"}:
        if reg == f"R{i}":
            return {f"{i}L", f"{i}", f"E{i}", f"R{i}"}
        elif reg == f"E{i}":
            return {f"{i}L", f"{i}", f"E{i}"}
        elif reg == f"{i}":
            return {f"{i}L", f"{i}"}
        elif reg == f"{i}L":
            return {f"{i}L"}

    for j in range(8, 16):
        if reg == f"R{j}":
            return {f"R{j}B", f"R{j}W", f"R{j}D", f"R{j}"}
        elif reg == f"R{j}D":
            return {f"R{j}B", f"R{j}W", f"R{j}D"}
        elif reg == f"R{j}W":
            return {f"R{j}B", f"R{j}W"}
        elif reg == f"R{j}B":
            return {f"R{j}B"}

    print(f"Unsupported register {reg}")
    exit(1)


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
        self.debug = False
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
                if op.src:
                    self.src_regs.append(op.value)
                if op.dest:
                    self.dest_regs.append(op.value)
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
        # Compute the new dependency maps

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

        if self.debug:
            print("Tracking information")
            print(f"Source label: {src_label}")
            print(f"Registers: {self.reg_tracking}")
            print(f"Flags: {self.flag_tracking}")
            print(f"Memory: {self.mem_tracking}")

    def observe_instruction(self, mode):
        if self.debug:
            print(f"ObservedLabels: {self.observed_labels}")
        if mode == "PC":
            # Add regLabel(PC) to the set of observed labels
            self.observed_labels = \
                self.observed_labels.union(get_register_label(self.reg_tracking, "PC"))
        elif mode == "OPS":
            # For all registers r in the instruction operands
            # (i.e., all source registers), Add regLabel(r) to the set of observed labels
            for reg in self.src_regs:
                self.observed_labels = \
                    self.observed_labels.union(get_register_label(self.reg_tracking, reg))
        else:
            print(f"Invalid mode {mode}")
            exit(1)
        if self.debug:
            print(f"ObserveInstruction {mode} : {self.observed_labels}")

    def observe_memory_address(self, address: int, size: int):
        # Add memLabel(address) to the set of observed labels
        if self.debug:
            print(f"ObservedLabels: {self.observed_labels}")
        for i in range(0, size):
            self.observed_labels = \
                self.observed_labels.union(get_mem_label(self.mem_tracking, address + i))
        if self.debug:
            print(f"ObserveMemoryAddress {address} {size} : {self.observed_labels}")

    def save_state(self):
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
        if len(self.checkpoints) > 0:
            t = self.checkpoints.pop()
            self.restore_state(*t)
        else:
            print("There are no more checkpoints")
            exit(1)

    def get_observed_dependencies(self):
        return copy.deepcopy(self.observed_labels)
