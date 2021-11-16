from iced_x86 import *
from typing import Dict, Sequence
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


def decode_rflags_bits(rf: int) -> list:
    sb = []
    if (rf & RflagsBits.OF) != 0:
        sb.append("OF")
    if (rf & RflagsBits.SF) != 0:
        sb.append("SF")
    if (rf & RflagsBits.ZF) != 0:
        sb.append("ZF")
    if (rf & RflagsBits.AF) != 0:
        sb.append("AF")
    if (rf & RflagsBits.CF) != 0:
        sb.append("CF")
    if (rf & RflagsBits.PF) != 0:
        sb.append("PF")
    if (rf & RflagsBits.DF) != 0:
        sb.append("DF")
    if (rf & RflagsBits.IF) != 0:
        sb.append("IF")
    if (rf & RflagsBits.AC) != 0:
        sb.append("AC")
    if (rf & RflagsBits.UIF) != 0:
        sb.append("UIF")
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
    # TODO:
    # 1) When we observe an instruction operands,
    # right now we do not distinguish between 1st and 2nd operand. Fix that!!

    def __init__(self, code_biteness, initial_observations=None):
        if initial_observations is None:
            initial_observations = []
        self.flag_tracking = {}
        self.reg_tracking = {}
        self.mem_tracking = {}
        self.code_biteness = code_biteness
        self.src_regs = set()
        self.src_flags = set()
        self.src_mems = set()
        self.trg_regs = set()
        self.trg_flags = set()
        self.trg_mems = set()
        self.debug = False
        self.initial_observations = initial_observations
        self.observed_labels = set(self.initial_observations)
        self.strict_undefined = True
        self.checkpoints = []

    def reset(self):
        self.flag_tracking = {}
        self.reg_tracking = {}
        self.mem_tracking = {}
        self.observed_labels = set(self.initial_observations)
        self.src_regs = set()
        self.src_flags = set()
        self.src_mems = set()
        self.trg_regs = set()
        self.trg_flags = set()
        self.trg_mems = set()
        self.checkpoints = []

    def initialize(self, instruction):
        # TODO: this function is extremely slow, has to get optimized
        # Collect source and target registers/flags
        self.src_regs = set()
        self.src_flags = set()
        self.src_mems = set()
        self.trg_regs = set()
        self.trg_flags = set()
        self.trg_mems = set()

        decoder = Decoder(self.code_biteness, instruction)
        formatter = FastFormatter(FormatterSyntax.NASM)  # Formatter(FormatterSyntax.NASM)
        info_factory = InstructionInfoFactory()
        index = 0
        for instr in decoder:
            info = info_factory.info(instr)

            if self.debug:
                print(f"{instr}")
                for reg_info in info.used_registers():
                    print(f"    Used reg: {used_reg_to_string(reg_info)}")
                for mem_info in info.used_memory():
                    print(f"    Used mem: {used_mem_to_string(mem_info)}")
                if instr.rflags_read != RflagsBits.NONE:
                    print(f"    RFLAGS Read: {decode_rflags_bits(instr.rflags_read)}")
                if instr.rflags_written != RflagsBits.NONE:
                    print(f"    RFLAGS Written: {decode_rflags_bits(instr.rflags_written)}")
                if instr.rflags_cleared != RflagsBits.NONE:
                    print(f"    RFLAGS Cleared: {decode_rflags_bits(instr.rflags_cleared)}")
                if instr.rflags_set != RflagsBits.NONE:
                    print(f"    RFLAGS Set: {decode_rflags_bits(instr.rflags_set)}")
                if instr.rflags_undefined != RflagsBits.NONE:
                    print(f"    RFLAGS Undefined: {decode_rflags_bits(instr.rflags_undefined)}")
                if instr.rflags_modified != RflagsBits.NONE:
                    print(f"    RFLAGS Modified: {decode_rflags_bits(instr.rflags_modified)}")
                print(f"    FlowControl: {flow_control_to_string(instr.flow_control)}")

            for reg_info in info.used_registers():
                if op_access_to_string(reg_info.access) in ["READ", "READ_WRITE", "COND_READ"]:
                    self.src_regs.add(register_to_string(reg_info.register))
                if op_access_to_string(reg_info.access) in ["WRITE", "READ_WRITE", "COND_WRITE"]:
                    self.trg_regs.add(register_to_string(reg_info.register))
            if flow_control_to_string(instr.flow_control) != "NEXT":
                self.trg_regs.add("PC")

            self.src_flags = set(decode_rflags_bits(instr.rflags_read))
            if self.strict_undefined:
                self.src_flags = self.src_flags.union(
                    set(decode_rflags_bits(instr.rflags_undefined)))
            self.trg_flags = set(decode_rflags_bits(instr.rflags_modified))

            if self.debug:
                print(f"    Source Registers: {self.src_regs}")
                print(f"    Target Registers: {self.trg_regs}")
                print(f"    Source Flags: {self.src_flags}")
                print(f"    Target Flags: {self.trg_flags}")

            index = index + 1
            assert (index <= 1)

    def track_memory_access(self, address, size, mode):
        if self.debug:
            print(f"Track Memory Access {address} {size} {mode}")

        # Tracking concrete memory accesses
        if mode == "READ":
            for i in range(0, size):
                self.src_mems.add(address + i)
        elif mode == "WRITE":
            for i in range(0, size):
                self.trg_mems.add(address + i)
        else:
            print(f"Unsupported mode {mode}")
            exit(1)

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
        for reg in self.trg_regs:
            self.reg_tracking[reg] = list(src_label)
        for flg in self.trg_flags:
            self.flag_tracking[flg] = list(src_label)
        for mem in self.trg_mems:
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
