"""
File: Custom data types

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import shutil
import xxhash
from typing import List, Dict, Tuple, Optional, NamedTuple
from collections import defaultdict
from abc import ABC, abstractmethod
import numpy as np
from enum import Enum

PAGE_SIZE = 4096


# ==================================================================================================
# Instruction Specifications
# ==================================================================================================
class OT(Enum):
    """Operand Type"""
    REG = 1
    MEM = 2
    IMM = 3
    LABEL = 4
    AGEN = 5  # memory address in LEA instructions
    FLAGS = 6
    COND = 7

    def __str__(self):
        return str(self._name_)


class OperandSpec:
    values: List[str]
    type: OT
    width: int
    signed: bool = True
    src: bool
    dest: bool

    # certain operand values have special handling (e.g., separate opcode when RAX is a destination)
    # magic_value attribute indicates a specification for this special value
    magic_value: bool = False

    def __init__(self, values: List[str], type_: OT, src: bool, dest: bool):
        self.values = values
        self.type = type_
        self.src = src
        self.dest = dest
        self.width = 0

    def __str__(self):
        return f"{self.values}"


class InstructionSpec:
    name: str
    operands: List[OperandSpec]
    implicit_operands: List[OperandSpec]
    category: str
    control_flow = False

    has_mem_operand = False
    has_write = False
    has_magic_value: bool = False

    def __init__(self):
        self.operands = []
        self.implicit_operands = []

    def __str__(self):
        ops = ""
        for o in self.operands:
            ops += str(o) + " "
        return f"{self.name} {ops}"


class MacroSpec(NamedTuple):
    type_: SymbolType
    name: str
    args: Tuple[str, str, str, str]


# ==================================================================================================
# Sandbox layout and constants
# ==================================================================================================
# Note: the constants *must* be identical to the actor_data_t and actor_code_t in executor
# - Data layout:
#   +-------------------+ (page-aligned)
#   | OVERFLOW_PAD_SIZE |
#   +-------------------+
#   | REG_INIT_AREA_SIZE|
#   +-------------------+ (page-aligned)
#   | FAULTY_AREA_SIZE  |
#   +-------------------+ (page-aligned)
#   | MAIN_AREA_SIZE    |
#   +-------------------+ (page-aligned)
#   | UNDERFLOW_PAD_SIZE|
#   +-------------------+
#   | MACRO_STACK_SIZE  |
#   +-------------------+ (page-aligned)
MACRO_STACK_SIZE = 64
UNDERFLOW_PAD_SIZE = (PAGE_SIZE - MACRO_STACK_SIZE)
MAIN_AREA_SIZE = PAGE_SIZE
FAULTY_AREA_SIZE = PAGE_SIZE
GPR_SUBREGION_SIZE = 64  # 8 64-bit GPRs
SIMD_SUBREGION_SIZE = 256  # 8 256-bit YMMs
REG_INIT_AREA_SIZE = (GPR_SUBREGION_SIZE + SIMD_SUBREGION_SIZE)
OVERFLOW_PAD_SIZE = (PAGE_SIZE - REG_INIT_AREA_SIZE)
SANDBOX_DATA_SIZE = MAIN_AREA_SIZE + FAULTY_AREA_SIZE + 2 * PAGE_SIZE


def get_sandbox_addr(sandbox_base: int, name: str):
    name_to_addr = {
        "start": lambda x: x - UNDERFLOW_PAD_SIZE - MACRO_STACK_SIZE,
        "macro_stack": lambda x: x - UNDERFLOW_PAD_SIZE - MACRO_STACK_SIZE,
        "underflow_pad": lambda x: x - UNDERFLOW_PAD_SIZE,
        "main": lambda x: x,
        "faulty": lambda x: x + MAIN_AREA_SIZE,
        "sp": lambda x: x + MAIN_AREA_SIZE - 8,
        "gpr": lambda x: x + MAIN_AREA_SIZE + FAULTY_AREA_SIZE,
        "simd": lambda x: x + MAIN_AREA_SIZE + FAULTY_AREA_SIZE + GPR_SUBREGION_SIZE,
        "reg_init": lambda x: x + MAIN_AREA_SIZE + FAULTY_AREA_SIZE,
        "overflow_pad": lambda x: x + MAIN_AREA_SIZE + FAULTY_AREA_SIZE + REG_INIT_AREA_SIZE,
    }
    if name not in name_to_addr:
        raise Exception(f"Invalid sandbox region name: {name}")
    return name_to_addr[name](sandbox_base)


# - Code layout:
SANDBOX_CODE_SIZE = 3 * PAGE_SIZE

# ==================================================================================================
# Actors
# ==================================================================================================
ActorID = int
ActorName = str


class ActorMode(Enum):
    HOST = 0
    GUEST = 1


class ActorPL(Enum):
    KERNEL = 0
    USER = 1


class ElfSection(NamedTuple):
    id_: int  # section id; will match the actor id if the actor IDs are ordered and contiguous
    offset: int
    size: int


class Actor:
    name: ActorName
    mode: ActorMode
    privilege_level: ActorPL
    id_: ActorID
    elf_section: Optional[ElfSection] = None
    data_properties: int = 0
    data_ept_properties: int = 0
    code_properties: int = 0  # unused so far
    observer: bool = False

    def __init__(self, mode: ActorMode, pl: ActorPL, id_: ActorID, name: ActorName) -> None:
        self.mode = mode
        self.privilege_level = pl
        self.id_ = id_
        self.name = name


# ==================================================================================================
# Input
# ==================================================================================================
# InputFragment data type represents the input for a single actor. This array is designed to be
# easily serialized and deserialized into/from a binary file.
# InputFragment is a fixed-size array of 64-bit unsigned integers,
# structured into 2 sub-arrays representing memory (`main` and `faulty`),
# and 2 sub-arrays representing CPU registers (`gpr` and `simd`).
# The array is used to initialize sandbox memory and CPU registers.
#
# Ordering of GPRs:  RAX, RBX, RCX, RDX, RSI, RDI, FLAGS, (last 8 bytes unused)
# Ordering of SIMD registers: YMM0, YMM1, ..., YMM7
InputFragment = np.dtype(
    [
        ('main', np.uint64, MAIN_AREA_SIZE // 8),
        ('faulty', np.uint64, FAULTY_AREA_SIZE // 8),
        ('gpr', np.uint64, GPR_SUBREGION_SIZE // 8),
        ('simd', np.uint64, SIMD_SUBREGION_SIZE // 8),
        ('padding', np.uint64, (4096 - REG_INIT_AREA_SIZE) // 8),
    ],
    align=False,
)


class Input(np.ndarray):
    """
    This class represents a single input to a test case. It is a fixed-size array of
    64-bit unsigned integers, with a few addition methods for convenience. The array
    is used to initialize the sandbox memory and the CPU registers.

    The number of elements in Input is equal to the number of actors multiplied by
    the number of elements in InputFragment, i.e.,
        Input.size = n_actors * InputFragment.size
    """
    seed: int = 0
    data_size: int

    def __init__(self, n_actors: int = 1) -> None:
        pass  # unreachable; defined only for type checking

    def __new__(cls, n_actors: int = 1):
        obj = super().__new__(cls, (n_actors,), InputFragment, None, 0, None, None)  # type: ignore
        obj.data_size = (MAIN_AREA_SIZE + FAULTY_AREA_SIZE + REG_INIT_AREA_SIZE) // 8
        return obj

    def __array_finalize__(self, obj):
        if obj is None:
            return

    def __hash__(self) -> int:  # type: ignore
        # hash of input is hash of input data, registers and memory
        h = hash(self.tobytes())
        return h

    def get_simd128_registers(self, actor_id: int):
        vals = []
        for i in range(0, InputFragment['simd'].shape[actor_id], 2):
            vals.append(int(self[0]['simd'][i + 1]) << 64 | int(self[0]['simd'][i]))
        return vals

    def __str__(self):
        return str(self.seed)

    def __repr__(self):
        return str(self.seed)

    def linear_view(self, actor_id) -> np.ndarray:
        return self[actor_id].view((np.uint64, self[actor_id].itemsize // 8))

    def save(self, path: str) -> None:
        with open(path, 'wb') as f:
            f.write(self.tobytes())

    def load(self, path: str) -> None:
        with open(path, 'rb') as f:
            contents = np.fromfile(f, dtype=np.uint64)
            n_actors = self.shape[0]
            for actor_id in range(n_actors):
                actor_start = actor_id * self.itemsize // 8
                actor_end = actor_start + self.itemsize // 8
                self.linear_view(actor_id)[:] = contents[actor_start:actor_end]


class InputTaint(Input):
    """
    This class represents a taint vector for an input. It is a fixed-size array of
    boolean values, with a few addition methods for convenience. The array is used
    to indicate which input elements influence contract traces. The number of
    elements in InputTaint is identical to Input class.

    Each element is an boolean value: When it is True, the corresponding element of
    the input impacts the contract trace.
    """

    def __new__(cls, n_actors: int = 1):
        obj = super().__new__(cls, n_actors)  # type: ignore
        obj.fill(False)
        return obj

    def __init__(self, n_actors: int = 1) -> None:
        pass  # unreachable; defined only for type checking


# ==================================================================================================
# Test Cases
# ==================================================================================================
SymbolType = int
SymbolOffset = int
MacroArgument = int


class Symbol(NamedTuple):
    aid: ActorID
    offset: SymbolOffset
    type_: SymbolType
    arg: MacroArgument


class Operand(ABC):
    value: str
    type: OT
    width: int = 0
    src: bool
    dest: bool

    # certain operand values have special handling (e.g., separate opcode when RAX is a destination)
    # magic_value attribute indicates a specification for this special value
    magic_value: bool = False

    def __init__(self, value: str, type_, src: bool, dest: bool):
        self.value = value
        self.type = type_
        self.src = src
        self.dest = dest
        super(Operand, self).__init__()

    def get_width(self) -> int:
        return self.width


class RegisterOperand(Operand):

    def __init__(self, value: str, width: int, src: bool, dest: bool):
        self.width = width
        super().__init__(value.lower(), OT.REG, src, dest)


class MemoryOperand(Operand):

    def __init__(self, address: str, width: int, src: bool, dest: bool):
        self.width = width
        super().__init__(address.lower(), OT.MEM, src, dest)


class ImmediateOperand(Operand):

    def __init__(self, value: str, width: int):
        self.width = width
        super().__init__(value.lower(), OT.IMM, True, False)


class LabelOperand(Operand):

    def __init__(self, value):
        super().__init__(value, OT.LABEL, True, False)


class AgenOperand(Operand):

    def __init__(self, value: str, width: int):
        self.width = width
        super().__init__(value.lower(), OT.AGEN, True, False)


class FlagsOperand(Operand):
    _flag_values: List[str]
    _flag_names: List[str] = ["CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF"]

    def __init__(self, value):
        assert len(value) == len(self._flag_names)
        self._flag_values = value
        super().__init__("FLAGS", OT.FLAGS, False, False)

    def __str__(self):
        return "FLAGS: " \
               f"{self._flag_names[0]}{self._flag_values[0]}|" \
               f"{self._flag_names[1]}{self._flag_values[1]}|" \
               f"{self._flag_names[2]}{self._flag_values[2]}|" \
               f"{self._flag_names[3]}{self._flag_values[3]}|" \
               f"{self._flag_names[4]}{self._flag_values[4]}|" \
               f"{self._flag_names[5]}{self._flag_values[5]}|" \
               f"{self._flag_names[6]}{self._flag_values[6]}|" \
               f"{self._flag_names[7]}{self._flag_values[7]}|" \
               f"{self._flag_names[8]}{self._flag_values[8]}"

    def _get_flag_list(self, types) -> List[str]:
        flags = []
        for i, type_ in enumerate(self._flag_values):
            if type_ in types:
                flags.append(self._flag_names[i])
        return flags

    def get_read_flags(self) -> List[str]:
        return self._get_flag_list(['r', 'r/w', 'r/cw'])

    def get_write_flags(self) -> List[str]:
        return self._get_flag_list(['w', 'r/w', 'r/cw'])

    def get_overwrite_flags(self) -> List[str]:
        return self._get_flag_list(['w'])

    def get_undef_flags(self) -> List[str]:
        return self._get_flag_list(['undef'])

    def is_dependent(self, flags: FlagsOperand) -> bool:
        for i, mode2 in enumerate(self._flag_values):
            mode1 = flags._flag_values[i]
            if 'w' in mode1 and 'r' in mode2:
                return True
        return False


class CondOperand(Operand):

    def __init__(self, value):
        super().__init__(value, OT.COND, True, False)


class Instruction:
    name: str
    """ name: The name of the instruction without any operands """
    operands: List[Operand]
    """ operands: List of explicit operands of the instruction """
    implicit_operands: List[Operand]
    """ implicit_operands: List of implicit operands, which are not explicitly specified in the
    instruction but are used by the instruction. For example, flags operand in x86 instructions """
    category: str
    """ category: The category of the instruction, e.g., BASE-BINARY. The keyword matches
    the category in the instruction set description file (typically called base.json)"""
    control_flow: bool = False
    """ control_flow: If True, the instruction is a control flow instruction
    (branch, call, return, etc.) """

    next: Optional[Instruction] = None
    """ next: Next instruction in the double-linked list of instructions """
    previous: Optional[Instruction] = None
    """ previous: Previous instruction in the double-linked list of instructions """

    is_instrumentation: bool
    """ is_instrumentation: If True, the instruction is an instrumentation instruction,
    which means that it was inserted by the generator to prevent faults or false positives """
    is_from_template: bool = False
    """ is_from_template: If True, the instruction was directly copied from the template rather
    then being automatically created by the generator """
    is_noremove: bool = False
    """ is_noremove: If True, the instruction should be skipped while doing minimization passes """
    section_id: int = 0
    """ section_id: The ID of the section in the object file where the instruction is located """
    section_offset: int = 0
    """ section_offset: The section offset of the instruction in the object file """
    line_num: int = 0
    """ line_num: The line number in the source (assembly) file where the instruction is located """
    size: int = 0
    """ size: The size of the instruction in bytes, after it has been assembled """
    _inst_brief: str = ""
    """ _inst_brief: A brief representation of the instruction,
    used for hashing and for debug messages """

    def __init__(self, name: str, is_instrumentation=False, category="", control_flow=False):
        self.name = name
        self.operands = []
        self.implicit_operands = []
        self.is_instrumentation = is_instrumentation
        self.category = category
        self.control_flow = control_flow

    @classmethod
    def from_spec(cls, spec: InstructionSpec, is_instrumentation=False):
        # Make sure there are exactly three vertices, though :)
        return cls(spec.name, is_instrumentation, spec.category, spec.control_flow)

    def __str__(self) -> str:
        op_list = [
            "[" + o.value + "]" if isinstance(o, MemoryOperand) else o.value for o in self.operands
        ]
        operands = ', '.join(op_list)
        return f"{self.name} {operands}"

    def add_op(self, op: Operand, implicit=False):
        if not implicit:
            self.operands.append(op)
        else:
            self.implicit_operands.append(op)
        return self

    def has_mem_operand(self, include_implicit: bool = False):
        for o in self.operands:
            if o.type == OT.MEM:
                return True

        if include_implicit:
            for o in self.implicit_operands:
                if o.type == OT.MEM:
                    return True

        return False

    def has_write(self):
        for o in self.operands:
            if o.type == OT.MEM and o.dest:
                return True
        return False

    def has_read(self):
        for o in self.operands:
            if o.type == OT.MEM and o.src:
                return True
        return False

    def get_all_operands(self):
        return self.operands + self.implicit_operands

    def get_src_operands(self, include_implicit: bool = False) -> List[Operand]:
        res = []
        for o in self.operands:
            if o.src:
                res.append(o)

        if include_implicit:
            for o in self.implicit_operands:
                if o.src:
                    res.append(o)

        return res

    def get_dest_operands(self, include_implicit: bool = False) -> List[Operand]:
        res = []
        for o in self.operands:
            if o.dest:
                res.append(o)

        if include_implicit:
            for o in self.implicit_operands:
                if o.dest:
                    res.append(o)

        return res

    def get_mem_operands(self) -> List[MemoryOperand]:
        res = []
        for o in self.operands:
            if isinstance(o, MemoryOperand):
                res.append(o)

        for o in self.implicit_operands:
            if isinstance(o, MemoryOperand):
                res.append(o)

        return res

    def get_implicit_mem_operands(self):
        res = []
        for o in self.implicit_operands:
            if isinstance(o, MemoryOperand):
                res.append(o)
        return res

    def get_flags_operand(self) -> Optional[FlagsOperand]:
        for o in self.implicit_operands:
            if isinstance(o, FlagsOperand):
                return o

        for o in self.operands:
            if isinstance(o, FlagsOperand):
                return o
        return None

    def get_reg_operands(self) -> List[RegisterOperand]:
        res = []
        for o in self.implicit_operands:
            if isinstance(o, RegisterOperand):
                res.append(o)

        for o in self.operands:
            if isinstance(o, RegisterOperand):
                res.append(o)

        return res

    def get_cond_operand(self) -> Optional[CondOperand]:
        for o in self.operands:
            if isinstance(o, CondOperand):
                return o

        # not checking implicit operands -> conditions must be explicit
        return None

    def get_label_operand(self) -> Optional[LabelOperand]:
        for o in self.operands:
            if isinstance(o, LabelOperand):
                return o

        # not checking implicit operands -> labels must be explicit
        return None

    def get_imm_operands(self) -> List[ImmediateOperand]:
        res = []
        for o in self.implicit_operands:
            if isinstance(o, ImmediateOperand):
                res.append(o)

        for o in self.operands:
            if isinstance(o, ImmediateOperand):
                res.append(o)

        return res

    def get_brief(self) -> str:
        if self._inst_brief:
            return self._inst_brief

        brief = self.name
        for o in self.operands:
            if o.type == OT.REG:
                brief += f" R{o.width}"
            elif o.type == OT.MEM:
                brief += f" M{o.width}"
            elif o.type == OT.IMM:
                brief += f" I{o.width}"
            elif o.type == OT.LABEL:
                brief += " L"
            elif o.type == OT.AGEN:
                brief += f" A{o.width}"
            elif o.type == OT.FLAGS:
                brief += " F"
            elif o.type == OT.COND:
                brief += " C"
        self._inst_brief = brief
        return brief


class BasicBlock:
    name: str
    successors: List[BasicBlock]
    terminators: List[Instruction]
    start: Optional[Instruction] = None
    end: Optional[Instruction] = None

    def __init__(self, name: str):
        self.name = name
        self.successors = []
        self.terminators = []

    def __iter__(self):
        current_instruction = self.start
        while current_instruction:
            yield current_instruction
            current_instruction = current_instruction.next

    def __len__(self):
        count = 0
        if self.start:
            instr = self.start
            count = 1
            while instr.next:
                instr = instr.next
                count += 1
        return count

    def insert_after(self, position: Optional[Instruction], inst: Instruction):
        if not position:
            if not self.start:
                self.start = inst
                self.end = inst
                return
            else:
                position = self.start

        next_ = position.next
        position.next = inst
        inst.previous = position
        if next_:
            inst.next = next_
            next_.previous = inst
        else:
            self.end = inst

    def insert_before(self, position: Optional[Instruction], inst: Instruction):
        if not position:
            if not self.start:
                self.start = inst
                self.end = inst
                return
            else:
                position = self.start

        previous = position.previous
        position.previous = inst
        inst.next = position
        if previous:
            inst.previous = previous
            previous.next = inst
        else:
            self.start = inst

    def delete(self, target: Instruction):
        # verify that this instruction indeed belongs to this BB
        for inst in self:
            if inst == target:
                break
        else:
            raise Exception("Error deleting an instruction from a BB")

        # patch the linked list
        previous = target.previous
        next_ = target.next
        if previous is None and next_ is None:  # the only instruction in BB
            self.end = None
            self.start = None
        elif previous is None:  # the first instruction
            next_.previous = None  # type: ignore
            self.start = next_
        elif next_ is None:  # the last instruction
            previous.next = None
            self.end = previous
        else:  # somewhere in the middle
            previous.next = next_
            next_.previous = previous

    def insert_terminator(self, terminator: Instruction):
        self.terminators.append(terminator)

    def get_first(self):
        return self.start

    def get_last(self):
        return self.end


class Function:
    name: str
    owner: Actor
    _all_bb: List[BasicBlock]
    exit: BasicBlock
    obj_file_offset: int = 0

    def __init__(self, name: str, owner: Actor):
        self.name = name
        self.owner = owner
        self.exit = BasicBlock(f".exit_{name.removeprefix('.function_')}")
        self._all_bb = []

    def __len__(self):
        return len(self._all_bb)

    def __iter__(self):
        for bb in self._all_bb:
            yield bb

    def __getitem__(self, item):
        return self._all_bb[item]

    def append(self, bb: BasicBlock):
        self._all_bb.append(bb)

    def extend(self, bb_list: List[BasicBlock]):
        self._all_bb.extend(bb_list)

    def get_first_bb(self):
        return self._all_bb[0]


class TestCase:
    asm_path: str = ''
    obj_path: str = ''
    bin_path: str = ''
    actors: Dict[ActorName, Actor]
    functions: List[Function]
    address_map: Dict[ActorID, Dict[int, Instruction]]
    seed: int
    exit: BasicBlock
    symbol_table: List[Symbol]

    def __init__(self, seed: int):
        self.seed = seed
        self.actors = {"main": Actor(ActorMode.HOST, ActorPL.KERNEL, 0, "main")}
        self.functions = []
        self.address_map = {}
        self.symbol_table = []
        self.exit = BasicBlock(".test_case_exit")

    def __iter__(self):
        for func in self.functions:
            yield func

    def get_function_by_name(self, name: str) -> Function:
        for func in self.functions:
            if func.name == name:
                return func
        raise Exception(f"ERROR: Function {name} not found")

    def get_actor_by_id(self, aid: ActorID) -> Actor:
        for actor in self.actors.values():
            if actor.id_ == aid:
                return actor
        raise Exception(f"ERROR: Actor {aid} not found")

    def save(self, path: str) -> None:
        shutil.copy2(self.asm_path, path)


# ==================================================================================================
# Traces
# ==================================================================================================
InputID = int


class CTrace:
    """
    CTrace is a class that represents a contract trace. It is a container for a list of integers
    that represent raw trace collected from the model and a hash of the trace. The hash is used to
    compare traces for equality.
    """
    raw: List[int]
    hash_: int

    def __init__(self, raw_trace: List) -> None:
        self.raw = raw_trace
        self.hash_ = xxhash.xxh64(str(raw_trace), seed=0).intdigest()

    def __eq__(self, other):
        return self.hash_ == other.hash_

    def __lt__(self, other):
        return self.hash_ < other.hash_

    def __gt__(self, other):
        return self.hash_ > other.hash_

    def __len__(self):
        return len(self.raw)

    def __str__(self):
        return str(self.hash_)

    def __hash__(self) -> int:
        return self.hash_

    @classmethod
    def get_null(cls):
        """ Get a dummy CTrace object with empty contract trace """
        return cls([])


class HTrace:
    """
    HTrace is a class that represents a hardware trace. It is a container for a list of integers
    that represents hardware traces collected from the executor over multiple repeated runs
    with the same program and input. It also contains a hash of the trace and a list of values for
    performance counters collected together with the hardware trace. The hash is used to compare
    traces for equality.
    """
    raw: List[int]
    hash_: int
    perf_counters: np.ndarray
    perf_counters_max: List[int]

    def __init__(self, trace_list: List[int], perf_counters: Optional[np.ndarray] = None) -> None:
        self.raw = trace_list
        self.hash_ = xxhash.xxh64(str(trace_list), seed=0).intdigest()
        if perf_counters is None:
            self.perf_counters = np.array([0, 0, 0, 0, 0])
            self.perf_counters_max = [0, 0, 0, 0, 0]
        else:
            self.perf_counters = perf_counters
            self.perf_counters_max = max(perf_counters, key=lambda x: x[0])

    def __eq__(self, other):
        return self.hash_ == other.hash_

    def __len__(self):
        return len(self.raw)

    @classmethod
    def get_null(cls):
        """ Get a dummy HTrace object with empty hardware trace and zeros for perf counters """
        return cls([])


class Measurement(NamedTuple):
    input_id: InputID
    input_: Input
    ctrace: CTrace
    htrace: HTrace


class EquivalenceClass:
    ctrace: CTrace
    measurements: List[Measurement]
    htrace_groups: List[List[Measurement]]
    """ htrace_groups: a list of htrace groups; each group is a list of measurements that produced
    the same htrace (or a equivalent htraces under the current analyser). """

    MOD2P64 = pow(2, 64)

    def __init__(self, ctrace: CTrace, measurements: List[Measurement],
                 htrace_groups: List[List[Measurement]]) -> None:
        self.ctrace = ctrace
        self.measurements = measurements
        self.htrace_groups = htrace_groups

    def __len__(self):
        return len(self.measurements)


class Violation(EquivalenceClass):
    """ Violation is a special type of equivalence class that represents a violation of a contract.
    It is a container for a list of measurements that triggered the violation, a list of groups of
    htraces, and a sequence of inputs that triggered the violation. """

    ctrace: CTrace
    measurements: List[Measurement]
    htrace_groups: List[List[Measurement]]
    """ htrace_groups: a list of htrace groups; each group is a list of measurements that produced
    the same htrace (or a equivalent htraces under the current analyser). """
    input_sequence: List[Input]
    """ input_sequence: the complete sequence of inputs that triggered the violation """

    def __init__(self, eq_cls: EquivalenceClass, inputs: List[Input]) -> None:
        self.measurements = eq_cls.measurements
        self.ctrace = eq_cls.ctrace
        self.htrace_groups = eq_cls.htrace_groups
        self.input_sequence = inputs

    @classmethod
    def from_measurements(cls, ctrace: CTrace, measurements: List[Measurement],
                          htrace_groups: List[List[Measurement]], inputs: List[Input]):
        return cls(EquivalenceClass(ctrace, measurements, htrace_groups), inputs)


# Execution Tracing
class TracedMemAccess(NamedTuple):
    m_address: int
    value: int
    is_store: bool


class TracedInstruction(NamedTuple):
    i_address: int
    accesses: List[TracedMemAccess]


ExecutionTrace = List[TracedInstruction]


# ==================================================================================================
# Interfaces of Modules
# ==================================================================================================
class InstructionSetAbstract(ABC):
    instructions: List[InstructionSpec]
    instruction_unfiltered: List[InstructionSpec]
    has_unconditional_branch: bool = False
    has_conditional_branch: bool = False
    has_indirect_branch: bool = False
    has_reads: bool = False
    has_writes: bool = False

    @abstractmethod
    def __init__(self, filename: str, include_categories=None):
        pass


class CPUDesc(NamedTuple):
    vendor: str
    model: str
    family: str
    stepping: str


class TargetDesc(ABC):
    register_sizes: Dict[str, int]
    registers: Dict[int, List[str]]
    simd_registers: Dict[int, List[str]]
    branch_conditions: Dict[str, List[str]]
    reg_normalized: Dict[str, str]
    reg_denormalized: Dict[str, Dict[int, str]]
    macro_specs: Dict[str, MacroSpec]
    pte_bits: Dict[str, Tuple[int, bool]]
    epte_bits: Dict[str, Tuple[int, bool]]
    cpu_desc: CPUDesc

    @staticmethod
    @abstractmethod
    def is_unconditional_branch(inst: Instruction) -> bool:
        pass

    @staticmethod
    @abstractmethod
    def is_call(inst: Instruction) -> bool:
        pass


class AsmParser(ABC):
    """ Class responsible for parsing (and optionally patching) assembly files
    and producing TestCases from them """

    @abstractmethod
    def parse_file(self, asm_file: str) -> TestCase:
        """
        Read a test case from a file and create a complete TestCase object based on it.
        Used instead of create_test_case when Revizor works with a user-provided test case.
        """
        pass


class Generator(ABC):
    instruction_set: InstructionSetAbstract
    target_desc: TargetDesc
    asm_parser: AsmParser
    _state: int = 0

    def __init__(self, instruction_set: InstructionSetAbstract, seed: int):
        self.instruction_set = instruction_set
        self.set_seed(seed)
        super().__init__()

    def set_seed(self, seed: int) -> None:
        """
        Set the seed value used to generate test programs
        :param seed: The seed value
        """
        self._state = seed

    def get_state(self) -> int:
        """
        Get the current state of the generator.
        The method complements and is compatible with `set_seed`.
        :return: Current state of the generator
        """
        return self._state

    @abstractmethod
    def create_test_case(self, path: str, disable_assembler: bool = False) -> TestCase:
        """
        Generate a random test case base on the config options.
        Run instrumentation passes and print the result into a file
        """
        pass

    @abstractmethod
    def create_test_case_from_template(self, template: str) -> TestCase:
        """
        Generate a test case based on a template by expanding RANDOM_* macros.
        Run instrumentation passes and print the result into a file
        """
        pass

    @staticmethod
    @abstractmethod
    def assemble(asm_file: str, obj_file: str, bin_file: str) -> None:
        """
        Assemble an assembly file into an object file and creates a stripped binary
        """
        pass

    @abstractmethod
    def get_elf_data(self, test_case: TestCase, obj_file: str) -> None:
        """
        Extract ELF data from an object file and populate the test case
        """
        pass

    @abstractmethod
    def create_actors(self, test_case: TestCase) -> None:
        """
        Create actors for the test case based on the description in CONF._actors
        """
        pass


class InputGenerator(ABC):
    _state: int = 0
    n_actors: int = 1

    def __init__(self, seed: int):
        self.set_seed(seed)
        super().__init__()

    def set_seed(self, seed: int) -> None:
        """Set the seed value used to generate inputs
        :param seed: The seed value
        """
        self._state = seed

    def get_seed(self) -> int:
        """Get the current state of the generator.
        The method complements and is compatible with `set_seed`.
        :return: Current state of the generator
        """
        return self._state

    @abstractmethod
    def reset_boosting_state(self) -> None:
        pass

    @abstractmethod
    def generate(self, count: int) -> List[Input]:
        pass

    @abstractmethod
    def extend_equivalence_classes(self, inputs: List[Input],
                                   taints: List[InputTaint]) -> List[Input]:
        pass

    @abstractmethod
    def load(self, input_paths: List[str]) -> List[Input]:
        """
        Load a sequence of inputs from a directory with binary inputs.
        """
        pass


class Tracer(ABC):
    trace: List

    @abstractmethod
    def produce_trace(self, model: Model) -> CTrace:
        pass


class Model(ABC):
    sandbox_base: int = 0
    code_start: int = 0
    code_end: int = 0
    data_start: int = 0
    data_end: int = 0
    tracer: Tracer
    instruction_coverage: Dict[str, int]
    is_speculative_contract: bool = False

    mismatch_check_mode: bool = False
    """ mismatch_check_mode: If True, the model will return GPR values instead of
    contract traces, which is used to check for mismatches between the model and the executor """

    def __init__(self,
                 sandbox_base: int,
                 code_start: int,
                 tracer: Tracer,
                 enable_mismatch_check_mode: bool = False):
        self.code_start = code_start
        self.sandbox_base = sandbox_base
        self.tracer = tracer
        self.mismatch_check_mode = enable_mismatch_check_mode

        self.instruction_coverage = defaultdict(int)
        super().__init__()

    @abstractmethod
    def load_test_case(self, test_case: TestCase) -> None:
        pass

    @abstractmethod
    def trace_test_case(self, inputs: List[Input], nesting: int) -> List[CTrace]:
        pass

    @abstractmethod
    def dbg_get_trace_detailed(self, input, nesting) -> List[str]:
        pass

    @abstractmethod
    def trace_test_case_with_taints(self, inputs, nesting) -> Tuple[List[CTrace], List[InputTaint]]:
        pass


class Executor(ABC):
    mismatch_check_mode: bool = False
    """ mismatch_check_mode: If True, the executor will return GPR values instead of
    hardware traces, which is used to check for mismatches between the model and the executor """

    @abstractmethod
    def __init__(self, enable_mismatch_check_mode: bool = False):
        self.mismatch_check_mode = enable_mismatch_check_mode
        super().__init__()

    @abstractmethod
    def load_test_case(self, test_case: TestCase):
        pass

    @abstractmethod
    def trace_test_case(self, inputs: List[Input], n_reps: int) -> List[HTrace]:
        """ Call the executor kernel module to collect the hardware traces for
         the test case (previously loaded with `load_test_case`) and the given inputs.

        :param inputs: list of inputs to be used for the test case
        :param n_reps: number of times to repeat each measurement
        :return: a list of HTrace objects, one for each input
         """
        pass

    @abstractmethod
    def read_base_addresses(self) -> Tuple[int, int]:
        pass

    @abstractmethod
    def set_ignore_list(self, ignore_list: List[int]):
        """ Sets a list of inputs IDs that should be ignored by the executor.
        The executor will executed the inputs with these IDs as normal (in case they are
        necessary for priming the uarch state), but their htraces will be set to zero """
        pass

    @abstractmethod
    def extend_ignore_list(self, ignore_list: List[int]):
        """ Updates the ignore list with a new list of inputs IDs that should be ignored
        by the executor."""
        pass


class Analyser(ABC):

    @abstractmethod
    def filter_violations(self,
                          inputs: List[Input],
                          ctraces: List[CTrace],
                          htraces: List[HTrace],
                          stats=False) -> List[Violation]:
        pass

    @abstractmethod
    def htraces_are_equivalent(self, htrace1: HTrace, htrace2: HTrace) -> bool:
        """ Compare two hardware traces according to the current analyser's rules.

        :param htrace1: first hardware trace
        :param htrace2: second hardware trace
        :return: True if the traces are equivalent, False otherwise
        """
        pass


class Fuzzer(ABC):
    model: Model
    executor: Executor
    asm_parser: AsmParser
    generator: Generator
    input_gen: InputGenerator
    analyser: Analyser

    @abstractmethod
    def initialize_modules(self):
        pass

    @abstractmethod
    def filter(self, test_case, inputs) -> bool:
        """
        A filter function that can be used to check if a test case is not useful
        :param test_case: The test case to be checked
        :param inputs: The inputs to be used with the test case
        :return: True if the test case should be filtered out (not useful), False otherwise (useful)
        """
        pass

    @abstractmethod
    def fuzzing_round(self,
                      test_case: TestCase,
                      inputs: List[Input],
                      ignore_list: List[int] = []) -> Optional[Violation]:
        pass


class Minimizer(ABC):

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSetAbstract):
        pass

    @abstractmethod
    def run(self, test_case_asm: str, n_inputs: int, test_case_outfile: str, input_outdir: str,
            n_attempts: int, **kwargs):
        """
        Run the minimizer on a test case.
        See postprocessor.py:MainMinimizer for the full list of arguments.
        """
        pass


class TaintTrackerInterface(ABC):

    def __init__(self, initial_observations: List[str], sandbox_base: int = 0):
        pass

    def reset(self, initial_observations: List[str]):
        pass

    def start_instruction(self, instruction: Instruction) -> None:
        pass

    def track_memory_access(self, address: int, size: int, is_write: bool) -> None:
        pass

    def taint_pc(self):
        pass

    def taint_memory_access_address(self):
        pass

    def taint_loaded_value(self):
        pass

    def checkpoint(self):
        pass

    def rollback(self):
        pass

    @abstractmethod
    def get_taint(self) -> InputTaint:
        pass


# ==================================================================================================
# Exceptions
# ==================================================================================================
class GeneratorException(Exception):
    """ Exception raised when an error occurs during test case generation """
    pass


class HardwareTracingError(Exception):
    """ Exception raised when an error occurs during hardware tracing """
    pass


class NotSupportedException(Exception):
    """ Exception raised when a feature is not supported """
    pass


class UnreachableCode(Exception):
    """ Exception raised when an unreachable code path is reached """
    pass
