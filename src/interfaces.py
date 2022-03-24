"""
File: Custom data types

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import List, Dict, Tuple, Optional
from collections import defaultdict
from abc import ABC, abstractmethod
import numpy as np
from enum import Enum

from config import CONF


# ==================================================================================================
# Components of a Test Case
# ==================================================================================================
class OT(Enum):
    """Operand Type"""
    REG = 1
    MEM = 2
    IMM = 3
    LABEL = 4
    AGEN = 5  # memory address in LEA instructions
    FLAGS = 6

    def __str__(self):
        return str(self._name_)


class Operand(ABC):
    value: str
    type: OT
    width: int = 0
    src: bool
    dest: bool

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
        super().__init__(value, OT.REG, src, dest)


class MemoryOperand(Operand):
    def __init__(self, address: str, width: int, src: bool, dest: bool):
        self.width = width
        super().__init__(address, OT.MEM, src, dest)


class ImmediateOperand(Operand):
    def __init__(self, value: str, width: int):
        self.width = width
        super().__init__(value, OT.IMM, True, False)


class LabelOperand(Operand):
    bb: BasicBlock

    def __init__(self, bb):
        self.bb = bb
        super().__init__("." + bb.name, OT.LABEL, True, False)


class AgenOperand(Operand):
    def __init__(self, value: str):
        super().__init__(value, OT.AGEN, True, False)


class FlagsOperand(Operand):
    CF: str = "none"
    PF: str = "none"
    ZF: str = "none"
    SF: str = "none"
    OF: str = "none"

    def __init__(self, value, src: bool, dest: bool):
        self.CF = value[0]
        self.PF = value[1]
        self.ZF = value[2]
        self.SF = value[3]
        self.OF = value[4]
        super().__init__("FLAGS", OT.FLAGS, src, dest)

    def __str__(self):
        return f"FLAGS: CF={self.CF}, PF={self.PF}, ZF={self.ZF}, SF={self.SF}, OF={self.OF}"

    def _get_flag_list(self, types) -> List[str]:
        flags = []
        if self.CF in types:
            flags.append('CF')
        if self.PF in types:
            flags.append('PF')
        if self.ZF in types:
            flags.append('ZF')
        if self.SF in types:
            flags.append('SF')
        if self.OF in types:
            flags.append('OF')
        return flags

    def get_read_flags(self) -> List[str]:
        return self._get_flag_list(['r', 'r/w', 'r/cw'])

    def get_write_flags(self) -> List[str]:
        return self._get_flag_list(['w', 'r/w', 'r/cw'])

    def get_undef_flags(self) -> List[str]:
        return self._get_flag_list(['undef'])


class Instruction:
    name: str
    operands: List[Operand]
    implicit_operands: List[Operand]
    category: str
    control_flow = False

    zeroing: bool = False
    rnsae: bool = False
    sae: bool = False

    next: Optional[Instruction] = None
    previous: Optional[Instruction] = None
    is_instrumentation: bool

    # TODO: remove latest_reg_operand from this class. It belongs in the generator
    latest_reg_operand: Optional[Operand] = None  # for avoiding dependencies

    def __init__(self, name: str, is_instrumentation=False, category="", control_flow=False):
        self.name = name
        self.operands = []
        self.implicit_operands = []
        self.is_instrumentation = is_instrumentation
        self.category = category
        self.control_flow = control_flow

    def __str__(self) -> str:
        operands = ', '.join([o.value for o in self.operands])
        return f"{self.name} {operands}"

    def add_op(self, op: Operand):
        self.operands.append(op)
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

    def has_src_operand(self, include_implicit: bool = False):
        for o in self.operands:
            if o.src:
                return True

        if include_implicit:
            for o in self.implicit_operands:
                if o.src:
                    return True

        return False

    def has_dest_operand(self, include_implicit: bool = False):
        for o in self.operands:
            if o.dest:
                return True

        if include_implicit:
            for o in self.implicit_operands:
                if o.dest:
                    return True

        return False

    def get_mem_operands(self) -> List[MemoryOperand]:
        res = []
        for o in self.operands:
            if isinstance(o, MemoryOperand):
                res.append(o)
        return res

    def get_implicit_mem_operands(self):
        res = []
        for o in self.implicit_operands:
            if o.type == OT.MEM:
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

    def get_first(self):
        return self.start

    def get_last(self):
        return self.end


class Function:
    name: str
    _all_bb: List[BasicBlock]
    entry: BasicBlock
    exit: BasicBlock

    def __init__(self, name):
        self.name = name

        # create entry and exit points for the function
        self._all_bb = [self.entry, self.exit]

    def __len__(self):
        return len(self._all_bb)

    def __iter__(self):
        for bb in self._all_bb:
            yield bb

    def insert(self, bb: BasicBlock):
        self._all_bb = self._all_bb[0: -1]
        self._all_bb.append(bb)
        self._all_bb.append(self.exit)

    def insert_multiple(self, bb_list: List[BasicBlock]):
        self._all_bb = self._all_bb[0: -1]
        self._all_bb += bb_list
        self._all_bb.append(self.exit)

    def get_all(self):
        return self._all_bb


class TestCase:
    asm_path: str = ''
    bin_path: str = ''
    main: Function
    functions: List[Function]
    address_map: Dict[int, Instruction]

    def __init__(self):
        self.functions = []

    def __iter__(self):
        for func in self.functions:
            yield func


# ==================================================================================================
# Custom Data Types
# ==================================================================================================
CTrace = int
HTrace = int
InputID = int
CombinedHTrace = int


class Input(np.ndarray):
    """
    A class representing a single input to a test case.
    It is a fixed-size array of 64-bit unsigned integers, with a few addition
    methods for convenience.
    The array is used to initialize the sandbox memory and the CPU registers.
    The array layout is:

    +----------------------+
    |   Register Values    | Conf.input_register_region_size
    +----------------------+
    |                      |
    |                      | Conf.input_assist_region_size
    | Assist Region Values |
    +----------------------+
    |                      |
    |                      | Conf.input_main_region_size
    |  Main Region Values  |
    +----------------------+
    """
    seed: int = 0
    data_size: int = 0

    def __init__(self) -> None:
        pass  # unreachable; defined only for type checking

    def __new__(cls):
        data_size = CONF.input_main_region_size + \
               CONF.input_assist_region_size + \
               CONF.input_register_region_size
        aligned_size = data_size + (4096 // 8 - CONF.input_register_region_size)
        obj = super().__new__(cls, (aligned_size,), np.uint64, None, 0, None, None)  # type: ignore
        obj.data_size = data_size
        return obj

    def __array_finalize__(self, obj):
        if obj is None:
            return
        pass

    def get_registers(self):
        return list(self[self.data_size-CONF.input_register_region_size:self.data_size-1])

    def __str__(self):
        return str(self.seed)

    def __repr__(self):
        return str(self.seed)


class InputTaint(np.ndarray):
    """
    An array that represents which input elements influence contract traces.
    The number of elements in InputTaint is identical to Input class.
    Each element is an boolean value: When it is True, the corresponding element
    of the input impacts the contract trace.
    """
    def __init__(self) -> None:
        pass  # unreachable; defined only for type checking

    def __new__(cls):
        size = CONF.input_main_region_size + \
               CONF.input_assist_region_size + \
               CONF.input_register_region_size
        obj = super().__new__(cls, (size,), np.bool, None, 0, None, None)    # type: ignore
        return obj


class EquivalenceClass:
    ctrace: CTrace
    original_positions: List[InputID]
    inputs: List[Input]
    htraces: List[HTrace]
    htrace_groups: Dict[HTrace, List[int]]
    primed_positions: Dict[int, List[int]]
    mod2p64 = pow(2, 64)

    def __init__(self):
        self.inputs = []
        self.htraces = []
        self.original_positions = []

    def __str__(self):
        s = f"Size: {len(self.inputs)}\n"
        s += f"Ctrace:\n" \
             f"{self.ctrace % self.mod2p64:064b} [ns]\n" \
             f"{(self.ctrace >> 64) % self.mod2p64:064b} [s]\n"
        s += "Htraces:\n"
        for h in self.htrace_groups.keys():
            s += f"{h:064b}\n"
        s = s.replace("0", "_").replace("1", "^")
        return s

    def update_groups(self) -> None:
        """ group inputs by htraces """
        groups = defaultdict(list)
        for i, htrace in enumerate(self.htraces):
            groups[htrace].append(i)
        self.htrace_groups = groups


# ==================================================================================================
# Interfaces of Modules
# ==================================================================================================
class InstructionSetAbstract(ABC):
    all: List = []
    control_flow: List = []
    has_unconditional_branch: bool = False
    has_conditional_branch: bool = False
    has_indirect_branch: bool = False
    has_reads: bool = False
    has_writes: bool = False

    @abstractmethod
    def __init__(self, filename: str, include_categories=None):
        pass


class Generator(ABC):
    instruction_set: InstructionSetAbstract

    def __init__(self, instruction_set: InstructionSetAbstract):
        self.instruction_set = instruction_set
        super().__init__()

    @abstractmethod
    def create_test_case(self, path: str) -> TestCase:
        """
        Create a simple test case with a single BB
        Run instrumentation passes and print the result into a file
        """
        pass

    @abstractmethod
    def parse_existing_test_case(self, asm_file: str) -> TestCase:
        """
        Read a test case from a file and create a complete TestCase object based on it.
        Used instead of create_test_case when Revizor works with a user-provided test case.
        """
        pass


class InputGenerator(ABC):
    @abstractmethod
    def generate(self, seed: int, count: int) -> List[Input]:
        pass

    @abstractmethod
    def extend_equivalence_classes(self,
                                   inputs: List[Input],
                                   taints: List[InputTaint]) -> List[Input]:
        pass


class Coverage(ABC):
    instruction_set: InstructionSetAbstract

    def __init__(self,
                 instruction_set: InstructionSetAbstract,
                 executor: Executor,
                 model: Model,
                 analyser: Analyser):
        self.instruction_set = instruction_set
        executor.set_coverage(self)
        model.set_coverage(self)
        analyser.set_coverage(self)
        super().__init__()

    @abstractmethod
    def get(self) -> int:
        pass

    @abstractmethod
    def update(self):
        pass

    @abstractmethod
    def load_test_case(self, test_case: TestCase):
        pass

    @abstractmethod
    def model_hook(self, feedback):
        pass

    @abstractmethod
    def executor_hook(self, feedback):
        pass

    @abstractmethod
    def analyser_hook(self, feedback):
        pass


class Model(ABC):
    coverage: Coverage

    @abstractmethod
    def __init__(self, sandbox_base: int, code_base: int):
        super().__init__()

    @abstractmethod
    def load_test_case(self, test_case: TestCase) -> None:
        pass

    @abstractmethod
    def trace_test_case(self, inputs: List[Input], nesting: int, dbg: bool = False) -> \
            Tuple[List[CTrace], List[InputTaint]]:
        pass

    def set_coverage(self, coverage: Coverage):
        self.coverage = coverage


class Executor(ABC):
    coverage: Coverage

    @abstractmethod
    def load_test_case(self, test_case: TestCase):
        pass

    @abstractmethod
    def trace_test_case(self, inputs: List[Input], num_measurements: int = 0) \
            -> List[CombinedHTrace]:
        pass

    @abstractmethod
    def read_base_addresses(self) -> Tuple[int, int]:
        pass

    def set_coverage(self, coverage: Coverage):
        self.coverage = coverage


class Analyser(ABC):
    coverage: Coverage

    @abstractmethod
    def filter_violations(self, inputs: List[Input], ctraces: List[CTrace],
                          htraces: List[HTrace], stats=False) -> List[EquivalenceClass]:
        pass

    def set_coverage(self, coverage: Coverage):
        self.coverage = coverage
