"""
File: Test Case Generation

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import random
import abc
import xml.etree.ElementTree as ET
from enum import Enum
from typing import List, Dict, Optional, Set

from interfaces import Generator, TestCase
from helpers import NotSupportedException
from config import CONF


# ==================================================================================================
# Parser of instruction specs
# ==================================================================================================
class OT(Enum):  # Operand Type
    REG = 1
    MEM = 2
    IMM = 3
    LABEL = 4
    AGEN = 5  # memory address in LEA instructions
    FLAGS = 6

    def __str__(self):
        return str(self._name_)


class OperandSpec:
    values: List[str]
    masks: List[str]
    type: OT
    width: int
    src: bool
    dest: bool

    def __init__(self, values: List[str], type_: OT, src: str, dest: str):
        self.values = values
        self.type = type_
        self.src = True if src == "1" else False
        self.dest = True if dest == "1" else False
        self.width = 0

    def __str__(self):
        return f"{self.values}"


class InstructionSpec:
    name: str
    operands: List[OperandSpec]
    implicit_operands: List[OperandSpec]
    category: str
    sae = False
    rnsae = False
    zeroing = False
    has_mem_operand = False
    has_write = False
    control_flow = False

    def __init__(self):
        self.operands = []
        self.implicit_operands = []

    def __str__(self):
        ops = ""
        for o in self.operands:
            ops += str(o) + " "
        return f"{self.name} {ops}"


class InstructionSet:
    all: List[InstructionSpec] = []
    control_flow: List[InstructionSpec] = []
    instruction: InstructionSpec
    has_unconditional_branch: bool = False
    has_conditional_branch: bool = False
    has_indirect_branch: bool = False
    has_reads: bool = False
    has_writes: bool = False

    def parse_reg_operand(self, op):
        registers = op.text.split(',')
        if op.attrib.get('opmask', '') == '1':
            self.instruction.operands[-1].masks.append(registers)
            return

        spec = OperandSpec(registers, OT.REG,
                           op.attrib.get('r', "0"),
                           op.attrib.get('w', "0"))
        spec.width = int(op.attrib.get('width'))
        return spec

    @staticmethod
    def parse_mem_operand(op):
        width = int(op.attrib['width'])

        # asserts are for unsupported instructions
        assert op.attrib.get('VSIB', '0') == '0'  # asm += '[' + op.attrib.get('VSIB') + '0]'
        assert op.attrib.get('memory-suffix', '') == ''

        choices = []
        if op.attrib.get('base', ''):
            choices = [op.attrib.get('base', '')]

        spec = OperandSpec(choices, OT.MEM,
                           op.attrib.get('r', "0"),
                           op.attrib.get('w', "0"))
        spec.width = width
        return spec

    @staticmethod
    def parse_agen_operand(_):
        return OperandSpec([], OT.AGEN, "1", "0")

    @staticmethod
    def parse_imm_operand(op):
        if op.attrib.get('implicit', '0') == '1':
            value = [op.text]
        else:
            value = []
        spec = OperandSpec(value, OT.IMM, "1", "0")
        spec.width = int(op.attrib['width'])
        return spec

    @staticmethod
    def parse_label_operand(_):
        return OperandSpec([], OT.LABEL, "1", "0")

    @staticmethod
    def parse_flags_operand(op):
        # TODO: this is x86-specific. Has to be decoupled from the generic data types
        flags = [
            op.attrib.get("flag_CF", "none"),
            op.attrib.get("flag_PF", "none"),
            op.attrib.get("flag_ZF", "none"),
            op.attrib.get("flag_SF", "none"),
            op.attrib.get("flag_OF", "none"),
        ]
        return OperandSpec(flags, OT.FLAGS,
                           op.attrib.get('r', "0"),
                           op.attrib.get('w', "0"))

    def init_from_file(self, filename: str, include_categories=None):
        root = ET.parse(filename)
        for instruction_node in root.iter('instruction'):
            if include_categories and instruction_node.attrib['category'] not in include_categories:
                continue

            self.instruction = InstructionSpec()
            self.instruction.name = instruction_node.attrib['asm']
            self.instruction.category = instruction_node.attrib['category']

            for op_node in instruction_node.iter('op'):
                op_type = op_node.attrib['type']
                if op_type == 'reg':
                    parsed_op = self.parse_reg_operand(op_node)
                elif op_type == 'mem':
                    parsed_op = self.parse_mem_operand(op_node)
                    self.instruction.has_mem_operand = True
                    if parsed_op.dest:
                        self.instruction.has_write = True
                elif op_type == 'agen':
                    op_node.text = instruction_node.attrib['agen']
                    parsed_op = self.parse_agen_operand(op_node)
                elif op_type == 'imm':
                    parsed_op = self.parse_imm_operand(op_node)
                elif op_type == 'relbr':
                    parsed_op = self.parse_label_operand(op_node)
                    self.instruction.control_flow = True
                elif op_type == 'flags':
                    parsed_op = self.parse_flags_operand(op_node)
                else:
                    raise Exception("Unknown operand type " + op_type)

                if not parsed_op:
                    continue

                if op_node.attrib.get('suppressed', '0') == '1':
                    self.instruction.implicit_operands.append(parsed_op)
                else:
                    self.instruction.operands.append(parsed_op)

            if instruction_node.attrib.get('zeroing', '') == '1':
                self.instruction.zeroing = True

            if instruction_node.attrib.get('roundc', '') == '1':
                self.instruction.rnsae = True
            elif instruction_node.attrib.get('sae', '') == '1':
                self.instruction.sae = True

            self.all.append(self.instruction)

    def reduce(self):
        """ Remove unsupported instructions and operand choices """

        def is_supported(spec: InstructionSpec):
            if spec.sae or spec.rnsae or spec.zeroing:
                return False

            if spec.name in CONF.instruction_blocklist:
                return False

            for operand in spec.operands:
                if operand.type == OT.MEM and operand.values \
                        and operand.values[0] in CONF.gpr_blocklist:
                    return False

            for implicit_operand in spec.implicit_operands:
                assert implicit_operand.type != OT.LABEL  # I know no such instructions
                if implicit_operand.type == OT.MEM and \
                        implicit_operand.values[0] in CONF.gpr_blocklist:
                    return False

                if implicit_operand.type == OT.REG and \
                        implicit_operand.values[0] in CONF.gpr_blocklist:
                    assert len(implicit_operand.values) == 1
                    return False
            return True

        skip_list = []
        for s in self.all:
            # Unsupported instructions
            if not is_supported(s):
                skip_list.append(s)
                continue

            # Control-flow instructions go into a separate category
            if s.control_flow:
                skip_list.append(s)
                self.control_flow.append(s)

            skip_pending = False
            for op in s.operands:
                if op.type == OT.REG:
                    choices = list(set(op.values) - set(CONF.gpr_blocklist))
                    if not choices:
                        skip_pending = True
                        break
                    op.values = choices

                    # FIXME: temporary disabled generation of higher reg. bytes
                    for i, reg in enumerate(op.values):
                        if reg[-1] == 'H':
                            op.values[i] = reg.replace('H', 'L', )

            if skip_pending:
                skip_list.append(s)

        # remove the unsupported
        for s in skip_list:
            self.all.remove(s)

        # set parameters
        for inst in self.all + self.control_flow:
            if inst.control_flow:
                if inst.category == "UNCOND_BR":
                    self.has_unconditional_branch = True
                else:
                    self.has_conditional_branch = True
            elif inst.has_mem_operand:
                if inst.has_write:
                    self.has_writes = True
                else:
                    self.has_reads = True


# ==================================================================================================
# Test case DAG and its nodes
# ==================================================================================================
class Operand(abc.ABC):
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
        super().__init__("." + bb.label, OT.LABEL, True, False)


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

    def get_write_flags(self):
        return self._get_flag_list(['w', 'r/w', 'r/cw'])

    def get_undef_flags(self):
        return self._get_flag_list(['undef'])


class Instruction:
    name: str
    operands: List[Operand]
    implicit_operands: List[Operand]
    next: Optional[Instruction] = None
    previous: Optional[Instruction] = None
    latest_reg_operand: Optional[RegisterOperand] = None  # for avoiding dependencies
    is_instrumentation: bool

    def __init__(self, name: str, is_instrumentation=False):
        self.name = name
        self.operands = []
        self.implicit_operands = []
        self.is_instrumentation = is_instrumentation

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

    def is_store(self):
        for o in self.operands:
            if isinstance(o, MemoryOperand) and o.dest:
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
            if isinstance(o, MemoryOperand):
                res.append(o)
        return res

    def get_flags_operand(self) -> Optional[FlagsOperand]:
        for op in self.implicit_operands:
            if isinstance(op, FlagsOperand):
                return op

        for op in self.operands:
            if isinstance(op, FlagsOperand):
                return op
        return None


class InstructionList:
    """
    A linked list of instructions
    """
    start: Optional[Instruction] = None
    end: Optional[Instruction] = None

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


class BasicBlock:
    label: str
    successors: List[BasicBlock]
    terminators: List[Instruction]
    __instructions: InstructionList

    def __init__(self, label: str):
        self.label = label
        self.__instructions = InstructionList()
        self.successors = []
        self.terminators = []

    def __iter__(self):
        return self.__instructions.__iter__()

    def __len__(self):
        return len(self.__instructions)

    def insert_after(self, position: Instruction, inst: Instruction):
        if not position and not self.__instructions.start:
            self.__instructions.start = inst
            self.__instructions.end = inst
            return

        next_ = position.next
        position.next = inst
        inst.previous = position
        if next_:
            inst.next = next_
            next_.previous = inst
        else:
            self.__instructions.end = inst

    def insert_before(self, position: Instruction, inst: Instruction):
        if not position and not self.__instructions.start:
            self.__instructions.start = inst
            self.__instructions.end = inst
            return

        previous = position.previous
        position.previous = inst
        inst.next = position
        if previous:
            inst.previous = previous
            previous.next = inst
        else:
            self.__instructions.start = inst

    def delete(self, target: Instruction):
        # verify that this instruction indeed belongs to this BB
        for inst in self.__instructions:
            if inst == target:
                break
        else:
            raise Exception("Error deleting an instruction from a BB")

        # patch the linked list
        previous = target.previous
        next_ = target.next
        if previous is None and next_ is None:  # the only instruction in BB
            self.__instructions.end = None
            self.__instructions.start = None
        elif previous is None:  # the first instruction
            next_.previous = None  # type: ignore
            self.__instructions.start = next_
        elif next_ is None:  # the last instruction
            previous.next = None
            self.__instructions.end = previous
        else:  # somewhere in the middle
            previous.next = next_
            next_.previous = previous

    def get_first(self):
        return self.__instructions.start

    def get_last(self):
        return self.__instructions.end


class Function:
    name: str
    all_bb: List[BasicBlock]
    entry: BasicBlock
    exit: BasicBlock

    def __init__(self, name):
        self.name = name

        # create entry and exit points for the function
        self.entry = BasicBlock(f"{self.name}.entry")
        self.exit = BasicBlock(f"{self.name}.exit")
        self.all_bb = [self.entry, self.exit]

    def __iter__(self):
        for bb in self.all_bb:
            yield bb


class TestCaseDAG:
    main: Function
    functions: List[Function]

    def __init__(self):
        self.functions = []


# ==================================================================================================
# Generator Interface
# ==================================================================================================
class Pass(abc.ABC):
    @abc.abstractmethod
    def run_on_dag(self, DAG: TestCaseDAG) -> None:
        pass


class Printer(abc.ABC):
    @abc.abstractmethod
    def print(self, DAG: TestCaseDAG, outfile: str) -> None:
        pass


class RegisterSet(abc.ABC):
    register_sizes: Dict[str, int]
    registers: Dict[int, List[str]]
    simd_registers: Dict[int, List[str]]


class ConfigurableGenerator(Generator, abc.ABC):
    """
    The interface description for Generator classes.
    """

    test_case: TestCaseDAG
    passes: List[Pass]  # set by subclasses
    printer: Printer  # set by subclasses
    register_set: RegisterSet  # set by subclasses

    def __init__(self, instruction_set_spec: str):
        super().__init__(instruction_set_spec)
        instruction_set = InstructionSet()
        instruction_set.init_from_file(instruction_set_spec, CONF.supported_categories)
        instruction_set.reduce()
        self.instruction_set = instruction_set

    def reset_generator(self):
        pass

    def create_test_case(self, asm_file: str) -> TestCase:
        """
        Create a simple test case with a single BB
        Run instrumentation passes and print the result into a file
        """
        self.reset_generator()
        self.test_case = TestCaseDAG()

        # create the main function
        func = self.generate_function("test_case_main")

        # fill the function with instructions
        self.add_terminators_in_function(func)
        self.add_instructions_in_function(func)

        # add it to the test case
        self.test_case.functions.append(func)
        self.test_case.main = func

        # process the test case
        for p in self.passes:
            p.run_on_dag(self.test_case)

        self.printer.print(self.test_case, asm_file)

        # measure coverage, if applicable
        if self.coverage:
            feedback = None
            if type(self.coverage).__name__ == 'PatternCoverage':
                feedback = {
                    'DAG': self.test_case,
                    'instruction_set': self.instruction_set
                }

            self.coverage.generator_hook(feedback)

        return TestCase(asm_file)

    @abc.abstractmethod
    def generate_function(self, name: str):
        pass

    @abc.abstractmethod
    def generate_instruction(self, spec: InstructionSpec):
        pass

    def generate_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        generators = {
            OT.REG: self.generate_reg_operand,
            OT.MEM: self.generate_mem_operand,
            OT.IMM: self.generate_imm_operand,
            OT.LABEL: self.generate_label_operand,
            OT.AGEN: self.generate_agen_operand,
            OT.FLAGS: self.generate_flags_operand,
        }
        return generators[spec.type](spec, parent)

    @abc.abstractmethod
    def generate_reg_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_mem_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_imm_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_label_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_agen_operand(self, _: OperandSpec, __: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_flags_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def add_terminators_in_function(self, func: Function):
        pass

    @abc.abstractmethod
    def add_instructions_in_function(self, func: Function):
        pass


# ==================================================================================================
# ISA-independent Generators
# ==================================================================================================
class RandomGenerator(ConfigurableGenerator, abc.ABC):
    """
    Implements an ISA-independent logic of random test case generation.
    Subclasses are responsible for the ISA-specific parts.
    """
    had_recent_memory_access: bool = False

    def generate_function(self, name: str):
        """ Generates a random DAG of basic blocks within a function """
        func = Function(name)

        # Define the maximum allowed number of successors for any BB
        max_successors = 2 if self.instruction_set.has_conditional_branch else 1
        max_successors = CONF.max_bb_successors if CONF.max_bb_successors else max_successors
        min_successors = 1

        # Create basic blocks
        node_count = random.randint(CONF.min_bb_per_function, CONF.max_bb_per_function)
        nodes = [BasicBlock(f"bb{i}") for i in range(node_count)]

        # Connect BBs into a graph
        for i in range(node_count):
            current_bb = nodes[i]

            # the last node has only one successor - exit
            if i == node_count - 1:
                current_bb.successors = [func.exit]
                break

            # the rest of the node have a random number of successors
            successor_count = random.randint(min_successors, max_successors)
            if successor_count + i > node_count:
                # the number is adjusted to the position when close to the end
                successor_count = node_count - i

            # one of the targets is always the next node - to avoid dead code
            current_bb.successors.append(nodes[i + 1])

            # all other successors are random, selected from next nodes
            options = nodes[i + 2:]
            options.append(func.exit)
            for j in range(1, successor_count):
                target = random.choice(options)
                options.remove(target)
                current_bb.successors.append(target)

        func.entry.successors = [nodes[0]]

        # Function return
        if not CONF.single_function_test_case:
            func.exit.terminators = [self.get_return_instruction()]

        # Finalize the function
        func.all_bb = [func.entry] + nodes + [func.exit]
        return func

    def generate_instruction(self, spec: InstructionSpec):
        # fill up with random operands, following the spec
        inst = Instruction(spec.name)

        # generate explicit operands
        for operand_spec in spec.operands:
            operand = self.generate_operand(operand_spec, inst)
            inst.operands.append(operand)

        # generate implicit operands
        for operand_spec in spec.implicit_operands:
            operand = self.generate_operand(operand_spec, inst)
            inst.implicit_operands.append(operand)

        return inst

    def generate_reg_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        reg_type = spec.values[0]
        if reg_type == 'GPR':
            choices = self.register_set.registers[spec.width]
        elif reg_type == "SIMD":
            choices = self.register_set.simd_registers[spec.width]
        else:
            choices = spec.values

        if not CONF.avoid_data_dependencies:
            reg = random.choice(choices)
            return RegisterOperand(reg, spec.width, spec.src, spec.dest)

        if parent.latest_reg_operand and parent.latest_reg_operand.value in choices:
            return parent.latest_reg_operand

        reg = random.choice(choices)
        op = RegisterOperand(reg, spec.width, spec.src, spec.dest)
        parent.latest_reg_operand = op
        return op

    def generate_mem_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        if spec.values:
            address_reg = random.choice(spec.values)
        else:
            address_reg = random.choice(self.register_set.registers[64])
        return MemoryOperand(address_reg, spec.width, spec.src, spec.dest)

    def generate_imm_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        if spec.values:
            value = spec.values[0]
        else:
            value = str(random.randint(pow(2, spec.width - 1) * -1, pow(2, spec.width - 1) - 1))
        return ImmediateOperand(value, spec.width)

    def generate_label_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        raise NotSupportedException()

    def generate_agen_operand(self, _: OperandSpec, __: Instruction) -> Operand:
        n_operands = random.randint(1, 3)
        reg1 = random.choice(self.register_set.registers[64])
        if n_operands == 1:
            return AgenOperand(reg1)

        reg2 = random.choice(self.register_set.registers[64])
        if n_operands == 2:
            return AgenOperand(reg1 + " + " + reg2)

        imm = str(random.randint(0, pow(2, 16) - 1))
        return AgenOperand(reg1 + " + " + reg2 + " + " + imm)

    def generate_flags_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        return FlagsOperand(spec.values, spec.src, spec.dest)

    def add_terminators_in_function(self, func: Function):
        for bb in func.all_bb:
            if len(bb.successors) == 0:
                # Return instruction
                continue

            elif len(bb.successors) == 1:
                # the last basic block simply falls through
                if bb.successors[0] == func.exit:
                    continue

                # Unconditional branch
                terminator = self.get_unconditional_jump_instruction()
                terminator.operands = [LabelOperand(bb.successors[0])]
                bb.terminators.append(terminator)

            elif len(bb.successors) == 2:
                # Conditional branch
                spec = random.choice(self.instruction_set.control_flow)
                terminator = Instruction(spec.name)
                terminator.operands = [LabelOperand(bb.successors[0])]
                for op in spec.implicit_operands:
                    if op.type == OT.FLAGS:
                        terminator.implicit_operands = \
                            [FlagsOperand(op.values, op.src, op.dest)]
                        break
                bb.terminators.append(terminator)

                terminator = self.get_unconditional_jump_instruction()
                terminator.operands = [LabelOperand(bb.successors[1])]
                bb.terminators.append(terminator)
            else:
                # Indirect jump
                raise NotSupportedException()

    def add_instructions_in_function(self, func: Function):
        # evenly fill all BBs with random instructions
        basic_blocks_to_fill = func.all_bb[1:-1]
        for _ in range(0, CONF.test_case_size):
            bb = random.choice(basic_blocks_to_fill)
            spec = self._pick_random_instruction_spec()
            inst = self.generate_instruction(spec)
            bb.insert_after(bb.get_last(), inst)

    def _pick_random_instruction_spec(self) -> InstructionSpec:
        instruction_spec: InstructionSpec

        # ensure the requested avg. number of mem. accesses
        search_for_memory_access = False
        memory_access_probability = CONF.avg_mem_accesses / CONF.test_case_size
        if CONF.generate_memory_accesses_in_pairs:
            memory_access_probability = 1 if self.had_recent_memory_access else \
                (CONF.avg_mem_accesses / 2) / (CONF.test_case_size - CONF.avg_mem_accesses / 2)

        if random.random() < memory_access_probability:
            search_for_memory_access = True
            self.had_recent_memory_access = not self.had_recent_memory_access

        search_for_store = random.random() < 0.5  # 50% probability of stores

        # select a random instruction spec for generation
        while True:
            instruction_spec = random.choice(self.instruction_set.all)
            if search_for_memory_access:
                if instruction_spec.has_mem_operand and \
                        instruction_spec.has_write == search_for_store:
                    break
            else:
                if not instruction_spec.has_mem_operand:
                    break

        return instruction_spec

    @abc.abstractmethod
    def get_return_instruction(self) -> Instruction:
        pass

    @abc.abstractmethod
    def get_unconditional_jump_instruction(self) -> Instruction:
        pass


# ==================================================================================================
# x86 Generators
# ==================================================================================================
class X86Registers(RegisterSet):
    register_sizes = {
        "RAX": 64, "RBX": 64, "RCX": 64, "RDX": 64, "RSI": 64, "RDI": 64, "RSP": 64, "RBP": 64,
        "R8": 64, "R9": 64, "R10": 64, "R11": 64, "R12": 64, "R13": 64, "R14": 64, "R15": 64,
        "EAX": 32, "EBX": 32, "ECX": 32, "EDX": 32, "ESI": 32, "EDI": 32, "R8D": 32, "R9D": 32,
        "R10D": 32, "R11D": 32, "R12D": 32, "R13D": 32, "R14D": 32, "R15D": 32,
        "AX": 16, "BX": 16, "CX": 16, "DX": 16, "SI": 16, "DI": 16, "R8W": 16, "R9W": 16,
        "R10W": 16, "R11W": 16, "R12W": 16, "R13W": 16, "R14W": 16, "R15W": 16,
        "AL": 8, "BL": 8, "CL": 8, "DL": 8, "SIL": 8, "DIL": 8, "R8B": 8, "R9B": 8,
        "R10B": 8, "R11B": 8, "R12B": 8, "R13B": 8, "R14B": 8, "R15B": 8,
        "AH": 8, "Bh": 8, "CH": 8, "DH": 8,
    }
    gpr_normalized = {
        "RAX": "A", "EAX": "A", "AX": "A", "AL": "A", "AH": "A",
        "RBX": "B", "EBX": "B", "BX": "B", "BL": "B", "BH": "B",
        "RCX": "C", "ECX": "C", "CX": "C", "CL": "C", "CH": "C",
        "RDX": "D", "EDX": "D", "DX": "D", "DL": "D", "DH": "D",
        "RSI": "SI", "ESI": "SI", "SI": "SI", "SIL": "SI",
        "RDI": "DI", "EDI": "DI", "DI": "DI", "DIL": "DI",
        "R8": "8", "R8D": "8", "R8W": "8", "R8B": "8",
        "R9": "9", "R9D": "9", "R9W": "9", "R9B": "9",
        "R10": "10", "R10D": "10", "R10W": "10", "R10B": "10",
        "R11": "11", "R11D": "11", "R11W": "11", "R11B": "11",
        "R12": "12", "R12D": "12", "R12W": "12", "R12B": "12",
        "R13": "13", "R13D": "13", "R13W": "13", "R13B": "13",
        "FLAGS": "FLAGS"
    }
    registers = {
        8: ["AL", "BL", "CL", "DL", "SIL", "DIL", "R8B", "R9B", "R10B", "R11B", "R12B", "R13B"],
        16: ["AX", "BX", "CX", "DX", "SI", "DI", "R8W", "R9W", "R10W", "R11W", "R12W", "R13W"],
        32: ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "R8D", "R9D", "R10D", "R11D", "R12D", "R13D"],
        64: ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13"],
    }
    simd_registers = {
        64: [f"MM{i}" for i in range(0, 8)],
        128: [f"XMM{i}" for i in range(0, 32)],
        256: [f"YMM{i}" for i in range(0, 32)],
        512: [f"ZMM{i}" for i in range(0, 32)],
    }

    def __init__(self):
        super().__init__()
        # remove blocked registers
        filtered_decoding = {}
        for size, registers in self.registers.items():
            filtered_decoding[size] = []
            for register in registers:
                if register not in CONF.gpr_blocklist:
                    filtered_decoding[size].append(register)
        self.registers = filtered_decoding


class X86Generator(ConfigurableGenerator, abc.ABC):
    def __init__(self, instruction_set_spec: str):
        super(X86Generator, self).__init__(instruction_set_spec)
        self.passes = [
            X86SandboxPass(),
            X86PatchUndefinedFlagsPass(self.instruction_set, self),
            X86PatchUndefinedResultPass(),
        ]
        self.printer = X86Printer()
        self.register_set = X86Registers()

    def get_return_instruction(self) -> Instruction:
        return Instruction("RET")

    def get_unconditional_jump_instruction(self) -> Instruction:
        return Instruction("JMP")


class X86LFENCEPass(Pass):
    def run_on_dag(self, DAG: TestCaseDAG) -> None:
        for func in DAG.functions:
            for bb in func:
                insertion_points = []
                for instr in bb:
                    # make a copy to avoid infinite insertions
                    insertion_points.append(instr)

                for instr in insertion_points:
                    bb.insert_after(instr, Instruction("LFENCE", True))


class X86SandboxPass(Pass):
    mask_3bits = "0b111"

    def __init__(self):
        super().__init__()
        if CONF.enable_assist_page:
            self.sandbox_address_mask = "0b1"
        else:
            self.sandbox_address_mask = "0b0"
        self.sandbox_address_mask += "1" * (12 - CONF.memory_access_zeroed_bits) + \
                                     "0" * CONF.memory_access_zeroed_bits

    def run_on_dag(self, DAG: TestCaseDAG) -> None:
        for func in DAG.functions:
            for bb in func.all_bb:
                if bb == func.entry:
                    continue

                # collect all instructions that require sandboxing
                memory_instructions = []
                divisions = []
                bit_tests = []
                repeated_instructions = []
                for inst in bb:
                    if inst.has_mem_operand(True):
                        memory_instructions.append(inst)
                    if inst.name in ["DIV", "REX DIV"]:
                        divisions.append(inst)
                    elif inst.name in ["BT", "BTC", "BTR", "BTS", "LOCK BT", "LOCK BTC", "LOCK BTR",
                                       "LOCK BTS"]:
                        bit_tests.append(inst)
                    elif "REP" in inst.name:
                        repeated_instructions.append(inst)

                # sandbox them
                for inst in memory_instructions:
                    self.sandbox_memory_access(inst, bb)

                for inst in divisions:  # must be after memory accesses
                    self.sandbox_division(inst, bb)

                for inst in bit_tests:
                    self.sandbox_bit_test(inst, bb)

                for inst in repeated_instructions:
                    self.sandbox_repeated_instruction(inst, bb)

    def sandbox_memory_access(self, instr: Instruction, parent: BasicBlock):
        """ Force the memory accesses into the page starting from R14 """
        mem_operands = instr.get_mem_operands()
        if mem_operands:
            assert len(mem_operands) == 1
            assert len(instr.get_implicit_mem_operands()) == 0
            mem_operand: MemoryOperand = mem_operands[0]
            address_reg = mem_operand.value
            imm_width = mem_operand.width if mem_operand.width <= 32 else 32
            apply_mask = Instruction("AND", True) \
                .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                .add_op(ImmediateOperand(self.sandbox_address_mask, imm_width))
            parent.insert_before(instr, apply_mask)
            instr.get_mem_operands()[0].value = "R14 + " + address_reg
            return

        mem_operands = instr.get_implicit_mem_operands()
        if mem_operands:
            assert len(mem_operands) == 1
            mem_operand = mem_operands[0]
            address_reg = mem_operand.value
            imm_width = mem_operand.width if mem_operand.width <= 32 else 32
            apply_mask = Instruction("AND", True) \
                .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                .add_op(ImmediateOperand(self.sandbox_address_mask, imm_width))
            add_base = Instruction("ADD", True) \
                .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                .add_op(RegisterOperand("R14", 64, True, False))
            parent.insert_before(instr, apply_mask)
            parent.insert_before(instr, add_base)
            return

        # print(X86Printer().instruction_to_str(instr))
        raise Exception("Attempt to sandbox an instruction without memory operands")

    def sandbox_division(self, inst: Instruction, parent: BasicBlock):
        """
        We do not support handling of division faults so far, so we have to prevent them.
        Specifically, we need to prevent two types of faults:
        - division by zero
        - division overflow (i.e., quotient is larger than the destination register)
        For this, we ensure that the *D register (upper half of the dividend) is always
        less than the divisor with a bit trick like this ( D & divisor >> 1).

        The first corner case when it won't work is when the divisor is D. This case 
        is impossible to resolve, as far as I can tell. We just give up.

        The second corner case is 8-bit division, when the divisor is the AX register alone.
        Here the instrumentation become too complicated, and we simply set AX to 1.
        """
        divisor = inst.operands[0]

        # make sure the divisor is not zero
        instrumentation = Instruction("OR", True).\
            add_op(divisor).\
            add_op(ImmediateOperand("1", 8))
        parent.insert_before(inst, instrumentation)

        # dividend in AX?
        if divisor.width == 8:
            if "RAX" not in divisor.value:
                instrumentation = Instruction("MOV", True).\
                    add_op(RegisterOperand("AX", 16, False, True)).\
                    add_op(ImmediateOperand("1", 16))
                parent.insert_before(inst, instrumentation)
                return
            else:
                # AX is both the dividend and the offset in memory.
                # Too complex (impossible?). Giving up
                parent.delete(inst)
                return

        # divisor in D or in memory with RDX offset? Impossible case, give up
        if divisor.value in ["RDX", "EDX", "DX", "DH", "DL"] or "RDX" in divisor.value:
            parent.delete(inst)
            return

        # Normal case
        # D = (D & divisor) >> 1
        d_register = {64: "RDX", 32: "EDX", 16: "DX"}[divisor.width]
        instrumentation = Instruction("AND", True).\
            add_op(RegisterOperand(d_register, divisor.width, False, True)).\
            add_op(divisor)
        parent.insert_before(inst, instrumentation)
        instrumentation = Instruction("SHR", True).\
            add_op(RegisterOperand(d_register, divisor.width, False, True)).\
            add_op(ImmediateOperand("1", 8))
        parent.insert_before(inst, instrumentation)

    def sandbox_bit_test(self, inst: Instruction, parent: BasicBlock):
        """
        The address accessed by a BT* instruction is based on both of its operands.
        `sandbox_memory_access` take care of the first operand.
        This function ensures that the offset is always within a byte.
        """
        address = inst.operands[0]
        if isinstance(address, RegisterOperand):
            # this is a version that does not access memory
            # no need for sandboxing
            return

        offset = inst.operands[1]
        if isinstance(offset, ImmediateOperand):
            # The offset is an immediate
            # Simply replace it with a smaller value
            offset.value = str(random.randint(0, 7))
            return

        # The offset is in a register
        # Mask its upper bits to reduce the stored value to at most 7
        if address.value != offset.value:
            apply_mask = Instruction("AND", True) \
                .add_op(offset) \
                .add_op(ImmediateOperand(self.mask_3bits, 8))
            parent.insert_before(inst, apply_mask)
            return

        # Special case: offset and address use the same register
        # Sandboxing is impossible. Give up
        parent.delete(inst)

    def sandbox_repeated_instruction(self, inst: Instruction, parent: BasicBlock):
        apply_mask = Instruction("AND", True) \
            .add_op(RegisterOperand("RCX", 64, True, True)) \
            .add_op(ImmediateOperand("0xff", 8))
        add_base = Instruction("ADD", True) \
            .add_op(RegisterOperand("RCX", 64, True, True)) \
            .add_op(ImmediateOperand("1", 1))
        parent.insert_before(inst, apply_mask)
        parent.insert_before(inst, add_base)

    @staticmethod
    def requires_sandbox(inst: Instruction):
        if inst.has_mem_operand(True):
            return True
        if inst.name in ["DIV", "REX DIV"]:
            return True
        if inst.name in ["BT", "BTC", "BTR", "BTS", "LOCK BT", "LOCK BTC", "LOCK BTR", "LOCK BTS"]:
            return True
        return False


class X86PatchUndefinedFlagsPass(Pass):
    """
    Some instructions have undefined effect on FLAGS (e.g., SHL may or may not overwrite OF).
    This causes a mismatch between Model execution and Executor, if the undefined behavior
    is implemented differently. It leads to false positives.
    To prevent them, we analyse the test cases in search for the cases where an instruction
    with undefined flags is followed by an instruction that uses this flag. We then
    insert another random instruction in-between, such that this
    instruction overwrites the undefined flag.

    I.e., we replace
        SHL eax, eax  // undefined OF
        JNO .label    // uses OF
    with
        SHL eax, eax
        ADD ebx, ecx  // random instruction that overwrites OF
        JNO .label
    """

    def __init__(self, instruction_set: InstructionSet, generator: ConfigurableGenerator):
        super().__init__()
        self.instruction_set = instruction_set
        self.generator = generator

    def run_on_dag(self, DAG: TestCaseDAG) -> None:
        for func in DAG.functions:
            for bb in func.all_bb:
                # get a list of all instructions in the BB
                all_instructions = []
                for inst in bb:
                    all_instructions.append(inst)
                if len(bb.terminators) == 2:  # include conditional terminators
                    all_instructions.append(bb.terminators[0])

                # keep track of the FLAGS dependencies as we iterate over instructions
                flags_to_set: Set[str] = set()

                # walk the list in inverse order
                while all_instructions:
                    inst = all_instructions.pop()
                    flags: FlagsOperand = inst.get_flags_operand()
                    if not flags:
                        continue

                    # fix undefined flags by adding another instruction in-between
                    undef_flags = [i for i in flags.get_undef_flags() if i in flags_to_set]
                    if undef_flags:
                        patch = self.find_flags_patch(undef_flags, flags_to_set)
                        bb.insert_after(inst, patch)
                        patch.is_instrumentation = True
                        # remove the flags overwritten by the patch
                        for f in patch.get_flags_operand().get_write_flags():
                            flags_to_set.discard(f)

                    # remove the flags overwritten by the instruction
                    for f in flags.get_write_flags():
                        flags_to_set.discard(f)

                    # add new flag dependencies
                    if flags.src:
                        for f in flags.get_read_flags():
                            flags_to_set.add(f)

                # make sure that we do not have undefined flags when we enter the BB
                if flags_to_set:
                    patch = self.find_flags_patch(list(flags_to_set), flags_to_set)
                    bb.insert_before(bb.get_first(), patch)
                    patch.is_instrumentation = True

    def find_flags_patch(self, undef_flags, flags_to_set):
        """
        Find an instruction that would overwrite the undefined flags

        FIXME: the implementation uses random sampling from the instruction set, which is
        suboptimal performance-wise. A better implementation would be to pre-collect a list of
        instructions useful for patching, and then just pick a correct instruction when necessary
        """

        attempts = 100  # 100 is an arbitrary number
        for _ in range(attempts):  # try to sample for a patch instruction several times

            # pick a random instruction
            instruction_spec = random.choice(self.instruction_set.all)
            patch = self.generator.generate_instruction(instruction_spec)

            # check if the instruction is safe to use on its own
            if X86SandboxPass.requires_sandbox(patch):
                continue

            # check if it overwrites the undefined flags,
            # and does not create new undefined dependencies
            patch_flags = patch.get_flags_operand()
            if not patch_flags or patch_flags.src:
                continue
            new_undef_flags = [i for i in patch_flags.get_undef_flags() if i in flags_to_set]
            not_patched_flags = [i for i in undef_flags if i not in patch_flags.get_write_flags()]

            if not new_undef_flags and not not_patched_flags:
                return patch

        # unreachable under normal conditions - should always find within 100 attempts
        raise Exception("ERROR: Could not generate a test case from the given instruction set")


class X86PatchUndefinedResultPass(Pass):
    def run_on_dag(self, DAG: TestCaseDAG) -> None:
        for func in DAG.functions:
            for bb in func.all_bb:
                if bb == func.entry:
                    continue

                # collect all instructions that require patching
                bit_scan = []
                for inst in bb:
                    if inst.name in ["BSF", "BSR"]:
                        bit_scan.append(inst)

                # patch them
                for inst in bit_scan:
                    self.patch_bit_scan(inst, bb)

    @staticmethod
    def patch_bit_scan(inst: Instruction, parent: BasicBlock):
        """
        Bit Scan instructions give an undefined result when the source operand is zero.
        To avoid it, set the most significant bit.
        """
        source = inst.operands[1]
        mask = bin(1 << (source.width - 1))
        mask_size = source.width
        if source.width in [64, 32]:
            mask = "0b1000000000000000000000000000000"
            mask_size = 32
        apply_mask = Instruction("OR", True) \
            .add_op(source) \
            .add_op(ImmediateOperand(mask, mask_size))
        parent.insert_before(inst, apply_mask)


class X86Printer(Printer):
    memory_prefixes = {8: "byte ptr", 16: "word ptr", 32: "dword ptr", 64: "qword ptr"}

    def __init__(self):
        super().__init__()

    def print(self, DAG: TestCaseDAG, outfile: str) -> None:
        with open(outfile, "w") as f:
            cache_line_offset = random.randint(0, 15) if CONF.randomized_mem_alignment else 0
            cache_line_offset *= 4  # the memory slots are 4-bytes wide
            f.write(".intel_syntax noprefix\n"
                    ".test_case_enter:\n"
                    f"LEA R14, [R14 + {cache_line_offset}] # instrumentation\n"
                    "MFENCE # instrumentation\n"
                    )

            if not CONF.single_function_test_case:
                f.write("CALL .test_case_main\n"
                        "JMP .test_case_exit\n")

            for func in DAG.functions:
                f.write(f".{func.name}:\n")
                for bb in func.all_bb:
                    self.print_basic_block(bb, f)

            f.write(".test_case_exit:\n"
                    f"LEA R14, [R14 - {cache_line_offset}] # instrumentation\n"
                    "MFENCE # instrumentation\n")

    def print_basic_block(self, bb: BasicBlock, file):
        file.write(f".{bb.label}:\n")
        for inst in bb:
            file.write(self.instruction_to_str(inst) + "\n")
        for inst in bb.terminators:
            file.write(self.instruction_to_str(inst) + "\n")

    def instruction_to_str(self, inst: Instruction):
        operands = ", ".join([self.operand_to_str(op) for op in inst.operands])
        comment = "# instrumentation" if inst.is_instrumentation else ""
        return f"{inst.name} {operands} {comment}"

    def operand_to_str(self, op: Operand) -> str:
        if isinstance(op, MemoryOperand):
            prefix = self.memory_prefixes[op.width]
            return f"{prefix} [{op.value}]"
        elif isinstance(op, AgenOperand):
            return f"[{op.value}]"

        return op.value


# ==================================================================================================
# Concrete generators
# ==================================================================================================
class X86RandomGenerator(X86Generator, RandomGenerator):
    def __init__(self, instruction_set_spec: str):
        super().__init__(instruction_set_spec)


def get_generator(instruction_set_spec: str) -> Generator:
    if CONF.instruction_set == 'x86-64':
        if CONF.generator == 'random':
            return X86RandomGenerator(instruction_set_spec)

    print("Error: unknown value of `instruction_set` configuration option")
    exit(1)
