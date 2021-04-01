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
from custom_types import Optional, List, Tuple

from helpers import NotSupportedException
from config import CONF


# ===========================
# x86-specific
# ===========================

class X86Registers:
    gpr_sizes = {
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

    # more sparse encoding for SIMD because the 'width' field is not always reliable
    simd_decoding = {
        'SIMD64-8': ['MM0', 'MM1', 'MM2', 'MM3', 'MM4', 'MM5', 'MM6', 'MM7'],
        'SIMD128-32': ['XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7', 'XMM8',
                       'XMM9', 'XMM10', 'XMM11', 'XMM12', 'XMM13', 'XMM14', 'XMM15', 'XMM16',
                       'XMM17', 'XMM18', 'XMM19', 'XMM20', 'XMM21', 'XMM22', 'XMM23', 'XMM24',
                       'XMM25', 'XMM26', 'XMM27', 'XMM28', 'XMM29', 'XMM30', 'XMM31'],
        'SIMD128-16': ['XMM0', 'XMM1', 'XMM2', 'XMM3', 'XMM4', 'XMM5', 'XMM6', 'XMM7', 'XMM8',
                       'XMM9', 'XMM10', 'XMM11', 'XMM12', 'XMM13', 'XMM14', 'XMM15'],
        'SIMD256-32': ['YMM0', 'YMM1', 'YMM2', 'YMM3', 'YMM4', 'YMM5', 'YMM6', 'YMM7', 'YMM8',
                       'YMM9', 'YMM10', 'YMM11', 'YMM12', 'YMM13', 'YMM14', 'YMM15', 'YMM16',
                       'YMM17', 'YMM18', 'YMM19', 'YMM20', 'YMM21', 'YMM22', 'YMM23', 'YMM24',
                       'YMM25', 'YMM26', 'YMM27', 'YMM28', 'YMM29', 'YMM30', 'YMM31'],
        'SIMD256-16': ['YMM0', 'YMM1', 'YMM2', 'YMM3', 'YMM4', 'YMM5', 'YMM6', 'YMM7', 'YMM8',
                       'YMM9', 'YMM10', 'YMM11', 'YMM12', 'YMM13', 'YMM14', 'YMM15'],
        'SIMD512-32': ['ZMM0', 'ZMM1', 'ZMM2', 'ZMM3', 'ZMM4', 'ZMM5', 'ZMM6', 'ZMM7', 'ZMM8',
                       'ZMM9', 'ZMM10', 'ZMM11', 'ZMM12', 'ZMM13', 'ZMM14', 'ZMM15', 'ZMM16',
                       'ZMM17', 'ZMM18', 'ZMM19', 'ZMM20', 'ZMM21', 'ZMM22', 'ZMM23', 'ZMM24',
                       'ZMM25', 'ZMM26', 'ZMM27', 'ZMM28', 'ZMM29', 'ZMM30', 'ZMM31'],
    }


# ===========================
# Instruction Loader
# ===========================
class OT(Enum):  # Operand Type
    REG = 1
    MEM = 2
    IMM = 3
    LABEL = 4
    AGEN = 5  # memory address in LEA instructions
    FLAGS = 6


class OperandSpec:
    choices: List[str]
    masks: List[str]
    type: OT
    width: int
    src: bool
    dest: bool

    def __init__(self, choices: List[str], type_: OT, src: str, dest: str):
        self.choices = choices
        self.type = type_
        self.src = True if src == "1" else False
        self.dest = True if dest == "1" else False

    def __str__(self):
        return f"{self.choices}"


class InstructionSpec:
    name: str
    operands: List[OperandSpec]
    implicit_operands: List[OperandSpec]
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
    has_conditional_branch: bool = False
    has_indirect_branch: bool = False

    def parse_reg_operand(self, op):
        registers = op.text.split(',')
        if op.attrib.get('opmask', '') == '1':
            self.instruction.operands[-1].masks.append(registers)
            return

        spec = OperandSpec(registers, OT.REG,
                           op.attrib.get('r', "0"),
                           op.attrib.get('w', "0"))
        spec.width = int(op.attrib.get('width', '0'))
        assert spec.width or registers != ['GPR']
        return spec

    @staticmethod
    def parse_mem_operand(op):
        width = op.attrib['width']

        # asserts are for unsupported instructions
        assert op.attrib.get('VSIB', '0') == '0'  # asm += '[' + op.attrib.get('VSIB') + '0]'
        assert op.attrib.get('memory-suffix', '') == ''

        name = op.attrib.get('memory-prefix', '')
        assert name != ''

        spec = OperandSpec([name], OT.MEM,
                           op.attrib.get('r', "0"),
                           op.attrib.get('w', "0"))
        spec.width = width
        return spec

    @staticmethod
    def parse_agen_operand(op):
        return OperandSpec([], OT.AGEN, "1", "0")

    @staticmethod
    def parse_imm_operand(op):
        spec = OperandSpec([], OT.IMM, "1", "0")
        spec.width = int(op.attrib['width'])
        return spec

    @staticmethod
    def parse_label_operand(op):
        return OperandSpec([], OT.LABEL, "1", "0")

    @staticmethod
    def parse_flags_operand(op):
        return OperandSpec([], OT.FLAGS,
                           op.attrib.get('r', "0"),
                           op.attrib.get('w', "0"))

    def init_from_file(self, filename: str, include_categories=None):
        root = ET.parse(filename)
        for instruction_node in root.iter('instruction'):
            if include_categories and instruction_node.attrib['category'] not in include_categories:
                continue

            self.instruction = InstructionSpec()
            self.instruction.name = instruction_node.attrib['asm']

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

            for implicit_operand in spec.implicit_operands:
                assert implicit_operand.type != OT.LABEL  # I know no such instructions
                if implicit_operand.type == OT.MEM:
                    return False

                if implicit_operand.type == OT.REG and \
                        implicit_operand.choices[0] in CONF.gpr_blocklist:
                    assert len(implicit_operand.choices) == 1
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
                self.has_conditional_branch = True
                skip_list.append(s)
                self.control_flow.append(s)

            skip_pending = False
            for op in s.operands:
                if op.type == OT.REG:
                    choices = list(set(op.choices) - set(CONF.gpr_blocklist))
                    if not choices:
                        skip_pending = True
                        break
                    op.choices = choices

                    # temporary disable generation of higher reg. bytes
                    for i, reg in enumerate(op.choices):
                        if reg[-1] == 'H':
                            op.choices[i] = reg.replace('H', 'L', )

            if skip_pending:
                skip_list.append(s)

        # remove the unsupported
        for s in skip_list:
            self.all.remove(s)

        # conditional_reg = 0
        # uncond = 0
        # store = 0
        # load = 0
        # reg = 0
        # for s in self.all + self.control_flow:
        #     if s.control_flow:
        #         if "JMP" in s.name:
        #             uncond += 1
        #         else:
        #             conditional_reg += 1
        #     elif s.has_mem_operand:
        #         if s.has_write:
        #             store += 1
        #         else:
        #             load += 1
        #     else:
        #         reg += 1
        # print(f"Unconditional: {uncond}")
        # print(f"Conditional: {conditional_reg}")
        # print(f"Store: {store}")
        # print(f"Load: {load}")
        # print(f"Misc: {reg}")


# ===========================
# Test Case DAG
# ===========================
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

    def __str__(self):
        return self.value

    def get_width(self) -> int:
        return self.width


class RegisterOperand(Operand):
    def __init__(self, value: str, src: bool, dest: bool):
        self.width = X86Registers.gpr_sizes[value]
        super().__init__(value, OT.REG, src, dest)


class MemoryOperand(Operand):
    prefix_sizes = {"byte ptr": 8, "word ptr": 16, "dword ptr": 32, "qword ptr": 64}

    def __init__(self, prefix: str, base: str, src: bool, dest: bool):
        self.width = self.prefix_sizes[prefix]
        self.prefix: str = prefix
        self.base: str = base
        super().__init__(base, OT.MEM, src, dest)

    def __str__(self):
        return f"{self.prefix} [{self.base}]"


class ImmediateOperand(Operand):
    def __init__(self, value: str):
        super().__init__(value, OT.IMM, True, False)


class LabelOperand(Operand):
    BB: BasicBlock

    def __init__(self, BB):
        self.BB = BB
        super().__init__("." + BB.label, OT.LABEL, True, False)


class AgenOperand(Operand):
    def __init__(self, value: str):
        super().__init__(value, OT.AGEN, True, False)


class FlagsOperand(Operand):
    def __init__(self, src: bool, dest: bool):
        super().__init__("FLAGS", OT.FLAGS, src, dest)


class Instruction:
    name: str
    operands: List[Operand]
    implicit_operands: List[Operand]
    next: Instruction = None
    previous: Instruction = None
    latest_reg_operand: RegisterOperand = None  # for avoiding dependencies
    is_instrumentation: bool

    def __init__(self, name: str, is_instrumentation=False):
        self.name = name
        self.operands = []
        self.implicit_operands = []
        self.is_instrumentation = is_instrumentation

    def __str__(self):
        operands = ", ".join([str(op) for op in self.operands])
        comment = "# instrumentation" if self.is_instrumentation else ""
        return f"{self.name} {operands} {comment}"

    def add_op(self, op: Operand):
        self.operands.append(op)
        return self

    def add_reg(self, name: str, src: bool, dest: bool):
        return self.add_op(RegisterOperand(name, src, dest))

    def add_imm(self, value: str):
        return self.add_op(ImmediateOperand(value))

    def add_mem(self, prefix, address, src: bool, dest: bool):
        return self.add_op(MemoryOperand(prefix, address, src, dest))

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

    def append_non_terminator(self, I: Instruction):
        if not self.__instructions.start:
            # first instructions
            self.__instructions.start = I
            self.__instructions.end = I
            return

        self.__instructions.end.next = I
        I.previous = self.__instructions.end
        self.__instructions.end = I

    def insert_after(self, position: Instruction, I: Instruction):
        next_ = position.next
        position.next = I
        I.previous = position
        if next_:
            I.next = next_
            next_.previous = I
        else:
            self.__instructions.end = I

    def insert_before(self, position: Instruction, I: Instruction):
        previous = position.previous
        position.previous = I
        I.next = position
        if previous:
            I.previous = previous
            previous.next = I
        else:
            self.__instructions.start = I

    def delete(self, target: Instruction):
        # verify that this instruction indeed belongs to this BB
        for I in self.__instructions:
            if I == target:
                break
        else:
            raise Exception("Error deleting an instruction from a BB")

        # patch the linked list
        previous = target.previous
        next_ = target.next
        if not previous and not next_:  # the only instruction in BB
            self.__instructions.end = None
            self.__instructions.start = None
        elif not previous:  # the first instruction
            next_.previous = None
            self.__instructions.start = next_
        elif not next_:  # the last instruction
            previous.next = None
            self.__instructions.end = previous
        else:  # somewhere in the middle
            previous.next = next_
            next_.previous = previous

    def get_first(self):
        return self.__instructions.start


class Function:
    name: str
    BBs: List[BasicBlock]
    entry: BasicBlock
    exit: BasicBlock

    def __init__(self, name):
        self.name = name

        # create entry and exit points for the function
        self.entry = BasicBlock(f"{self.name}.entry")
        self.exit = BasicBlock(f"{self.name}.exit")
        if not CONF.single_function_test_case:
            self.exit.terminators = [Instruction("RET")]
        self.BBs = [self.entry, self.exit]

    def __iter__(self):
        for BB in self.BBs:
            yield BB


class TestCaseDAG:
    main: Function
    functions: List[Function]

    def __init__(self):
        self.functions = []


# ===========================
# Generator and passes
# ===========================

class Generator:
    test_case: TestCaseDAG
    coverage = None

    def __init__(self, instruction_set_spec: str):
        instruction_set = InstructionSet()
        instruction_set.init_from_file(instruction_set_spec, CONF.supported_categories)
        instruction_set.reduce()
        self.instruction_set = instruction_set

    def set_coverage(self, coverage):
        self.coverage = coverage

    def create_test_case(self, asm_file: str, test_mode: bool = False, serial_mode: bool = False):
        """
        Create a simple test case with a single BB
        Run instrumentation passes and print the result into a file
        """
        self.test_case = TestCaseDAG()

        # create a test function and add to the test case
        function = self._generate_random_function("test_case_main", shuffle=False)
        self.test_case.functions.append(function)
        self.test_case.main = function

        # fill the test case with instructions
        SetTerminatorsPass(self.instruction_set).run_on_dag(self.test_case)
        AddRandomInstructionsPass(self.instruction_set, CONF.test_case_size, test_mode=test_mode). \
            run_on_dag(self.test_case)

        # process the test case
        passes = [
            SandboxPass()
        ]
        if serial_mode:
            passes.append(LFENCEPass())
        passes.append(PrinterPass(asm_file))

        for p in passes:
            p.run_on_dag(self.test_case)

        # measure coverage, if applicable
        if self.coverage:
            self.coverage.generator_hook(self.test_case, self.instruction_set)

    def _generate_random_function(self, name: str, shuffle: bool = False):
        """ Generates a random DAG of basic blocks within a function """
        function = Function(name)

        # Define the maximum allowed number of successors for any BB
        max_successors = 2 if self.instruction_set.has_conditional_branch else 1
        max_successors = CONF.max_bb_successors if CONF.max_bb_successors else max_successors
        min_successors = 2 if max_successors >= 2 else 1

        # Create basic blocks
        node_count = random.randint(CONF.min_bb_per_function, CONF.max_bb_per_function)
        nodes = [BasicBlock(f"bb{i}") for i in range(node_count)]

        # Connect BBs into a graph
        for i in range(node_count):
            current_bb = nodes[i]
            successor_count = random.randint(min_successors, max_successors)
            if successor_count + i >= node_count:
                successor_count = node_count - i - 1

            if successor_count <= 0:
                continue

            # one of the targets is always the next node - to avoid dead code
            current_bb.successors.append(nodes[i + 1])

            # all other successors are random, selected from next nodes
            options = nodes[i + 2:]
            for j in range(1, successor_count):
                target = random.choice(options)
                options.remove(target)
                current_bb.successors.append(target)

        function.entry.successors = [nodes[0]]
        nodes[-1].successors = [function.exit]

        if not shuffle:
            function.BBs = [function.entry] + nodes + [function.exit]
            return function

        # Shuffle them to make the function less straight-line + add entry and exit nodes
        function.BBs = [function.entry]
        while nodes:
            current_bb = random.choice(nodes)
            nodes.remove(current_bb)
            function.BBs.append(current_bb)
        function.BBs.append(function.exit)
        return function


class Pass(abc.ABC):
    @abc.abstractmethod
    def run_on_dag(self, DAG: TestCaseDAG) -> None:
        pass


class SetTerminatorsPass(Pass):
    def __init__(self, instruction_set: InstructionSet):
        self.instruction_set = instruction_set

    def run_on_dag(self, DAG: TestCaseDAG):
        for function in DAG.functions:
            for BB in function.BBs:
                if len(BB.successors) == 0:
                    # Return instruction
                    continue

                elif len(BB.successors) == 1:
                    # Unconditional branch
                    terminator = Instruction("JMP")
                    terminator.operands = [LabelOperand(BB.successors[0])]
                    BB.terminators.append(terminator)

                elif len(BB.successors) == 2:
                    # Conditional branch
                    spec = random.choice(self.instruction_set.control_flow)
                    terminator = Instruction(spec.name)
                    terminator.operands = [LabelOperand(BB.successors[0])]
                    BB.terminators.append(terminator)

                    terminator = Instruction("JMP")
                    terminator.operands = [LabelOperand(BB.successors[1])]
                    BB.terminators.append(terminator)
                else:
                    # Indirect jump
                    raise NotSupportedException()


class AddRandomInstructionsPass(Pass):
    # dense register encoding for GPRs
    gpr_decoding = [
        {64: "RAX", 32: "EAX", 16: "AX", 8: "AL"},
        {64: "RBX", 32: "EBX", 16: "BX", 8: "BL"},
        {64: "RCX", 32: "ECX", 16: "CX", 8: "CL"},
        {64: "RDX", 32: "EDX", 16: "DX", 8: "DL"},
        {64: "RSI", 32: "ESI", 16: "SI", 8: "SIL"},
        {64: "RDI", 32: "EDI", 16: "DI", 8: "DIL"},
        {64: "R8", 32: "R8D", 16: "R8W", 8: "R8B"},
        {64: "R9", 32: "R9D", 16: "R9W", 8: "R9B"},
        {64: "R10", 32: "R10D", 16: "R10W", 8: "R10B"},
        {64: "R11", 32: "R11D", 16: "R11W", 8: "R11B"},
        {64: "R12", 32: "R12D", 16: "R12W", 8: "R12B"},
        {64: "R13", 32: "R13D", 16: "R13W", 8: "R13B"},
    ]
    gprs_by_size = {64: [], 32: [], 16: [], 8: []}  # generated dynamically from grp_decoding

    def __init__(self, instruction_set: InstructionSet, max_length: int, test_mode: bool = False):
        self.instruction_set = instruction_set
        self.max_length = max_length
        self.test_mode = test_mode

        # remove blocked regs.
        filtered = []
        for reg in self.gpr_decoding:
            if reg[64] not in CONF.gpr_blocklist:
                filtered.append(reg)
                self.gprs_by_size[64].append(reg[64])
                self.gprs_by_size[32].append(reg[32])
                self.gprs_by_size[16].append(reg[16])
                self.gprs_by_size[8].append(reg[8])
        self.gpr_decoding = filtered

    def run_on_dag(self, DAG: TestCaseDAG) -> None:
        # sometimes, we might want to generate all possible instructions, for testing
        if self.test_mode:
            self.generate_all_instructions(DAG)
            return

        # otherwise, fill the DAG with random instructions
        for function in DAG.functions:
            max_per_bb = self.max_length // (len(function.BBs) - 2)
            for basic_block in function.BBs:
                if basic_block == function.entry or basic_block == function.exit:
                    continue

                for _ in range(max_per_bb):
                    instruction = self.generate_instruction()
                    basic_block.append_non_terminator(instruction)

    def generate_instruction(self) -> Instruction:
        instruction_spec: InstructionSpec

        # ensure the requested avg. number of mem. accesses
        is_memory_access = False
        if random.random() < CONF.avg_mem_accesses / CONF.test_case_size:
            is_memory_access = True

        # select a random instruction spec for generation
        while True:
            instruction_spec = random.choice(self.instruction_set.all)
            if instruction_spec.has_mem_operand == is_memory_access:
                break

        # fill up with random operand, following the spec
        instruction = Instruction(instruction_spec.name)
        for operand_spec in instruction_spec.operands:
            # generate an operand
            operand = self.get_operand_from_spec(operand_spec, instruction)
            instruction.operands.append(operand)

        # copy the implicit operands
        for operand_spec in instruction_spec.implicit_operands:
            operand = self.get_operand_from_spec(operand_spec, instruction)
            instruction.implicit_operands.append(operand)

        return instruction

    def generate_reg_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        reg_type = spec.choices[0]
        if reg_type == 'GPR':
            choices = self.gprs_by_size[spec.width]
        elif reg_type.startswith("SIMD"):
            choices = X86Registers.simd_decoding[reg_type]
        else:
            choices = spec.choices

        if not CONF.avoid_data_dependencies:
            reg = random.choice(choices)
            return RegisterOperand(reg, spec.src, spec.dest)

        if parent.latest_reg_operand and parent.latest_reg_operand.value in choices:
            return parent.latest_reg_operand

        reg = random.choice(choices)
        op = RegisterOperand(reg, spec.src, spec.dest)
        parent.latest_reg_operand = op
        return op

    def generate_mem_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        assert len(spec.choices) == 1
        prefix = spec.choices[0]

        base = random.choice(self.gpr_decoding)[64]
        return MemoryOperand(prefix, base, spec.src, spec.dest)

    @staticmethod
    def generate_imm_operand(spec: OperandSpec, parent: Instruction) -> Operand:
        assert len(spec.choices) == 0
        random_value = random.randint(pow(2, spec.width - 1) * -1, pow(2, spec.width - 1) - 1)
        return ImmediateOperand(str(random_value))

    def generate_label_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        raise NotSupportedException()

    def generate_agen_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        raise NotSupportedException()

    @staticmethod
    def generate_flags_operand(spec: OperandSpec, parent: Instruction) -> Operand:
        return FlagsOperand(spec.src, spec.dest)

    def get_operand_from_spec(self, spec: OperandSpec, parent: Instruction) -> Operand:
        generators = {
            OT.REG: self.generate_reg_operand,
            OT.MEM: self.generate_mem_operand,
            OT.IMM: self.generate_imm_operand,
            OT.LABEL: self.generate_label_operand,
            OT.AGEN: self.generate_agen_operand,
            OT.FLAGS: self.generate_flags_operand,
        }
        return generators[spec.type](spec, parent)

    def generate_all_instructions(self, DAG: TestCaseDAG):
        for function in DAG.functions:
            for basic_block in function:
                for instruction_spec in self.instruction_set.all:
                    # fill up with random operand, following the spec
                    instruction = Instruction(instruction_spec.name)

                    for operand_spec in instruction_spec.operands:
                        # generate an operand
                        operand = self.get_operand_from_spec(operand_spec, instruction)
                        instruction.operands.append(operand)

                    # copy the implicit operands
                    for operand_spec in instruction_spec.implicit_operands:
                        operand = self.get_operand_from_spec(operand_spec, instruction)
                        instruction.implicit_operands.append(operand)

                    basic_block.append_non_terminator(instruction)


class LFENCEPass(Pass):
    def run_on_dag(self, DAG: TestCaseDAG) -> None:
        for function in DAG.functions:
            for BB in function:
                insertion_points = []
                for instr in BB:
                    insertion_points.append(instr)  # make a copy to avoid infinite insertions

                for instr in insertion_points:
                    BB.insert_after(instr, Instruction("LFENCE", True))


class SandboxPass(Pass):
    sandbox_address_mask = "0b" + "1" * 6 + "0" * 6
    mask_3bits = "0b111"

    def __init__(self):
        if CONF.enable_mds:
            self.sandbox_address_mask = "0b" + "1" * 7 + "0" * 6

    def run_on_dag(self, DAG: TestCaseDAG) -> None:
        for function in DAG.functions:
            for BB in function.BBs:
                if BB == function.entry:
                    continue

                # collect all instructions that require sandboxing
                memory_instructions = []
                divisions = []
                bit_tests = []
                for I in BB:
                    if I.has_mem_operand():
                        memory_instructions.append(I)
                    if I.name in ["DIV", "REX DIV"]:
                        divisions.append(I)
                    elif I.name in ["BT", "BTC", "BTR", "BTS", "LOCK BT", "LOCK BTC", "LOCK BTR",
                                    "LOCK BTS"]:
                        bit_tests.append(I)

                # sandbox them
                for I in memory_instructions:
                    self.sandbox_memory_access(I, BB)

                for I in divisions:  # must be after memory accesses
                    self.sandbox_division(I, BB)

                for I in bit_tests:
                    self.sandbox_bit_test(I, BB)

    def sandbox_memory_access(self, instr: Instruction, parent: BasicBlock):
        """ Force the memory accesses into the page starting from R14 """
        assert len(instr.get_mem_operands()) == 1
        mem_reg = instr.get_mem_operands()[0].base
        apply_mask = Instruction("AND", True) \
            .add_op(RegisterOperand(mem_reg, True, True)) \
            .add_op(ImmediateOperand(self.sandbox_address_mask))
        align_to_r14 = Instruction("ADD", True) \
            .add_op(RegisterOperand(mem_reg, True, True)) \
            .add_op(RegisterOperand("R14", True, False))

        parent.insert_before(instr, apply_mask)
        parent.insert_before(instr, align_to_r14)

    @staticmethod
    def sandbox_division(I: Instruction, parent: BasicBlock):
        """
        1. Ensure that the divisor is never zero by ORing it with a random value.
        OR - because it guarantees that the result is not zero.
        Random value - to test various modes of operations in DIV.
        2. Truncate the source register pair RDX:RAX to prevent overflows in division.
        """
        divisor = I.operands[0]

        if divisor.value in ["RDX", "EDX", "DX", "DH", "DL", "RAX"]:
            # sandboxing is too complex, give up
            parent.delete(I)
            return

        zero_rdx = Instruction("MOV", True) \
            .add_op(RegisterOperand("RDX", False, True)) \
            .add_imm('0')
        parent.insert_before(I, zero_rdx)

        divisor_mask = hex(random.randint(1, 255))
        apply_divisor_mask = Instruction("OR", True).add_op(divisor).add_imm(divisor_mask)
        parent.insert_before(I, apply_divisor_mask)

        apply_ax_mask = Instruction("AND", True) \
            .add_op(RegisterOperand("RAX", True, True)) \
            .add_imm('0xff')
        parent.insert_before(I, apply_ax_mask)

    def sandbox_bit_test(self, I: Instruction, parent: BasicBlock):
        """
        The address accessed by a BT* instruction is based on both of its operands.
        `sandbox_memory_access` take care of the first operand.
        This function ensures that the offset is always within a byte.
        """
        address = I.operands[0]
        if isinstance(address, RegisterOperand):
            # this is a version that does not access memory
            # no need for sandboxing
            return

        offset = I.operands[1]
        if isinstance(offset, ImmediateOperand):
            # The offset is an immediate
            # Simply replace it with a smaller value
            offset.value = str(random.randint(0, 7))
            return

        # The offset is in a register
        # Mask its upper bits to reduce the stored value to at most 7
        if address.value != offset.value:
            apply_mask = Instruction("AND", True).add_op(offset).add_imm(self.mask_3bits)
            parent.insert_before(I, apply_mask)

        # Special case: offset and address use the same register
        # Sandboxing is impossible. Give up
        parent.delete(I)


class PrinterPass(Pass):
    def __init__(self, output_file: str):
        self.output_file = output_file

    def run_on_dag(self, DAG: TestCaseDAG):
        with open(self.output_file, "w") as f:
            cache_line_offset = random.randint(0, 63) if CONF.randomized_mem_alignment else 0
            f.write(".intel_syntax noprefix\n"
                    ".test_case_enter:\n"
                    "MFENCE # instrumentation\n"
                    f"LEA R14, [R14 + {cache_line_offset}] # instrumentation\n")

            if not CONF.single_function_test_case:
                f.write("CALL .test_case_main\n"
                        "JMP .test_case_exit\n")

            for function in DAG.functions:
                f.write(f".{function.name}:\n")
                for BB in function.BBs:
                    self.run_on_basic_block(BB, f)

            f.write(".test_case_exit:\n"
                    f"LEA R14, [R14 - {cache_line_offset}] # instrumentation\n"
                    "MFENCE # instrumentation\n")

    def run_on_basic_block(self, basic_block: BasicBlock, file):
        file.write(f".{basic_block.label}:\n")
        for i in basic_block:
            self.run_on_instruction(i, file)
        for i in basic_block.terminators:
            self.run_on_instruction(i, file)

    @staticmethod
    def run_on_instruction(instruction: Instruction, file):
        file.write(str(instruction) + "\n")
