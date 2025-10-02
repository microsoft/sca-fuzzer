"""
File: Collection of classes to represent instructions in a test case program and their components.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
from typing import List, Optional, Final, Literal, Union, Type, Tuple, get_args, cast
from typing_extensions import assert_never

from ..instruction_spec import OT, InstructionSpec, OperandSpec

FlagType = Literal['r', 'w', 'r/w', 'r/cw', 'undef']
RegSize = Literal[8, 16, 32, 64, 128, 256]


# ==================================================================================================
# Operands
# ==================================================================================================
@dataclass
class Operand(ABC):
    """ Operand of an instruction """

    value: str
    """ The value of the operand, e.g., name of a register, memory address, etc. """

    src: Final[bool]
    """ If True, the operand is a source operand """

    dest: Final[bool]
    """ If True, the operand is a destination operand """

    has_magic_value: bool = False
    """
    If True, the operand value has special meaning for the parent instruction.
    Special meaning is normally a separate opcode or encoding,
    such as when shift by 1 is a separate opcode.
    """

    def __init__(self, value: str, src: bool, dest: bool):
        self.value = value.lower()
        self.src = src
        self.dest = dest
        super().__init__()

    @classmethod
    def from_fixed_spec(cls, spec: OperandSpec) -> AnyOperand:  # pylint: disable=r1710,r0911
        """
        Create an Operand instance from a fixed operand specification.
        Fixed means that the specification does not have any multiple-option fields
        (e.g., only one possible value).
        :param spec: The operand specification
        :return: The Operand instance of the type that corresponds to the specification
        """
        # NOTE on pylint disable above:
        # - r1710 - mitigates a false positive due to assert_never
        # - r0911 - the large number of returns is a good design choice here

        assert len(spec.values) <= 1 or spec.type == OT.FLAGS, \
            f"Attempt to call from_fixed_spec with a non-fixed spec {spec.values}"
        value = spec.values[0] if spec.values else ""
        if spec.type == OT.REG:
            return RegisterOp(value, spec.width, spec.src, spec.dest)
        if spec.type == OT.MEM:
            return MemoryOp(value, spec.width, spec.src, spec.dest)
        if spec.type == OT.IMM:
            return ImmediateOp(value, spec.width)
        if spec.type == OT.LABEL:
            return LabelOp(value)
        if spec.type == OT.AGEN:
            return AgenOp(value, spec.width)
        if spec.type == OT.FLAGS:
            return FlagsOp(spec.values)
        if spec.type == OT.COND:
            return CondOp(value)
        assert_never(spec.type)
        # unreachable, hence no return


class RegisterOp(Operand):
    """ Register operand of an instruction """

    width: Final[RegSize]

    def __init__(self, value: str, width: int, src: bool, dest: bool):
        assert width in get_args(RegSize), f"Invalid register width {width} for register {value}"
        self.width = cast(RegSize, width)
        super().__init__(value, src, dest)


class MemoryOp(Operand):
    """ Memory operand of an instruction """

    width: Final[int]

    def __init__(self, address: str, width: int, src: bool, dest: bool) -> None:
        self.width = width
        super().__init__(address, src, dest)

    def get_base_register(self) -> Optional[RegisterOp]:
        """
        Get the base register of the memory operand, if any.
        E.g., for [rax + 8], return rax.
        :return: The base register, or None if there is no base register
        """
        addr = self.value.strip()

        # Split by + and - to find base register
        tokens = [t.strip() for t in addr.replace('-', '+').split('+')]

        # Filter out numeric tokens
        tokens = [t for t in tokens if not t.replace('0x', '').isdigit()]
        tokens = [t for t in tokens if not t.replace('0b', '').isdigit()]

        for t in tokens:
            # the first non-numeric token is the base register
            return RegisterOp(t.lower(), self.width, True, False)
        return None


class ImmediateOp(Operand):
    """ Immediate operand of an instruction """

    width: Final[int]

    def __init__(self, value: str, width: int) -> None:
        self.width = width
        super().__init__(value, True, False)


class LabelOp(Operand):
    """ Label operand of an instruction """

    def __init__(self, value: str) -> None:
        super().__init__(value, True, False)


class AgenOp(Operand):
    """ Address generation operand of an instruction (used by LEA instruction) """

    width: Final[int]

    def __init__(self, value: str, width: int) -> None:
        self.width = width
        super().__init__(value, True, False)


class FlagsOp(Operand):
    """ Flags operand of an instruction """

    _flag_values: Final[Tuple[str, ...]]
    _flag_names: Final[Tuple[str, ...]] = ("CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF")

    def __init__(self, value: Tuple[str, ...]) -> None:
        assert len(value) == len(self._flag_names)
        self._flag_values = value
        super().__init__("FLAGS", False, False)

    def __str__(self) -> str:
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

    def _get_flag_list(self, types: List[FlagType]) -> List[str]:
        """
        Get a list of flags with the specified types.
        :param types: A list of flag types to include
        :return: A list of flags
        """
        flags = []
        for i, type_ in enumerate(self._flag_values):
            if type_ in types:
                flags.append(self._flag_names[i])
        return flags

    def get_flags_by_type(self, type_: Literal['read', 'write', 'overwrite', 'undef']) -> List[str]:
        """
        Get a list of flags with the specified types.
        :param types: Type of flags to include (read, write, overwrite, undef)
        :return: A list of flags
        """
        flag_types: List[FlagType]
        if type_ == "read":
            flag_types = ['r', 'r/w', 'r/cw']
        elif type_ == "write":
            flag_types = ['w', 'r/w', 'r/cw']
        elif type_ == "overwrite":
            flag_types = ['w']
        elif type_ == "undef":
            flag_types = ['undef']
        else:
            assert_never(type_)

        return self._get_flag_list(flag_types)


@dataclass
class CondOp(Operand):
    """ Condition operand of an instruction """

    def __init__(self, value: str) -> None:
        super().__init__(value, True, False)


# ==================================================================================================
# Operand Modification Interface
# ==================================================================================================
_ValueModifiableOperand = Union[RegisterOp, MemoryOp, ImmediateOp, LabelOp, AgenOp, CondOp]
_SrcDestModifiableOperand = Union[RegisterOp, MemoryOp]
AnyOperand = Union[RegisterOp, MemoryOp, ImmediateOp, LabelOp, AgenOp, CondOp, FlagsOp]


def copy_op_with_value_modification(op: _ValueModifiableOperand,
                                    value: str) -> _ValueModifiableOperand:
    """
    Make a copy of an operand with a modification to its value
    :param op: The operand to copy
    :param value: The new value of the operand
    :return: The modified operand
    """
    if isinstance(op, RegisterOp):
        return RegisterOp(value, op.width, op.src, op.dest)
    if isinstance(op, MemoryOp):
        return MemoryOp(value, op.width, op.src, op.dest)
    if isinstance(op, ImmediateOp):
        return ImmediateOp(value, op.width)
    if isinstance(op, LabelOp):
        return LabelOp(value)
    if isinstance(op, AgenOp):
        return AgenOp(value, op.width)
    if isinstance(op, CondOp):
        return CondOp(value)
    assert_never(op)


def copy_op_with_flow_modification(op: _SrcDestModifiableOperand,
                                   src: Optional[bool] = None,
                                   dest: Optional[bool] = None) -> _SrcDestModifiableOperand:
    """
    Make a copy of an operand with modifications to its flow properties
    :param op: The operand to copy
    :param src: If not None, the new src property of the operand
    :param dest: If not None, the new dest property of the operand
    :return: The modified operand
    """
    if src is None:
        src = op.src
    if dest is None:
        dest = op.dest

    if isinstance(op, RegisterOp):
        return RegisterOp(op.value, op.width, src, dest)
    if isinstance(op, MemoryOp):
        return MemoryOp(op.value, op.width, src, dest)
    assert_never(op)


# ==================================================================================================
# Instructions and Symbols
# ==================================================================================================
class Instruction:
    """ Instruction in a test case program """

    # pylint: disable=too-many-instance-attributes
    # NOTE: This is a data container class, so it is expected to have many attributes
    # pylint: disable=too-many-public-methods
    # NOTE: This contains separate accessors for each operand type,
    # so it is expected to have many methods

    name: Final[str]
    """ name: The name of the instruction without any operands """
    category: Final[str]
    """ category: The category of the instruction, e.g., BASE-BINARY. The keyword matches
    the category in the instruction set description file (typically called base.json)"""

    is_control_flow: Final[bool]
    """ _control_flow: If True, the instruction is a control flow instruction
    (branch, call, return, etc.) """
    is_instrumentation: Final[bool]
    """ _is_instrumentation: If True, the instruction is an instrumentation instruction,
    which means that it was inserted by the generator to prevent faults or false positives """
    is_noremove: Final[bool]
    """ is_noremove: If True, the instruction should be skipped while doing minimization passes """
    is_from_template: bool = False
    """ is_from_template: If True, the instruction was directly copied from the template rather
    then being automatically created by the generator. """
    is_macro_placeholder: bool = False
    """ is_macro_placeholder: If True, this instruction is a part of a placeholder that will be
    replaced by a macro call in the executor/model; this instruction is expected to be a NOP.
    For most instructions, this is always False. """

    operands: Final[List[AnyOperand]]
    """ operands: List of explicit operands of the instruction """
    implicit_operands: Final[List[AnyOperand]]
    """ implicit_operands: List of implicit operands, which are not explicitly specified in the
    instruction but are used by the instruction. For example, flags operand in x86 instructions """

    _line_num: int = -1  # line number in the source asm; access via line_num()
    _section_id: int = -1  # section ID in the object file; access via section_id()
    _section_offset: int = -1  # instruction offset in the section; access via section_offset()
    _size: int = -1  # size of the instruction in bytes; access via size()
    _inst_brief: str = ""  # cached brief representation of the instruction

    # ----------------------------------------------------------------------------------------------
    # Constructors

    def __init__(self,
                 name: str,
                 category: str = "",
                 is_control_flow: bool = False,
                 is_instrumentation: bool = False,
                 is_noremove: bool = False) -> None:
        self.name = name
        self.category = category
        self.is_control_flow = is_control_flow
        self.is_instrumentation = is_instrumentation
        self.is_noremove = is_noremove

        self.operands = []
        self.implicit_operands = []

    @classmethod
    def from_spec(cls: Type[Instruction],
                  sp: InstructionSpec,
                  is_instrumentation: bool = False,
                  is_noremove: bool = False) -> Instruction:
        """
        Create an instruction with NO OPERANDS from an instruction specification.
        :param spec: The instruction specification
        :param is_instrumentation: If True, the instruction is an instrumentation instruction
        :param is_noremove: If True, the instruction be kept during minimization
        :return: The instruction
        """
        obj = cls(
            sp.name,
            sp.category,
            sp.is_control_flow,
            is_instrumentation=is_instrumentation,
            is_noremove=is_noremove)
        return obj

    # ----------------------------------------------------------------------------------------------
    # Printing

    def __str__(self) -> str:
        op_list = [
            "[" + o.value + "]" if isinstance(o, MemoryOp) else o.value for o in self.operands
        ]
        operands = ', '.join(op_list)
        return f"{self.name} {operands}"

    # ----------------------------------------------------------------------------------------------
    # Operand Management

    def add_op(self, op: AnyOperand, implicit: bool = False) -> Instruction:
        """
        Add operand to the instruction. Returns the instruction for chaining.
        :param op: Operand to add
        :param implicit: If True, the operand is implicit
        :return: The instruction
        """
        if not implicit:
            self.operands.append(op)
        else:
            self.implicit_operands.append(op)
        return self

    def has_mem_operand(self, include_implicit: bool) -> bool:
        """
        Check if the instruction has a memory operand.
        :param include_implicit: If True, include implicit operands in the check
        :return: True if the instruction has a memory operand, False otherwise
        """
        for o in self.operands:
            if isinstance(o, MemoryOp):
                return True
        if include_implicit:
            for o in self.implicit_operands:
                if isinstance(o, MemoryOp):
                    return True
        return False

    def has_write(self, include_implicit: bool = False) -> bool:
        """
        Check if the instruction has a memory operand that writes to memory.
        :param include_implicit: If True, include implicit operands in the check
        :return: True if the instruction has a memory operand that writes to memory, False otherwise
        """
        for o in self.operands:
            if isinstance(o, MemoryOp) and o.dest:
                return True
        if include_implicit:
            for o in self.implicit_operands:
                if isinstance(o, MemoryOp) and o.dest:
                    return True
        return False

    def has_read(self, include_implicit: bool = False) -> bool:
        """
        Check if the instruction has a memory operand that reads from memory.
        :param include_implicit: If True, include implicit operands in the check
        :return: True if the instruction has a memory operand that reads memory, False otherwise
        """
        for o in self.operands:
            if isinstance(o, MemoryOp) and o.src:
                return True
        if include_implicit:
            for o in self.implicit_operands:
                if isinstance(o, MemoryOp) and o.src:
                    return True
        return False

    def get_all_operands(self) -> List[AnyOperand]:
        """
        Get a list of all operands of the instruction,
        including both explicit and implicit operands.
        :return: A list of all operands
        """
        return self.operands + self.implicit_operands

    def get_src_operands(self, include_implicit: bool = False) -> List[AnyOperand]:
        """
        Get a list of source operands of the instruction.
        :param include_implicit: If True, include implicit operands in the list
        :return: A list of source operands
        """
        res = []
        for o in self.operands:
            if o.src:
                res.append(o)
        if include_implicit:
            for o in self.implicit_operands:
                if o.src:
                    res.append(o)
        return res

    def get_dest_operands(self, include_implicit: bool = False) -> List[AnyOperand]:
        """
        Get a list of destination operands of the instruction.
        :param include_implicit: If True, include implicit operands in the list
        :return: A list of destination operands
        """
        res = []
        for o in self.operands:
            if o.dest:
                res.append(o)
        if include_implicit:
            for o in self.implicit_operands:
                if o.dest:
                    res.append(o)
        return res

    def get_mem_operands(self,
                         include_explicit: bool = True,
                         include_implicit: bool = False) -> List[MemoryOp]:
        """
        Get a list of memory operands of the instruction.
        :param include_implicit: If True, include implicit operands in the list
        :return: A list of memory operands
        """
        assert include_explicit or include_implicit, "At least one of include_explicit or " \
                                                     "include_implicit must be True"
        res = []
        if include_explicit:
            for o in self.operands:
                if isinstance(o, MemoryOp):
                    res.append(o)
        if include_implicit:
            for o in self.implicit_operands:
                if isinstance(o, MemoryOp):
                    res.append(o)
        return res

    def get_flags_operand(self) -> Optional[FlagsOp]:
        """
        Get the flags operand of the instruction.
        :return: The flags operand, or None if the instruction does not have one
        """
        for o in self.implicit_operands:
            if isinstance(o, FlagsOp):
                return o
        for o in self.operands:
            if isinstance(o, FlagsOp):
                return o
        return None

    def get_reg_operands(self, include_implicit: bool = False) -> List[RegisterOp]:
        """
        Get a list of register operands of the instruction.
        :param include_implicit: If True, include implicit operands in the list
        :return: A list of register operands
        """
        res = []
        for o in self.operands:
            if isinstance(o, RegisterOp):
                res.append(o)
        if include_implicit:
            for o in self.implicit_operands:
                if isinstance(o, RegisterOp):
                    res.append(o)
        return res

    def get_cond_operand(self) -> Optional[CondOp]:
        """
        Get the condition operand of the instruction.
        :return: The condition operand, or None if the instruction does not have one
        """
        for o in self.operands:
            if isinstance(o, CondOp):
                return o
        # not checking implicit operands -> conditions must be explicit
        return None

    def get_label_operand(self) -> Optional[LabelOp]:
        """
        Get the label operand of the instruction.
        :return: The label operand, or None if the instruction does not have one
        """
        for o in self.operands:
            if isinstance(o, LabelOp):
                return o
        # not checking implicit operands -> labels must be explicit
        return None

    def get_imm_operands(self, include_implicit: bool = False) -> List[ImmediateOp]:
        """
        Get a list of immediate operands of the instruction.
        :param include_implicit: If True, include implicit operands in the list
        :return: A list of immediate operands
        """
        res = []
        for o in self.operands:
            if isinstance(o, ImmediateOp):
                res.append(o)
        if include_implicit:
            for o in self.implicit_operands:
                if isinstance(o, ImmediateOp):
                    res.append(o)
        return res

    def get_agen_operands(self) -> List[AgenOp]:
        """
        Get a list of address generation operands of the instruction.
        :return: A list of address generation operands
        """
        res = []
        for o in self.operands:
            if isinstance(o, AgenOp):
                res.append(o)
        # not checking implicit operands -> agen must be explicit
        return res

    # ----------------------------------------------------------------------------------------------
    # Instruction in Assembly
    def assign_line_num(self, line_num: int) -> None:
        """ Assign the line number in the source file where the instruction is located. """
        assert self._line_num == -1, "Line number is already assigned"
        self._line_num = line_num

    def line_num(self) -> int:
        """ Get the line number in the source file where the instruction is located. """
        assert self._line_num != -1, "Line number is not assigned"
        return self._line_num

    # ----------------------------------------------------------------------------------------------
    # Instruction in Binary
    def assign_binary_properties(self, section_id: int, offset: int, size: int) -> None:
        """
        Assign properties of the instruction in the binary file after it has been assembled.
        :param section_id: The ID of the section in the object file where the instruction is located
        :param offset: The section offset of the instruction in the object file
        :param size: The size of the instruction in bytes, after it has been assembled
        """
        assert self._section_id == -1, "Instruction properties are already assigned \n" \
            "    (assign_binary_properties() can only be called once)"
        self._section_id = section_id
        self._section_offset = offset
        self._size = size

    def section_id(self) -> int:
        """ Get the ID of the section in the object file where the instruction is located. """
        assert self._section_id != -1, "Instruction properties are not assigned \n" \
            "    (assign_binary_properties() must be called before section_id() can be used)"
        return self._section_id

    def section_offset(self) -> int:
        """ Get the section offset of the instruction in the object file. """
        assert self._section_offset != -1, "Instruction properties are not assigned \n" \
            "    (assign_binary_properties() must be called before section_offset() can be used)"
        return self._section_offset

    def size(self) -> int:
        """ Get the size of the instruction in bytes. """
        assert self._size != -1, "Instruction properties are not assigned \n" \
            "    (assign_binary_properties() must be called before size() can be used)"
        return self._size


def copy_inst_with_modification(instruction: Instruction,
                                name: Optional[str] = None,
                                category: Optional[str] = None,
                                is_control_flow: Optional[bool] = None,
                                is_instrumentation: Optional[bool] = None,
                                is_noremove: Optional[bool] = None) -> Instruction:
    """
    Make a copy of an instruction with modifications to its properties
    :param instruction: The instruction to copy
    :param name: If not None, the new name of the instruction
    :param category: If not None, the new category of the instruction
    :param is_control_flow: If not None, the new is_control_flow property of the instruction
    :param is_instrumentation: If not None, the new is_instrumentation property of the instruction
    :param is_noremove: If not None, the new is_noremove property of the instruction
    :return: The new modified instruction
    """
    if name is None:
        name = instruction.name
    if category is None:
        category = instruction.category
    if is_control_flow is None:
        is_control_flow = instruction.is_control_flow
    if is_instrumentation is None:
        is_instrumentation = instruction.is_instrumentation
    if is_noremove is None:
        is_noremove = instruction.is_noremove

    new_inst = Instruction(name, category, is_control_flow, is_instrumentation, is_noremove)
    new_inst.is_from_template = instruction.is_from_template
    new_inst.is_macro_placeholder = instruction.is_macro_placeholder
    new_inst.operands.extend(instruction.operands.copy())
    new_inst.implicit_operands.extend(instruction.implicit_operands.copy())
    new_inst._section_id = instruction._section_id  # pylint: disable=protected-access
    new_inst._section_offset = instruction._section_offset  # pylint: disable=protected-access
    new_inst._size = instruction._size  # pylint: disable=protected-access
    new_inst._line_num = instruction._line_num  # pylint: disable=protected-access

    return new_inst
