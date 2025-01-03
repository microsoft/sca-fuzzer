"""
File: Collection of classes that represent instruction specifications.
The specifications typically originate from a JSON ISA spec file.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from dataclasses import dataclass
from enum import Enum
from typing import List, Final, Tuple


class OT(Enum):
    """
    Enumeration class representing an Operand Type (OT) of an instruction.
    """
    REG = 1  # Register Operand
    MEM = 2  # Memory Operand
    IMM = 3  # Immediate Operand
    LABEL = 4  # Label Operand
    AGEN = 5  # Memory address in LEA instructions
    FLAGS = 6  # Flags Operand
    COND = 7  # Condition Operand

    def __str__(self) -> str:
        return str(self._name_)  # pylint: disable=no-member  # This is an intended private use


@dataclass
class OperandSpec:
    """
    Specification of an operand in an instruction.
    Typically used in connection with an InstructionSpec.
    """

    values: Final[Tuple[str, ...]]
    """ List of operand values (e.g., register names, immediate values). """

    type: Final[OT]
    """ Type of the operand (e.g., register, memory, immediate). """

    width: Final[int]
    """ Width of the operand in bits, if applicable (e.g., 64 for 64-bit register). """

    src: bool
    """ Indicates if the operand is a source; i.e., if it is read by the instruction. """

    dest: bool
    """ Indicates if the operand is a destination; i.e., if it is written by the instruction. """

    is_signed: Final[bool]
    """ Indicates if the operand is signed. """

    has_magic_value: Final[bool]
    """ Indicates if the operand has a special value that requires unique handling.
    (e.g., separate opcode when RAX is a destination)
    """

    def __init__(self,
                 values: List[str],
                 type_: OT,
                 src: bool,
                 dest: bool,
                 width: int = 0,
                 is_signed: bool = True,
                 has_magic_value: bool = False):
        self.values = tuple(values)
        self.type = type_
        self.src = src
        self.dest = dest
        self.width = width
        self.is_signed = is_signed
        self.has_magic_value = has_magic_value

    def __str__(self) -> str:
        return "(" + ", ".join(self.values) + ")"


@dataclass
class InstructionSpec:
    """
    Specification of an instruction.
    Typically originates from a JSON specification file (base.json).
    """

    name: Final[str]
    """ Name of the instruction. """

    category: Final[str]
    """ Category of the instruction. Originates from the JSON specification file. """

    is_control_flow: Final[bool]
    """ Indicates if the instruction alters control flow (e.g., jumps, calls). """

    operands: List[OperandSpec]
    """ List of explicit operands for the instruction. """

    implicit_operands: List[OperandSpec]
    """ List of implicit operands for the instruction. """

    has_mem_operand: bool = False
    """ Indicates if the instruction has a memory operand. """

    has_write: bool = False
    """ Indicates if the instruction writes to a destination operand. """

    has_magic_value: bool = False
    """ Indicates if the instruction has a special value that requires unique handling. """

    def __init__(self, name: str, category: str, is_control_flow: bool = False):
        self.name = name
        self.category = category
        self.is_control_flow = is_control_flow

        self.operands = []
        self.implicit_operands = []

    def __str__(self) -> str:
        ops = ""
        for o in self.operands:
            ops += str(o) + " "
        return f"{self.name} {ops}"

    def __hash__(self) -> int:
        return hash(str(self))
