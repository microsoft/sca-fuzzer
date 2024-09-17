"""
File: Collection of classes that represent instruction specifications.
The specifications typically originate from a JSON ISA spec file.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from dataclasses import dataclass
from enum import Enum
from typing import List


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

    def __str__(self):
        return str(self._name_)


@dataclass
class OperandSpec:
    """
    Specification of an operand in an instruction.
    Typically used in connection with an InstructionSpec.
    """

    values: List[str]
    """ List of operand values (e.g., register names, immediate values). """

    type: OT
    """ Type of the operand (e.g., register, memory, immediate). """

    width: int
    """ Width of the operand in bits, if applicable (e.g., 64 for 64-bit register). """

    src: bool
    """ Indicates if the operand is a source; i.e., if it is read by the instruction. """

    dest: bool
    """ Indicates if the operand is a destination; i.e., if it is written by the instruction. """

    signed: bool = True
    """ Indicates if the operand is signed. """

    magic_value: bool = False
    """ Indicates if the operand has a special value that requires unique handling.
    (e.g., separate opcode when RAX is a destination)
    """

    def __init__(self, values: List[str], type_: OT, src: bool, dest: bool):
        self.values = values
        self.type = type_
        self.src = src
        self.dest = dest
        self.width = 0

    def __str__(self):
        return f"{self.values}"


@dataclass
class InstructionSpec:
    """
    Specification of an instruction.
    Typically originates from a JSON specification file (base.json).
    """

    name: str
    """ Name of the instruction. """

    operands: List[OperandSpec]
    """ List of explicit operands for the instruction. """

    implicit_operands: List[OperandSpec]
    """ List of implicit operands for the instruction. """

    category: str
    """ Category of the instruction. Originates from the JSON specification file. """

    control_flow: bool = False
    """ Indicates if the instruction alters control flow (e.g., jumps, calls). """

    has_mem_operand: bool = False
    """ Indicates if the instruction has a memory operand. """

    has_write: bool = False
    """ Indicates if the instruction writes to a destination operand. """

    has_magic_value: bool = False
    """ Indicates if the instruction has a special value that requires unique handling. """

    def __init__(self):
        self.operands = []
        self.implicit_operands = []

    def __str__(self):
        ops = ""
        for o in self.operands:
            ops += str(o) + " "
        return f"{self.name} {ops}"

    def __hash__(self) -> int:
        return hash(str(self))
