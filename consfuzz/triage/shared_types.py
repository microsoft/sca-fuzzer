"""
File: Types shared between different modules of the inspector.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from enum import Enum


type RegId = int
type RegName = str
type MemAddr = int
type TraceLineNum = int

class UseType(Enum):
    """
    Indicates a register or memory use.
    """
    MEM = 0
    REG = 1


class Use:
    """
    Indicates a use of a specific register/memory value.
    """
    use_type: UseType
    addr: RegId | MemAddr

    def __init__(self, use_type: UseType, addr: RegId | MemAddr) -> None:
        self.use_type = use_type
        self.addr = addr

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.use_type == other.use_type) and (self.addr == other.addr)
        else:
            return False

    def __hash__(self):
        return hash((self.use_type, self.addr))
