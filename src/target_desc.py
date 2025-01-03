"""
File: Architectural details of the target platform,
such as register sizes, register names, and CPU description.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, NamedTuple, Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from .tc_components.instruction import Instruction

# ==================================================================================================
# Custom Types
# ==================================================================================================
Vendor = Literal["Intel", "AMD", "Unknown"]
RegSize = Literal[8, 16, 32, 64, 128]
RegName = str
RegNormalizedName = str
RegUnicornID = int
PTEName = str
EPTEName = str
PTEBitOffset = int


# ==================================================================================================
# Use-case Specific Descriptors
# ==================================================================================================
class CPUDesc(NamedTuple):
    """ CPU description. """

    vendor: Vendor
    model: int
    family: int
    stepping: int


class MacroSpec(NamedTuple):
    """ Macro specification. """

    type_: int
    name: str
    args: Tuple[str, str, str, str]


class UnicornTargetDesc:  # pylint: disable=too-few-public-methods
    """ Target description in the context of a Unicorn-based model """

    usable_registers: List[RegUnicornID]
    """ List of Unicorn register IDs that are used by test cases on the target platform. """

    usable_simd128_registers: List[RegUnicornID]
    """ List of Unicorn SIMD register IDs that are used by test cases on the target platform. """

    reg_str_to_constant: Dict[RegName, RegUnicornID]
    """ Mapping from register names to their Unicorn constants. """

    reg_norm_to_constant: Dict[RegNormalizedName, RegUnicornID]
    """ Mapping from normalized register names to their Unicorn constants. """

    barriers: List[str]
    """ List of instruction names that are considered as speculation barriers """

    flags_register: RegUnicornID
    """ Unicorn register ID of the flags register """

    pc_register: RegUnicornID
    """ Unicorn register ID of the program counter register """

    sp_register: RegUnicornID
    """ Unicorn register ID of the stack pointer register """

    actor_base_register: RegUnicornID
    """ Unicorn register ID of the register that holds the base address of the active actor """


# ==================================================================================================
# Main Target Description
# ==================================================================================================
class TargetDesc(ABC):
    """ Abstract class defining the interface to target description classes. """

    cpu_desc: CPUDesc
    """ Terget CPU description. """

    macro_specs: Dict[str, MacroSpec]
    """ Dictionary of all macro specifications available for the given target """

    uc_target_desc: UnicornTargetDesc
    """ Target description in the context of a Unicorn-based model """

    register_sizes: Dict[RegName, RegSize]
    """ Dictionary mapping register names to their sizes in bits. """

    registers_by_size: Dict[RegSize, List[RegName]]
    """ Dictionary with lists of all registers for a given size. """

    reg_normalized: Dict[RegName, RegNormalizedName]
    """ Mapping from full register names to normalized size-independent names. E.g., rax -> A"""

    reg_denormalized: Dict[RegNormalizedName, Dict[RegSize, RegName]]
    """ Reverse mapping from normalized names to full register names.
    E.g., A -> {64: rax, 32: eax, 16: ax, 8: al} """

    pte_bits: Dict[PTEName, Tuple[PTEBitOffset, bool]]
    """
    Dictionary mapping page table entry field names to their bit offsets and their default values.
    """

    epte_bits: Dict[EPTEName, Tuple[PTEBitOffset, bool]]
    """
    Dictionary mapping extended page table entry field names to their bit offsets
    and their default values.
    """

    branch_conditions: Dict[str, List[str]]
    """ Dictionary mapping branch instructions to their condition codes. """

    @staticmethod
    @abstractmethod
    def is_unconditional_branch(inst: Instruction) -> bool:
        """ Check if the instruction is an unconditional branch. """

    @staticmethod
    @abstractmethod
    def is_call(inst: Instruction) -> bool:
        """ Check if the instruction is a call. """

    def get_macro_spec_from_type(self, type_: int) -> MacroSpec:
        """
        Get the macro specification of a given macro type.
        :param type_: macro type
        :return: macro specification
        """
        for macro_spec in self.macro_specs.values():
            if macro_spec.type_ == type_:
                return macro_spec
        raise KeyError(f"Unknown macro type: {type_}")
