"""
File: Interface to target description classes.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, NamedTuple
from enum import Enum


class Vendor(Enum):
    """ Enumeration class representing the CPU vendor. """
    INTEL = 0
    AMD = 1
    UNKNOWN = 2


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


class TargetDesc(ABC):
    """ Abstract class defining the interface to target description classes. """

    register_sizes: Dict[str, int]
    """ Dictionary mapping register names to their sizes in bits. """

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
    def is_unconditional_branch(inst) -> bool:
        pass

    @staticmethod
    @abstractmethod
    def is_call(inst) -> bool:
        pass

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
