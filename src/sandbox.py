"""
File: Constants defining the memory layout for the data and code sandboxes,
      which should be identical between the executor and the model.
      See docs/sandbox.md for more information.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from enum import Enum
from typing import Dict, List, Tuple, TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from .tc_components.test_case_code import TestCaseProgram

PAGE_SIZE = 4096

SandboxAddr = int
DataAddr = SandboxAddr
CodeAddr = SandboxAddr
BaseAddrTuple = Tuple[DataAddr, CodeAddr]


# ==================================================================================================
# Area Enumerations
# ==================================================================================================
class DataArea(Enum):
    """
    Enumeration class representing data areas in the sandbox.
    """
    START = 0
    MACRO_STACK = 1
    UNDERFLOW_PAD = 2
    MAIN = 3
    FAULTY = 4
    REG_INIT = 5
    GPR = 6
    SIMD = 7
    OVERFLOW_PAD = 8
    RSP_INIT = 9


class CodeArea(Enum):
    """
    Enumeration class representing code areas in the sandbox.
    """
    START = 0
    MAIN = 1
    MACRO = 2


# ==================================================================================================
# Sandbox Layout Class
# ==================================================================================================
class SandboxLayout:
    """
    Layout of the data and code sandboxes. This class is responsible for ensuring
    consistency of memory layouts between the executor, the model, and the generators.
    """
    data_start: DataAddr
    data_end: DataAddr
    code_start: CodeAddr
    code_end: CodeAddr

    _data_addresses: List[Dict[DataArea, DataAddr]]
    _code_addresses: List[Dict[CodeArea, CodeAddr]]

    # NOTE: the constants in _DataAreaLayout and _CodeAreaLayout *must* be identical
    # to the actor_data_t and actor_code_t in executor (src/x86/executor/include/sandbox_manager.h)
    _DataAreaLayout = np.dtype(
        [
            ('MACRO_STACK', np.uint8, 64),
            ('UNDERFLOW_PAD', np.uint8, PAGE_SIZE - 64),
            ('MAIN', np.uint8, PAGE_SIZE),
            ('FAULTY', np.uint8, PAGE_SIZE),
            ('GPR', np.uint8, 64),  # 8 64-bit GPRs
            ('SIMD', np.uint8, 256),  # 8 256-bit YMMs
            ('OVERFLOW_PAD', np.uint8, PAGE_SIZE - 64 - 256),
        ],
        align=False,
    )

    _CodeAreaLayout = np.dtype(
        [
            ('MAIN', np.uint8, 2 * PAGE_SIZE),
            ('MACRO', np.uint8, PAGE_SIZE),
        ],
        align=False,
    )

    # ==============================================================================================
    # Constant Accessors
    # ==============================================================================================
    @classmethod
    def data_area_size(cls, area: DataArea) -> int:
        """
        Get the size of a specific area in the data sandbox.
        :param area: The area to get the size of.
        :return: The size of the area in bytes.
        """
        return cls._DataAreaLayout[area.name].itemsize

    @classmethod
    def data_area_offset(cls, area: DataArea) -> int:
        """
        Get the offset of a specific area in the data sandbox.
        :param area: The area to get the offset of.
        :return: The offset of the area in bytes.
        """
        if area == DataArea.START:
            return 0
        if area == DataArea.REG_INIT:
            return cls._DataAreaLayout.fields['GPR'][1]  # type: ignore
        if area == DataArea.RSP_INIT:
            return cls._DataAreaLayout.fields['FAULTY'][1] - 8  # type: ignore
        return cls._DataAreaLayout.fields[area.name][1]  # type: ignore

    @classmethod
    def data_size_per_actor(cls) -> int:
        """
        Get the size of the data sandbox for a single actor.
        :return: The size of the data sandbox for a single actor in bytes.
        """
        return cls._DataAreaLayout.itemsize

    @classmethod
    def code_area_size(cls, area: CodeArea) -> int:
        """
        Get the size of a specific area in the code sandbox.
        :param area: The area to get the size of.
        :return: The size of the area in bytes.
        """
        return cls._CodeAreaLayout[area.name].itemsize

    @classmethod
    def code_area_offset(cls, area: CodeArea) -> int:
        """
        Get the offset of a specific area in the code sandbox.
        :param area: The area to get the offset of.
        :return: The offset of the area in bytes.
        """
        if area == CodeArea.START:
            return 0
        return cls._CodeAreaLayout.fields[area.name][1]  # type: ignore

    @classmethod
    def code_size_per_actor(cls) -> int:
        """
        Get the size of the code sandbox for a single actor.
        :return: The size of the code sandbox for a single actor in bytes.
        """
        return cls._CodeAreaLayout.itemsize

    # ==============================================================================================
    # Object Interface
    # ==============================================================================================
    def __init__(self, bases: BaseAddrTuple, n_actors: int):
        # Data boundaries
        self.data_start = bases[0]
        self.data_size = self._DataAreaLayout.itemsize * n_actors
        self.data_end = bases[0] + self.data_size
        assert self.data_size % PAGE_SIZE == 0

        # Code boundaries
        self.code_start = bases[1]
        self.code_size = self._CodeAreaLayout.itemsize * n_actors
        self.code_end = bases[1] + self.code_size
        assert self.code_size % PAGE_SIZE == 0

        # Pre-compute data and code addresses
        # Note: This is makes sense because we assume that the object will be initialized
        # once and used many times.
        self._data_addresses = []
        for actor_id in range(n_actors):
            actor_data_start = self.data_start + actor_id * self.data_size_per_actor()
            self._data_addresses.append(
                {area: actor_data_start + self.data_area_offset(area) for area in DataArea})
        self._code_addresses = []
        for actor_id in range(n_actors):
            actor_code_start = self.code_start + actor_id * self.code_size_per_actor()
            self._code_addresses.append(
                {area: actor_code_start + self.code_area_offset(area) for area in CodeArea})

    def get_data_addr(self, area: DataArea, actor_id: int) -> DataAddr:
        """
        Get the starting address of a specific area in the data sandbox for a given actor.
        :param area: The area to get the address of.
        :param actor_id: The actor to get the address for.
        :return: The starting address of the area in the data sandbox.
        """
        actor_data_start = self.data_start + actor_id * self.data_size_per_actor()
        return actor_data_start + self.data_area_offset(area)

    def get_code_addr(self, area: CodeArea, actor_id: int) -> CodeAddr:
        """
        Get the starting address of a specific area in the code sandbox for a given actor.
        :param area: The area to get the address of.
        :param actor_id: The actor to get the address for.
        :return: The starting address of the area in the code sandbox.
        """
        actor_code_start = self.code_start + actor_id * self.code_size_per_actor()
        return actor_code_start + self.code_area_offset(area)

    def get_exit_addr(self, test_case: TestCaseProgram) -> CodeAddr:
        """
        Get the address of the exit instruction in the code sandbox for a given test case.
        :param test_case: The test case to get the exit address for.
        :return: The exit address
        """
        main_section = test_case.find_section(name="main")
        main_size = main_section.get_elf_data()["size"]
        exit_offset = self.code_start + main_size - 1
        return exit_offset

    def is_data_addr(self, addr: DataAddr) -> bool:
        """
        Check if the given address is within the data sandbox.
        :param addr: The address to check.
        :return: True if the address is within the data sandbox, False otherwise.
        """
        return self.data_start <= addr < self.data_end

    def is_code_addr(self, addr: CodeAddr) -> bool:
        """
        Check if the given address is within the code sandbox.
        :param addr: The address to check.
        :return: True if the address is within the code sandbox, False otherwise.
        """
        return self.code_start <= addr < self.code_end

    def data_addr_to_offset(self, addr: DataAddr) -> DataAddr:
        """
        Convert the given address to an offset within the data sandbox.
        :param addr: The address to convert.
        :return: The offset within the data sandbox.
        """
        return addr - self.data_start

    def code_addr_to_offset(self, addr: CodeAddr) -> CodeAddr:
        """
        Convert the given address to an offset within the code sandbox.
        :param addr: The address to convert.
        :return: The offset within the code sandbox.
        """
        return addr - self.code_start

    def code_addr_to_actor_id(self, addr: CodeAddr) -> int:
        """
        Given a code address, identify the actor ID that the code address belongs to.
        :param addr: Code address
        :return: Actor ID
        """
        return (addr - self.code_start) // self.code_size_per_actor()

    def data_addr_to_actor_id(self, addr: DataAddr) -> int:
        """
        Given a data address, identify the actor ID that the data address belongs to.
        :param addr: Data address
        :return: Actor ID
        """
        return (addr - self.data_start) // self.data_size_per_actor()
