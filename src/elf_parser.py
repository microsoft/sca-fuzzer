"""
File: Parsing of ELF files to populate sections of a TestCaseCode object.
      This file contains ISA-independent code; see <isa>/<isa>_elf_parser.py for ISA-specific code.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Final, TYPE_CHECKING

if TYPE_CHECKING:
    from .target_desc import TargetDesc
    from .tc_components.test_case_code import TestCaseProgram
    from .tc_components.test_case_binary import TestCaseBinary


class ELFParser(ABC):
    """
    ISA-independent implementation of ELF parsing.
    """

    _target_desc: Final[TargetDesc]

    def __init__(self, target_desc: TargetDesc) -> None:
        self._target_desc = target_desc

    @abstractmethod
    def populate_elf_data(self, test_case_bin: TestCaseBinary,
                          test_case_code: TestCaseProgram) -> None:
        """
        Populate .symbol_table and .instruction_map attributes of a TestCaseBinary object
        by parsing the ELF file associated with this object (TestCaseBinary.obj_path).
        """
