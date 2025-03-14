""" File: Abstract interfaces for minimization passes and common functionality.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import abc
import tempfile
from typing import TYPE_CHECKING, List, Final

from ..config import CONF

if TYPE_CHECKING:
    from ..fuzzer import Fuzzer
    from ..isa_spec import InstructionSet
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_data import InputData
    from .progress_printer import ProgressPrinter


class BaseMinimizationPass(abc.ABC):
    """ Base class for all minimization passes. Provides common functionality """
    name: str = ""
    _fuzzer: Final[Fuzzer]
    _instruction_set_spec: Final[InstructionSet]
    _progress: Final[ProgressPrinter]
    _ignore_list: List[int]

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSet,
                 progress: ProgressPrinter):
        self._fuzzer = fuzzer
        self._instruction_set_spec = instruction_set_spec
        self._progress = progress
        self._ignore_list = []

    def set_ignore_list(self, ignore_list: List[int]) -> None:
        """ Set the list of input IDs to ignore """
        self._ignore_list = ignore_list

    def _get_test_case_from_instructions(self,
                                         instructions: List[str],
                                         path: str = "") -> TestCaseProgram:
        """
        Create a test case object from a list of instructions.
        The test case is stored in a file at the given path.
        :param instructions: List of instructions
        :param path: Path to store the test case; if empty, a temporary file is created
        :return: Test case object
        """
        # create a temporary file if no path is given
        if not path:
            with tempfile.NamedTemporaryFile(dir="/tmp/rvzr_minimize", delete=False) as fp:
                path = fp.name
        # print(path)

        # write the instructions to the file
        with open(path, "w+") as f:
            for line in instructions:
                f.write(line)
        tc = self._fuzzer.asm_parser.parse_file(path, self._fuzzer.code_gen,
                                                self._fuzzer.elf_parser)
        return tc

    def _check_for_violation(self, test_case: TestCaseProgram, inputs: List[InputData],
                             local_ignore_list: List[int]) -> bool:
        """
        Check if the test case triggers the violation.
        :param test_case: The test case to check
        :param inputs: List of inputs to use for verification
        :param ignore_list: List of input IDs to ignore
        :return: True if the violation is triggered, False otherwise
        """
        for _ in range(CONF.minimizer_retries):
            violation = self._fuzzer.fuzzing_round(test_case, inputs, local_ignore_list)
            if violation is not None:
                return True
        return False
