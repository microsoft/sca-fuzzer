"""
File: Architecture-independent Interface Definition of the Executor Module

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import List, TYPE_CHECKING, Final
from abc import ABC, abstractmethod

from .sandbox import BaseAddrTuple

if TYPE_CHECKING:
    from .tc_components.test_case_code import TestCaseProgram
    from .tc_components.test_case_data import InputData
    from .traces import HTrace


class Executor(ABC):
    """
    Interface for the executor module. The executor is a module responsible for executing
    test cases on the CPU-under-test and collecting the corresponding hardware traces.
    """

    _enable_mismatch_check_mode: Final[bool]
    """ mismatch_check_mode: If True, the executor will return GPR values instead of
    hardware traces, which is used to check for mismatches between the model and the executor """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        self._enable_mismatch_check_mode = enable_mismatch_check_mode
        super().__init__()

    @abstractmethod
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        Load a test case into the executor. This method should be called before calling
        `trace_test_case`.
        :param test_case: test case to be loaded
        :return: None
        """

    @abstractmethod
    def trace_test_case(self, inputs: List[InputData], n_reps: int) -> List[HTrace]:
        """ Call the executor kernel module to collect the hardware traces for
         the test case (previously loaded with `load_test_case`) and the given inputs.

        :param inputs: list of inputs to be used for the test case
        :param n_reps: number of times to repeat each measurement
        :return: a list of HTrace objects, one for each input
         """

    @abstractmethod
    def read_base_addresses(self) -> BaseAddrTuple:
        """
        Reads the base addresses of two sandbox regions (data and code) from the executor
        kernel module and returns them as a tuple.
        This data is primarily used to synchronize the memory layout between the executor
        and the model.
        :return: a tuple with the base addresses of the data and code regions
        """

    @abstractmethod
    def set_ignore_list(self, ignore_list: List[int]) -> None:
        """
        Sets a list of inputs IDs that should be ignored by the executor.
        The executor will executed the inputs with these IDs as normal (in case they are
        necessary for priming the uarch state), but their htraces will be set to zero
        """

    @abstractmethod
    def extend_ignore_list(self, ignore_list: List[int]) -> None:
        """
        Updates the ignore list with a new list of inputs IDs that should be ignored
        by the executor.
        """
