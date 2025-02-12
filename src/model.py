"""
File: Model Interface (Backend- and ISA-independent)
      A model is a module that can execute a test case according to a contract
      and collect contract traces.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Tuple, TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .traces import CTrace
    from .sandbox import SandboxLayout, BaseAddrTuple
    from .tc_components.test_case_data import InputData, InputTaint
    from .tc_components.test_case_code import TestCaseProgram


class Model(ABC):
    """
    Abstract interface for all contract models.
    The specific implementation depends on the selected backend and the target ISA.
    """

    layout: SandboxLayout
    """ The memory layout of the most-recently loaded test case within the model """

    is_speculative: bool
    """ Indicates whether the model implements any form of speculative execution """

    _enable_mismatch_check_mode: bool = False
    """ mismatch_check_mode: If True, the model will return GPR values instead of
    contract traces, which is used to check for mismatches between the model and the executor """

    @abstractmethod
    def __init__(self,
                 bases: BaseAddrTuple,
                 *args: Any,
                 enable_mismatch_check_mode: bool = False) -> None:
        pass

    @abstractmethod
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        Load a test case into the model, which implies allocating memory for the code
        and data, initializing permissions, and doing other necessary setup.

        This method *must* be called before calling `trace_test_case`.
        """

    @abstractmethod
    def trace_test_case(self, inputs: List[InputData], nesting: int) -> List[CTrace]:
        """
        Execute a previously loaded test case in the model with the given inputs,
        and collect the traces for each execution (i.e., one trace per input).
        """

    @abstractmethod
    def trace_test_case_with_taints(self, inputs: List[InputData],
                                    nesting: int) -> Tuple[List[CTrace], List[InputTaint]]:
        """
        Execute a previously loaded test case in the model with the given inputs,
        and collect the traces for each execution (i.e., one trace per input).
        While collecting the traces, also collect the taints for each input.
        """

    @abstractmethod
    def report_coverage(self, path: str) -> None:
        """
        Report the coverage of the fuzzing campaign w.r.t. the model, and store the report
        in the given file path.
        """


class DummyModel(Model):
    """
    Dummy implementation of the Model interface that does nothing. All traces produced by
    this model are empty, and thus all inputs form the same equivalence class.

    This model is useful for testing purposes or for cases where it's necessary to
    run the fuzzer without a model (e.g., for standalone hardware tracing).
    """

    def __init__(self,
                 bases: BaseAddrTuple,
                 *args: Any,
                 enable_mismatch_check_mode: bool = False) -> None:
        pass

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        pass

    def trace_test_case(self, inputs: List[InputData], nesting: int) -> List[CTrace]:
        return [CTrace.empty_trace() for _ in inputs]

    def trace_test_case_with_taints(self, inputs: List[InputData],
                                    nesting: int) -> Tuple[List[CTrace], List[InputTaint]]:
        taints = [InputTaint() for _ in inputs]
        traces = [CTrace.empty_trace() for _ in inputs]
        return traces, taints

    def report_coverage(self, path: str) -> None:
        pass
