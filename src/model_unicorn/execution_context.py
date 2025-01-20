"""
File: Execution state of the model during a single test case execution

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Final, Optional, Dict, Tuple

from unicorn import Uc
from ..sandbox import SandboxLayout, CodeArea
from ..tc_components.actor import ActorID

if TYPE_CHECKING:
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.instruction import Instruction
    from ..tc_components.actor import Actor
    from ..target_desc import TargetDesc

PAGE_PERMISSION_MAP = Dict[ActorID, Tuple[bool, bool]]
""" Data type for storing page permissions for actors """


class ModelExecutionState:
    """
    Set of state variables that track a single execution of a test case program with a given
    input on the model
    """

    current_instruction: Instruction
    """ The instruction currently being executed by the model """

    current_actor: Actor
    """ The actor whose code is currently being executed by the model """

    exit_addr: int
    """ The address of the exit instruction in the current test case """

    fault_handler_addr: int
    """ The address of the fault handler in the current test case """

    pending_fault: int = 0
    """ Interface to signal pending soft faults to the model;
    If a fault was triggered but not handled yet, its ID is stored here """

    previous_context: Optional[object] = None
    """ Context of the emulator before the current instruction was executed;
    used to patch a bug in Unicorn """

    had_arch_fault: bool = False
    """ Indicates whether the model has already had a non-speculative fault in the current run """

    page_permissions: Optional[PAGE_PERMISSION_MAP] = None
    """ Dictionary of the page permissions for each actor at the start of execution.
    Only containts permissions on the faulty area, as all other areas are always RW."""

    _test_case: Final[TestCaseProgram]  # The test case being currently executed by the model
    _layout: Final[SandboxLayout]  # The layout of the sandbox

    def __init__(self, test_case: TestCaseProgram, layout: SandboxLayout, target_desc: TargetDesc):
        self._test_case = test_case
        self._layout = layout

        self.exit_addr = self._layout.get_exit_addr(test_case)
        self._set_fault_handler_addr(target_desc.macro_specs["fault_handler"].type_)
        self.full_reset()

    def full_reset(self) -> None:
        """ Complete reset of the model state; has to be called before each test case """
        self.had_arch_fault = False
        self.pending_fault = 0
        self.current_actor = self._test_case.find_actor(name="main")

    def reset_after_em_stop(self, start_pc: int) -> None:
        """
        Reset the model state after the emulator stops;
        has to be called before each start of the emulator iteration
        :param start_pc: the address where the emulator will start execution
        :return: None
        """
        self.pending_fault = 0
        aid = self._layout.code_addr_to_actor_id(start_pc)
        self.current_actor = self._test_case.find_actor(actor_id=aid)

    def is_exit_addr(self, address: int) -> bool:
        """ Check if the given address is the exit address """
        return address == self.exit_addr or \
            (self.current_actor.is_main and address > self.exit_addr)

    def update_context(self, em: Uc, address: int) -> None:
        """ Update the state of the model after each instruction """
        self.previous_context = em.context_save()
        aid = self.current_actor.get_id()
        section_start = self._layout.get_code_addr(CodeArea.MAIN, aid)
        instruction_map = self._test_case.get_obj().instruction_map()
        self.current_instruction = instruction_map[aid][address - section_start]

    def current_test_case(self) -> TestCaseProgram:
        """ Return the current test case being executed """
        return self._test_case

    def _set_fault_handler_addr(self, fh_id: int) -> None:
        test_case_obj = self._test_case.get_obj()
        code_start = self._layout.code_start
        offset = test_case_obj.get_macro_offset(fh_id)
        if offset == -1:
            self.fault_handler_addr = self.exit_addr
            return

        self.fault_handler_addr = code_start + offset
