"""
File: Collection of minimization passes that operate on the test case input data.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import abc
from copy import deepcopy
from math import log2

from typing import TYPE_CHECKING, List, Final, Optional, Tuple

from .pass_abc import BaseMinimizationPass
from ..config import CONF

if TYPE_CHECKING:
    from ..traces import Violation
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_data import InputData

_PER_ACTOR_INPUT_SIZE: Final[int] = 0x4000  # 16 KB per actor
_PRINT_BLOCK_SIZE: Final[int] = 8  # print progress indicator in 8-byte blocks
_PRINT_LINE_SIZE: Final[int] = 64  # print progress indicator in (64 * 8)-byte lines
_MAX_BLOCK_SIZE: Final[int] = 64  # try to zero out up to 64 bytes at once


class BaseInputMinimizationPass(BaseMinimizationPass):
    """ Base class for a minimization pass that operates on inputs. """

    @abc.abstractmethod
    def run(self, test_case: TestCaseProgram, org_inputs: List[InputData],
            org_violation: Violation) -> List[InputData]:
        """ Main function that runs the minimization pass
        :param test_case: The test case object to work on
        :param org_inputs: List of inputs to minimize
        :param org_violation: The original violation
        :return: List of minimized inputs
        """


class InputSequenceMinimizationPass(BaseInputMinimizationPass):
    """
    A minimization pass that iteratively removes inputs from the violating the input sequence
    and checks if the violation is still triggered.
    """
    name = "Input Sequence Minimization"

    def run(self, test_case: TestCaseProgram, org_inputs: List[InputData],
            org_violation: Violation) -> List[InputData]:
        self._progress.pass_msg("Reducing the number of inputs by halving")
        org_len = len(org_inputs)

        violation = org_violation
        nonboosted_inputs = org_inputs
        while len(nonboosted_inputs) > 5:
            new_inputs = nonboosted_inputs[:len(nonboosted_inputs) // 2]
            new_violation = self._fuzzer.fuzzing_round(test_case, new_inputs, [])
            if not new_violation:
                break
            nonboosted_inputs = new_inputs
            violation = new_violation

        if len(nonboosted_inputs) < org_len:
            self._progress.pass_msg(f"Result: Reduced to {len(nonboosted_inputs)} inputs")
        else:
            self._progress.pass_msg("Result: Could not reduce the number of inputs")

        # Get boosted inputs and disable boosting from now on
        inputs = violation.input_sequence
        org_ipc = CONF.inputs_per_class
        CONF.inputs_per_class = 1  # disable boosting from now on

        n_iterations = 10
        self._progress.pass_msg("Reducing the input sequence iteratively")
        for iteration in range(n_iterations):
            self._progress.pass_msg(f"Iteration {iteration + 1}")
            org_len = len(inputs)
            for input_id in range(org_len, 0, -1):
                new_inputs = inputs[0:input_id] + inputs[input_id + 1:]
                new_violation = self._fuzzer.fuzzing_round(test_case, new_inputs, [])
                if not new_violation:
                    self._progress.next(False)
                    continue
                self._progress.next(True)
                inputs = new_inputs
                violation = new_violation
            self._progress.pass_finish()
            if len(inputs) == org_len:
                break
        self._progress.pass_msg(f"Result: Reduced to {len(inputs)} inputs")
        CONF.inputs_per_class = org_ipc
        return violation.input_sequence


class DifferentialInputMinimizerPass(BaseInputMinimizationPass):
    """
    A minimization pass that iteratively minimizes the difference between two violating inputs.
    It tries to zero out blocks of decreasing size and checks if the violation is still triggered.
    If this is not possible, it tries to copy the byte between the two inputs.
    """
    name = "Differential Input Minimizer"

    _test_case: Optional[TestCaseProgram] = None
    _inputs: Optional[List[InputData]] = None
    _violating_ids: Optional[Tuple[int, int]] = None
    _local_ignore_list: List[int] = []
    _leaked_addresses: List[int] = []

    def run(self, test_case: TestCaseProgram, _: List[InputData],
            org_violation: Violation) -> List[InputData]:

        # Set the context for this pass
        self._set_pass_context(test_case, org_violation)
        assert self._violating_ids is not None
        self._progress.pass_msg("Minimizing the difference between inputs"
                                f" {self._violating_ids[0]} and {self._violating_ids[1]}")

        # Disable boosting for this pass as we already operate on the boosted inputs
        org_conf = (CONF.inputs_per_class,)
        CONF.inputs_per_class = 1

        # Print header for progress output
        print(f'\n{"Address":<11}', end="", flush=True)
        for i in range(0, 64, 8):
            print(f"+0x{i * 8:<6x}", end="", flush=True)

        # Start the pass
        for actor_id in range(len(CONF.get_actors_conf())):
            self._process_actor(actor_id)
        print("")

        # Print summary
        self._progress.pass_msg(f"Result: Leaked {len(self._leaked_addresses)} bytes")
        self._progress.pass_msg(f"Addresses: {[hex(addr) for addr in self._leaked_addresses]}")

        # Restore original configuration
        assert self._inputs is not None
        new_inputs = list(self._inputs)
        CONF.inputs_per_class = org_conf[0]
        self._reset_pass_context()

        return new_inputs

    def _set_pass_context(self, test_case: TestCaseProgram, org_violation: Violation) -> None:
        """
        Set the context for the minimization pass.
        :param test_case: The test case object to work on
        :param org_violation: The original violation
        :return: None
        """
        # Store the test case and inputs
        self._test_case = test_case
        self._inputs = org_violation.input_sequence

        # For convenience, also store the two inputs to minimize
        violating_input_ids = [i.input_id for i in org_violation.measurements]
        if len(violating_input_ids) > 2:
            violating_input_ids = violating_input_ids[:2]
        self._violating_ids = (violating_input_ids[0], violating_input_ids[1])

        # Store a list of all other input IDs, which we will ignore during checks
        self._local_ignore_list = [
            i for i in range(len(self._inputs)) if i not in violating_input_ids
        ]

        # Finally, make a list to store all leaked addresses
        self._leaked_addresses = []

    def _reset_pass_context(self) -> None:
        """ Reset the context for the minimization pass. """
        self._test_case = None
        self._inputs = None
        self._local_ignore_list = []
        self._leaked_addresses = []

    def _process_actor(self, actor_id: int) -> None:
        """
        Process the input regions of a single actor.
        :param actor_id: The actor ID
        """
        assert self._inputs is not None and self._violating_ids is not None

        # Process all input regions of the actor
        region_offset = 0
        for region_name in ['main', 'faulty', 'gpr', 'simd']:
            region_size = len(self._inputs[self._violating_ids[0]][actor_id][region_name])

            # Within each region, process all bytes
            i = 0
            while i < region_size:
                absolute_address = actor_id * _PER_ACTOR_INPUT_SIZE + region_offset + i * 8

                # Periodically break lines and print spaces for better readability
                if i % _PRINT_LINE_SIZE == 0:
                    print(f"\n0x{absolute_address:08x} ", end="", flush=True)
                elif i % _PRINT_BLOCK_SIZE == 0:
                    print(" ", end="", flush=True)

                # Process the block starting at the current index
                processed_block_size = self._process_block(actor_id, region_name, i, region_size,
                                                           absolute_address)
                i += processed_block_size

            region_offset += region_size * 8

    def _process_block(self, actor_id: int, region_name: str, block_start: int, region_size: int,
                       absolute_address: int) -> int:
        """
        Try to minimize the difference between the two inputs at the given index.
        """
        assert self._test_case is not None and self._inputs is not None \
               and self._violating_ids is not None
        input_a = self._inputs[self._violating_ids[0]]
        input_b = self._inputs[self._violating_ids[1]]
        org_input_a = deepcopy(input_a)
        org_input_b = deepcopy(input_b)

        def _restore_addr(addr: int) -> None:
            input_a[actor_id][region_name][addr] = org_input_a[actor_id][region_name][addr]
            input_b[actor_id][region_name][addr] = org_input_b[actor_id][region_name][addr]

        def _zero_out_block() -> int:
            """
            Try to zero out a block of memory and check if the violation is still triggered.
            Start with the largest possible block size and iteratively decrease the block size
            until violation is triggered or the block size is 1.
            :param actor_id: The actor ID
            :param region_name: The name of the region
            :param block_start: The start index of the block
            :return: The size of the block that was successfully zeroed out, or 1
            """
            assert input_a is not None and input_b is not None and \
                self._test_case is not None and self._inputs is not None

            # Find a suitable starting block size, fulfilling the following criteria:
            #    * the block size is less then 512 bytes (64 * 8)
            block_size = _MAX_BLOCK_SIZE - (block_start % _MAX_BLOCK_SIZE)
            #    * the block does not overlap with the next region
            block_size = min(block_size, region_size - block_start)
            #    * the block size is a power of 2
            block_size = 2**int(log2(block_size))
            #    * i mod block_size == 0
            while block_size > 1 and block_start % block_size != 0:
                block_size //= 2

            # Starting from the determined block size, try to find the largest block
            # such that zeroing out the block still triggers the violation
            while block_size > 1:
                # Try zeroing out the block
                for i in range(block_size):
                    input_a[actor_id][region_name][block_start + i] = 0
                    input_b[actor_id][region_name][block_start + i] = 0

                # Check if the violation is still triggered
                if self._check_for_violation(self._test_case, self._inputs,
                                             self._local_ignore_list):
                    # If reproduced, we managed to zero out the block; return
                    return block_size

                # If not reproduced, restore the original values and try a smaller block
                for i in range(block_size):
                    _restore_addr(block_start + i)
                block_size //= 2

            # If we reach here, we could not zero out a block larger than 1 byte
            return 1

        # First, try setting a large block of bytes to zero
        block_size = _zero_out_block()
        if block_size > 1:
            # If reproduced, print progress and return the block size
            n_64byte_blocks = block_size // 8
            n_remainder_bytes = block_size % 8
            if n_remainder_bytes > 0:
                print("." * n_remainder_bytes, end="", flush=True)
                if n_64byte_blocks > 0:
                    print(" ", end="", flush=True)
            if n_64byte_blocks > 0:
                print(("." * 8 + " ") * (n_64byte_blocks - 1), end="", flush=True)
                print("." * 8, end="", flush=True)
            return block_size

        # try zeroing out a single byte
        input_a[actor_id][region_name][block_start] = 0
        input_b[actor_id][region_name][block_start] = 0
        if self._check_for_violation(self._test_case, self._inputs, self._local_ignore_list):
            print(".", end="", flush=True)
            return 1
        _restore_addr(block_start)

        # check if the bytes are already equal; if so, nothing more to do here
        if input_a[actor_id][region_name][block_start] == \
           input_b[actor_id][region_name][block_start]:
            print("=", end="", flush=True)
            return 1

        # try copying the byte between the two inputs
        input_a[actor_id][region_name][block_start] = \
            org_input_a[actor_id][region_name][block_start]
        input_b[actor_id][region_name][block_start] = \
            input_a[actor_id][region_name][block_start]
        if self._check_for_violation(self._test_case, self._inputs, self._local_ignore_list):
            print("+", end="", flush=True)
            return 1
        _restore_addr(block_start)

        # if failing, we found a leaked address
        print("^", end="", flush=True)
        self._leaked_addresses.append(absolute_address)
        return 1
