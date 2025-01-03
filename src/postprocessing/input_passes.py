""" File: Collection of minimization passes that operate on the test case input data.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import abc
from copy import deepcopy
from math import log2

from typing import TYPE_CHECKING, List

from .pass_abc import BaseMinimizationPass
from ..config import CONF

if TYPE_CHECKING:
    from ..traces import Violation
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_data import InputData


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
                new_violation = self._fuzzer.fuzzing_round(test_case, inputs, [])
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

    def run(self, test_case: TestCaseProgram, _: List[InputData],
            org_violation: Violation) -> List[InputData]:
        # pylint: disable=too-many-locals
        # pylint: disable=too-many-branches
        # pylint: disable=too-many-statements
        # pylint: disable=too-many-nested-blocks
        # FIXME: this function was written in a hurry and needs to be refactored

        inputs = org_violation.input_sequence

        # Disable boosting for this pass as we already operate on the boosted inputs
        org_conf = (CONF.inputs_per_class,)
        CONF.inputs_per_class = 1

        # Determine the violating input IDs
        violating_input_ids = [i.input_id for i in org_violation.measurements]
        if len(violating_input_ids) > 2:
            violating_input_ids = violating_input_ids[:2]

        # Set the non-violating inputs as the ignore list; do it locally to avoid side effects
        local_ignore_list = [
            i for i in range(len(org_violation.input_sequence)) if i not in violating_input_ids
        ]

        # make a copy of the inputs
        input_a = inputs[violating_input_ids[0]]
        input_b = inputs[violating_input_ids[1]]
        input_a_org = deepcopy(input_a)
        input_b_org = deepcopy(input_b)

        leaked = []
        n_actors = len(CONF.get_actors_conf())
        assert len(input_a) == n_actors
        assert len(input_b) == n_actors

        self._progress.pass_msg("Minimizing the difference between inputs"
                                f" {violating_input_ids[0]} and {violating_input_ids[1]}")

        # print header
        print(f'\n{"Address":<11}', end="", flush=True)
        for i in range(0, 64, 8):
            print(f"+0x{i * 8:<6x}", end="", flush=True)

        for actor_id in range(n_actors):
            region_offset = 0
            for region_name in ['main', 'faulty', 'gpr', 'simd']:
                i = -1
                region_size = len(input_a[actor_id][region_name])
                while i < (region_size - 1):
                    i += 1

                    # progress indicator
                    absolute_address = actor_id * 0x4000 + region_offset + i * 8
                    if i % 64 == 0:
                        print(f"\n0x{absolute_address:08x} ", end="", flush=True)
                    elif i % 8 == 0:
                        print(" ", end="", flush=True)

                    # Try zeroing out blocks of decreasing size:
                    # 1. find a suitable starting block size, fulfilling the following conditions:
                    #    * the block size is less then 512 bytes (64 * 8)
                    block_size = 64 - (i % 64)
                    #    * the block does not overlap with the next region
                    block_size = min(block_size, region_size - i)
                    #    * the block size is a power of 2
                    block_size = 2**int(log2(block_size))
                    #    * i mod block_size == 0
                    while block_size > 1 and i % block_size != 0:
                        block_size //= 2
                    # 2. binary search for the largest zeroed-out block that
                    #    still triggers the violation
                    success = False
                    while block_size > 1:
                        for j in range(block_size):
                            input_a[actor_id][region_name][i + j] = 0
                            input_b[actor_id][region_name][i + j] = 0
                        if self._check_for_violation(test_case, inputs, local_ignore_list):
                            n_64byte_blocks = block_size // 8
                            n_remainder_bytes = block_size % 8
                            if n_remainder_bytes > 0:
                                print("." * n_remainder_bytes, end="", flush=True)
                                if n_64byte_blocks > 0:
                                    print(" ", end="", flush=True)
                            if n_64byte_blocks > 0:
                                print(("." * 8 + " ") * (n_64byte_blocks - 1), end="", flush=True)
                                print("." * 8, end="", flush=True)
                            i += block_size - 1
                            success = True
                            break
                        for j in range(block_size):
                            input_a[actor_id][region_name][i + j] = \
                                input_a_org[actor_id][region_name][i + j]
                            input_b[actor_id][region_name][i + j] = \
                                input_b_org[actor_id][region_name][i + j]
                        block_size //= 2
                    if success:
                        continue

                    # try zeroing out a single byte
                    input_a[actor_id][region_name][i] = 0
                    input_b[actor_id][region_name][i] = 0
                    if self._check_for_violation(test_case, inputs, local_ignore_list):
                        print(".", end="", flush=True)
                        continue

                    # move on if the bytes are already equal
                    if input_a_org[actor_id][region_name][i] == \
                       input_b_org[actor_id][region_name][i]:
                        input_a[actor_id][region_name][i] = input_a_org[actor_id][region_name][i]
                        input_b[actor_id][region_name][i] = input_b_org[actor_id][region_name][i]
                        print("=", end="", flush=True)
                        continue

                    # try copying the byte between the two inputs
                    input_a[actor_id][region_name][i] = input_a_org[actor_id][region_name][i]
                    input_b[actor_id][region_name][i] = input_a_org[actor_id][region_name][i]
                    if self._check_for_violation(test_case, inputs, local_ignore_list):
                        print("+", end="", flush=True)
                        continue

                    # if failing, restore the original value
                    print("^", end="", flush=True)
                    leaked.append(absolute_address)
                    input_a[actor_id][region_name][i] = input_a_org[actor_id][region_name][i]
                    input_b[actor_id][region_name][i] = input_b_org[actor_id][region_name][i]

                region_offset += region_size * 8
        print("")

        self._progress.pass_msg(f"Result: Leaked {len(leaked)} bytes")
        self._progress.pass_msg(f"Addresses: {[hex(x) for x in leaked]}")

        CONF.inputs_per_class = org_conf[0]
        return inputs
