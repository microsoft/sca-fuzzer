"""
File: Input Generation.

      An input is a sequence of bytes that is used to initialize memory and registers in
      the model or executor before running a test case program. The input generator
      is responsible for generating random inputs for the test cases.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import os
import random
from typing import List, Tuple

import numpy as np

from .tc_components.test_case_data import InputData, InputTaint
from .config import CONF
from .logs import inform

POW32 = pow(2, 32)


class DataGenerator:
    """ Class responsible for generating random inputs for test cases. """

    _state: int = 0
    _boosting_state: int = 0

    def __init__(self, seed: int):
        self.max_input_value = pow(2, CONF.data_generator_entropy_bits)
        self._state = seed

    def get_state(self) -> int:
        """
        Return the current state of the generator.
        State is the seed value that will be used to generate the next input.
        """
        return self._state

    def _reset_boosting_state(self) -> None:
        """ Reset the state (i.e., seed) of the generator to the last state before boosting """
        self._boosting_state = self._state

    def generate(self, count: int, n_actors: int) -> List[InputData]:
        """
        Generate a list of random inputs.
        :param count: The number of inputs to generate
        :return: A list of generated inputs
        """
        # if it's the first invocation and the seed is zero - use random seed
        if self._state == 0:
            self._state = random.randint(0, pow(2, 32) - 1)
            inform("data_gen", f"Setting input seed to: {self._state}")

        generated_inputs = []
        for _ in range(count):
            input_, self._state = self._generate_one(self._state, n_actors)
            generated_inputs.append(input_)

        # make sure that boosted inputs will continue from the updated state
        self._boosting_state = self._state
        return generated_inputs

    def generate_boosted(self, inputs: List[InputData], taints: List[InputTaint],
                         inputs_per_class: int) -> List[InputData]:
        """
        Extend the given input sequence with new inputs such that the new inputs should produce
        the same contract traces as the original inputs. This achieved by copying the original
        inputs and modifying them based on the taints collected by the model while tracing the
        test case with the original inputs (i.e, non-tainted values are replaced with random values,
        and the tainted values are copied).

        For example, if the original inputs are [A, B, C] and inputs_per_class=3,
        then the new sequence will be [A, B, C, A', B', C', A'', B'', C''],
        where A, A', and A'' produce the same contract traces, and so on.

        NOTE: The function is idempotent, i.e., calling it multiple times with the same inputs
        and taints will produce the same sequence of new inputs. This is because the state of the
        generator is reset to the last state before boosting every time the function is called.
        """
        if not inputs:
            return []
        assert len(inputs) == len(taints), "Error: Cannot extend inputs. The number of taints" \
                                           " does not match the number of inputs."
        n_actors = len(inputs[0])
        input_size = InputData.n_data_entries_per_actor()

        self._reset_boosting_state()
        boosted_inputs = list(inputs)  # make a copy
        for _ in range(inputs_per_class - 1):
            for i, input_ in enumerate(inputs):
                # Generate new, fully random input
                new_input, self._boosting_state = self._generate_one(self._boosting_state, n_actors)

                # Copy tainted values from the original input
                for actor_id in range(n_actors):
                    taint = taints[i].linear_view(actor_id)
                    input_old = input_.linear_view(actor_id)
                    input_new = new_input.linear_view(actor_id)
                    for j in range(input_size):
                        if taint[j]:
                            input_new[j] = input_old[j]

                # Add the new input to the sequence
                boosted_inputs.append(new_input)
        return boosted_inputs

    def load(self, input_paths: List[str]) -> List[InputData]:
        """
        Load a sequence of inputs from a directory with binary inputs.
        """
        # mirror the state update in generate() as 'load' function is used for reproducing
        # violations, which requires the generator state to be identical to the one during
        # fuzzing
        if self._state == 0:
            self._state = random.randint(0, pow(2, 32) - 1)
            inform("data_gen", f"Setting input seed to: {self._state}")

        inputs = []
        n_actors = len(CONF.get_actors_conf())
        for input_path in input_paths:
            input_ = InputData(n_actors)

            # check that the file is not corrupted
            size = os.path.getsize(input_path)
            expected = input_.itemsize * n_actors
            if size != expected:
                raise ValueError(f"Incorrect size of input `{input_path}` "
                                 f"({size} B, expected {expected} B)")

            input_.load(input_path)
            inputs.append(input_)
            self._state += 1

        self._boosting_state = self._state
        return inputs

    def _generate_one(self, state: int, n_actors: int) -> Tuple[InputData, int]:
        input_ = InputData(n_actors)
        input_.seed = state

        size = input_.itemsize // 8

        rng = np.random.default_rng(seed=state)
        n_inputs = len(input_)
        for i in range(n_inputs):
            # generate random data
            data = rng.integers(self.max_input_value, size=size, dtype=np.uint64)  # type: ignore

            # copy lower 32-bits to upper 32-bits, for every 8-byte word
            data = (data << np.uint64(32)) + data

            input_.set_actor_data(i, data)

        return input_, state + 1
