"""
File: Input Generation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import os
import random
import numpy as np
from typing import List, Tuple
from .interfaces import Input, InputTaint, InputGenerator, InputFragment
from .config import CONF
from .util import Logger

POW32 = pow(2, 32)


class NumpyRandomInputGenerator(InputGenerator):
    """ Numpy-based implementation of the input gen """

    _state: int = 0
    _boosting_state: int = 0
    n_actors = 1

    def __init__(self, seed: int):
        super().__init__(seed)
        self.LOG = Logger()
        self.max_input_value = pow(2, CONF.input_gen_entropy_bits)

    def _generate_one(self, state: int) -> Tuple[Input, int]:
        input_ = Input(self.n_actors)
        input_.seed = state

        size = input_.itemsize // 8

        rng = np.random.default_rng(seed=state)
        for i in range(len(input_)):
            # generate random data
            data = rng.integers(self.max_input_value, size=size, dtype=np.uint64)  # type: ignore

            # copy lower 32-bits to upper 32-bits, for every 8-byte word
            data = (data << np.uint64(32)) + data

            # cast to InputFragment
            input_[i] = data.view(InputFragment)

            # zero-fill the unused parts of the input
            input_[i]['padding'] = 0

        return input_, state + 1

    def generate(self, count: int) -> List[Input]:
        # if it's the first invocation and the seed is zero - use random seed
        if self._state == 0:
            self._state = random.randint(0, pow(2, 32) - 1)
            self.LOG.inform("input_gen", f"Setting input seed to: {self._state}")

        generated_inputs = []
        for _ in range(count):
            input_, self._state = self._generate_one(self._state)
            generated_inputs.append(input_)

        # make sure that boosted inputs will continue from the updated state
        self._boosting_state = self._state
        return generated_inputs

    def reset_boosting_state(self) -> None:
        self._boosting_state = self._state

    def extend_equivalence_classes(self, inputs: List[Input],
                                   taints: List[InputTaint]) -> List[Input]:
        """
        Produce a new sequence of random inputs, but copy the tainted values from
        the base sequence
        """
        if not inputs:
            return []

        if len(inputs) != len(taints):
            raise Exception("Error: Cannot extend inputs. "
                            "The number of taints does not match the number of inputs.")
        n_actors = len(inputs[0])

        # create inputs
        new_inputs = []
        for i, input_ in enumerate(inputs):
            new_input, self._boosting_state = self._generate_one(self._boosting_state)
            for actor_id in range(n_actors):
                taint = taints[i].linear_view(actor_id)
                input_old = input_.linear_view(actor_id)
                input_new = new_input.linear_view(actor_id)
                for j in range(input_.data_size):
                    if taint[j]:
                        input_new[j] = input_old[j]
            new_inputs.append(new_input)

        return new_inputs

    def load(self, input_paths: List[str]) -> List[Input]:
        # mirror the state update in generate() as 'load' function is used for reproducing
        # violations, which requires the generator state to be identical to the one during
        # fuzzing
        if self._state == 0:
            self._state = random.randint(0, pow(2, 32) - 1)
            self.LOG.inform("input_gen", f"Setting input seed to: {self._state}")

        inputs = []
        for input_path in input_paths:
            input_ = Input(self.n_actors)

            # check that the file is not corrupted
            size = os.path.getsize(input_path)
            expected = input_.itemsize * self.n_actors
            if size != expected:
                self.LOG.error(f"Incorrect size of input `{input_path}` "
                               f"({size} B, expected {expected} B)")

            input_.load(input_path)
            inputs.append(input_)
            self._state += 1

        self._boosting_state = self._state
        return inputs
