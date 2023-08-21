"""
File: Input Generation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import os
import random
import numpy as np
from typing import List, Tuple
from .interfaces import Input, InputTaint, InputGenerator
from .config import CONF
from .util import Logger

POW32 = pow(2, 32)


class NumpyRandomInputGenerator(InputGenerator):
    """ Numpy-based implementation of the input gen """

    _state: int = 0
    _boosting_state: int = 0

    def __init__(self, seed: int):
        super().__init__(seed)
        self.LOG = Logger()
        self.max_input_value = pow(2, CONF.input_gen_entropy_bits)

    def _generate_one(self, state: int) -> Tuple[Input, int]:
        input_ = Input()
        input_.seed = state

        rng = np.random.default_rng(seed=state)
        data = rng.integers(self.max_input_value, size=input_.data_size, dtype=np.uint64)
        data = data << CONF.memory_access_zeroed_bits  # type: ignore
        input_[:input_.data_size] = (data << 32) + data

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
        if len(inputs) != len(taints):
            raise Exception("Error: Cannot extend inputs. "
                            "The number of taints does not match the number of inputs.")

        # create inputs
        new_inputs = []
        for i, input_ in enumerate(inputs):
            taint = taints[i]
            new_input, self._boosting_state = self._generate_one(self._boosting_state)
            for j in range(input_.data_size):
                if taint[j]:
                    new_input[j] = input_[j]
            new_inputs.append(new_input)

        return new_inputs

    def load(self, input_paths: List[str]) -> List[Input]:
        inputs = []
        for input_path in input_paths:
            input_ = Input()

            # check that the file is not corrupted
            size = os.path.getsize(input_path)
            if size != len(input_) * 8:
                self.LOG.error(f"Incorrect size of input `{input_path}` "
                               f"({size} B, expected {len(input_) * 8} B)")

            input_.load(input_path)
            inputs.append(input_)
        return inputs
