"""
File: Input Generation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import random
import numpy as np
from typing import List
from interfaces import Input, InputTaint, InputGenerator
from config import CONF
from service import LOGGER

POW32 = pow(2, 32)


class LegacyRandomInputGenerator(InputGenerator):
    """
    Legacy implementation. Exist only for backwards compatibility.
    NumpyRandomInputGenerator is a preferred implementation.

    Implements a simple 32-bit LCG with a=2891336453 and c=54321.
    """

    def __init__(self, seed: int):
        super().__init__(seed)
        self.input_mask = pow(2, (CONF.input_gen_entropy_bits % 33)) - 1

    def generate(self, count: int) -> List[Input]:
        # if it's the first invocation and the seed is zero - use random seed
        if self._state == 0:
            self._state = random.randint(0, pow(2, 32) - 1)
            LOGGER.inform("input_gen", f"Setting input seed to: {self._state}")

        generated_inputs = []
        for i in range(count):
            input_ = self._generate_one()
            generated_inputs.append(input_)
        return generated_inputs

    def extend_equivalence_classes(self, inputs: List[Input],
                                   taints: List[InputTaint]) -> List[Input]:
        if len(inputs) != len(taints):
            raise Exception("Error: Cannot extend inputs. "
                            "The number of taints does not match the number of inputs.")

        # produce a new sequence of random inputs, but copy the tainted values from
        # the previous sequence
        new_inputs = []
        for i, input_ in enumerate(inputs):
            taint = taints[i]
            new_input = self._generate_one()
            for j in range(input_.data_size):
                if taint[j]:
                    new_input[j] = input_[j]
            new_inputs.append(new_input)

        return new_inputs

    def _generate_one(self) -> Input:
        input_ = Input()
        input_.seed = self._state

        randint = self._state
        for i in range(input_.data_size):
            # this weird implementation is a legacy of our old PRNG.
            # basically, it's a 32-bit PRNG, assigned to 4-byte chucks of memory
            randint = ((randint * 2891336453) % POW32 + 54321) % POW32
            masked_rvalue = (randint ^ (randint >> 16)) & self.input_mask
            masked_rvalue = masked_rvalue << 6
            input_[i] = masked_rvalue << 32

            randint = ((randint * 2891336453) % POW32 + 54321) % POW32
            masked_rvalue = (randint ^ (randint >> 16)) & self.input_mask
            masked_rvalue = masked_rvalue << 6
            input_[i] += masked_rvalue

        # again, to emulate the legacy (and kinda broken) input generator,
        # initialize only the first 32 bits of registers
        for i in range(CONF.input_register_region_size // 8):
            input_[-i - 1] = input_[-i - 1] % POW32

        self._state = randint
        return input_


class NumpyRandomInputGenerator(InputGenerator):
    """ Numpy-based implementation of the input gen """

    def __init__(self, seed: int):
        super().__init__(seed)
        self.max_input_value = pow(2, CONF.input_gen_entropy_bits)

    def generate(self, count: int) -> List[Input]:
        # if it's the first invocation and the seed is zero - use random seed
        if self._state == 0:
            self._state = random.randint(0, pow(2, 32) - 1)
            LOGGER.inform("input_gen", f"Setting input seed to: {self._state}")

        generated_inputs = []
        for _ in range(count):
            input_ = self._generate_one()
            generated_inputs.append(input_)
        return generated_inputs

    def extend_equivalence_classes(self, inputs: List[Input],
                                   taints: List[InputTaint]) -> List[Input]:
        if len(inputs) != len(taints):
            raise Exception("Error: Cannot extend inputs. "
                            "The number of taints does not match the number of inputs.")

        # produce a new sequence of random inputs, but copy the tainted values from
        # the previous sequence
        new_inputs = []
        for i, input_ in enumerate(inputs):
            taint = taints[i]
            new_input = self._generate_one()
            for j in range(input_.data_size):
                if taint[j]:
                    new_input[j] = input_[j]
            new_inputs.append(new_input)

        return new_inputs

    def _generate_one(self) -> Input:
        input_ = Input()
        input_.seed = self._state

        rng = np.random.default_rng(seed=self._state)
        data = rng.integers(self.max_input_value, size=input_.data_size, dtype=np.uint64)
        data = data << CONF.memory_access_zeroed_bits  # type: ignore
        input_[:input_.data_size] = (data << 32) + data

        self._state += 1
        return input_
