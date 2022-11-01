"""
File: Input Generation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import os
import random
import numpy as np
from typing import List, Tuple
from interfaces import Input, InputTaint, InputGenerator
from config import CONF
from service import LOGGER

POW32 = pow(2, 32)


class InputGeneratorCommon(InputGenerator):

    def load(self, input_paths: List[str]) -> List[Input]:
        inputs = []
        for input_path in input_paths:
            input_ = Input()

            # check that the file is not corrupted
            size = os.path.getsize(input_path)
            if size != len(input_) * 8:
                LOGGER.error(f"Incorrect size of input `{input_path}` "
                             f"({size} B, expected {len(input_) * 8} B)")

            input_.load(input_path)
            inputs.append(input_)
        return inputs


class LegacyRandomInputGenerator(InputGeneratorCommon):
    """
    Legacy implementation. Will be deprecated in the future because of low performance.
    Simple 32-bit LCG with a=2891336453 and c=54321.
    """

    def __init__(self):
        super().__init__()
        self.input_mask = pow(2, (CONF.input_gen_entropy_bits % 33)) - 1

    def generate(self, seed: int, count: int) -> List[Input]:
        if seed == 0:
            seed = random.randint(0, pow(2, 32) - 1)
            LOGGER.inform("input_gen", str(seed))

        generated_inputs = []
        for i in range(count):
            input_, seed = self._generate_one(seed)
            generated_inputs.append(input_)
        return generated_inputs

    def extend_equivalence_classes(self, inputs: List[Input],
                                   taints: List[InputTaint]) -> List[Input]:
        if len(inputs) != len(taints):
            raise Exception("Error: Cannot extend inputs. "
                            "The number of taints does not match the number of inputs.")

        # continue the sequence of random values from the last one
        # in the previous input sequence
        _, seed = self._generate_one(inputs[-1].seed)

        # produce a new sequence of random inputs, but copy the tainted values from
        # the previous sequence
        new_inputs = []
        for i, input_ in enumerate(inputs):
            taint = taints[i]
            new_input, seed = self._generate_one(seed)
            for j in range(input_.data_size):
                if taint[j]:
                    new_input[j] = input_[j]
            new_inputs.append(new_input)

        return new_inputs

    def _generate_one(self, seed: int) -> Tuple[Input, int]:
        input_ = Input()
        input_.seed = seed

        randint = seed
        for i in range(input_.data_size):
            # this weird implementation is a legacy of our old PRNG.
            # basically, it's a 32-bit PRNG, assigned to 4-byte chucks of memory
            # TODO: replace it with a more sane implementation after the artifact is done
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

        return input_, randint


class NumpyRandomInputGenerator(InputGeneratorCommon):
    """ Numpy-based implementation of the input gen """

    def __init__(self):
        super().__init__()
        self.max_input_value = pow(2, CONF.input_gen_entropy_bits)

    def generate(self, seed: int, count: int) -> List[Input]:
        if seed == 0:
            seed = random.randint(0, pow(2, 32) - 1)
            LOGGER.inform("input_gen", str(seed))

        generated_inputs = []
        for _ in range(count):
            input_, seed = self._generate_one(seed)
            generated_inputs.append(input_)
        return generated_inputs

    def extend_equivalence_classes(self, inputs: List[Input],
                                   taints: List[InputTaint]) -> List[Input]:
        if len(inputs) != len(taints):
            raise Exception("Error: Cannot extend inputs. "
                            "The number of taints does not match the number of inputs.")

        # continue the sequence of random values from the last one
        # in the previous input sequence
        _, seed = self._generate_one(inputs[-1].seed)

        # produce a new sequence of random inputs, but copy the tainted values from
        # the previous sequence
        new_inputs = []
        for i, input_ in enumerate(inputs):
            taint = taints[i]
            new_input, seed = self._generate_one(seed)
            for j in range(input_.data_size):
                if taint[j]:
                    new_input[j] = input_[j]
            new_inputs.append(new_input)

        return new_inputs

    def _generate_one(self, seed: int) -> Tuple[Input, int]:
        input_ = Input()
        input_.seed = seed

        rng = np.random.default_rng(seed)
        data = rng.integers(self.max_input_value, size=input_.data_size, dtype=np.uint64)
        data = data << CONF.memory_access_zeroed_bits  # type: ignore
        input_[:input_.data_size] = (data << 32) + data

        return input_, seed + 1
