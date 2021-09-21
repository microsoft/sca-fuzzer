"""
File: Input Generation

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from abc import ABC, abstractmethod
from custom_types import List, Input
from config import CONF

POW32 = pow(2, 32)


class InputGenerator(ABC):
    coverage = None

    @abstractmethod
    def generate(self, seed: int, count: int) -> List[Input]:
        pass

    def set_coverage(self, coverage):
        self.coverage = coverage


class RandomInputGenerator(InputGenerator):
    """ Simple 32-bit LCG with a=2891336453 and c=54321 """

    def generate(self, seed, count) -> List[Input]:
        generated_inputs = []
        randint = seed
        input_mask = pow(2, (CONF.prng_entropy_bits % 33)) - 1

        for i in range(count):
            input_ = Input()
            input_.seed = randint
            for j, _ in enumerate(input_):
                randint = ((randint * 2891336453) % POW32 + 54321) % POW32
                masked_rvalue = (randint ^ (randint >> 16)) & input_mask
                masked_rvalue = masked_rvalue << 6
                input_[j] = masked_rvalue
            generated_inputs.append(input_)
        return generated_inputs


def get_input_generator() -> InputGenerator:
    options = {
        'random': RandomInputGenerator,
    }
    if CONF.input_generator not in options:
        print("Error: unknown input_generator in config.py")
        exit(1)
    return options[CONF.input_generator]()
