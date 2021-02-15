"""
File: Input Generation

Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from abc import ABC, abstractmethod
from typing import List

POW32 = pow(2, 32)


class InputGenerator(ABC):
    @abstractmethod
    def generate(self, seed: int, count: int) -> List[int]:
        pass


class RandomInputGenerator(InputGenerator):
    """ Simple 32-bit LCG with a=2891336453 and c=12345 """

    def generate(self, seed, count):
        inputs = []
        value = seed
        for i in range(count):
            inputs.append(value)
            value = ((value * 2891336453) % POW32 + 12345) % POW32
        return inputs
