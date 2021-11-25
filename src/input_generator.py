"""
File: Input Generation

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List, Tuple
from interfaces import Input, InputTaint, InputGenerator
from config import CONF

POW32 = pow(2, 32)


class RandomInputGenerator(InputGenerator):
    """ Simple 32-bit LCG with a=2891336453 and c=54321 """

    def __init__(self):
        super().__init__()
        self.input_mask = pow(2, (CONF.prng_entropy_bits % 33)) - 1

    def generate(self, seed: int, count: int) -> List[Input]:
        generated_inputs = []
        for i in range(count):
            input_, seed = self._generate_one(seed)
            generated_inputs.append(input_)
        return generated_inputs

    def extend_equivalence_classes(self,
                                   inputs: List[Input],
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
            for j, _ in enumerate(input_):
                if taint[j]:
                    new_input[j] = input_[j]
            new_inputs.append(new_input)

        return new_inputs

    def _generate_one(self, seed: int) -> Tuple[Input, int]:
        input_ = Input()
        input_.seed = seed

        randint = seed
        for i, _ in enumerate(input_):
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

        # print(input_.get_registers())
        return input_, randint


def get_input_generator() -> InputGenerator:
    options = {
        'random': RandomInputGenerator,
    }
    if CONF.input_generator not in options:
        print("Error: unknown input_generator in config.py")
        exit(1)
    return options[CONF.input_generator]()
