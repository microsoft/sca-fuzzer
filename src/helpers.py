"""
File: Various helper functions used by multiple parts of the project

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from subprocess import run


class NotSupportedException(Exception):
    pass


def get_prng_state_after_iterations(seed: int, num_iterations: int) -> int:
    # each test case (and, accordingly, each iteration) generates 7 random values
    total_executions = num_iterations * 7
    state = seed
    mod = pow(2, 64)

    for i in range(0, total_executions):
        state = (state * 2891336453) % mod
        state = (state + 12345) % mod
    return state


def write_to_pseudo_file(value, path: str) -> None:
    run(f"sudo bash -c 'echo -n {value} > {path}'", shell=True, check=True)


def write_to_pseudo_file_bytes(value: bytes, path: str) -> None:
    with open(path, "wb") as f:
        f.write(value)


MASK_64BIT = pow(2, 64)
POW2_64 = pow(2, 64)
TWOS_COMPLEMENT_MASK_64 = pow(2, 64) - 1


def pretty_bitmap(bits: int, merged=False):
    if not merged:
        s = f"{bits:064b}"
    else:
        s = f"{bits % MASK_64BIT:064b} [ns]\n" \
            f"{(bits >> 64) % MASK_64BIT:064b} [s]"
    s = s.replace("0", "_").replace("1", "^")
    return s


def bit_count(n):
    count = 0
    while n:
        count += n & 1
        n >>= 1
    return count
