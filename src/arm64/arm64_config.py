"""
File: arm64-specific configuration options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List

arm64_input_register_region_size: int = 7 * 8

# x86_option_values attribute MUST be the first attribute in the file
arm64_option_values = {
    'executor_mode': ['P+P'],
}

arm64_instruction_categories: List[str] = [] # support all categories
arm64_instruction_blocklist: List[str] = [] # suppport all instructions

arm64_register_blocklist: List[str] = [
    # not supported by the generator
    "WSP",
    "SP",
    # not supported by the generator
    "XZR",
    "WZR",
    # not included into the input
    "W6",
    "W7",
    "W8",
    "W9",
    "W10",
    "W11",
    "W12",
    "W13",
    "W14",
    "W15",
    "W16",
    "W17",
    "W18",
    "W19",
    "W20",
    "W21",
    "W22",
    "W23",
    "W24",
    "W25",
    "W26",
    "W27",
    "W28",
    "W29",
    "W30",
    "X6",
    "X7",
    "X8",
    "X9",
    "X10",
    "X11",
    "X12",
    "X13",
    "X14",
    "X15",
    "X16",
    "X17",
    "X18",
    "X19",
    "X20",
    "X21",
    "X22",
    "X23",
    "X24",
    "X25",
    "X26",
    "X27",
    "X28",
    "X29",
    "X30"
]
