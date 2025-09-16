"""
File: arm64-specific Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List, Dict

_option_values = {
    'actor': [
        'name',
        'mode',
        'privilege_level',
        'data_properties',
        'data_ept_properties',
        'observer',
        'instruction_blocklist',
        'fault_blocklist',
    ],
    "actor_mode": ['host',],
    "actor_privilege_level": ['kernel',],
    "actor_data_properties": [
        'present',
        'writable',
        'user',
        'accessed',
        'dirty',
        'executable',
        'reserved_bit',
        'randomized',
    ],
    "actor_data_ept_properties": [
        "present",
        "writable",
        "executable",
        "accessed",
        "dirty",
        'reserved_bit',
        'randomized',
    ],
    'unicorn_instruction_categories': [
        "general-arithmetic",
        "general-barrier",
        "general-bitwise",
        "general-branch",
        "general-comparison",
        "general-condsel",
        "general-dataxfer",
        "general-misc",
    ],
    "dr_instruction_categories": [
        # DynamoRIO backend is not yet supported on ARM
    ],
}

# in contrast to x86, on ARM64, we handle all fault types by default
_handled_faults: List[str] = ["PF", "DE", "DB", "BP", "BR", "UD", "PF", "GP"]

instruction_categories: List[str] = ["general-arithmetic"]
""" instruction_categories: a default list of tested instruction categories """

_buggy_instructions: List[str] = []

instruction_blocklist: List[str] = [
]  # yapf: disable
instruction_blocklist.extend(_buggy_instructions)


register_blocklist: List[str] = [
    # free - x0 .. x5
    'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
    'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23',
    'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'x31',
    'sp', 'pc',
    'w6', 'w7', 'w8', 'w9', 'w10', 'w11', 'w12', 'w13', 'w14', 'w15',
    'w16', 'w17', 'w18', 'w19', 'w20', 'w21', 'w22', 'w23',
    'w24', 'w25', 'w26', 'w27', 'w28', 'w29', 'w30', 'w31',
    'wsp', 'wpc',
    'xzr', 'wzr',
]  # yapf: disable


# FIXME: this is copied from x86, needs to be adapted for ARM64
_generator_fault_to_fault_name: Dict[str, str] = {
    'div-by-zero': "DE",
    'div-overflow': "DE",
    'opcode-undefined': "UD",
    'bounds-range-exceeded': "BR",
    'breakpoint': "BP",
    'debug-register': "DB",
    'non-canonical-access': "GP",
    'user-to-kernel-access': "PF",
}

_actor_default = {
    'name': "main",
    'mode': "host",
    'privilege_level': "kernel",
    'observer': False,
    'data_properties': {
        'present': True,
        'writable': True,
        'user': False,
        'accessed': True,
        'executable': False,
        'randomized': False,
    },
    'data_ept_properties': {
        'present': True,
        'writable': True,
        'executable': False,
        'accessed': True,
        'user': False,
        'randomized': False,
    },
    'instruction_blocklist': set(),
    'fault_blocklist': set(),
}
