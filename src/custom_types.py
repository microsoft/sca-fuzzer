"""
File: Custom data types

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict
from config import CONF

import numpy as np

CTrace = int
HTrace = int
InputID = int
CombinedHTrace = int


class Input(np.ndarray):
    seed: int = 0

    def __new__(cls):
        size = CONF.input_main_region_size + \
               CONF.input_assist_region_size + \
               CONF.input_register_region_size
        obj = super().__new__(cls, (size,), np.uint64, None, 0, None, None)
        return obj

    def __array_finalize__(self, obj):
        if obj is None:
            return
        pass  # placeholder

    def get_registers(self):
        return self[-CONF.input_register_region_size:-1]

    def __str__(self):
        return str(self.seed)

    def __repr__(self):
        return str(self.seed)


class EquivalenceClass:
    ctrace: CTrace
    original_positions: List[InputID]
    inputs: List[Input]
    htraces: List[HTrace]
    htrace_groups: Dict[HTrace, List[int]]
    primed_positions: Dict[int, List[int]]
    mod2p64 = pow(2, 64)

    def __init__(self):
        self.inputs = []
        self.htraces = []
        self.original_positions = []

    def __str__(self):
        s = f"Size: {len(self.inputs)}\n"
        s += f"Ctrace:\n" \
             f"{self.ctrace % self.mod2p64:064b} [ns]\n" \
             f"{(self.ctrace >> 64) % self.mod2p64:064b} [s]\n"
        s += "Htraces:\n"
        for h in self.htrace_groups.keys():
            s += f"{h:064b}\n"
        s = s.replace("0", "_").replace("1", "^")
        return s

    def update_groups(self) -> None:
        """ group inputs by htraces """
        groups = defaultdict(list)
        for i, htrace in enumerate(self.htraces):
            groups[htrace].append(i)
        self.htrace_groups = groups


EquivalenceClassMap = Dict[CTrace, EquivalenceClass]
