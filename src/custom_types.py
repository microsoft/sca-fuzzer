"""
File: Custom data types

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List, Dict, Set, Tuple, Optional
from collections import defaultdict

CTrace = int
HTrace = int
Input = int
InputID = int
CombinedHTrace = int
InputList = List[int]


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
