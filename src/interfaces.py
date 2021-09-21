"""
File: Custom data types

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List, Dict, Tuple
from collections import defaultdict
from abc import ABC, abstractmethod
import numpy as np

from config import CONF
from helpers import run

# ==================================================================================================
# Custom Data Types
# ==================================================================================================
CTrace = int
HTrace = int
InputID = int
CombinedHTrace = int


class TestCase:
    asm_path: str = ''

    def __init__(self, path: str):
        self.asm_path = path

    def to_binary(self) -> str:
        """
        Assemble the test case into a stripped binary
        """
        outfile = self.asm_path[:-4] + ".o"
        run(f"as {self.asm_path} -o {outfile}", shell=True, check=True)
        run(f"strip --remove-section=.note.gnu.property {outfile}", shell=True, check=True)
        run(f"objcopy {outfile} -O binary {outfile}", shell=True, check=True)
        return outfile


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
        pass

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


# ==================================================================================================
# Interfaces of Modules
# ==================================================================================================
class Coverage(ABC):
    @abstractmethod
    def load_test_case(self, test_case: TestCase):
        pass

    @abstractmethod
    def update(self):
        pass

    @abstractmethod
    def generator_hook(self, feedback):
        pass

    @abstractmethod
    def model_hook(self, feedback):
        pass

    @abstractmethod
    def executor_hook(self, feedback):
        pass

    @abstractmethod
    def analyser_hook(self, feedback):
        pass

    @abstractmethod
    def get(self) -> int:
        pass


class Generator(ABC):
    coverage: Coverage

    @abstractmethod
    def __init__(self, instruction_set_spec: str):
        super().__init__()

    @abstractmethod
    def create_test_case(self, path: str) -> TestCase:
        pass

    def set_coverage(self, coverage: Coverage):
        self.coverage = coverage


class InputGenerator(ABC):
    coverage: Coverage

    @abstractmethod
    def generate(self, seed: int, count: int) -> List[Input]:
        pass

    def set_coverage(self, coverage: Coverage):
        self.coverage = coverage


class Model(ABC):
    coverage: Coverage

    @abstractmethod
    def __init__(self, sandbox_base: int, code_base: int):
        super().__init__()

    @abstractmethod
    def load_test_case(self, test_case: TestCase) -> None:
        pass

    @abstractmethod
    def trace_test_case(self, inputs: List[Input], nesting: int, dbg: bool = False) -> List[CTrace]:
        pass

    def set_coverage(self, coverage: Coverage):
        self.coverage = coverage


class Executor(ABC):
    coverage: Coverage

    @abstractmethod
    def load_test_case(self, test_case: TestCase):
        pass

    @abstractmethod
    def trace_test_case(self, inputs: List[Input], num_measurements: int = 0) \
            -> List[CombinedHTrace]:
        pass

    @abstractmethod
    def read_base_addresses(self) -> Tuple[int, int]:
        pass

    def set_coverage(self, coverage: Coverage):
        self.coverage = coverage


class Analyser(ABC):
    coverage: Coverage

    @abstractmethod
    def filter_violations(self, inputs: List[Input], ctraces: List[CTrace],
                          htraces: List[HTrace], stats=False) -> List[EquivalenceClass]:
        pass

    def set_coverage(self, coverage: Coverage):
        self.coverage = coverage
