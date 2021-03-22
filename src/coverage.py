"""
File: Various helper functions used by multiple parts of the project

Copyright (C) 2021 Oleksii Oleksenko
SPDX-License-Identifier: MIT
"""
import re
from enum import Enum
from abc import ABC, abstractmethod

from generator import TestCaseDAG, Instruction, X86Registers, OT
from custom_types import *
from helpers import *


class DT(Enum):  # Dependency Type
    REG = 1
    MEM = 2
    CONTROL = 3


class Hazard:
    instructions: Tuple[str, str]
    dependency_type: DT
    positions: Tuple[int, int]
    addresses: Tuple[int, int] = (0, 0)
    covered: bool = False

    def __init__(self, instructions, positions, type_):
        self.instructions = instructions
        self.positions = positions
        self.dependency_type = type_

    def __str__(self):
        return f"[{self.covered}] {self.instructions[0]} -> {self.dependency_type} -> {self.instructions[1]} at " \
               f"[{self.positions[0]}, {self.addresses[0]}], " \
               f"[{self.positions[1]}, {self.addresses[1]}]"


class Coverage(ABC):
    @abstractmethod
    def load_test_case(self, asm_file):
        pass

    @abstractmethod
    def update(self):
        pass

    @abstractmethod
    def generator_hook(self, DAG: TestCaseDAG):
        pass

    @abstractmethod
    def model_hook(self, coverage_traces):
        pass

    @abstractmethod
    def executor_hook(self):
        pass

    @abstractmethod
    def analyser_hook(self, input_classes):
        pass

    @abstractmethod
    def get(self) -> int:
        pass


class PatternCoverage(Coverage):
    coverage_map: Set[str]
    current_patterns: List[Hazard]
    coverage_traces: List[List[Tuple[bool, int]]]

    def __init__(self):
        self.current_patterns = []
        self.coverage_map = set()

    def update(self):
        if not self.coverage_traces:
            return

        base_address = self.coverage_traces[0][0][1]

        covered_addresses = set()
        for trace in self.coverage_traces:
            for observation in trace:
                if observation[0]:  # instruction
                    address = observation[1] - base_address
                    covered_addresses.add(address)

        for pattern in self.current_patterns:
            if pattern.dependency_type == DT.REG:
                pattern.covered = pattern.addresses[0] in covered_addresses

            if pattern.dependency_type == DT.CONTROL:
                pattern.covered = pattern.addresses[0] in covered_addresses \
                                  and pattern.addresses[1] in covered_addresses

        for h in self.current_patterns:
            if h.covered:
                self.coverage_map.add(
                    f"{h.instructions[0]} {h.dependency_type} {h.instructions[1]}")

        self.current_patterns = []

    def get(self) -> int:
        return len(self.coverage_map)

    def generator_hook(self, DAG: TestCaseDAG):
        # collect instruction positions
        counter = 0
        positions = {}
        for function in DAG.functions:
            for BB in function:
                for instr in BB:
                    positions[instr] = counter
                    counter += 1
                for t in BB.terminators:
                    positions[t] = counter
                    counter += 1

        # collect control hazards
        for function in DAG.functions:
            for BB in function:
                for t in BB.terminators:
                    for target in t.operands:
                        target_instruction = target.BB.get_first()
                        if target_instruction:
                            pair = (t.name, target_instruction.name)
                            pair_ids = (positions[t], positions[target_instruction])
                            self.current_patterns.append(
                                Hazard(pair, pair_ids, DT.CONTROL))

        # collect all instruction pairs
        pairs: List[Tuple[Instruction, Instruction]] = []
        for function in DAG.functions:
            for BB in function:
                for instr in BB:
                    if instr.next:
                        pairs.append((instr, instr.next))

        # filter pairs to those with potential data dependencies
        for p in pairs:
            # memory dependency?
            if p[0].has_mem_operand() and p[1].has_mem_operand():
                pair = (p[0].name, p[1].name)
                pair_ids = (positions[p[0]], positions[p[1]])
                self.current_patterns.append(
                    Hazard(pair, pair_ids, DT.MEM))

            # flags or register dependency?
            destinations = [X86Registers.gpr_normalized[op.value]
                            for op in p[0].operands + p[0].implicit_operands if
                            op.dest and op.type in [OT.REG, OT.FLAGS]]
            sources = [X86Registers.gpr_normalized[op.value]
                       for op in p[1].operands + p[1].implicit_operands if
                       op.src and op.type in [OT.REG, OT.FLAGS]]
            dependencies = [op for op in sources if op in destinations]
            if dependencies:
                pair = (p[0].name, p[1].name)
                pair_ids = (positions[p[0]], positions[p[1]])
                self.current_patterns.append(
                    Hazard(pair, pair_ids, DT.REG))

    def load_test_case(self, asm_file: str):
        assemble(asm_file, 'tmp.o')
        output = run('objdump -D tmp.o -b binary -m i386:x86-64', shell=True, check=True,
                     capture_output=True)
        lines = output.stdout.decode().split("\n")
        addresses = {}
        counter = 0
        for line in lines:
            address = re.search(r" ([0-9a-f]+):", line)
            if address:
                addresses[counter] = int(address.group(1), 16)
                counter += 1

        for pattern in self.current_patterns:
            pattern.addresses = (
                addresses[pattern.positions[0]],
                addresses[pattern.positions[1]]
            )

    def model_hook(self, coverage_traces):
        self.coverage_traces = coverage_traces

    def executor_hook(self):
        pass

    def analyser_hook(self, classes: List[EquivalenceClass]):
        effective_traces = []
        for eq_cls in classes:
            if len(eq_cls.inputs) >= 2:
                member_input_id = eq_cls.original_positions[0]
                effective_traces.append(self.coverage_traces[member_input_id])
        self.coverage_traces = effective_traces


def get_coverage() -> Coverage:
    if CONF.coverage_type == 'dependencies':
        return PatternCoverage()
    else:
        print("Error: unknown value of `coverage_type` configuration option")
        exit(1)
