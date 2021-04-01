"""
File: Various helper functions used by multiple parts of the project

Copyright (C) 2021 Oleksii Oleksenko
SPDX-License-Identifier: MIT
"""
import re
from enum import IntEnum
from abc import ABC, abstractmethod
from itertools import combinations
from math import factorial

from generator import TestCaseDAG, Instruction, X86Registers, OT, InstructionSet
from custom_types import *
from helpers import *


class DT(IntEnum):  # Dependency Type
    REG_GPR = 1
    REG_FLAGS = 2
    MEM_LL = 4
    MEM_LS = 5
    MEM_SL = 6
    MEM_SS = 7
    CONTROL_DIRECT = 8
    CONTROL_COND = 9


class PatternInstance:
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
    def generator_hook(self, DAG: TestCaseDAG, instruction_set: InstructionSet):
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
    coverage: Set[Tuple[int]]
    current_patterns: List[PatternInstance]
    coverage_traces: List[List[Tuple[bool, int]]]
    positions_to_names: Dict[int, str]
    max_cov: int = 0
    combination_length: int = 1
    num_patterns: int = 8
    max_combinations_of_current_length: int = 8

    def __init__(self):
        self.current_patterns = []
        self.coverage = set()
        self.positions_to_names = {}

    def get(self) -> int:
        return len(self.coverage)

    def generator_hook(self, DAG: TestCaseDAG, instruction_set: InstructionSet):
        # collect instruction positions
        counter = 2  # function prologue is 2 instructions long
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

                        # skip instrumentation
                        while target_instruction and target_instruction.is_instrumentation:
                            target_instruction = target_instruction.next

                        if not target_instruction or not target_instruction.has_dest_operand(True):
                            continue
                        pair = (t.name, target_instruction.name)
                        pair_ids = (positions[t], positions[target_instruction])
                        type_ = DT.CONTROL_DIRECT if "JMP" in t.name else DT.CONTROL_COND
                        self.current_patterns.append(PatternInstance(pair, pair_ids, type_))

        # collect all instruction pairs
        pairs: List[Tuple[Instruction, Instruction]] = []
        for function in DAG.functions:
            for BB in function:
                for instr in BB:
                    if instr.next:
                        # skip instrumentation
                        next_instr = instr.next
                        while next_instr and next_instr.is_instrumentation:
                            next_instr = next_instr.next
                        if not next_instr:
                            continue

                        pairs.append((instr, next_instr))

        # filter pairs to those with potential data dependencies
        for p in pairs:
            # memory dependency?
            if p[0].has_mem_operand() and p[1].has_mem_operand() and p[1].has_dest_operand(True):
                pair = (p[0].name, p[1].name)
                pair_ids = (positions[p[0]], positions[p[1]])
                if p[0].is_store():
                    type_ = DT.MEM_SS if p[1].is_store() else DT.MEM_SL
                else:
                    type_ = DT.MEM_LS if p[1].is_store() else DT.MEM_LL
                self.current_patterns.append(PatternInstance(pair, pair_ids, type_))

            # flags or register dependency?
            destinations = [X86Registers.gpr_normalized[op.value]
                            for op in p[0].operands + p[0].implicit_operands if
                            op.dest and op.type in [OT.REG, OT.FLAGS]]
            sources = [X86Registers.gpr_normalized[op.value]
                       for op in p[1].operands + p[1].implicit_operands if
                       op.src and op.type in [OT.REG, OT.FLAGS]]
            dependencies = [op for op in sources if op in destinations]
            if dependencies and p[1].has_dest_operand(True):
                pair = (p[0].name, p[1].name)
                pair_ids = (positions[p[0]], positions[p[1]])
                type_ = DT.REG_FLAGS if dependencies[0] == "FLAGS" else DT.REG_GPR
                self.current_patterns.append(PatternInstance(pair, pair_ids, type_))

    def load_test_case(self, asm_file: str):
        assemble(asm_file, 'tmp.o')
        output = run('objdump -D tmp.o -b binary --no-show-raw-insn -m i386:x86-64', shell=True,
                     check=True,
                     capture_output=True)
        lines = output.stdout.decode().split("\n")
        addresses = {}
        counter = 0
        for line in lines:
            match = re.search(r" ([0-9a-f]+):", line)
            if match:
                address = int(match.group(1), 16)
                addresses[counter] = address
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
                # FIXME: should take the first from each coverage class, not from each input class
                member_input_id = eq_cls.original_positions[0]
                effective_traces.append(self.coverage_traces[member_input_id])
        self.coverage_traces = effective_traces

    def update(self):
        if not self.coverage_traces:
            self.current_patterns = []
            return

        base_address = self.coverage_traces[0][0][1]

        covered_instr_addresses = set()
        covered_with_matching_memory = set()
        for trace in self.coverage_traces:
            combined_trace = []
            latest_instruction = []

            for observation in trace:
                if observation[0]:  # instruction address
                    if latest_instruction:
                        combined_trace.append(latest_instruction)
                    latest_instruction = [observation[1] - base_address]
                else:  # address of the instruction's memory access
                    if len(latest_instruction) != 1 and latest_instruction[1] == observation[1]:
                        continue
                    latest_instruction.append(observation[1])
            combined_trace.append(latest_instruction)

            # simple coverage
            for instr in combined_trace:
                covered_instr_addresses.add(instr[0])

            # memory hazards
            access_trace = [t for t in combined_trace if len(t) > 1]
            for i in range(len(access_trace)):
                # can this instruction be in a pair of mem. accesses?
                if i == len(access_trace) - 1:
                    continue

                # does the address match the next instruction?
                # FIXME: this code will be incorrect when the instruction
                #  can access several different addresses
                if access_trace[i][1] == access_trace[i + 1][1]:
                    covered_with_matching_memory.add(access_trace[i][0])

        for pattern in self.current_patterns:
            if pattern.dependency_type in [DT.CONTROL_COND, DT.CONTROL_DIRECT]:
                pattern.covered = pattern.addresses[0] in covered_instr_addresses \
                                  and pattern.addresses[1] in covered_instr_addresses

            if pattern.dependency_type in [DT.REG_FLAGS, DT.REG_GPR]:
                pattern.covered = pattern.addresses[0] in covered_instr_addresses

            if pattern.dependency_type in [DT.MEM_LL, DT.MEM_SL, DT.MEM_LS, DT.MEM_SS]:
                pattern.covered = pattern.addresses[0] in covered_with_matching_memory

        covered_patterns = [int(p.dependency_type) for p in self.current_patterns if p.covered]
        covered_patterns = sorted(covered_patterns)
        for c in combinations(covered_patterns, self.combination_length):
            self.coverage.add(tuple(c))
        STAT.coverage = len(self.coverage)

        # increase the combination length?
        if len(self.coverage) == self.max_combinations_of_current_length:
            self.combination_length += 1
            n = self.num_patterns
            r = self.combination_length
            self.max_combinations_of_current_length += \
                factorial(n + r - 1) / factorial(r) / factorial(n - 1)

        self.current_patterns = []


def get_coverage() -> Coverage:
    if CONF.coverage_type == 'dependencies':
        return PatternCoverage()
    else:
        print("Error: unknown value of `coverage_type` configuration option")
        exit(1)
