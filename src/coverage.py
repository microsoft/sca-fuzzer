"""
File: Various helper functions used by multiple parts of the project

Copyright (C) 2021 Oleksii Oleksenko
SPDX-License-Identifier: MIT
"""
import re
from enum import Enum
from abc import ABC, abstractmethod

from generator import TestCaseDAG, Instruction, X86Registers, OT, InstructionSet
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
    coverage_map_cont: Set[str]
    coverage_map_mem: Set[str]
    coverage_map_reg: Set[str]
    current_patterns: List[Hazard]
    coverage_traces: List[List[Tuple[bool, int]]]
    positions_to_names: Dict[int, str]
    max_cov: int = 0

    def __init__(self):
        self.current_patterns = []
        self.coverage_map_cont = set()
        self.coverage_map_mem = set()
        self.coverage_map_reg = set()
        self.positions_to_names = {}

    def get(self) -> int:
        return len(self.coverage_map_cont) + len(self.coverage_map_mem) + len(self.coverage_map_reg)

    def get_detailed(self) -> Tuple[int, int, int]:
        return len(self.coverage_map_cont), len(self.coverage_map_mem), len(self.coverage_map_reg)

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
            if pattern.dependency_type == DT.CONTROL:
                pattern.covered = pattern.addresses[0] in covered_instr_addresses \
                                  and pattern.addresses[1] in covered_instr_addresses

            if pattern.dependency_type == DT.REG:
                pattern.covered = pattern.addresses[0] in covered_instr_addresses

            if pattern.dependency_type == DT.MEM:
                pattern.covered = pattern.addresses[0] in covered_with_matching_memory

        for p in self.current_patterns:
            if p.covered:
                name = f"{p.instructions[0]} {p.dependency_type} {p.instructions[1]}"
                if p.dependency_type == DT.CONTROL:
                    self.coverage_map_cont.add(name)
                elif p.dependency_type == DT.REG:
                    self.coverage_map_reg.add(name)
                elif p.dependency_type == DT.MEM:
                    self.coverage_map_mem.add(name)

        STAT.cov_patterns_cont = len(self.coverage_map_cont)
        STAT.cov_patterns_mem = len(self.coverage_map_mem)
        STAT.cov_patterns_reg = len(self.coverage_map_reg)

        self.current_patterns = []

    def generator_hook(self, DAG: TestCaseDAG, instruction_set: InstructionSet):
        # calculate max. coverage
        if not self.max_cov:
            reg_src = 0
            reg_dest = 0
            flags_src = 0
            flags_dest = 0
            mem = 0
            control = 0

            for instr in instruction_set.all + instruction_set.control_flow:
                if instr.has_mem_operand:
                    mem += 1

                if instr.control_flow:
                    control += 1

                has_reg_src = False
                has_reg_dest = False
                has_flags_src = False
                has_flags_dest = False
                for op in instr.operands:
                    has_reg_src |= op.type == OT.REG and op.src
                    has_reg_dest |= op.type == OT.REG and op.dest
                    has_flags_src |= op.type == OT.FLAGS and op.src
                    has_flags_dest |= op.type == OT.FLAGS and op.dest
                if has_reg_src:
                    reg_src += 1
                if has_reg_dest:
                    reg_dest += 1
                if has_flags_src:
                    flags_src += 1
                if has_flags_dest:
                    flags_dest += 1

            self.max_cov = control * (reg_dest + flags_dest + mem) + \
                reg_src * reg_dest + flags_src * flags_dest + mem * mem
            print(f"Max coverage: {self.max_cov}")

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
                        if not target_instruction:
                            continue
                        if not target_instruction.has_dest_operand(True):
                            continue
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
            if p[0].has_mem_operand() and p[1].has_mem_operand() and p[1].has_dest_operand(True):
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
            if dependencies and p[1].has_dest_operand(True):
                pair = (p[0].name, p[1].name)
                pair_ids = (positions[p[0]], positions[p[1]])
                self.current_patterns.append(
                    Hazard(pair, pair_ids, DT.REG))

    def load_test_case(self, asm_file: str):
        # update positions of patterns in the test case
        updated_positions = {}
        with open(asm_file, "r") as f:
            old_position = 0
            new_position = 0
            for line in f:
                if line[0] == '.':  # ignore labels - they are not compiled in the binary
                    continue
                if "instrumentation" not in line:
                    updated_positions[old_position] = new_position
                    old_position += 1
                new_position += 1

        for pattern in self.current_patterns:
            pattern.positions = (updated_positions[pattern.positions[0]],
                                 updated_positions[pattern.positions[1]])

        assemble(asm_file, 'tmp.o')
        output = run('objdump -D tmp.o -b binary -m i386:x86-64', shell=True, check=True,
                     capture_output=True)
        lines = output.stdout.decode().split("\n")
        addresses = {}
        counter = 0  # start from 2 because there are 2 instructions in the prologue
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
                member_input_id = eq_cls.original_positions[0]
                effective_traces.append(self.coverage_traces[member_input_id])
        self.coverage_traces = effective_traces


def get_coverage() -> Coverage:
    if CONF.coverage_type == 'dependencies':
        return PatternCoverage()
    else:
        print("Error: unknown value of `coverage_type` configuration option")
        exit(1)
