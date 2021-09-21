"""
File: Various helper functions used by multiple parts of the project

Copyright (C) 2021 Oleksii Oleksenko
SPDX-License-Identifier: MIT
"""
import re
from enum import IntEnum
from collections import defaultdict
from itertools import combinations
from typing import Tuple, Dict, Set, List

from generator import TestCaseDAG, Instruction, X86Registers, OT, InstructionSet
from interfaces import Coverage, EquivalenceClass, TestCase
from config import CONF
from helpers import *


# ==================================================================================================
# Coverage Disabled
# ==================================================================================================
class NoCoverage(Coverage):
    """
    A dummy class with empty functions.
    Used when fuzzing without coverage
    """

    def load_test_case(self, asm_file):
        pass

    def update(self):
        pass

    def generator_hook(self, feedback):
        pass

    def model_hook(self, feedback):
        pass

    def executor_hook(self, feedback):
        pass

    def analyser_hook(self, feedback):
        pass

    def get(self) -> int:
        return 0


# ==================================================================================================
# Pattern Coverage
# ==================================================================================================
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
               f"[{self.positions[0]}, {hex(self.addresses[0])}], " \
               f"[{self.positions[1]}, {hex(self.addresses[1])}]"


class PatternCoverage(Coverage):
    coverage: Dict[int, Set[Tuple[int]]]
    current_patterns: List[PatternInstance]
    coverage_traces: List[List[Tuple[bool, int]]]
    combination_length: int = 1
    num_patterns: int = 0
    previous_target_coverage: int = 0
    current_max_combinations: int = 1
    previous_max_combinations: int = 0
    instruction_set_processed: bool = False

    def __init__(self):
        super().__init__()
        self.current_patterns = []
        self.coverage = defaultdict(set)

        if CONF.avg_mem_accesses:
            self.memory_patterns = [DT.MEM_LL, DT.MEM_SL, DT.MEM_SS, DT.MEM_LS]
        else:
            self.memory_patterns = []
        self.register_patters = [DT.REG_GPR, DT.REG_FLAGS]
        self.control_patterns = [DT.CONTROL_DIRECT]

    def process_instruction_set(self, instruction_set: InstructionSet):
        if instruction_set.has_conditional_branch:
            self.control_patterns = [DT.CONTROL_COND, DT.CONTROL_DIRECT]

        self.num_patterns = \
            len(self.memory_patterns) + len(self.register_patters) + len(self.control_patterns)

        self.combination_length = CONF.combination_length_min
        self.current_max_combinations = \
            self.calculate_max_combinations(self.num_patterns, CONF.combination_length_min)

        if CONF.feedback_driven_generator:
            CONF.min_bb_per_function = 1
            CONF.max_bb_per_function = 1 + CONF.combination_length_min
            CONF.avg_mem_accesses = 2 * CONF.combination_length_min if CONF.avg_mem_accesses else 0
            CONF.test_case_size = 8 * CONF.combination_length_min

    def get(self) -> int:
        return sum([len(c) for c in self.coverage.values()])

    def generator_hook(self, feedback: Dict):
        if not self.instruction_set_processed:
            self.process_instruction_set(feedback['instruction_set'])
            self.instruction_set_processed = True

        dag: TestCaseDAG = feedback['DAG']

        # collect instruction positions
        counter = 2  # account for the test case prologue
        positions = {}
        for func in dag.functions:
            for bb in func:
                for instr in bb:
                    positions[instr] = counter
                    counter += 1
                for t in bb.terminators:
                    positions[t] = counter
                    counter += 1

        # collect control hazards
        for func in dag.functions:
            for bb in func:
                for t in bb.terminators:
                    for target in t.operands:
                        target_instruction = target.bb.get_first()

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
        for func in dag.functions:
            for bb in func:
                for instr in bb:
                    if not instr.is_instrumentation and instr.next:
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
                continue

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

    def load_test_case(self, test_case: TestCase):
        obj_file = test_case.to_binary()
        output = run(f'objdump -D {obj_file} -b binary --no-show-raw-insn -m i386:x86-64',
                     shell=True,
                     check=False,
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

        self.current_patterns = list(sorted(self.current_patterns, key=lambda x: x.positions[0]))

    def model_hook(self, coverage_traces):
        self.coverage_traces = coverage_traces

    def executor_hook(self, feedback):
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
        if not self.coverage_traces or not self.coverage_traces[0]:
            self.current_patterns = []
            return

        # transform traces into a more usable form
        base_address = self.coverage_traces[0][0][1]
        combined_traces = []
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
            combined_traces.append(combined_trace)

        # collect patterns per trace
        # start = datetime.now()
        combined_covered_patterns = set()
        for trace in combined_traces:
            covered_instr_addresses = []
            covered_with_matching_memory = []

            # simple coverage
            for instr in trace:
                covered_instr_addresses.append(instr[0])

            # memory hazards
            access_trace = [t for t in trace if len(t) > 1]
            for i in range(len(access_trace)):
                # can this instruction be in a pair of mem. accesses?
                if i == len(access_trace) - 1:
                    continue

                # does the address match the next instruction?
                # FIXME: this code will be incorrect when the instruction
                #  can access several different addresses
                if access_trace[i][1] == access_trace[i + 1][1]:
                    covered_with_matching_memory.append(access_trace[i][0])

            # which of the patterns got covered
            covered_patterns = []
            for pattern in self.current_patterns:
                if pattern.dependency_type in self.register_patters \
                        and pattern.addresses[0] in covered_instr_addresses:
                    covered_patterns.append(int(pattern.dependency_type))
                    continue

                if pattern.dependency_type in self.control_patterns \
                        and pattern.addresses[0] in covered_instr_addresses \
                        and pattern.addresses[1] in covered_instr_addresses:
                    covered_patterns.append(int(pattern.dependency_type))
                    continue

                if pattern.dependency_type in self.memory_patterns \
                        and pattern.addresses[0] in covered_with_matching_memory:
                    covered_patterns.append(int(pattern.dependency_type))
                    continue
            combined_covered_patterns.add(tuple(covered_patterns))

        # print(combined_covered_patterns)
        for covered_patterns in combined_covered_patterns:
            for i in range(self.combination_length - 1, len(covered_patterns)):
                for comb in combinations(covered_patterns, i):
                    self.coverage[i].add(comb)

        # Below is debugging code. Commented out intentionally
        # duration = (datetime.now() - start).microseconds // 1000
        # if duration > 500:
        #     print(f"duration: {duration}")
        # if STAT.test_cases % 10 == 0:
        #     all_patterns = self.memory_patterns + self.control_patterns + self.register_patters
        #     all_patterns = [int(i) for i in all_patterns]
        #     all_combinations = set(product(all_patterns,
        #                                    repeat=self.combination_length))
        #     all_combinations = set([tuple(comb) for comb in all_combinations])
        #     remaining_combinations = all_combinations - self.coverage[self.combination_length]
        #     previous_remaining = \
        #         self.previous_max_combinations - len(self.coverage[self.combination_length - 1])
        #     print(f"\nremaining coverage - previous: {previous_remaining}")
        #     print(f"remaining coverage - current: {len(remaining_combinations)}")
        #     # print(sorted(remaining_combinations))

        # save the result
        STAT.coverage = sum([len(c) for c in self.coverage.values()])
        STAT.coverage_longest_uncovered = len(self.coverage[self.combination_length])

        # increase the combination length?
        if len(self.coverage[self.combination_length]) >= 0.98 * self.current_max_combinations:
            self.length_covered()

        self.current_patterns = []

    def length_covered(self):
        # store and notify about the progress
        STAT.fully_covered = self.combination_length
        print(f"\nCOVERAGE: Fully covered length {self.combination_length}")

        # update coverage parameters
        self.previous_max_combinations = self.current_max_combinations
        self.combination_length += 1
        self.current_max_combinations = \
            self.calculate_max_combinations(self.num_patterns, self.combination_length)

        # update test case size
        if CONF.feedback_driven_generator:
            CONF.max_bb_per_function += 1
            CONF.avg_mem_accesses += 2 if CONF.avg_mem_accesses else 0
            CONF.test_case_size += 8
            print(f"GENERATOR: increasing BBs to {CONF.max_bb_per_function}")
            print(f"GENERATOR: increasing memory: {CONF.avg_mem_accesses}")
            print(f"GENERATOR: increasing size: {CONF.test_case_size}")

    @staticmethod
    def calculate_max_combinations(n, r):
        return pow(n, r)


def get_coverage() -> Coverage:
    if CONF.coverage_type == 'dependencies':
        return PatternCoverage()
    elif CONF.coverage_type == 'none':
        return NoCoverage()
    else:
        print("Error: unknown value of `coverage_type` configuration option")
        exit(1)
