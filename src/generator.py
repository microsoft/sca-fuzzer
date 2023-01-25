"""
File: Test Case Generation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import random
import abc
import re
import json
from typing import List, Dict
from subprocess import CalledProcessError, run
from collections import OrderedDict

from isa_loader import InstructionSet
from interfaces import Generator, TestCase, Operand, RegisterOperand, FlagsOperand, MemoryOperand, \
    ImmediateOperand, AgenOperand, LabelOperand, OT, Instruction, BasicBlock, Function, \
    OperandSpec, InstructionSpec, CondOperand, TargetDesc
from service import NotSupportedException
from config import CONF


# Helpers
class GeneratorException(Exception):
    pass


class AsmParserException(Exception):

    def __init__(self, line_number, explanation):
        msg = "Could not parse line " + str(line_number + 1) + "\n  Reason: " + explanation
        super().__init__(msg)


def parser_assert(condition: bool, line_number: int, explanation: str):
    if not condition:
        raise AsmParserException(line_number, explanation)


# ==================================================================================================
# Generator Interface
# ==================================================================================================
class Pass(abc.ABC):

    @abc.abstractmethod
    def run_on_test_case(self, test_case: TestCase) -> None:
        pass


class Printer(abc.ABC):
    prologue_template: List[str]
    epilogue_template: List[str]

    @abc.abstractmethod
    def print(self, test_case: TestCase, outfile: str) -> None:
        pass


class ConfigurableGenerator(Generator, abc.ABC):
    instruction_set: InstructionSet
    """
    The interface description for Generator classes.
    """
    test_case: TestCase
    passes: List[Pass]  # set by subclasses
    printer: Printer  # set by subclasses
    target_desc: TargetDesc  # set by subclasses
    gadgets: []

    def __init__(self, instruction_set: InstructionSet, seed: int):
        super().__init__(instruction_set, seed)
        self.control_flow_instructions = \
            [i for i in self.instruction_set.instructions if i.control_flow]
        if CONF.max_bb_per_function > 1:
            assert self.control_flow_instructions, \
                "The instruction set is insufficient to generate a test case"

        self.non_control_flow_instructions = \
            [i for i in self.instruction_set.instructions if not i.control_flow]
        assert self.non_control_flow_instructions, \
            "The instruction set is insufficient to generate a test case"

        self.non_memory_access_instructions = \
            [i for i in self.non_control_flow_instructions if not i.has_mem_operand]
        if CONF.avg_mem_accesses != 0:
            memory_access_instructions = \
                [i for i in self.non_control_flow_instructions if i.has_mem_operand]
            self.load_instruction = [i for i in memory_access_instructions if not i.has_write]
            self.store_instructions = [i for i in memory_access_instructions if i.has_write]
            assert self.load_instruction and self.store_instructions, \
                "The instruction set does not have memory accesses while `avg_mem_accesses > 0`"

        self.gadgets = []
        if len(CONF.gadget_file) > 0:
            with open(CONF.gadget_file, "r") as fp:
                gdata = json.loads(fp.read())
                for entry in gdata:
                    self.gadgets.append(CodeGadget.from_dict(entry))
            # sort the gadgets by length (descending) to make searching easier
            self.gadgets = sorted(self.gadgets, key=lambda g: len(g), reverse=True)
    
    def set_seed(self, seed: int):
        if not seed:
            seed = random.randint(1, 1000000)
        self._state = seed
        random.seed(seed)

    def create_test_case(self, asm_file: str, disable_assembler: bool = False) -> TestCase:
        self.test_case = TestCase()

        # create the main function
        func = self.generate_function(".function_main")

        # fill the function with instructions
        self.add_terminators_in_function(func)
        self.add_instructions_in_function(func)

        # add it to the test case
        self.test_case.functions.append(func)
        self.test_case.main = func

        # process the test case
        for p in self.passes:
            p.run_on_test_case(self.test_case)

        self.printer.print(self.test_case, asm_file)
        self.test_case.asm_path = asm_file

        if disable_assembler:
            return self.test_case

        bin_file = asm_file[:-4] + ".o"
        self.assemble(asm_file, bin_file)
        self.test_case.bin_path = bin_file

        self.map_addresses(self.test_case, bin_file)

        return self.test_case

    @staticmethod
    def assemble(asm_file: str, bin_file: str) -> None:
        """Assemble the test case into a stripped binary"""
        try:
            run(f"as {asm_file} -o {bin_file}", shell=True, check=True, capture_output=True)
        except CalledProcessError as e:
            error_msg = e.stderr.decode()
            if "Assembler messages:" not in error_msg:
                print(error_msg)
                raise e

            with open(asm_file, "r") as f:
                lines = f.read().split("\n")

            for msg in error_msg.split("\n"):
                msg = msg.removeprefix(asm_file + ":")
                line_num_str = re.search(r"(\d+):", msg)
                if not line_num_str:
                    print(msg)
                else:
                    line = lines[int(line_num_str.group(1))]
                    print(msg + " -> " + line)
            raise e

        run(f"strip --remove-section=.note.gnu.property {bin_file}", shell=True, check=True)
        run(f"objcopy {bin_file} -O binary {bin_file}", shell=True, check=True)

    def parse_existing_test_case(self, asm_file: str) -> TestCase:
        test_case = TestCase()
        test_case.asm_path = asm_file

        # prepare regexes
        re_redundant_spaces = re.compile(r"(?<![a-zA-Z0-9]) +")

        # prepare a map of all instruction specs
        instruction_map: Dict[str, List[InstructionSpec]] = {}
        for spec in self.instruction_set.instructions:
            if spec.name in instruction_map:
                instruction_map[spec.name].append(spec)
            else:
                instruction_map[spec.name] = [spec]

        # load the text and clean it up
        lines = []
        started = False
        with open(asm_file, "r") as f:
            for line in f:
                # remove extra spaces
                line = line.strip()
                line = re_redundant_spaces.sub("", line)

                # skip comments and empty lines
                if not line or line[0] in ["", "#", "/"]:
                    continue

                # skip footer and header
                if not started:
                    started = (line == ".test_case_enter:")
                    if line[0] != ".":
                        test_case.num_prologue_instructions += 1
                    continue
                if line == ".test_case_exit:":
                    break

                lines.append(line)

        # set defaults in case the main function is implicit
        if not lines or not lines[0].startswith(".function_main:"):
            lines = [".function_main:"] + lines

        # map lines to functions and basic blocks
        current_function = ""
        current_bb = ".bb_main.entry"
        test_case_map: Dict[str, Dict[str, List[str]]] = OrderedDict()
        for line in lines:
            # instruction
            if not line.startswith("."):
                test_case_map[current_function][current_bb].append(line)
                continue

            # function
            if line.startswith(".function_"):
                current_function = line[:-1]
                test_case_map[current_function] = OrderedDict()

                current_bb = ".bb_" + current_function.removeprefix(".function_") + ".entry"
                test_case_map[current_function][current_bb] = []
                continue

            # basic block
            current_bb = line[:-1]
            if current_bb not in test_case_map[current_function]:
                test_case_map[current_function][current_bb] = []

        # parse lines and create their object representations
        line_id = 1
        for func_name, bbs in test_case_map.items():
            # print(func_name)
            line_id += 1
            func = Function(func_name)
            test_case.functions.append(func)
            if func_name == ".function_main":
                test_case.main = func

            for bb_name, lines in bbs.items():
                # print(">>", bb_name)
                line_id += 1
                if bb_name.endswith("entry"):
                    bb = func.entry
                elif bb_name.endswith("exit"):
                    bb = func.exit
                else:
                    bb = BasicBlock(bb_name)
                    func.insert(bb)

                terminators_started = False
                for line in lines:
                    # print(f"    {line}")
                    line_id += 1
                    inst = self.parse_line(line, line_id, instruction_map)
                    if inst.control_flow and not self.target_desc.is_call(inst):
                        terminators_started = True
                        bb.insert_terminator(inst)
                    else:
                        parser_assert(not terminators_started, line_id,
                                      "Terminator not at the end of BB")
                        bb.insert_after(bb.get_last(), inst)

        # connect basic blocks
        bb_names = {bb.name.upper(): bb for func in test_case for bb in func}
        bb_names[".TEST_CASE_EXIT"] = func.exit
        previous_bb = None
        for func in test_case:
            for bb in func:
                # fallthrough
                if previous_bb:  # skip the first BB
                    # there is a fallthrough only if the last terminator is not a direct jump
                    if not previous_bb.terminators or \
                          not self.target_desc.is_unconditional_branch(previous_bb.terminators[-1]):
                        previous_bb.successors.append(bb)
                previous_bb = bb

                # taken branches
                for terminator in bb.terminators:
                    for op in terminator.operands:
                        if isinstance(op, LabelOperand):
                            successor = bb_names[op.value]
                            bb.successors.append(successor)

        bin_file = asm_file[:-4] + ".o"
        self.assemble(asm_file, bin_file)
        test_case.bin_path = bin_file

        self.map_addresses(test_case, bin_file)

        return test_case

    @abc.abstractmethod
    def parse_line(self, line: str, line_num: int,
                   instruction_map: Dict[str, List[InstructionSpec]]) -> Instruction:
        pass

    @abc.abstractmethod
    def map_addresses(self, test_case: TestCase, bin_file: str) -> None:
        pass

    @abc.abstractmethod
    def generate_function(self, name: str) -> Function:
        pass

    @abc.abstractmethod
    def generate_instruction(self, spec: InstructionSpec) -> Instruction:
        pass

    def generate_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        generators = {
            OT.REG: self.generate_reg_operand,
            OT.MEM: self.generate_mem_operand,
            OT.IMM: self.generate_imm_operand,
            OT.LABEL: self.generate_label_operand,
            OT.AGEN: self.generate_agen_operand,
            OT.FLAGS: self.generate_flags_operand,
            OT.COND: self.generate_cond_operand,
        }
        return generators[spec.type](spec, parent)

    @abc.abstractmethod
    def generate_reg_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_mem_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_imm_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_label_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_agen_operand(self, _: OperandSpec, __: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_flags_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def generate_cond_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        pass

    @abc.abstractmethod
    def add_terminators_in_function(self, func: Function):
        pass

    @abc.abstractmethod
    def add_instructions_in_function(self, func: Function):
        pass


# ==================================================================================================
# ISA-independent Generators
# ==================================================================================================
class RandomGenerator(ConfigurableGenerator, abc.ABC):
    """
    Implements an ISA-independent logic of random test case generation.
    Subclasses are responsible for the ISA-specific parts.
    """
    had_recent_memory_access: bool = False

    def __init__(self, instruction_set: InstructionSet, seed: int):
        super().__init__(instruction_set, seed)
        uncond_name = self.get_unconditional_jump_instruction().name.lower()
        self.cond_branches = \
            [i for i in self.control_flow_instructions if i.name.lower() != uncond_name]
        if CONF.max_successors_per_bb > 1:
            assert self.cond_branches, \
                "The instruction set does not contain cond branches while max_successors_per_bb > 1"
        self.mem_access_count = 0 # counts the number of generated memory-accessing instructions

    def generate_function(self, label: str):
        """ Generates a random DAG of basic blocks within a function """
        func = Function(label)

        # Define the maximum allowed number of successors for any BB
        if self.instruction_set.has_conditional_branch:
            max_successors = CONF.max_successors_per_bb if CONF.max_successors_per_bb < 2 else 2
            min_successors = CONF.min_successors_per_bb \
                if CONF.min_successors_per_bb < max_successors else max_successors
        else:
            max_successors = 1
            min_successors = 1

        # Create basic blocks
        node_count = random.randint(CONF.min_bb_per_function, CONF.max_bb_per_function)
        func_name = label.removeprefix(".function_")
        nodes = [BasicBlock(f".bb_{func_name}.{i}") for i in range(node_count)]

        # Connect BBs into a graph
        for i in range(node_count):
            current_bb = nodes[i]

            # the last node has only one successor - exit
            if i == node_count - 1:
                current_bb.successors = [func.exit]
                break

            # the rest of the node have a random number of successors
            successor_count = random.randint(min_successors, max_successors)
            if successor_count + i > node_count:
                # the number is adjusted to the position when close to the end
                successor_count = node_count - i

            # one of the targets (the first successor) is always the next node - to avoid dead code
            current_bb.successors.append(nodes[i + 1])

            # all other successors are random, selected from next nodes
            options = nodes[i + 2:]
            options.append(func.exit)
            for j in range(1, successor_count):
                target = random.choice(options)
                options.remove(target)
                current_bb.successors.append(target)

        func.entry.successors = [nodes[0]]

        # Function return
        if label != ".function_main":
            func.exit.terminators = [self.get_return_instruction()]

        # Finalize the function
        func.insert_multiple(nodes)
        return func

    def generate_instruction(self, spec: InstructionSpec) -> Instruction:
        # fill up with random operands, following the spec
        inst = Instruction.from_spec(spec)

        # generate explicit operands
        for operand_spec in spec.operands:
            operand = self.generate_operand(operand_spec, inst)
            inst.operands.append(operand)

        # generate implicit operands
        for operand_spec in spec.implicit_operands:
            operand = self.generate_operand(operand_spec, inst)
            inst.implicit_operands.append(operand)

        return inst

    def generate_reg_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        reg_type = spec.values[0]
        if reg_type == 'GPR':
            choices = self.target_desc.registers[spec.width]
        elif reg_type == "SIMD":
            choices = self.target_desc.simd_registers[spec.width]
        else:
            choices = spec.values

        if not CONF.avoid_data_dependencies:
            reg = random.choice(choices)
            return RegisterOperand(reg, spec.width, spec.src, spec.dest)

        if parent.latest_reg_operand and parent.latest_reg_operand.value in choices:
            return parent.latest_reg_operand

        reg = random.choice(choices)
        op = RegisterOperand(reg, spec.width, spec.src, spec.dest)
        parent.latest_reg_operand = op
        return op

    def generate_mem_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        if spec.values:
            address_reg = random.choice(spec.values)
        else:
            address_reg = random.choice(self.target_desc.registers[64])
        return MemoryOperand(address_reg, spec.width, spec.src, spec.dest)

    def generate_imm_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        if spec.values:
            if spec.values[0] == "bitmask":
                # FIXME: this implementation always returns the same bitmask
                # make it random
                value = str(pow(2, spec.width) - 2)
            else:
                assert "[" in spec.values[0], spec.values
                range_ = spec.values[0][1:-1].split("-")
                if range_[0] == "":
                    range_ = range_[1:]
                    range_[0] = "-" + range_[0]
                assert len(range_) == 2
                value = str(random.randint(int(range_[0]), int(range_[1])))
        else:
            value = str(random.randint(pow(2, spec.width - 1) * -1, pow(2, spec.width - 1) - 1))
        return ImmediateOperand(value, spec.width)

    def generate_label_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        return LabelOperand("")  # the actual label will be set in add_terminators_in_function

    def generate_agen_operand(self, spec: OperandSpec, __: Instruction) -> Operand:
        n_operands = random.randint(1, 3)
        reg1 = random.choice(self.target_desc.registers[64])
        if n_operands == 1:
            return AgenOperand(reg1, spec.width)

        reg2 = random.choice(self.target_desc.registers[64])
        if n_operands == 2:
            return AgenOperand(reg1 + " + " + reg2, spec.width)

        imm = str(random.randint(0, pow(2, 16) - 1))
        return AgenOperand(reg1 + " + " + reg2 + " + " + imm, spec.width)

    def generate_flags_operand(self, spec: OperandSpec, parent: Instruction) -> Operand:
        cond_op = parent.get_cond_operand()
        if not cond_op:
            return FlagsOperand(spec.values)

        flag_values = self.target_desc.branch_conditions[cond_op.value]
        if not spec.values:
            return FlagsOperand(flag_values)

        # combine implicit flags with the condition
        merged_flags = []
        for flag_pair in zip(flag_values, spec.values):
            if "undef" in flag_pair:
                merged_flags.append("undef")
            elif "r/w" in flag_pair:
                merged_flags.append("r/w")
            elif "w" in flag_pair:
                if "r" in flag_pair:
                    merged_flags.append("r/w")
                else:
                    merged_flags.append("w")
            elif "cw" in flag_pair:
                if "r" in flag_pair:
                    merged_flags.append("r/cw")
                else:
                    merged_flags.append("cw")
            elif "r" in flag_pair:
                merged_flags.append("r")
            else:
                merged_flags.append("")
        return FlagsOperand(merged_flags)

    def generate_cond_operand(self, spec: OperandSpec, _: Instruction) -> Operand:
        cond = random.choice(list(self.target_desc.branch_conditions))
        return CondOperand(cond)

    def add_terminators_in_function(self, func: Function):
        def add_fallthrough(bb: BasicBlock, destination: BasicBlock):
            # create an unconditional branch and add it
            terminator = self.get_unconditional_jump_instruction()
            terminator.operands = [LabelOperand(destination.name)]
            bb.terminators.append(terminator)

        for bb in func:
            if len(bb.successors) == 0:
                # Return instruction
                continue

            elif len(bb.successors) == 1:
                # Unconditional branch
                dest = bb.successors[0]
                if dest == func.exit:
                    # DON'T insert a branch to the exit
                    # the last basic block always falls through implicitly
                    continue
                add_fallthrough(bb, dest)

            elif len(bb.successors) == 2:
                # Conditional branch
                spec = random.choice(self.cond_branches)
                terminator = self.generate_instruction(spec)
                label = terminator.get_label_operand()
                assert label
                label.value = bb.successors[0].name
                bb.terminators.append(terminator)

                add_fallthrough(bb, bb.successors[1])
            else:
                # Indirect jump
                raise NotSupportedException()

    def add_instructions_in_function(self, func: Function):
        # in this function, we evenly fill all BBs with random instructions by
        # randomly choosing basic blocks and adding one instruction (or gadget)
        # at a time
        basic_blocks_to_fill = func.get_all()[1:-1]

        # compute a probability of a gadget being selected, based on the average
        # length of a gadget and 'CONF.avg_gadgets_per_bb'
        gadget_counts = {}
        avg_gadget_size = 0
        if len(self.gadgets) > 0:
            avg_gadget_size = sum(len(g) for g in self.gadgets) / len(self.gadgets)
        gadget_chance = (avg_gadget_size * CONF.avg_gadgets_per_bb * len(basic_blocks_to_fill)) / CONF.program_size

        instructions_remaining = CONF.program_size
        while instructions_remaining > 0:
            bb = random.choice(basic_blocks_to_fill)

            # track the number of gadgets placed in each basic block
            if bb.name not in gadget_counts:
                gadget_counts[bb.name] = 0

            # decide between placing a code gadget or a random instruction
            # (don't interrupt the placement of two memory-access instructions)
            use_gadget = random.uniform(0, 1) < gadget_chance and \
                         not self.had_recent_memory_access and \
                         gadget_counts[bb.name] < CONF.max_gadgets_per_bb

            # CASE 1: we choose to use a gadget. Select one at random and place
            # all of its instructions, in order, into the basic block
            if use_gadget:
                # compute the number of memory accesses that need to be placed
                # and generate an appropriate gadget
                remaining_mem_accesses = CONF.avg_mem_accesses - self.mem_access_count
                g = self._pick_random_gadget(max_len=instructions_remaining,
                                             mem_access_limit=remaining_mem_accesses)
                
                # if we found a gadget to place, iterate and place all of its
                # instructions
                if g is not None:
                    for (i, ispec) in enumerate(g):
                        inst = self.generate_instruction(ispec)
                        inst.set_comment("gadget: %s (%d/%d)" % (g.name, (i + 1), len(g)))
                        bb.insert_after(bb.get_last(), inst)
                        instructions_remaining -= 1
                        if ispec.has_mem_operand:
                            self.mem_access_count += 1
                    gadget_counts[bb.name] += 1
                    continue

            # CASE 2: we choose *not* to use a gadget (or we failed to find an
            # appropriate gadget), and instead choose to use a single random
            # instruction
            ispec = self._pick_random_instruction_spec()
            bb.insert_after(bb.get_last(), self.generate_instruction(ispec))
            instructions_remaining -= 1
        
    def _pick_random_instruction_spec(self) -> InstructionSpec:
        instruction_spec: InstructionSpec

        # ensure the requested avg. number of mem. accesses
        search_for_memory_access = False
        memory_access_probability = CONF.avg_mem_accesses / CONF.program_size
        if CONF.generate_memory_accesses_in_pairs:
            memory_access_probability = 1 if self.had_recent_memory_access else \
                (CONF.avg_mem_accesses / 2) / (CONF.program_size - CONF.avg_mem_accesses / 2)

        if random.random() < memory_access_probability:
            search_for_memory_access = True
            self.had_recent_memory_access = not self.had_recent_memory_access

        search_for_store = random.random() < 0.5  # 50% probability of stores

        # select a random instruction spec for generation
        if not search_for_memory_access:
            return random.choice(self.non_memory_access_instructions)
        
        self.mem_access_count += 1
        if search_for_store:
            return random.choice(self.store_instructions)

        return random.choice(self.load_instruction)
    
    # Looks for a gadget given the optional limits. Returns a CodeGadget object
    # on success. On failure to find an appropriate gadget, None is returned.
    def _pick_random_gadget(self, max_len=None, mem_access_limit=None) -> CodeGadget:
        gadget_max = len(self.gadgets)
        gadget_min = 0
        if max_len is not None:
            # our gagdet list is in sorted order by length (descending), so we'll
            # walk and index down the list until we hit the first gadget that
            # fits within the maximum length specified by the caller
            while gadget_min < gadget_max and \
                  len(self.gadgets[gadget_min]) > max_len:
                gadget_min += 1

        # if the range is too tight, give up
        if gadget_min == gadget_max:
            return None

        # select a random index from within the acceptable range, and iterate
        # (circularly) until we find a suitable gadget
        idx = random.randrange(gadget_min, gadget_max)
        circular_increment = lambda _idx : (_idx + 1) % (gadget_max - gadget_min)
        chance = random.random()
        for i in range(gadget_max - gadget_min):
            g = self.gadgets[idx]

            # if the gadget's weight isn't met, move onto the next one
            if chance >= g.weight:
                idx = circular_increment(idx)
                continue

            # if memory access limits are in place, make sure this gadget won't
            # exceed the limit
            if mem_access_limit is not None and \
               g.count_mem_accesses() > mem_access_limit:
                idx = circular_increment(idx)
                continue

            # otherwise, return the chosen gadget
            return g

        # if nothing was returned above, then no suitable gadget was found
        return None

    @abc.abstractmethod
    def get_return_instruction(self) -> Instruction:
        pass

    @abc.abstractmethod
    def get_unconditional_jump_instruction(self) -> Instruction:
        pass


# ==================================================================================================
# Generator Gadgets
# ==================================================================================================
# In the security world, a 'gadget' represents a small snippet of code (made up
# of one or more machine instructions) that may invoke interesting, unexpected,
# or even exploit-inducing behavior in a target that executes it.
# This class represents one such 'gadget'. Revizor's program generator can use
# user-defined gadgets to make generated test cases more interesting.
#
# A gadget is specified in the same format as the ISA specification JSON file
# the InstructionSet class parses. In this case, this class parses the
# specifications exactly as the main generator does.
class CodeGadget:
    # Constructor. Accepts a name for the gadget and a list of instruction
    # specification (InstructionSpec) objects. Optionally accepts a proability
    # (from 0.0 to 1.0) of how likely the gadget is to be selected, compared to
    # other gadgets. (default for all is 1.0)
    def __init__(self, name: str, instructions=InstructionSet(), weight=1.0):
        self.name = name
        self.instruction_set = instructions
        self.weight = max(0.0, min(1.0, weight))
        self.num_mem_accesses = self.count_mem_accesses()

        # forbid the use of control-flow instructions in Revizor gadgets
        for ispec in self.instruction_set.instructions:
            assert not ispec.control_flow, "gadgets cannot contain control-flow instructions " \
                                           "(such as \"%s\")" % ispec.name

    # Computes the length of the gadget's instruction list.
    def __len__(self):
        return len(self.instruction_set.instructions)
    
    # Allows for iteration through the gadget's instruction.
    def __iter__(self):
        for ispec in self.instruction_set.instructions:
            yield ispec
    
    # Counts and returns the number of memory-accessing instructions in the
    # gadget.
    def count_mem_accesses(self):
        # this only has to be computed once
        if not hasattr(self, "num_mem_accesses"):
            self.num_mem_accesses = 0
            for i in self.instruction_set.instructions:
                self.num_mem_accesses += 1 if i.has_mem_operand else 0
        return self.num_mem_accesses
    
    # Returns a list of instructions contained in the gadget.
    def get_instructions(self, generator: Generator):
        # for each instruction specification in the gadget, generate an
        # instruction using the given program generator
        instructions = []
        for spec in self.instruction_set.instructions:
            i = generator.generate_instruction(spec)
            instructions.append(i)
        return instructions
    
    # Takes in a dictionary and attempts to create a CodeGadget object from
    # the dictionary's entries. An exception is thrown if the dictionary's data
    # is not in the correct format. Otherwise, a new CodeGadget object is
    # returned.
    @staticmethod
    def from_dict(data: dict):
        g = CodeGadget("gadget")

        # check a number of expected and/or optional dictionary fields
        fields = {
            "name":             {"type": str,   "required": True},
            "instructions":     {"type": list,  "required": True},
            "weight":           {"type": float, "required": False, "default": 1.0}
        }
        for f in fields:
            fdata = fields[f]
            ftype = fdata["type"]

            # if the field is required, enforce it
            if fdata["required"]:
                assert f in data, "the given dictionary must contain \"%s\" (%s)" % \
                                  (f, ftype)
            # if the field isn't present, set its default
            if f not in data:
                data[f] = fdata["default"]

            # type-check the field and add it to the object
            assert type(data[f]) == ftype, "the given dictionary's \"%s\" must be a %s" % \
                                           (f, ftype)

        # create a gadget object with the name and instructions and return
        iset = InstructionSet()
        iset.init_from_list(data["instructions"])
        g = CodeGadget(data["name"], instructions=iset, weight=data["weight"])
        return g

