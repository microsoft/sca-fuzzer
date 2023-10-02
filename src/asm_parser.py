"""
File: Parsing of assembly files into our internal representation (TestCase).
      This file contains ISA-independent code; see <isa>/<isa>_asm_parser.py for ISA-specific code.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import re
import abc

from typing import List, Dict, Tuple
from collections import OrderedDict

from .interfaces import AsmParser, OT, Instruction, InstructionSpec, TestCase, OperandSpec, \
    LabelOperand, Actor, ActorType, Function, BasicBlock, Generator
from .util import Logger

ControlFlowMap = Dict[str, Dict[str, List[str]]]
ActorMap = Dict[str, str]


class AsmParserException(Exception):

    def __init__(self, line_number, explanation):
        msg = "Could not parse line " + str(line_number + 1) + "\n  Reason: " + explanation
        super().__init__(msg)


def parser_assert(condition: bool, line_number: int, explanation: str):
    if not condition:
        logger = Logger()
        logger.error(
            f"[AsmParser]:  Error while parsing assembly (line {line_number + 1})\n"
            f"       Issue: {explanation}",
            print_last_tb=True)


class AsmParserGeneric(AsmParser):

    def __init__(self, generator: Generator) -> None:
        self.generator = generator
        self.target_desc = generator.target_desc
        pass

    def parse_file(self, input_file: str) -> TestCase:
        # FIXME: it's a dirty implementation. It should be rewritten.

        asm_file = input_file + ".patched.asm"
        self._patch_asm(input_file, asm_file)

        test_case = TestCase(0)
        test_case.asm_path = asm_file

        # prepare a map of all instruction specs
        instruction_map = self._create_instruction_spec_map()

        # load the text and clean it up
        lines = self._get_clean_lines_from_file(asm_file)

        # map lines to functions and basic blocks
        test_case_map, function_owners = self._get_tc_maps(lines)

        # create actors
        actor_names = self._create_actors(function_owners, test_case)

        # parse lines and create their object representations
        line_id = 1
        for func_name, bbs in test_case_map.items():
            # print(func_name)
            line_id += 1
            actor = actor_names[function_owners[func_name]]
            func = Function(func_name, actor)
            test_case.functions.append(func)

            for bb_name, lines in bbs.items():
                # print(">>", bb_name)
                line_id += 1
                bb = BasicBlock(bb_name)
                func.append(bb)

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
        bb_names[".TEST_CASE_EXIT"] = test_case.exit
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
                            parser_assert(op.value in bb_names, -1, "Unknown label " + op.value)
                            successor = bb_names[op.value]
                            bb.successors.append(successor)

            # last BB always falls through to the exit
            func[-1].successors.append(func.exit)

        # special case: empty test case
        if not test_case.functions:
            instr = Instruction("NOP", False, "BASE-NOP", False)
            bb = BasicBlock(".bb_0")
            main = Function(".function_0", Actor(ActorType.HOST, 0))
            bb.insert_after(bb.get_last(), instr)
            main.append(bb)
            bb.successors.append(main.exit)
            test_case.functions.append(main)

        bin_file = asm_file[:-4]
        obj_file = bin_file + ".o"
        self.generator.assemble(asm_file, obj_file, bin_file)
        test_case.bin_path = bin_file
        test_case.obj_path = obj_file

        self.generator.get_elf_data(test_case, obj_file)

        return test_case

    @abc.abstractmethod
    def parse_line(self, line: str, line_num: int,
                   instruction_map: Dict[str, List[InstructionSpec]]) -> Instruction:
        pass

    @abc.abstractmethod
    def _patch_asm(self, asm_file: str, patched_asm_file: str):
        pass

    def _create_instruction_spec_map(self) -> Dict[str, List[InstructionSpec]]:
        instruction_map: Dict[str, List[InstructionSpec]] = {}
        for spec in self.generator.instruction_set.instructions:
            if spec.name in instruction_map:
                instruction_map[spec.name].append(spec)
            else:
                instruction_map[spec.name] = [spec]

            # add an entry for direct opcodes
            opcode_spec = InstructionSpec()
            opcode_spec.name = "OPCODE"
            opcode_spec.category = "OPCODE"
            instruction_map["OPCODE"] = [opcode_spec]

            # entry for macros
            macro_spec = InstructionSpec()
            macro_spec.name = "MACRO"
            macro_spec.category = "MACRO"
            macro_spec.operands = [
                OperandSpec([], OT.LABEL, False, False),
                OperandSpec([], OT.LABEL, False, False)
            ]
            instruction_map["MACRO"] = [macro_spec]
        return instruction_map

    def _create_actors(self, function_owners, test_case) -> Dict[str, Actor]:
        actor_names: Dict[str, Actor] = {}
        for actor_label in sorted(set(function_owners.values())):
            words = actor_label.split(".")
            assert len(words) == 3, f"Invalid actor label: {actor_label}"
            subwords = words[2].split("_")
            assert len(subwords) == 2, f"Invalid actor label: {actor_label}"

            id_ = int(subwords[0])
            if subwords[1] == "host":
                type_ = ActorType.HOST
            elif subwords[1] == "guest":
                type_ = ActorType.GUEST
            else:
                parser_assert(False, 0, f"Invalid actor type: {subwords[1]}")

            if id_ == 0:
                assert type_ == ActorType.HOST, "Actor 0 must be the host"  # type: ignore
                actor = test_case.actors[0]
            else:
                actor = Actor(type_, id_)  # type: ignore

            assert id_ not in test_case.actors or test_case.actors[id_] == actor, "Duplicate actor"
            test_case.actors[id_] = actor
            actor_names[actor_label] = actor
        return actor_names

    def _get_clean_lines_from_file(self, input_file: str) -> List[str]:
        re_redundant_spaces = re.compile(r"(?<![a-zA-Z0-9]) +")

        lines = []
        started = False
        finished = False
        with open(input_file, "r") as f:
            for i, line in enumerate(f):
                # remove extra spaces
                line = line.strip()
                line = re_redundant_spaces.sub("", line)

                # skip comments and empty lines
                if not line or line[0] in ["", "#", "/"]:
                    continue

                # check footer and header
                if not started:
                    started = (line == ".test_case_enter:")
                    if line[0] != ".":
                        parser_assert(started, i, "Found instructions before .test_case_enter")
                    continue
                if line[:16] == ".test_case_exit:":
                    finished = True
                    continue
                parser_assert(not finished, i, f"Found instructions after .test_case_exit: {line}")

                lines.append(line)
            parser_assert(finished, len(lines), ".test_case_exit not found")
        return lines

    def _get_tc_maps(self, lines: List[str]) -> Tuple[ControlFlowMap, ActorMap]:
        current_function = ""
        current_bb = ""
        current_actor = ""
        autogenerated_bb = False
        test_case_map: ControlFlowMap = OrderedDict()
        function_owners: ActorMap = {}

        for i, line in enumerate(lines):
            # directives - ignored
            if line.startswith(".global"):
                continue

            # section start
            if line.startswith(".section"):
                words = line.split()
                assert len(words) == 2
                if words[1] == "exit":
                    continue  # exit section does not represent any actor
                current_actor = words[1]
                current_function = ""
                current_bb = ""
                continue
            parser_assert(current_actor != "", i, "Missing actor declaration (missing .section)")

            # function start
            if line.startswith(".function_"):
                assert line[-1] == ":", f"Invalid function header: {line}"
                current_function = line[:-1]
                test_case_map[current_function] = OrderedDict()
                function_owners[current_function] = current_actor

                autogenerated_bb = True
                current_bb = ".bb_" + current_function.removeprefix(".function_") + ".entry"
                test_case_map[current_function][current_bb] = []
                continue

            # implicit declaration of the main function
            if not current_function and not test_case_map:
                current_function = ".function_0"
                test_case_map[current_function] = OrderedDict()
                function_owners[current_function] = current_actor

                autogenerated_bb = True
                current_bb = ".bb_" + current_function.removeprefix(".function_") + ".entry"
                test_case_map[current_function][current_bb] = []
            parser_assert(current_function != "", i, "Missing function declaration")

            # opcode
            if line[:4] == ".bcd " or line[:5] in [".byte", ".long", ".quad"] \
               or line[6:] in [".value", ".2byte", ".4byte", ".8byte"]:
                assert current_bb
                test_case_map[current_function][current_bb].append("OPCODE")
                continue

            # macros
            if line.startswith(".macro"):
                parser_assert(current_bb != "", i, "Macro declared outside of a basic block")
                test_case_map[current_function][current_bb].append(
                    self._macro_label_to_instr(line, i))
                continue

            # basic block
            if line.startswith("."):
                assert line[-1] == ":", f"Invalid basic block header: {line}"
                # remove empty default BBs
                if autogenerated_bb and not test_case_map[current_function][current_bb]:
                    del test_case_map[current_function][current_bb]

                autogenerated_bb = False
                current_bb = line[:-1]
                if current_bb not in test_case_map[current_function]:
                    test_case_map[current_function][current_bb] = []
                continue

            # instruction
            parser_assert(current_bb != "", i, "Missing basic block declaration")
            test_case_map[current_function][current_bb].append(line)

        return test_case_map, function_owners

    def _macro_label_to_instr(self, line: str, line_id: int) -> str:
        """
        This function replaces label-like macros with a pseudo-instruction MACRO
        As such, we simplify further parsing of the test case
        """
        # get rid of the NOP placeholder
        words = line.split(":")
        parser_assert(len(words) == 2, line_id, "Invalid macro declaration")
        parser_assert(words[1][:3] == "nop", line_id, "Patching error")

        # get the macro name and its arguments
        subwords = words[0].split(".")
        parser_assert(len(subwords) >= 3, line_id, f"Invalid macro: {line}")
        parser_assert(len(subwords) <= 7, line_id, f"Invalid macro: {line}")
        macro_id = subwords[2]
        args = '.'.join(subwords[3:])
        if args:
            instr = f"MACRO .{macro_id}, .{args}"
        else:
            instr = f"MACRO .{macro_id}, .noarg"

        return instr
