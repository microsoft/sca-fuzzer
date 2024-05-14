"""
File: Parsing of assembly files into our internal representation (TestCase).
      This file contains ISA-independent code; see <isa>/<isa>_asm_parser.py for ISA-specific code.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import re
import abc

from typing import List, Dict, Tuple, NoReturn
from collections import OrderedDict

from .interfaces import AsmParser, OT, Instruction, InstructionSpec, TestCase, OperandSpec, \
    LabelOperand, Function, BasicBlock, Generator, ActorPL, ActorMode
from .util import Logger
from .config import CONF

RE_REDUNDANT_SPACES = re.compile(r"(?<![a-zA-Z0-9]) +")


def parser_error(line_number: int, explanation: str) -> NoReturn:
    logger = Logger()
    logger.error(
        f"[AsmParser]  Error while parsing assembly (line {line_number + 1})\n"
        f"       Issue: {explanation}",
        print_last_tb=True)


def parser_assert(condition: bool, line_number: int, explanation: str):
    if not condition:
        parser_error(line_number, explanation)


class ASMLine:

    def __init__(self, str_, line_num) -> None:
        self.str = str_
        self.clean_str = str_.strip().lower()
        self.clean_str = RE_REDUNDANT_SPACES.sub("", self.clean_str)
        self.line_num = line_num
        self.patched_line_num = 0
        self.clean_line_num = 0


ControlFlowMap = Dict[str, Dict[str, List[ASMLine]]]
ActorMap = Dict[str, str]


class AsmParserGeneric(AsmParser):

    def __init__(self, generator: Generator) -> None:
        self.generator = generator
        self.generator.asm_parser = self
        self.target_desc = generator.target_desc
        self.instruction_map = self._create_instruction_spec_map()
        self.lines: List[ASMLine] = []

    def parse_file(self, input_file: str) -> TestCase:
        with open(input_file, 'r') as f:
            self.lines = [ASMLine(l, i) for i, l in enumerate(f)]

        # add default labels to the file
        asm_file = input_file + ".patched.asm"
        self._patch_asm(input_file, asm_file)

        # update line list after patching
        patched_lines = []
        with open(asm_file, 'r') as patched:
            org_line_num = 0
            for patched_line_num, p_line in enumerate(patched):
                o_line_obj = self.lines[org_line_num]
                o_line = o_line_obj.str.strip().lower()

                p_line = p_line.strip().lower()
                p_line_obj = ASMLine(p_line, 0)
                p_line_obj.patched_line_num = patched_line_num

                if o_line in p_line:
                    p_line_obj.line_num = o_line_obj.line_num
                    org_line_num += 1

                patched_lines.append(p_line_obj)
        self.lines = patched_lines

        # load the text and clean it up
        clean_lines = self._get_clean_lines()

        # map lines to functions and basic blocks
        test_case_map, function_owners = self._get_tc_maps(clean_lines)

        # create an empty test case
        test_case = TestCase(0)
        test_case.asm_path = asm_file

        # set actors based on the config
        self.generator.create_actors(test_case)

        # parse lines and create their object representations
        for func_name, bbs in test_case_map.items():
            # print(func_name)
            actor = test_case.actors[function_owners[func_name]]
            func = Function(func_name, actor)
            test_case.functions.append(func)

            for bb_name, lines in bbs.items():
                # print(">>", bb_name)
                bb = BasicBlock(bb_name)
                func.append(bb)

                terminators_started = False
                for line in lines:
                    # print(f"    {line}")
                    inst = self.parse_line(line.clean_str, line.line_num, self.instruction_map)
                    inst.line_num = line.line_num
                    if inst.control_flow and not self.target_desc.is_call(inst):
                        terminators_started = True
                        bb.insert_terminator(inst)
                    else:
                        parser_assert(not terminators_started, line.line_num,
                                      "Terminator not at the end of BB")
                        bb.insert_after(bb.get_last(), inst)

        # connect basic blocks
        bb_names = {bb.name.lower(): bb for func in test_case for bb in func}
        bb_names[".test_case_exit"] = test_case.exit
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
            instr = Instruction("nop", False, "BASE-NOP", False)
            bb = BasicBlock(".bb_0")
            main = Function(".function_0", test_case.actors["main"])
            bb.insert_after(bb.get_last(), instr)
            main.append(bb)
            bb.successors.append(main.exit)
            test_case.functions.append(main)

        self._check_asm_correctness(test_case, asm_file)
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
        for spec in self.generator.instruction_set.instruction_unfiltered:
            if spec.name in instruction_map:
                instruction_map[spec.name].append(spec)
            else:
                instruction_map[spec.name] = [spec]

            # add an entry for direct opcodes
            opcode_spec = InstructionSpec()
            opcode_spec.name = "opcode"
            opcode_spec.category = "opcode"
            instruction_map["opcode"] = [opcode_spec]

            # entry for macros
            macro_spec = InstructionSpec()
            macro_spec.name = "macro"
            macro_spec.category = "macro"
            macro_spec.operands = [
                OperandSpec([], OT.LABEL, False, False),
                OperandSpec([], OT.LABEL, False, False)
            ]
            instruction_map["macro"] = [macro_spec]
        return instruction_map

    def _get_clean_lines(self) -> List[ASMLine]:
        lines = []
        started = False
        finished = False
        for line_obj in self.lines:
            line = line_obj.clean_str

            # skip comments and empty lines
            if not line or line[0] in ["", "#", "/"]:
                continue

            # check footer and header
            if not started:
                started = (line == ".test_case_enter:")
                if line[0] != ".":
                    parser_assert(started, line_obj.line_num,
                                  "Found instructions before .test_case_enter")
                continue
            if line[:16] == ".test_case_exit:":
                finished = True
                continue
            parser_assert(not finished, line_obj.line_num,
                          f"Found instructions after .test_case_exit: {line_obj.str}")

            lines.append(line_obj)

        parser_assert(finished, 0, ".test_case_exit not found")
        return lines

    def _get_tc_maps(self, lines: List[ASMLine]) -> Tuple[ControlFlowMap, ActorMap]:
        current_function = ""
        current_bb = ""
        current_actor = ""
        autogenerated_bb = False
        test_case_map: ControlFlowMap = OrderedDict()
        function_owners: ActorMap = {}

        for line_obj in lines:
            line_num = line_obj.line_num
            line = line_obj.clean_str

            # directives - ignored
            if line.startswith(".global"):
                continue

            # section start
            if line.startswith(".section"):
                words = line.split()
                assert len(words) == 2, f"Invalid section label: {line}"
                if words[1] == "exit":
                    continue  # exit section does not represent any actor
                subwords = words[1].split(".")
                parser_assert(len(subwords) == 3, line_num, f"Invalid section label: {line}")
                current_actor = subwords[2]
                parser_assert(current_actor in CONF._actors, line_num,
                              f"Actor {current_actor} was not defined in the config file")
                current_function = ""
                current_bb = ""
                continue
            parser_assert(current_actor != "", line_num,
                          "Missing actor declaration (missing .section)")

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
            parser_assert(current_function != "", line_num, "Missing function declaration")

            # opcode
            if line[:4] == ".bcd " or line[:5] in [".byte", ".long", ".quad"] \
               or line[6:] in [".value", ".2byte", ".4byte", ".8byte"]:
                assert current_bb
                test_case_map[current_function][current_bb].append(ASMLine("opcode", line_num))
                continue

            # macros
            if line.startswith(".macro"):
                parser_assert(current_bb != "", line_num, "Macro declared outside of a basic block")
                str_ = self._macro_label_to_instr(line, line_num)
                test_case_map[current_function][current_bb].append(ASMLine(str_, line_num))
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
            parser_assert(current_bb != "", line_num, "Missing basic block declaration")
            test_case_map[current_function][current_bb].append(line_obj)

        return test_case_map, function_owners

    def _macro_label_to_instr(self, line: str, line_num: int) -> str:
        """
        This function replaces label-like macros with a pseudo-instruction MACRO
        As such, we simplify further parsing of the test case
        """
        # get rid of the NOP placeholder
        words = line.split(":")
        parser_assert(len(words) == 2, line_num, "Invalid macro declaration")
        parser_assert(words[1][:3] == "nop", line_num, "Patching error")

        # get the macro name and its arguments
        subwords = words[0].split(".")
        parser_assert(len(subwords) >= 3, line_num, f"Invalid macro: {line}")
        parser_assert(len(subwords) <= 7, line_num, f"Invalid macro: {line}")
        macro_id = subwords[2]
        args = '.'.join(subwords[3:])
        if args:
            instr = f"macro .{macro_id}, .{args}"
        else:
            instr = f"macro .{macro_id}, .noarg"

        return instr

    def _check_asm_correctness(self, test_case: TestCase, asm_file: str) -> None:
        """ Check that the parsed assembly file is valid """

        # check that all actor switch macros have landing sites
        switch_labels = [".set_k2u_target", ".set_u2k_target", ".set_h2g_target", ".set_g2h_target"]
        switches = []
        for func in test_case:
            for bb in func:
                for inst in bb:
                    if inst.name == "macro" and inst.operands[0].value in switch_labels:
                        switches.append(inst)

        for switch in switches:
            target = switch.operands[1].value.split(".")[2]
            target_function = None
            for func in test_case:
                stripped_name = func.name[1:]
                if stripped_name == target:
                    target_function = func
                    break
            parser_assert(target_function is not None, -1,
                          f"Macro {switch} targets a non-existing function")

            first_inst = target_function.get_first_bb().get_first()  # type: ignore
            if first_inst is None or not first_inst.operands or \
               "landing" not in first_inst.operands[0].value:
                parser_error(-1, f"{switch} does not target a landing site macro")
            target_name = first_inst.operands[0].value

            if switch.operands[0].value == ".set_k2u_target" and target_name != ".landing_k2u":
                parser_error(switch.line_num, f"{switch} does not target landing_k2u")
            elif switch.operands[0].value == ".set_u2k_target" and target_name != ".landing_u2k":
                parser_error(switch.line_num, f"{switch} does not target landing_u2k")
            elif switch.operands[0].value == ".set_h2g_target" and target_name != ".landing_h2g":
                parser_error(switch.line_num, f"{switch} does not target landing_h2g")
            elif switch.operands[0].value == ".set_g2h_target" and target_name != ".landing_g2h":
                parser_error(switch.line_num, f"{switch} does not target landing_g2h")

        # check that there is at most one fault handler
        n_fault_handlers = 0
        for func in test_case:
            for bb in func:
                for inst in bb:
                    if inst.name == "macro" and inst.operands[0].value == ".fault_handler":
                        n_fault_handlers += 1
                    if n_fault_handlers > 1:
                        parser_error(inst.line_num, "Found more than one fault handler")

        # check that PT modification happens only in kernel host mode
        for func in test_case:
            for bb in func:
                owner = func.owner
                for inst in bb:
                    if inst.name == "macro" and inst.operands[0].value == ".set_data_permissions":
                        parser_assert(
                            owner.privilege_level == ActorPL.KERNEL
                            and owner.mode == ActorMode.HOST, inst.line_num,
                            "PT modification is allowed only in kernel host mode")
