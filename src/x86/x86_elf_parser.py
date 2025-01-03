"""
File: Parser of ELF files for x86 architecture

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Tuple, TypedDict, NamedTuple
from subprocess import run
from elftools.elf.elffile import ELFFile, SymbolTableSection  # type: ignore

from ..elf_parser import ELFParser
from ..tc_components.test_case_binary import SymbolTable, SymbolTableEntry, TestCaseBinary
from ..tc_components.actor import ActorPL, ActorMode
from ..tc_components.instruction import Instruction

if TYPE_CHECKING:
    from ..tc_components.test_case_code import TestCaseProgram, CodeSection
    from ..tc_components.test_case_binary import InstructionMap


class _ParsingError(Exception):

    def __init__(self, message: str):
        full_msg = f"[X86ELFParser] Error while parsing assembly\n       Issue: {message}"
        super().__init__(full_msg)


# ==================================================================================================
# Private: ELF Symbol Table Parser
# ==================================================================================================
class _ELFData(TypedDict):
    section_data: Dict[int, _SectionData]
    exit_addr: int


class _SectionData(TypedDict):
    id_: int
    name: str
    offset: int
    size: int
    functions: Dict[str, _FunctionData]


class _FunctionData(TypedDict):
    id_: int
    name: str
    offset: int


class _SymtabParser:

    def parse(self, obj_file: str) -> _ELFData:
        """
        Parse the ELF symbol table to get the addresses of all functions and sections.
        The section and function IDs are assigned in the order they appear in the ELF file.
        :param obj_file: path to the ELF file
        :return: a dictionary containing the section data and the exit address
        """
        elf_data = self._get_unsorted_data(obj_file)
        self._sort_elf_data(elf_data)
        return elf_data

    def _get_unsorted_data(self, obj_file: str) -> _ELFData:
        """ Transform the ELF symbol table into a dictionary of sections and functions """
        elf_data: _ELFData = {"section_data": {}, "exit_addr": -1}

        with open(obj_file, "rb") as f:
            data = ELFFile(f)

            # sanity check: we build test cases in such a way that there should be no segments
            assert data.num_segments() == 0, f"{data.num_segments()}"

            # collect section info
            for s_id, s in enumerate(data.iter_sections()):
                if s.name[:6] != ".data.":
                    continue
                s_entry: _SectionData = {
                    "id_": s_id,
                    "name": s.name.split(".")[2],
                    "offset": s['sh_offset'],
                    "size": s['sh_size'],
                    "functions": {}
                }
                elf_data["section_data"][s_id] = s_entry

            # get addresses of functions and macros
            symtab: SymbolTableSection = data.get_section_by_name(".symtab")  # type: ignore
            for s in symtab.iter_symbols():
                if s.name.startswith(".function"):
                    f_entry: _FunctionData = {
                        "id_": -1,  # will be assigned later
                        "name": s.name,
                        "offset": s.entry.st_value
                    }
                    s_id = s['st_shndx']
                    elf_data["section_data"][s_id]["functions"][s.name] = f_entry

                if ".test_case_exit" in s.name:
                    elf_data["exit_addr"] = s.entry.st_value
        assert elf_data["exit_addr"] != -1, "Failed to find exit address"
        return elf_data

    def _sort_elf_data(self, elf_data: _ELFData) -> None:
        """ Sort sections and functions by their appearance in the ELF file """

        # assign consecutive ids to sections, in the order they appear in ELF
        sorted_section_ids = sorted(elf_data["section_data"].keys())
        new_section_data = {}
        for new_s_id, org_s_id in enumerate(sorted_section_ids):
            new_section_data[new_s_id] = elf_data["section_data"][org_s_id]
            new_section_data[new_s_id]["id_"] = new_s_id
        elf_data["section_data"] = new_section_data

        # assign consecutive ids to functions, in the order they appear in ELF
        sorted_new_section_ids = sorted(elf_data["section_data"].keys())
        new_f_id = 0  # function ids are unique across all sections
        for s_id in sorted_new_section_ids:
            function_data = elf_data["section_data"][s_id]["functions"]
            sorted_function_data = sorted(function_data.values(), key=lambda x: x["offset"])
            for f_data in sorted_function_data:
                f_data["id_"] = new_f_id
                new_f_id += 1


# ==================================================================================================
# Private: Objdump Output Parser
# ==================================================================================================
_SectionName = str
_InstructionAddr = int
_InstrAddrMap = Dict[_SectionName, List[_InstructionAddr]]


class _ObjdumpSectionDesc(NamedTuple):
    name: str
    skip: bool


class _ObjdumpOutputParser:

    def parse(self, obj_file: str) -> _InstrAddrMap:
        """
        Parse the output of objdump to get the addresses of all instructions
        :param obj_file: path to the ELF file
        :return: a dictionary mapping section names to lists of its instruction addresses
        """
        # Get raw objdump output
        dump = run(
            f"objdump --no-show-raw-insn -D -M intel -m i386:x86-64 {obj_file} "
            "| awk '/ [0-9a-f]+:/{print $1} /section/{print $0}'",
            shell=True,
            check=True,
            capture_output=True)

        # Prepare for parsing
        instruction_addresses: Dict[_SectionName, List[_InstructionAddr]] = {}
        section_desc = _ObjdumpSectionDesc("", False)

        # Loop over output lines, keeping track of the latest section header,
        # and recording addresses of instructions for each section
        for line in dump.stdout.decode().split("\n"):
            if not line:
                continue

            # Enter a new section
            if "section" in line:
                section_desc = self._parse_section_header(line)
                assert section_desc.name not in instruction_addresses
                instruction_addresses[section_desc.name] = []
                continue

            # Skip instruction in ignored sections
            if section_desc.skip:
                continue

            # Parse instruction addresses
            assert section_desc.name != "", "Failed to parse objdump output (section_name)"
            instruction_addresses[section_desc.name].append(int(line[:-1], 16))

        return instruction_addresses

    def _parse_section_header(self, line: str) -> _ObjdumpSectionDesc:
        if ".note.gnu" in line:
            return _ObjdumpSectionDesc("", True)
        if ".data." not in line:
            return _ObjdumpSectionDesc("", False)

        last_word = line.split()[-1]
        try:
            section_name = last_word[:-1]
            section_name = section_name.split(".")[2]
            return _ObjdumpSectionDesc(section_name, False)
        except ValueError as e:
            raise _ParsingError(
                "Failed to parse objdump output (section_name):\n"
                f"Issue: Invalid actor label or undefined actor: {last_word}") from e


# ==================================================================================================
# Public Interface: Parser Class
# ==================================================================================================
class X86ELFParser(ELFParser):
    """
    Implementation of ELF parsing for x86 architecture
    """

    # ----------------------------------------------------------------------------------------------
    # Public Methods
    def populate_elf_data(self, test_case_bin: TestCaseBinary,
                          test_case_code: TestCaseProgram) -> None:
        """
        Parse the ELF file and add the following data to the test case:
        - ELF section data
        - ELF symbol table data
        - instruction addresses
        """
        # get metadata from the ELF file and objdump output
        symbol_table: SymbolTable
        instruction_map: InstructionMap
        symbol_table, instruction_map = self._assign_bin_metadata(test_case_bin.obj_path,
                                                                  test_case_code)

        # check that the data was populated correctly and the macros are well-formed
        self._validate_sections(test_case_code.get_sections(), instruction_map)
        self._validate_macros(test_case_code, symbol_table)

        # assign the parsed data to the test case
        test_case_bin.assign_elf_data(symbol_table, instruction_map)

    # ----------------------------------------------------------------------------------------------
    # Private: Assignment of metadata to Section -> Function -> Instruction

    def _assign_bin_metadata(self, obj_file: str,
                             test_case_code: TestCaseProgram) -> Tuple[SymbolTable, InstructionMap]:
        # pylint: disable=too-many-locals
        # NOTE: the check is disabled because I haven't found a way to reduce the number of locals

        # Initialize data structures
        symbol_table: SymbolTable = []
        instruction_map: InstructionMap = {}

        # Extract data from the ELF file and objdump output
        elf_data = _SymtabParser().parse(obj_file)
        instr_addr_map = _ObjdumpOutputParser().parse(obj_file)

        # Use the data to construct the symbol table and instruction map
        sorted_sections = sorted(elf_data["section_data"].values(), key=lambda x: x["id_"])
        all_functions = [f for s in sorted_sections for f in s["functions"].values()]
        for section_data in sorted_sections:
            # Assign section metadata
            section_obj = test_case_code.find_section(name=section_data["name"])
            self._assign_section_metadata(section_data, section_obj)

            # Assign function metadata
            sorted_functions = sorted(section_data["functions"].values(), key=lambda x: x["id_"])
            for func_data in sorted_functions:
                self._assign_function_metadata(func_data, section_data, symbol_table)

            # Create a local instruction map for the section
            instruction_map[section_data["id_"]] = {}

            # Assign instruction metadata
            cursor = 0
            for func_data in sorted_functions:
                function_object = test_case_code.find_function(func_data["name"])
                assert function_object.get_owner() == section_obj.owner
                assert func_data["offset"] == instr_addr_map[section_data["name"]][cursor], \
                    f"offsets: {func_data['offset']} {instr_addr_map[section_data['name']][cursor]}"

                for bb in list(function_object) + [function_object.get_exit_bb()]:
                    for inst in list(bb) + bb.terminators:
                        self._assign_instruction_metadata(inst, instr_addr_map, cursor,
                                                          section_data, instruction_map)
                        if inst.name == "macro":
                            self._assign_macro_metadata(inst, sorted_sections, all_functions,
                                                        symbol_table)
                        cursor += 1

        # Fixup: the last instruction in .data.main is the test case exit, and it must map to a NOP
        instruction_map[0][elf_data["exit_addr"]] = \
            Instruction("nop", "BASE-NOP", is_instrumentation=True)

        # Sort symbols in the symbol table by section id and offset within the section
        symbol_table.sort(key=lambda x: (x.sid, x.offset))

        return symbol_table, instruction_map

    @staticmethod
    def _assign_section_metadata(section_data: _SectionData, section_obj: CodeSection) -> None:
        section_obj.assign_elf_data(
            offset=section_data["offset"], size=section_data["size"], id_=section_data["id_"])

    @staticmethod
    def _assign_function_metadata(func_data: _FunctionData, section_data: _SectionData,
                                  symbol_table: SymbolTable) -> None:
        func_symbol = SymbolTableEntry(
            sid=section_data["id_"],
            type_=0,
            offset=func_data["offset"],
            arg=func_data["id_"],
        )
        symbol_table.append(func_symbol)

    @staticmethod
    def _assign_instruction_metadata(inst: Instruction, instr_addr_map: _InstrAddrMap, cursor: int,
                                     section_data: _SectionData, instr_map: InstructionMap) -> None:
        section_name = section_data["name"]
        instr_addr_map_in_sec = instr_addr_map[section_name]

        # get instruction info
        address = instr_addr_map_in_sec[cursor]
        if cursor + 1 < len(instr_addr_map_in_sec):
            size = instr_addr_map_in_sec[cursor + 1] - address
        else:
            size = 0

        # assign instruction metadata
        inst.assign_binary_properties(section_id=section_data["id_"], offset=address, size=size)

        # add instruction to the instruction map
        instr_map[section_data["id_"]][address] = inst

    def _assign_macro_metadata(self, inst: Instruction, sections_data: List[_SectionData],
                               functions_data: List[_FunctionData],
                               symbol_table: SymbolTable) -> None:
        """
        Convert a macro instruction to a symbol table entry by parsing its symbolic arguments
        according to the macro specification (see x86_target_desc.py). Add the resulting
        symbol to the symbol table.

        Example:
        - Input (macro instruction): MACRO 1, .main.function_1
        - Processing:
            type: 1 (actor switch)
            arg 1: main -> 0 (offset of section main)
            arg 2: function_1 -> 12 (offset of function function_1 within section main)
            arg 3: none
            arg 4: none
            compressed macro argument: 0 + (12 << 16) + (0 << 32) + (0 << 48) = 786432
        - Output (symbol table entry): SymbolTableEntry(0, 1, 0, 786432)
        """

        # pylint: disable=too-many-locals
        # NOTE: the check is disabled because I haven't found a way to reduce the number of locals

        def section_name_to_id(name: str) -> int:
            for entry in sections_data:
                if entry["name"] == name:
                    return entry["id_"]
            raise _ParsingError(f"Macro references an unknown actor {name}")

        def function_name_to_id(name: str) -> int:
            for entry in functions_data:
                if entry["name"] == name:
                    return entry["id_"]
            raise _ParsingError(f"Macro references an unknown function {name}")

        assert inst.name == "macro"

        # find the spec for this macro arguments
        macro_name = inst.operands[0].value[1:].lower()
        try:
            macro_spec = self._target_desc.macro_specs[macro_name]
        except IndexError as e:
            raise _ParsingError(f"Unknown macro {macro_name} in {inst}") from e

        # convert macro operands to compressed symbol arguments
        str_args = inst.operands[1].value.split('.')[1:]
        symbol_args: int = 0
        for i, str_arg in enumerate(str_args):
            str_arg = str_arg.lower()
            if macro_spec.args[i] == "":
                continue
            if macro_spec.args[i] == "actor_id":
                actor_id = section_name_to_id(str_arg)
                symbol_args += (actor_id << i * 16)
                continue
            if macro_spec.args[i] == "function_id":
                symbol_args += (function_name_to_id("." + str_arg) << i * 16)
                continue
            if macro_spec.args[i] == "int":
                if str_arg.startswith("0x"):
                    val = int(str_arg, 16) & 0xFFFF
                else:
                    val = int(str_arg) & 0xFFFF
                symbol_args += (val << i * 16)
                continue
            raise ValueError(f"Invalid macro argument {macro_spec.args[i]}")

        # add the macro to the symbol table
        symbol_table.append(
            SymbolTableEntry(
                sid=inst.section_id(),
                type_=macro_spec.type_,
                offset=inst.section_offset(),
                arg=symbol_args,
            ))

    # ----------------------------------------------------------------------------------------------
    # Private: Validation of the parsed data
    def _validate_sections(self, sections: List[CodeSection],
                           instruction_map: InstructionMap) -> None:
        """
        Validate that all sections in the test case have been populated with ELF data
        :param sections: list of sections in the test case
        :param instruction_map: constructed InstructionMap
        :return: None
        :raises _ParsingError: if at least one section was not populated
        :raises _ParsingError: if the instruction map does not match the sections
        """
        if len(instruction_map) != len(sections):
            raise _ParsingError(
                "InstructionMap does not have the same number of sections as the test case")

        for section_obj in sections:
            try:
                _ = section_obj.get_elf_data()  # will throw an exception if the section is not set
            except AssertionError as e:
                raise _ParsingError(f"Failed to find section for actor `{section_obj.name}`") from e

    def _validate_macros(self, test_case: TestCaseProgram, symbol_table: SymbolTable) -> None:
        """ Validate that all macros in the test case are well-formed """
        for symbol in symbol_table:
            if symbol.type_ == 0:  # function
                continue
            macro_spec = self._target_desc.get_macro_spec_from_type(symbol.type_)

            # validate that the actor id is valid
            for i in range(4):
                if macro_spec.args[i] != "actor_id":
                    continue
                target_actor_id = (symbol.arg >> (i * 16)) & 0xFFFF

                # check that the actor exists
                try:
                    actor = test_case.find_actor(actor_id=target_actor_id)
                except KeyError as e:
                    raise _ParsingError(
                        f"Macro references an unknown actor id {target_actor_id}") from e

                # validate that the actor type matches the macro
                if macro_spec.name == "set_k2u_target" and \
                   actor.privilege_level != ActorPL.USER and actor.mode != ActorMode.HOST:
                    raise _ParsingError("Macro set_k2u_target expects a user actor")
                if macro_spec.name == "set_u2k_target" and \
                   actor.privilege_level != ActorPL.KERNEL and actor.mode != ActorMode.HOST:
                    raise _ParsingError("Macro set_u2k_target expects a kernel actor")
                if macro_spec.name == "set_h2g_target" and \
                   actor.mode != ActorMode.HOST and actor.privilege_level != ActorPL.KERNEL:
                    raise _ParsingError("Macro set_h2g_target expects a host actor")
                if macro_spec.name == "set_g2h_target" and \
                   actor.mode != ActorMode.GUEST and actor.privilege_level != ActorPL.KERNEL:
                    raise _ParsingError("Macro set_g2h_target expects a guest actor")
