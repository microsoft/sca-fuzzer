"""
File: Classes representing assembled test case code in a binary form (ELF object file).

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, NamedTuple, Final, Optional

from .instruction import Instruction
from ..logs import error

if TYPE_CHECKING:
    from .test_case_code import TestCaseProgram

SectionID = int
SymbolType = int
SymbolOffset = int
MacroArgument = int
InstructionMap = Dict[SectionID, Dict[int, Instruction]]


class SymbolTableEntry(NamedTuple):
    """ Symbol in a test case symbol table """

    sid: SectionID
    """ The ID of the section that contains the symbol """

    offset: SymbolOffset
    """ offset: The offset of the symbol in the actor's section """

    type_: SymbolType
    """ type_: The type of the symbol """

    arg: MacroArgument
    """ arg: The argument of the symbol """


SymbolTable = List[SymbolTableEntry]


class TestCaseBinary:
    """
    A class representing the object ELF file (i.e., compiled assembly) of a test case program
    """

    obj_path: Final[str]
    """ Path to the object file generated from the asm_path """

    _symbol_table: Optional[List[SymbolTableEntry]] = None
    """ List of symbols in the test case program """

    _instruction_map: Optional[InstructionMap] = None
    """ Dictionary mapping section ID + offset to the corresponding Instruction object """

    _parent: TestCaseProgram  # The parent test case program
    _obj_is_assembled: bool = False  # Flag indicating whether the object file has been assembled

    def __init__(self, obj_path: str, parent: TestCaseProgram):
        self.obj_path = obj_path
        self._parent = parent

    def mark_as_assembled(self) -> None:
        """ Mark the object file as assembled """
        self._obj_is_assembled = True

    def to_bytes(self, padded_section_size: int = 0, padding_byte: bytes = b'') -> bytes:
        """ Return the full binary of the assembled object file, with sections ordered by actor ID.
        Optionally, pad each section to a specified size with a specified padding byte.

        :param pad_to_size: The size to pad each section to
        :param padding_byte: The byte to use for padding
        :return: A list of byte strings, each containing the full compiled binary of a section
        """
        assert self._obj_is_assembled, \
            "Attempting to read sections from an non-assembled object file"
        assert padded_section_size == 0 or len(padding_byte) == 1, \
            "padding_byte must be specified as a single byte if pad_to_size is set"

        code = b''
        with open(self.obj_path, 'rb') as bin_file:
            for actor in self._parent.get_actors(sorted_=True):

                # Read the section from the object file
                section_data = actor.code_section().get_elf_data()
                offset = section_data["offset"]
                size = section_data["size"]

                bin_file.seek(offset)
                code += bin_file.read(size)

                # Apply padding
                assert padded_section_size >= size, \
                    "Padded section size is less than to the original section size"
                if padded_section_size > size:
                    padding = padded_section_size - size
                    code += padding_byte * padding

        return code

    def get_macro_offset(self, macro_type: int) -> int:
        """ Return the offset of the macro of the given type in its section.
        If there are multiple macros of the same type, the first one is returned.
        :param macro_id: The ID of the macro
        :return: The offset of the macro in the object file; -1 if not found
        """
        assert self._symbol_table is not None, \
            "assign_elf_data() has not been called on this object"
        for symbol in self._symbol_table:
            if symbol.type_ == macro_type:
                return symbol.offset
        return -1

    def assign_elf_data(self, symbol_table: List[SymbolTableEntry],
                        instruction_map: InstructionMap) -> None:
        """
        Assign the symbol table and instruction map based on the data parsed from the ELF file
        (normally assigned by an ELFParser instance).
        """
        assert self._symbol_table is None, "Attempting to reassign symbol table"
        assert self._instruction_map is None, "Attempting to reassign instruction map"
        self._symbol_table = symbol_table
        self._instruction_map = instruction_map

    def symbol_table(self) -> List[SymbolTableEntry]:
        """ Return the symbol table of the test case program """
        assert self._symbol_table is not None, "Symbol table has not been populated"
        return self._symbol_table

    def instruction_map(self) -> InstructionMap:
        """ Return the instruction map of the test case program """
        assert self._instruction_map is not None, "Instruction map has not been populated"
        return self._instruction_map

    def save_rcbf(self, path: str) -> None:
        """
        Save the test case binary in the RCBF format
        (see docs/devel/binary-formats.md for details).
        :param path: The path to save the RCBF file to
        """
        assert self._obj_is_assembled, "Attempting to save an un-assembled object file"
        actors = self._parent.get_actors(sorted_=True)
        symbol_table = self.symbol_table()

        # sanity check
        if any(symbol.type_ < 0 for symbol in symbol_table):
            error("attempt to use template as a test case")

        # write the RCBF file
        with open(path, 'wb') as f:
            # header
            f.write((len(actors)).to_bytes(8, byteorder='little'))  # n_actors
            f.write((len(symbol_table)).to_bytes(8, byteorder='little'))  # n_symbols

            # actor metadata
            for actor in actors:
                f.write((actor.get_id()).to_bytes(8, byteorder='little'))
                f.write((actor.mode.value).to_bytes(8, byteorder='little'))
                f.write((actor.privilege_level.value).to_bytes(8, byteorder='little'))
                f.write((actor.data_properties).to_bytes(8, byteorder='little'))
                f.write((actor.data_ept_properties).to_bytes(8, byteorder='little'))
                f.write((0).to_bytes(8, byteorder='little'))  # unused

            # symbol table (first functions sorted by argument, then macros sorted by actor+offset)
            function_symbols = [s for s in symbol_table if s[2] == 0]
            macro_symbols = [s for s in symbol_table if s[2] != 0]
            for aid, s_offset, s_id, arg in sorted(function_symbols, key=lambda s: s.arg):
                # print("function", s_id, aid, s_offset, arg)
                f.write((aid).to_bytes(8, byteorder='little'))
                f.write((s_offset).to_bytes(8, byteorder='little'))
                f.write((s_id).to_bytes(8, byteorder='little'))
                f.write((arg).to_bytes(8, byteorder='little'))
            for aid, s_offset, s_id, arg in sorted(macro_symbols, key=lambda s: (s.sid, s.offset)):
                # print("macro", aid, s_offset, s_id, arg)
                f.write((aid).to_bytes(8, byteorder='little'))
                f.write((s_offset).to_bytes(8, byteorder='little'))
                f.write((s_id).to_bytes(8, byteorder='little'))
                f.write((arg).to_bytes(8, byteorder='little'))

            # section metadata
            for actor in actors:
                section_data = actor.code_section().get_elf_data()
                # print("section\n")
                f.write((section_data["id"]).to_bytes(8, byteorder='little'))
                f.write((section_data["size"]).to_bytes(8, byteorder='little'))
                f.write((0).to_bytes(8, byteorder='little'))

            # code
            with open(self.obj_path, 'rb') as bin_file:
                for actor in actors:
                    section_data = actor.code_section().get_elf_data()
                    bin_file.seek(section_data["offset"])  # type: ignore
                    # print(code, section.size)
                    f.write(bin_file.read(section_data["size"]))

            # print(self.obj_path, f.tell())
