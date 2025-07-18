"""
File: SymbolServer and subclasses, used to print source locations from raw PCs.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from typing import Optional

from elftools.elf.elffile import ELFFile
from pygdbmi.gdbcontroller import GdbController


class SymbolServer:
    """
    Superclass for getting location information from a binary.
    """
    def __init__(self, binary: str) -> None:
        pass

    def get_location(self, address: int) -> Optional[str]:
        """
        Given a PC in the binary, return a string representing the source location and
        the corresponding source code.
        """
        return None


class GdbSymbolServer(SymbolServer):
    """
    Implement symbol name retrival using GDB.
    NOTE: this is significantly slower that parsing the ELF binary but it provides much more
    information even for code with missing symbols.
    """
    def __init__(self, binary: str) -> None:
        # Start gdb process
        self.gdbmi = GdbController()
        # Load binary
        _ = self.gdbmi.write(f'file {binary}')

    def _gdb_exec(self, cmd: str) -> str:
        """
        Execute a gdb command and return what gdb printed as a result.
        """
        response = self.gdbmi.write(cmd)
        return response[1]['payload'].strip()

    def get_func_name(self, address: int) -> str:
        """
        Return function name and assembly code corresponding to a program's PC
        """
        # Get function name from GDB
        payload = self._gdb_exec(f'info sym {hex(address)}')

        # Format as <module>+<offset>
        splitted = payload.split(' ')
        loc = splitted[0] + '+' + splitted[2]
        # Disassemble one instruction at that location
        payload = self._gdb_exec(f'x/1i {loc}')
        asm = ':'.join(payload.split(':')[1:])

        return loc.strip() + "   " + asm.strip()

    def get_location(self, address: int) -> str:
        """
        Returns a tuple of location string (file:line) and the corresponding source code if
        available, or function_name+offset and disassembly if no source code is available for that
        location (e.g. library code with no symbols).
        """
        # Try to get source location from gdb
        payload = self._gdb_exec(f'info line *{hex(address)}')

        # If not available, get at least function_name+offset and assembly
        if "No line number" in payload:
            return self.get_func_name(address)
        else:
            # Format as <file>:<line>
            splitted = payload.split(' ')
            loc = splitted[3].replace('\"','') + ':' + splitted[1]
            # Get source code from GDB
            payload = self._gdb_exec(f'list {loc.strip()},{loc.strip()}')
            code = "    " + ' '.join(payload.split(' ')[1:])

        return loc.strip() + "  " + code.strip()


class ElfSymbolServer(SymbolServer):
    """
    Implement symbol name retrival using the debug symbols embedded in the binary.
    NOTE: this is significantly faster than using GDB but some symbols might not be available.
    """
    def __init__(self, binary: str) -> None:
        with open(binary, "rb") as f:
            self._elf_data = ELFFile(f)
            self.dwarf_info = self._elf_data.get_dwarf_info()

    def get_location(self, address: int) -> Optional[str]:
        """
        Find the DWARF information in the ELF binary corresponding to a given PC.
        The corresponding source code is always empty.
        """
        # Go over all the line programs in the DWARF information, looking for
        # one that describes the given address.
        for CU in self.dwarf_info.iter_CUs():
            # First, look at line programs to find the file/line for the address
            line = self.dwarf_info.line_program_for_CU(CU)
            if not line:
                continue
            delta = 1 if line.header.version < 5 else 0
            prevstate = None
            for entry in line.get_entries():
                # We're interested in those entries where a new state is assigned
                if entry.state is None:
                    continue
                # Looking for a range of addresses in two consecutive states that
                # contain the required address.
                if prevstate and prevstate.address <= address < entry.state.address:
                    filename = line['file_entry'][prevstate.file - delta].name.decode()
                    line = prevstate.line
                    return f"{filename}:{line}"
                if entry.state.end_sequence:
                    # For the state with `end_sequence`, `address` means the address
                    # of the first byte after the target machine instruction
                    # sequence and other information is meaningless. We clear
                    # prevstate so that it's not used in the next iteration. Address
                    # info is used in the above comparison to see if we need to use
                    # the line information for the prevstate.
                    prevstate = None
                else:
                    prevstate = entry.state

        # if we're here, we didn't find a symbol
        return None


class CombinedSymbolServer(SymbolServer):
    """"
    Get the symbol location from the ELF binary when available, or fallback to the
    GDB server if needed.
    """
    def __init__(self, binary: str) -> None:
        # Fast
        self.elf_server = ElfSymbolServer(binary)
        # Slow
        self.gdb_server = GdbSymbolServer(binary)

    def get_location(self, address: int) -> Optional[str]:
        result = self.elf_server.get_location(address)
        if result is None:
            result = self.gdb_server.get_func_name(address)

        return result

