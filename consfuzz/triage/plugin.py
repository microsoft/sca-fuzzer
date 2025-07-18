"""
File: GDB plugin that can be used to navigate traces in GDB.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import gdb

# FIXME!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
import sys
sys.path.append("/home/alvise/venv-revizor-2/lib/python3.12/site-packages")
sys.path.append(".")
sys.path.append("..")

from typing import Any, List, Optional
from rvzr.model_dynamorio.trace_decoder import TraceDecoder, DebugTraceEntryType

# ------------------------------------------------------------------------------
# Trace Helpers
# ------------------------------------------------------------------------------

_glob_trace = None
_cached_lines = {}

_glob_cur_line = None
_glob_cur_spec_level = None
_glob_cur_spec_context = None

class SpecWinInfo:
    """
    Store relevant information about a specific speculative window.
    """
    first_pc: Optional[int]
    first_line: Optional[int]
    target_pc: int
    target_line: int
    target_count: int
    nesting: int

    def __init__(self, first_pc: Optional[int], first_line: Optional[int], target_pc: int, target_line: int, target_count: int, nesting: int):
        self.first_pc = first_pc
        self.target_pc = target_pc
        self.target_count = target_count
        self.nesting = nesting
        self.first_line = first_line
        self.target_line = target_line

    def __str__(self):
        prefix  = "    " * self.nesting
        if self.first_pc is None:
            return f"{prefix} └─ last architectural: {hex(self.target_pc)} (#{self.target_count}) [line: {self.target_line}]"

        # Check if we're at the beginning of this window
        global _glob_cur_line
        if _glob_cur_line == self.first_line:
            return f"{prefix} └─ last: {hex(self.first_pc)} [line: {self.first_line}]\n"
        else:
            s =  f"{prefix} ├─ speculated to: {hex(self.first_pc)} [line: {self.first_line}]\n"
            s += f"{prefix} └─ last: {hex(self.target_pc)} (#{self.target_count}) [line: {self.target_line}]"
            return s


def _is_arch(entry: Any) -> bool:
    """
    Is the entry architectural (debug trace entries only)
    """
    return entry.nesting_level == 0

def _is_spec(entry: Any) -> bool:
    """
    Is the entry speculative (debug trace entries only)
    """
    return entry.nesting_level != 0

def _build_spec_info(line):
    """
    Return a list of relevant information for each (nested) speculation window that leads to the
    instruction at line `line` in the trace.
    """
    spec_windows: list[SpecWinInfo] = []

    print(f" • Analyzing debug trace from line {line}...", flush=True)
    cur_idx = line
    prev_nesting = None

    while cur_idx > 0:
        # Visit trace in reverse order
        entry = _glob_trace[cur_idx]

        if DebugTraceEntryType(entry.type) == DebugTraceEntryType.ENTRY_REG_DUMP:
            # Found new instruction
            cur_pc = entry.regs.pc
            cur_nesting = entry.nesting_level
            if len(spec_windows) > 0:
                prev_nesting = spec_windows[-1].nesting

            if prev_nesting is None or cur_nesting < prev_nesting:
                # Found start of new speculation window
                start_spec_pc = cur_pc if _is_spec(entry) else None
                start_spec_line = cur_idx if _is_spec(entry) else None
                spec_windows.append(SpecWinInfo(start_spec_pc, start_spec_line, cur_pc, cur_idx, 1, cur_nesting))
            elif cur_nesting == prev_nesting:
                # Update the current speculation window
                if spec_windows[-1].first_pc is not None:
                    spec_windows[-1].first_pc = cur_pc
                    spec_windows[-1].first_line = cur_idx
                if cur_pc == spec_windows[-1].target_pc:
                    spec_windows[-1].target_count += 1

        cur_idx -= 1

    return spec_windows

def _get_line_info(line: int):
    """
    Return the relevant information for a given line (take from the cache if already computed).
    """
    if line in _cached_lines.keys():
        spec_windows = _cached_lines[line]
    else:
        spec_windows = _build_spec_info(line)
        _cached_lines[line] = spec_windows

    return spec_windows

# ------------------------------------------------------------------------------
# GDB Helpers
# ------------------------------------------------------------------------------

class Printing:
    """
    Customize the amount of information printed when running commands
    """
    @staticmethod
    def setup():
        gdb.execute("set print frame-arguments presence")

    @staticmethod
    def restore():
        gdb.execute("set print frame-arguments all")

class BpManager:
    """
    Breakpoints management
    """
    @staticmethod
    def add(bp: str | int) -> int:
        if isinstance(bp, int):
            result = gdb.execute(f"b *{hex(bp)}", to_string=True)
        else:
            result = gdb.execute(f"b {bp}", to_string=True)

        if result.startswith("Breakpoint"):
            bp_num = int(result.split(" ")[1])
        else:
            print(result)
            raise ValueError("Cannot add breakpoint")

        return bp_num

    @staticmethod
    def delete(n: int):
        gdb.execute(f"dis {n}")
        gdb.execute(f"del {n}")

    @staticmethod
    def ignore(bp: int, count: int):
        gdb.execute(f"ignore {bp} {count}")


class GdbExec:
    @staticmethod
    def run():
        gdb.execute("run", to_string=True)

    @staticmethod
    def cont():
        gdb.execute("continue", to_string=True)

    @staticmethod
    def backtrace():
        gdb.execute("bt")

    @staticmethod
    def jump(target_pc: int):
        gdb.execute(f"jump *{hex(target_pc)}", to_string=True)

# ------------------------------------------------------------------------------
# GDB Commands
# ------------------------------------------------------------------------------
class SpecPrefixCommand (gdb.Command):
  "Spec command."

  def __init__ (self):
    super (SpecPrefixCommand, self).__init__ ("spec",
                         gdb.COMMAND_SUPPORT,
                         gdb.COMPLETE_NONE, prefix=True)

SpecPrefixCommand()


class SpecSourceCommand (gdb.Command):
    """
    Load a debug trace generate by consfuzz.
    """
    def __init__ (self):
        super (SpecSourceCommand, self).__init__ ("spec source",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)
        self._decoder = TraceDecoder()

    def invoke (self, arg, from_tty):
        # Parse the debug trace
        print(f" • Decoding debug trace... {arg}", flush=True)

        _, dbg_traces = self._decoder.decode_trace_file(arg)
        if len(dbg_traces) != 1:
            print(" • Error! Not a debug trace.")
            return
        global _glob_trace
        _glob_trace = dbg_traces[0]

        print(" • Done!")

SpecSourceCommand ()


def spec_goto(context: List[SpecWinInfo], depth: int = 0, stop_at_first: bool = False):
    Printing.setup()

    # Restart the program
    bp = BpManager.add("wrapper")
    GdbExec.run()
    BpManager.delete(bp)

    # Simulate all windows
    relevant_context = context[depth:]
    for cur_n_win, win in enumerate(reversed(relevant_context)):
        # Check if we need to open a speculation window
        if win.first_pc is not None:
            # Break on the first speculative instruction
            bp = BpManager.add(win.first_pc)
            # Jump to the first speculative instruction (stops at previous breakpoint)
            GdbExec.jump(win.first_pc)
            # Disable entrypoint (in case it's visited again in the rest of the trace)
            BpManager.delete(bp)

        # Check if we need to stop at the first instruction of the current window
        if stop_at_first:
            if cur_n_win == len(relevant_context) -1:
                break

        # Check if this window has only one instruction
        if win.first_line != win.target_line:
            # Break on last instruction of the window
            bp = BpManager.add(win.target_pc)
            # Continue until the right number of occurrences have been found
            BpManager.ignore(bp, win.target_count - 1)
            GdbExec.cont()
            # Disable breakpoint (in case we encounter this instruction again later in the trace)
            BpManager.delete(bp)
        # Print Backtrace
        # print(f"------------------- Reached {hex(win.target_pc)} ----------------------")
        # GdbExec.backtrace()

    Printing.restore()


class SpecGotoCommand (gdb.Command):
    """
    Execute the program until we reach the instruction corresponding to the given line.
    """
    def __init__ (self):
        super (SpecGotoCommand, self).__init__ ("spec goto",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)

    def invoke (self, arg, from_tty):
        # Check validity of state and inputs
        if _glob_trace is None:
            print ("Error: no trace is sourced")
            return
        try:
            arg = int(arg)
        except:
            print ("Error: command expects a line number")
            return
        if arg > len(_glob_trace):
            print ("Error: invalid line for current trace")
            return

        global _glob_cur_line
        _glob_cur_line = arg
        global _glob_cur_spec_context
        _glob_cur_spec_context = _get_line_info(arg)
        global _glob_cur_spec_level
        _glob_cur_spec_level = 0

        spec_goto(_glob_cur_spec_context)

SpecGotoCommand ()


class SpecBtCommand (gdb.Command):
    """
    Get information about speculation backtrace for the currently selected line.
    """
    def __init__ (self):
        super (SpecBtCommand, self).__init__ ("spec bt",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)

    def invoke (self, arg, from_tty):
        global _glob_cur_spec_context
        global _glob_cur_spec_level

        # Check validity of state and inputs
        if _glob_cur_spec_context is None or _glob_cur_spec_level is None:
            print ("Error: no line selected - use 'spec goto' to select one")
            return

        # Print spec info
        for win in reversed(_glob_cur_spec_context[_glob_cur_spec_level:]):
            print(win)

SpecBtCommand ()


class SpecUpCommand (gdb.Command):
    """
    Goto "up" int the speculative backtrace, i.e. to the last instruction before speculation.
    """
    def __init__ (self):
        super (SpecUpCommand, self).__init__ ("spec up",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)

    def invoke (self, arg, from_tty):
        global _glob_cur_line
        global _glob_cur_spec_context
        global _glob_cur_spec_level

        # Check validity of state and inputs
        if _glob_cur_line is None or _glob_cur_spec_context is None or _glob_cur_spec_level is None:
            print ("Error: no line selected - use 'spec goto' to select one")
            return

        # Check at what point of the window we are
        cur_win = _glob_cur_spec_context[_glob_cur_spec_level]
        is_win_start = (_glob_cur_line == cur_win.first_line)

        if is_win_start:
            # Goto end of previous window
            if _glob_cur_spec_level >= len(_glob_cur_spec_context) - 1:
                print ("Already at top level")
                return

            _glob_cur_spec_level += 1
            _glob_cur_line = _glob_cur_spec_context[_glob_cur_spec_level].target_line
            spec_goto(_glob_cur_spec_context, _glob_cur_spec_level)
        else:
            # Goto start of the current window
            cur_line = _glob_cur_spec_context[_glob_cur_spec_level].first_line
            if cur_line == None:
                print ("Hit start of speculation!")
                return

            _glob_cur_line = cur_line
            spec_goto(_glob_cur_spec_context, _glob_cur_spec_level, stop_at_first=True)


SpecUpCommand()


class SpecDownCommand (gdb.Command):
    """
    Goto "down" int the speculative backtrace, i.e. to the last instruction of the next window.
    """
    def __init__ (self):
        super (SpecDownCommand, self).__init__ ("spec down",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)

    def invoke (self, arg, from_tty):
        global _glob_cur_line
        global _glob_cur_spec_context
        global _glob_cur_spec_level

        # Check validity of state and inputs
        if _glob_cur_line is None or _glob_cur_spec_context is None or _glob_cur_spec_level is None:
            print ("Error: no line selected - use 'spec goto' to select one")
            return

        # Check at what point of the window we are
        cur_win = _glob_cur_spec_context[_glob_cur_spec_level]
        is_win_end = (_glob_cur_line == cur_win.target_line)

        if is_win_end:
            # Goto start of next window
            if _glob_cur_spec_level == 0:
                print ("Already at bottom level")
                return

            _glob_cur_spec_level -= 1
            _glob_cur_line = _glob_cur_spec_context[_glob_cur_spec_level].first_line
            spec_goto(_glob_cur_spec_context, _glob_cur_spec_level, stop_at_first=True)
        else:
            # Goto end of the current window
            _glob_cur_line = _glob_cur_spec_context[_glob_cur_spec_level].target_line
            spec_goto(_glob_cur_spec_context, _glob_cur_spec_level)


SpecDownCommand()


class SpecPrevCommand (gdb.Command):
    """
    Goto the previous instruction in the trace that belongs to the same speculation window
    """
    def __init__ (self):
        super (SpecPrevCommand, self).__init__ ("spec prev",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)

    def invoke (self, arg, from_tty):
        global _glob_cur_line
        global _glob_cur_spec_context
        global _glob_cur_spec_level

        while True:
            if _glob_cur_line == 0:
                print("Already at first instruction of the trace!")
                return
            if _glob_cur_line == _glob_cur_spec_context[_glob_cur_spec_level].first_line:
                print("Already at first instruction of the current window!")
                print("Use 'spec up' to go to the previous window")
                return
            # Get cur nesting level
            cur_nesting = _glob_trace[_glob_cur_line].nesting_level
            # Get previous instruction
            _glob_cur_line -= 1
            entry = _glob_trace[_glob_cur_line]
            if DebugTraceEntryType(entry.type) == DebugTraceEntryType.ENTRY_REG_DUMP:
                if entry.nesting_level > cur_nesting:
                    # Ignore unrelated windows
                    continue
                # Found new instruction
                tmp_context = _get_line_info(_glob_cur_line)
                spec_goto(tmp_context)
                break

SpecPrevCommand()


class SpecNextCommand (gdb.Command):
    """
    Goto the next instruction in the trace that belongs to the same speculation window
    """
    def __init__ (self):
        super (SpecNextCommand, self).__init__ ("spec next",
                                                       gdb.COMMAND_SUPPORT,
                                                       gdb.COMPLETE_FILENAME)

    def invoke (self, arg, from_tty):
        global _glob_cur_line
        global _glob_cur_spec_context
        global _glob_cur_spec_level

        while True:
            if _glob_cur_line == len(_glob_trace) - 1:
                print("Already at last instruction of the trace!")
                return
            if _glob_cur_line == _glob_cur_spec_context[_glob_cur_spec_level].target_line:
                print("Already at last instruction of the current window!")
                print("Use 'spec down' to enter to the next window")
                return
            # Get cur nesting level
            cur_nesting = _glob_trace[_glob_cur_line].nesting_level
            # Get next instruction
            _glob_cur_line += 1
            entry = _glob_trace[_glob_cur_line]
            if DebugTraceEntryType(entry.type) == DebugTraceEntryType.ENTRY_REG_DUMP:
                if entry.nesting_level > cur_nesting:
                    # Ignore unrelated windows
                    continue
                # Found new instruction
                tmp_context = _get_line_info(_glob_cur_line)
                spec_goto(tmp_context)
                break

SpecNextCommand()
