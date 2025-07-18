"""
File: Inspect a single reported leakage.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import os
import subprocess as sp
from typing import Any, List, Optional, Tuple

from rvzr.model_dynamorio.trace_decoder import TraceDecoder, TraceEntryType, DebugTraceEntryType

from .triage import get_plugin_path
from .triage.config import LeakageInspectorConfig
from .triage.use_def_tracker import UseDefTracker
from .triage.shared_types import TraceLineNum
from .triage.symbol_server import SymbolServer, CombinedSymbolServer

_TRACING_FLAGS = "--log-level 5 --debug-trace-output {dbg_trace_file} "

type InstPc = int


def _parse_traces_info(file_and_line: str, baseline: str) -> List[Tuple[str, TraceLineNum]]:
    # Parse trace path and line of the cmdline arguments
    splitted = file_and_line.split(':')
    trace1 = ':'.join(splitted[:-2])
    line1 = int(splitted[-2])

    traces = [(trace1, line1)]

    if baseline != 'none':
        # Generate trace path and line for the baseline we should compare against (needed for
        # differential analysis)
        if baseline == 'auto':
            input_name = os.path.basename(trace1)
            ext = '.' + trace1.split('.')[-1]
            trace2 = trace1.replace(input_name, '000' + ext) # 000.trace or 000.dbgtrace
        else:
            trace2 = baseline

        line2 = int(splitted[-1])
        traces.append((trace2, line2))

    return traces


class LeakageInspector:
    """
    Extract information from the report for leakage analysis.
    """
    _decoder: TraceDecoder
    _config: LeakageInspectorConfig

    leak_trace: list[Any]
    debug_trace: list[Any]

    def __init__(self, config: LeakageInspectorConfig):
        self._decoder = TraceDecoder()
        self._config = config
        self.leak_trace = None
        self.debug_trace = None

    #---------------------------------------------------------------------------
    # Internal Helpers
    #---------------------------------------------------------------------------
    def _count_occurrences(self, trace: list[Any], pc: InstPc, until: TraceLineNum,
                           entry_type: TraceEntryType) -> int:
        """
        Count occurrences of `pc` in `trace` before line `until` in a leakage trace.
        """
        count = 0
        for entry in trace[:until]:
            type_ = TraceEntryType(entry.type)
            if type_ == entry_type and entry.addr == pc:
                count +=1
        return count

    def _count_dbg_occurrences(self, trace: list[Any], pc: InstPc, until: TraceLineNum,
                           only_arch: bool = False) -> int:
        """
        Count occurrences of `pc` in `trace` before line `until` in a debug trace.
        """
        count = 0
        for entry in trace[:until]:
            type_ = DebugTraceEntryType(entry.type)
            if only_arch and self._is_spec(entry):
                continue
            if type_ == DebugTraceEntryType.ENTRY_REG_DUMP and entry.regs.pc == pc:
                count +=1
        return count


    def _is_arch(self, entry: Any) -> bool:
        """
        Is the entry architectural (debug trace entries only)
        """
        return entry.nesting_level == 0

    def _is_spec(self, entry: Any) -> bool:
        """
        Is the entry speculative (debug trace entries only)
        """
        return entry.nesting_level != 0

    def _get_original_cmd(self, trace_file: str) -> str:
        """
        Get the original command that was ran to produce a given trace.
        NOTE: This requires that the original DynamoRIO command is logged in a separate `.log`
        file that has the same name of the trace file (minus the extension).
        """
        log_file = trace_file.replace(".trace", ".log").replace(".dbgtrace", ".log")
        print(f" • Reading original command from logfile {log_file}", flush=True)
        with open(log_file, "r") as log:
            for l in log:
                if l.startswith("$> "):
                    return l.replace("$> ", "").replace("\n","").strip()

        raise ValueError(f"Could not find command that produced {trace_file}")

    def _run_dbg_tracer(self, trace_file: str, regenerate_trace: bool) -> str:
        """
        Produce a debug trace for a given test case.
        Returns the file name of the trace.
        """
        cmd = self._get_original_cmd(trace_file)

        # Add debug flags to command
        dbg_trace_f = trace_file.replace(".trace", ".dbgtrace")
        dbg_flags = _TRACING_FLAGS.format(dbg_trace_file=dbg_trace_f)
        cmd = cmd.replace("libdr_model.so", f"libdr_model.so {dbg_flags} ")
        # Output debug trace in human-readable format
        # cmd += " > {dbg_trace_file}.asm".format(dbg_trace_file=dbg_trace_f)
        # Run debug command
        if regenerate_trace:
            print(f"{cmd}\n", flush=True)
            sp.check_call(cmd, shell=True)

        return dbg_trace_f

    #---------------------------------------------------------------------------
    # Leak trace analysis
    #---------------------------------------------------------------------------
    def find_leak_pc(self, trace_file: str, trace_line: TraceLineNum) -> tuple[InstPc, TraceEntryType, int]:
        """
        Given a trace file and a corresponding line, returns the PC of the intruction logged
        at that line and the number of occurrences of that PC before that line.
        This uniquely identifies an instruction in the trace.
        """
        print(f" • Decoding leak trace {trace_file}...", flush=True)
        traces, _ = self._decoder.decode_trace_file(trace_file)
        assert len(traces) == 1
        trace = traces[0]
        self.leak_trace = trace

        # Find last pc right before trace_line
        print(" • Finding leak PC...", flush=True)
        cur_line = trace_line
        while cur_line > 0:
            cur_line -= 1
            entry = trace[cur_line]

            # For 'I' violations, we want to get the PC of the previous instruction
            # For 'D' violations, we want to get the PC of the load/store instruction
            # For indirect call violations, we get the target PC
            entry_type = TraceEntryType(entry.type)
            if entry_type in [TraceEntryType.ENTRY_PC, TraceEntryType.ENTRY_IND]:
                leak_pc = entry.addr
                n_occurrences = self._count_occurrences(trace, pc=leak_pc, until=cur_line, entry_type=entry_type)
                n_occurrences += 1 # count also the last occurrence that we just found
                print(f"    • Found address {hex(leak_pc)} (occurrence #{n_occurrences})", flush=True)
                return (leak_pc, entry_type, n_occurrences)

        raise ValueError(f"No instruction found for trace line {trace_line}")

    #---------------------------------------------------------------------------
    # Debug trace analysis
    #---------------------------------------------------------------------------
    def find_dbg_line(self, trace_file: str, leak_pc: InstPc, entry_type: TraceEntryType,
                      leak_pc_count: int, regenerate_trace: bool) -> tuple[str, TraceLineNum]:
        """
        Find the line that contains the `leak_pc_count`-th occurrence of `leak_pc` in the debug trace.
        """
        print(" • Collecting debug trace...", flush=True)
        dbg_trace_f = self._run_dbg_tracer(trace_file, regenerate_trace)
        # Parse the debug trace
        print(" • Decoding debug trace...", flush=True)
        _, dbg_traces = self._decoder.decode_trace_file(dbg_trace_f)
        assert len(dbg_traces) == 1
        dbg_trace = dbg_traces[0]
        self.debug_trace = dbg_trace

        print(" • Analyzing debug trace...", flush=True)
        last_xcpt: Optional[Any] = None
        last_valid: TraceLineNum = 0
        last_lineno: TraceLineNum = 0
        n_found = 0

        for entry in dbg_trace:
            # NOTE: In some configurations (e.g. with --poison-value) the tracer will continue
            # execution when it encouters a fault on a speculative path. When running in GDB,
            # we cannot execute faulty instructions, so need to record the last _valid_ instruction.
            if last_xcpt and entry.nesting_level < last_xcpt.nesting_level:
                # Flush last_xcpt if we exited the corresponding speculation window
                last_xcpt = None
            if DebugTraceEntryType(entry.type) == DebugTraceEntryType.ENTRY_EXCEPTION:
                if not last_xcpt:
                    # Record exceptions
                    last_xcpt = entry

            elif DebugTraceEntryType(entry.type) == DebugTraceEntryType.ENTRY_REG_DUMP:
                if not last_xcpt:
                    # If there's not pending exception at this speculation level,
                    # update the last valid instruction
                    last_valid = last_lineno

                # Check if we found the PC we were looking for
                if entry_type == TraceEntryType.ENTRY_PC:
                    if entry.regs.pc == leak_pc:
                        n_found += 1
                    if n_found == leak_pc_count:
                        print(f"Done! Found leak at line {last_valid-1}")
                        return dbg_trace_f, last_valid-1

            elif DebugTraceEntryType(entry.type) == DebugTraceEntryType.ENTRY_IND:
                # Check if we found the indcall we were looking for
                if entry_type == TraceEntryType.ENTRY_IND:
                    if entry.ind.target == leak_pc:
                        n_found += 1
                    if n_found == leak_pc_count:
                        print(f"Done! Found leak at line {last_valid-1}")
                        return dbg_trace_f, last_valid-1

            last_lineno += 1

        raise IndexError(f"Could not find occurence {leak_pc_count} of pc {hex(leak_pc)} in {dbg_trace_f}")

    #---------------------------------------------------------------------------
    # GDB
    #---------------------------------------------------------------------------
    def generate_gdb_script(self, trace_file: str, trace_line: TraceLineNum) -> str:
        """
        Generate a GDB script that can follow the trace speculatively until the leakage point.
        """
        gdb_string = f"source {get_plugin_path()}/plugin.py"
        gdb_string += "\nspec source " + trace_file
        gdb_string += "\nspec goto " + str(trace_line)
        gdb_string += "\nspec bt"
        return gdb_string

    #---------------------------------------------------------------------------
    # Public interface
    #---------------------------------------------------------------------------
    def inspect(self, file_and_line: str,
                violation: str,
                baseline: str,
                binary: str,
                skip_tracing: bool,
                usedef: bool,
                debug_trace: bool) -> None:
        traces = _parse_traces_info(file_and_line, baseline)

        dbg_traces = []

        # Create a GDB script to reach the specified line
        for idx, (trace, line) in enumerate(traces):
            # If the specified line is a line in the trace, we need to find the corresponding line in
            # the _debug_ trace.
            if not debug_trace:
                # Find the target PC in the leak trace
                pc, leak_type, n_occurrences = self.find_leak_pc(trace, line)
                regenerate_trace = not skip_tracing
                # Generate the debug trace and find the corresponding line
                dbg_trace, dbg_line = self.find_dbg_line(trace, pc, leak_type, n_occurrences, regenerate_trace)
            else:
                dbg_trace = trace
                dbg_line = line
                _, decoded = self._decoder.decode_trace_file(dbg_trace)
                assert len(decoded) == 1
                self.debug_trace = decoded[0]

            # Create the gdb script to reach the target line
            script = self.generate_gdb_script(dbg_trace, dbg_line)
            script_name = f"spec_{idx}.gdb"
            with open(script_name, "w") as f:
                f.write(script)
            # Print the gdb command (user can copy-paste in separate terminal)
            program_cmd = self._get_original_cmd(trace).split(" -- ")[1]
            print(f"\n====== GDB Command:\ngdb -x {script_name} --args {program_cmd}\n======")

            # Append the already parsed trace, used later for use-def analysis
            raw_dbg_trace = self.debug_trace
            dbg_traces.append((raw_dbg_trace, dbg_line))

        if usedef:
            # Create output file
            trace1, line1 = traces[0]
            use_def_file = trace1.replace('.trace', '.usedef').replace('.dbgtrace', '.usedef')
            print(f"\n====== Printing use-def information at {use_def_file}")
            # Setup symbol server
            symbols = SymbolServer("") if binary is None else CombinedSymbolServer(binary) # GdbSymbolServer(binary)
            # Print textual representation of the use-def chain to a file
            tracker = UseDefTracker(use_def_file, self._config, symbols)

            if len(dbg_traces) == 1:
                dbg_traces.append((None, None))

            graph = tracker.analyze(dbg_traces[0][0], dbg_traces[0][1], dbg_traces[1][0], dbg_traces[1][1], violation)
            # Print use-def graph to a dot file
            dot_file = use_def_file + ".dot"
            print(f"\n====== Printing graph at {dot_file}")
            graph.draw(dot_file)
