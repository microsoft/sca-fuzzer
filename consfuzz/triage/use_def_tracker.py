"""
File: Implementation of differential origin tracking for leaked values using use-def chains.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from typing import Any, Dict, List, Optional

from .regs import REGS, strip_alias, init_reg_map
from .rvzr_trace import TraceState, ParsedInst
from .shared_types import *
from .use_def_graph import UseDefGraph, TerminatorNodeType, TerminatorNode, UseDefNode, UseDefEdge
from .symbol_server import SymbolServer
from .config import LeakageInspectorConfig

# --------------------------------------------------------------------------------------------------
# Local Types
# --------------------------------------------------------------------------------------------------

# Values used by an instruction.
UsesDict = Dict[Use, int]
# List of values for the same use across different traces.
MergedUsesDict = Dict[Use, List[Optional[int]]]

def _merge_uses(uses_dicts: List[UsesDict]) -> MergedUsesDict:
    """
    Merge uses from multiple traces.
    This will return a dictionary that has as keys the union of all the keys (sorted by type)
    and as values an array of values where each position corresponds to a separate trace.
    If a use is not present in one of the traces, it's corresponding value in the array is None.
    """
    merged = {}
    total = len(uses_dicts)

    for idx, uses in enumerate(uses_dicts):
        for use, val in uses:
            if use not in merged.keys():
                # If there's no entry, create a list as long as the number of dicts to merge
                merged[use] = [None]*total
            # Add the value at the index corresponding to the current dict being merged
            merged[use][idx] = val

    return merged

def print_use(use: Use) -> str:
    return hex(use.addr) if use.use_type == UseType.MEM else REGS[use.addr]

class DifferentialTraceState:
    """
    Hold the state of multiple traces together (for differential analysis).
    """
    states: list[TraceState]

    def __init__(self, states: list[TraceState]) -> None:
        self.states = states


# --------------------------------------------------------------------------------------------------
# Tracker implementation
# --------------------------------------------------------------------------------------------------

class UseDefTracker:
    """
    Class that implements reverse use-def exploration for multiple
    traces at a time.
    """
    _visited: list[list[int, int]]
    _out_file: str
    _symbol_server: SymbolServer
    _prefix: str
    _graph: UseDefGraph
    _config: LeakageInspectorConfig

    def __init__(self, out_file: str, config: LeakageInspectorConfig, symbol_server: SymbolServer) -> None:
        self._out_file = out_file
        self._symbol_server = symbol_server
        self._visited = []
        self._prefix = ""
        self._out_file = open(out_file, "w")
        self._graph = UseDefGraph()
        self._config = config

        # Initialize the list of registers
        init_reg_map()

    def _set_prefix(self, prefix: str) -> None:
        self._prefix = prefix

    def _print(self, x: Any) -> None:
        """
        Print to the selected out file.
        """
        print(str(self._prefix) + str(x), file=self._out_file)

    def _get_loc(self, instr: ParsedInst) -> str:
        """
        Return a formatted string representing the source location of an instruction.
        """
        loc = self._symbol_server.get_location(instr.get_pc())
        if loc is None:
            return instr.get_loc()
        return loc

    def _get_short_descr(self, instr: ParsedInst, line: int) -> str:
        """
        Return a formatted string representing an instruction in the trace.
        """
        return f"{hex(instr.get_pc())} (line: {line})   {self._get_loc(instr)}"

    def _get_defs(self, use: Use, cur_state: DifferentialTraceState) -> DifferentialTraceState:
        """
        For a given use, find the trace line corresponding to the last definition of that
        register or memory location in all the traces of `cur_state`.
        """
        defs = []

        # Get def of corresponding register/memory location for all traces.
        for s in cur_state.states:
            def_line = s.find_last_def(use, until=s.cur_idx)
            if def_line:
                defs.append(TraceState(s.trace, def_line))
            else:
                defs.append(None)
        # Group into a single DifferentialState.
        return DifferentialTraceState(defs)

    def _step_def_use_chain(self, diff_state: DifferentialTraceState, follow_regs: bool, follow_mem: bool) -> list[DifferentialTraceState]:
        """
        Go "up" one step in the def use chain for multiple traces at the same time. This returns a
        DifferentialTraceState for each register/memory location used by the current state.
        """
        # Parse the current instruction of each of the parallel traces.
        cur_insts = [s.parse_current() for s in diff_state.states]
        cur_line = diff_state.states[0].cur_idx
        # Print current instruction
        self._print(self._get_short_descr(cur_insts[0], cur_line))

        # Check if the current instruction is a sink.
        loc = self._get_loc(cur_insts[0])
        if any(loc.endswith(x) for x in self._config.declassified):
            self._print("    END: Found Declassified")
            self._graph.nodes[cur_line] = TerminatorNode(TerminatorNodeType.DECLASSIFIED, cur_line)
            return []
        if any(loc.endswith(x) for x in self._config.key):
            self._print("    END: Found Declassified")
            self._graph.nodes[cur_line] = TerminatorNode(TerminatorNodeType.KEY, cur_line)
            return []


        # Group together uses of the same register/memory location from different traces.
        uses = [i.get_uses(regs=follow_regs, mem=follow_mem) for i in cur_insts]
        merged = _merge_uses(uses)

        # Apply filters.
        to_follow = []
        trimmed_by_diff = 0
        for use, vals in merged.items():

            if use.use_type == UseType.REG and strip_alias(REGS[use.addr]) in self._config.get().dont_follow:
                # We avoid following some registers that are not logged and are known to
                # cause overtainting (i.e. AVX K registers).
                self._print("    Use of " + print_use(use))
                self._print("        SKIP: No-follow register ")
                idx = self._graph.add_terminator(TerminatorNodeType.NO_FOLLOW)
                self._graph.link(cur_line, idx, use)
                continue

            elif use.use_type == UseType.MEM and self._config.get_sym_annotation(use.addr) is not None:
                name, offset = self._config.get_sym_annotation(use.addr)
                self._print("    Use of " + print_use(use))
                self._print(f"        END: Annotated symbol: {name}+{offset}")
                idx = self._graph.add_terminator(TerminatorNodeType.KNOWN_SYMBOL)
                self._graph.link(cur_line, idx, use)
                continue

            elif all(v is None for v in vals):
                # If the value is unknown for _all_ traces, it means that the tracer
                # doesn't log it logged: don't remove it.
                self._print("    Use of " + print_use(use))
                self._print("        INFO: Untracked value, visiting")
                pass

            elif any(v is None for v in vals):
                # If a value is only used in some of the traces (e.g. a memory location that is
                # only read in one of the two tarces), we can't continue differentially:
                # stop backwards tracking for this use.
                self._print("    Use of " + print_use(use))
                self._print("        SKIP: Use only appears in some of the traces")
                idx = self._graph.add_terminator(TerminatorNodeType.TRIMMED_BY_DIFF)
                self._graph.link(cur_line, idx, use)
                continue

            elif len(vals) > 1 and all(v == vals[0] for v in vals):
                # If all the traces agree on a value, we can skip tracking for this use.
                self._print("    Use of " + print_use(use))
                self._print("        SKIP: Trimmed by differential tracking")
                idx = self._graph.add_terminator(TerminatorNodeType.TRIMMED_BY_DIFF)
                trimmed_by_diff += 1
                self._graph.link(cur_line, idx, use)
                continue

            to_follow.append(use)

        if trimmed_by_diff == len(merged.items()):
            self._graph.trim(cur_line)

        # Gef the def of each use
        next_states = []
        for use in to_follow:
            defs = self._get_defs(use, diff_state)

            # If there's no previous definition, we reached the top.
            if any(d is None for d in defs.states):
                self._print("    Use of " + print_use(use))
                self._print("        END: First use")
                idx = self._graph.add_terminator(TerminatorNodeType.FIRST_USE)
                self._graph.link(cur_line, idx, use)
                break

            defs.states[0].parse_current()
            node2 = self._graph.get_or_create(defs.states[0].cur_idx)
            if not node2.trimmed:
                next_states.append(defs)
                self._graph.link(cur_line, node2.line, use)

        return next_states

    def follow_def_use_chain_recursive(self, diff_states: list[DifferentialTraceState], follow_regs: bool, follow_mem: bool) -> None:
        """
        Recursively explore the def-use chain starting from a set of states.
        Only for the first step, we might want to follow only memory uses (for D-type violations)
        or only register uses (for I-type violations).
        """
        idx = 0
        prefix = self._prefix
        for diff_state in diff_states:
            cur_lines = [s.cur_idx for s in diff_state.states]
            # Cache results to avoid recomputing stuff.
            if cur_lines in self._visited:
                self._print("    └─ Skipping (already visited)")
                continue
            if all(x != None for x in cur_lines):
                self._visited.append(cur_lines)

            # Check if it's the last state.
            if idx == len(diff_states) - 1:
                cur_prefix = prefix + "    └─"
            else:
                cur_prefix = prefix + "    ├─"

            # Perform one reverse step in the def-use chain.
            self._set_prefix(cur_prefix)
            next_list = self._step_def_use_chain(diff_state, follow_regs, follow_mem)
            if idx == len(diff_states) - 1:
                next_prefix = prefix + "     "
            else:
                next_prefix = prefix + "    │"

            # Follow all the uses recursively.
            self._set_prefix(next_prefix)
            self.follow_def_use_chain_recursive(next_list, follow_regs=True, follow_mem=True)
            idx += 1

    def analyze(self, raw_trace1: list[Any], line1: TraceLineNum,
                raw_trace2: Optional[list[Any]], line2: Optional[TraceLineNum],
                violation: str) -> UseDefGraph:
        # Initialize trace(s)
        trace1 = TraceState(raw_trace1, line1)
        trace2 = None
        if raw_trace2 is not None:
            trace2 = TraceState(raw_trace2, line2)

        if violation == "D":
            # MEM violation: get all MEM uses
            init_state = DifferentialTraceState([trace1])
            if trace2 is not None:
                init_state.states.append(trace2)
            self.follow_def_use_chain_recursive(diff_states=[init_state], follow_mem=True, follow_regs=False)

        elif violation == "I":
            # PC violation: 1. go to previous instruction
            # NOTE: if a trace has two different PCs it means that the control-flow
            # instruction immediately preceding them had a different outcome.
            trace1.prev_entry()
            init_state = DifferentialTraceState([trace1])
            if trace2 is not None:
                trace2.prev_entry()
                init_state.states.append(trace2)
            # 2. follow all reg uses of the previous instruction
            self.follow_def_use_chain_recursive(diff_states=[init_state], follow_mem=False, follow_regs=True)

        elif violation == "C":
            # INDCALL violation: get all REG uses
            init_state = DifferentialTraceState([trace1])
            if trace2 is not None:
                init_state.states.append(trace2)
            self.follow_def_use_chain_recursive(diff_states=[init_state], follow_mem=False, follow_regs=True)

        else:
            self._out_file.close()
            assert False, "Unknown violation type"

        self._out_file.close()
        return self._graph
