"""
File: Module responsible for helping to "drill down" into specific findings from fuzzing;
      It allows users to deeply investigate specific program points of interest.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import os
import json
import shutil

from typing import Any, List, Dict, Tuple
from subprocess import run, PIPE

from rvzr.model_dynamorio.trace_decoder import TraceDecoder

from .leak_detector import PC, FileName
from .reporter import CodeLine
from .config import Config
from .util.compressor import Compressor
from .leak_detector import _Trace


class _DebugCmdBuilder:
    """
    Helper class used to construct the commands used to inspect the violation (tmux + gdb).
    """

    def __init__(self) -> None:
        pass

    @staticmethod
    def _create_gdb_script(leak_info: _LeakInfo, path: str) -> None:
        """
        Create a gdb script that reaches the violation described in leak_info
        and save it to the given path.
        """
        lvl = 0
        n_break = 0
        cmd = []

        def _add_break(pc: int) -> int:
            nonlocal n_break
            cmd.append(f"break *{pc:#x}")
            n_break += 1
            return n_break

        def _prompt(message: str) -> None:
            # cmd.append("frame")
            cmd.append(f'shell read -p "[MCFZ] {message}. Press [Enter] to continue..."')

        for win in leak_info.spec_windows:
            # Reach start
            b_num = _add_break(win.start_pc_gdb)
            if lvl == 0:
                # First arch instruction, we need to start gdb to reach it
                cmd.append("run")
                _prompt("Reached first architectural instruction")
            else:
                # Spec window start, we manually jump to simulate misprediction
                cmd.append(f"jump *{win.start_pc_gdb:#x}")
                _prompt(f'Reached start of spec window (level: {lvl}, pc: {win.start_pc_gdb:#x})')
            cmd.append(f"del {b_num}")
            # Reach target
            b_num = _add_break(win.pc_gdb)
            if win.pc_occurrence > 0:
                cmd.append(f"ignore {b_num} {win.pc_occurrence}")
            cmd.append("continue")

            if lvl == len(leak_info.spec_windows) - 1:
                _prompt(f'Reached leak instruction (level: {lvl}, pc: {win.pc_gdb:#x})')
            else:
                _prompt(f'Reached end of spec window (level: {lvl}, pc: {win.pc_gdb:#x})')
                cmd.append(f"del {b_num}")

            lvl += 1

        with open(path, 'w') as f:
            f.write("\n".join(cmd))

    @classmethod
    def build_gdb_command(cls, leak_info: _LeakInfo, script_path: str, ref_cmd: str) -> str:
        """
        Create the gdb script that reaches the violation and return the command to run it with gdb.
        """
        cls._create_gdb_script(leak_info, script_path)
        return f'gdb -x {script_path} --args {ref_cmd}'

    @staticmethod
    def build_tmux_command(script_path: str, ref_gdb_cmd: str, target_gdb_cmd: str, input_path: str,
                           pc: int) -> None:
        """
        Create a bash script with the tmux command. This command opens two gdb sessions
        side-by-side in tmux, one for the reference input and one for the target input.
        """

        script_content = f"""#!/bin/bash
# Debug script for violation at PC {pc:#x}
# Opens two gdb sessions side-by-side using tmux:
#   Left pane (0):  Reference input (000.bin)
#   Right pane (1): Target input ({os.path.basename(input_path)})

# Kill any existing session with the same name
tmux kill-session -t mysession 2>/dev/null

# Create new tmux session with two panes and labeled borders
tmux new-session -s mysession \\; \\
    set-option -g pane-border-status top \\; \\
    set-option -g pane-border-format " #{{pane_title}} " \\; \\
    split-window -h \\; \\
    select-pane -t 0 -T "000.bin" \\; \\
    select-pane -t 1 -T "{os.path.basename(input_path)}" \\; \\
    send-keys -t 0 '{ref_gdb_cmd}' C-m \\; \\
    send-keys -t 1 '{target_gdb_cmd}' C-m
"""

        with open(script_path, 'w') as f:
            f.write(script_content)
        # Make script executable
        os.chmod(script_path, 0o755)


class _SpecWinInfo:

    def __init__(self) -> None:
        self.start_pc: PC
        self.start_trace_line_id: int
        self.start_pc_gdb: int

        self.pc: PC
        self.trace_line_id: int
        self.pc_gdb: int
        self.pc_occurrence: int


class _LeakInfo:

    def __init__(self, clause_type: str, leak_type: str, code_line: str, pc_hex: str,
                 location_in_trace: str) -> None:
        # original info from the report
        self.clause_type = clause_type
        self.leak_type = leak_type
        self.code_line = CodeLine(code_line)
        self.org_pc = PC(int(pc_hex, 16))
        trace_file, loc_id, _ = self._parse_location_in_trace(location_in_trace)
        self.org_trace_path = trace_file
        self.org_trace_line_id = loc_id

        # spec windows info
        self.spec_windows: List[_SpecWinInfo] = []

        # set later
        self.bin_path = FileName("")
        self.input_path: FileName = FileName('')
        self.trace_path: FileName = FileName('')
        self.org_template_cmd: List[str] = []
        self.gdb_cmd: str = ""

    def _parse_location_in_trace(self, location_in_trace_str: str) -> Tuple[FileName, int, int]:
        # Input: "trace_file_path:target_line:ref_line"
        # Output: (trace_file_path, target_line, ref_line)
        parts = location_in_trace_str.rsplit(':', 2)
        trace_file_path = parts[0]
        target_line = int(parts[1])
        ref_line = int(parts[2])
        return FileName(trace_file_path), target_line, ref_line

    def _get_input_path(self) -> FileName:
        trace_dir = os.path.dirname(self.org_trace_path)
        trace_file: str = os.path.basename(self.org_trace_path)

        # Compute the input file path
        input_dir = trace_dir.replace('stage3', 'stage2')
        input_file = trace_file if trace_file.endswith('.trace') else trace_file
        if input_file.endswith('.bz2'):
            input_file = input_file[:-4]
        elif input_file.endswith('.gz'):
            input_file = input_file[:-3]
        input_file = input_file.replace('.trace', '.bin')
        input_path = os.path.join(input_dir, input_file)

        return FileName(input_path)

    @property
    def org_input_path(self) -> FileName:
        """Compute the input file path from the trace path."""
        return self._get_input_path()

    def build_gdb_cmd(self) -> None:
        """
        Generate a debug shell script that opens two gdb sessions in tmux.
        """
        assert self.org_template_cmd, "Original template command not set."
        output_dir = os.path.dirname(self.input_path)

        # Build command for reference input (000.bin)
        ref_input_path = os.path.join(output_dir, "000.bin")
        ref_cmd = [self.bin_path] + \
                  [arg.replace('@@', ref_input_path)
                   for arg in self.org_template_cmd[1:]]
        ref_cmd_str = " ".join(ref_cmd)
        # Build gdb command for reference input (pane 0)
        ref_gdb_script_path = os.path.join(output_dir, "debug_ref.gdb")
        ref_gdb_cmd = _DebugCmdBuilder.build_gdb_command(self,
                                                         ref_gdb_script_path,
                                                         ref_cmd_str)

        # Build command for target input
        modified_cmd = [self.bin_path] + \
            [arg.replace('@@', str(self.input_path))
             for arg in self.org_template_cmd[1:]]
        modified_cmd_str = " ".join(modified_cmd)
        # Build gdb command for reference input (pane)
        target_gdb_script_path = os.path.join(output_dir, "debug_target.gdb")
        target_gdb_cmd = _DebugCmdBuilder.build_gdb_command(self,
                                                            target_gdb_script_path,
                                                            modified_cmd_str)

        # Choose name of the script
        tmux_script_path = os.path.join(output_dir, "debug.sh")
        _DebugCmdBuilder.build_tmux_command(tmux_script_path,
                                            ref_gdb_cmd,
                                            target_gdb_cmd,
                                            self.input_path,
                                            self.org_pc)
        self.gdb_cmd = tmux_script_path

    def __str__(self) -> str:
        # Determine violation type description
        violation_type = f"{self.clause_type} ({self.leak_type}-type)"

        # Print the details
        s = ""
        s += "=" * 80 + "\n"
        s += f"Violation Details for PC {self.org_pc:x}\n"
        s += "\n"
        s += f"Source Code Location:  {self.code_line}\n"
        s += f"Violation Type:        {violation_type}\n"
        s += f"Orig. Input File:      {self.org_input_path}\n"
        s += f"Orig. Trace File:      {self.org_trace_path}\n"
        s += f"  Target Trace Line:   {self.org_trace_line_id}\n"
        s += "=" * 80 + "\n"

        lvl = 0
        prefix = ""
        for win in self.spec_windows:
            if lvl == 0:
                s += prefix + \
                    f"Architectural execution starts at pc {win.start_pc:#x}:\n"
            else:
                s += prefix + \
                    f"├── Start of spec window at PC {win.start_pc:#x}:\n"

            if lvl == len(self.spec_windows) - 1:
                s += prefix + \
                    f"└── LEAK! At line {win.trace_line_id} (PC: {win.pc:#x})\n"
            else:
                s += prefix + \
                    f"└── MISPREDICTION at line {win.trace_line_id} (PC: {win.pc:#x})\n"
            prefix += "    "
            lvl += 1

        s += "=" * 80 + "\n"

        # gdb command to reproduce the bug
        s += "\n"
        s += "To reproduce with gdb (opens two sessions in tmux):\n"
        s += f"  {self.gdb_cmd}\n"

        return s


class Driller:
    """Investigates specific findings from fuzzing by drilling down into violations."""

    def _get_gdb_mappings(self, template_cmd: List[str], seed_dir: str, entrypoint: str) \
            -> List[str]:
        """Run a dummy gdb session and find where modules are mapped under gdb."""

        # Create a string representing a valid driver invocation by replacing the input placeholder
        # with the path of a random seed from the corpus. This is needed just to make sure that the
        # command is able to reach at least the driving entrypoint, we don't care about the content.
        seed_path = seed_dir + '/' + next(os.scandir(seed_dir)).name
        dummy_cmd = [seed_path if s == "@@" else s for s in template_cmd]

        gdb_cmd = [
            'gdb',
            '--batch',
            '-ex',
            f'b {entrypoint}',
            '-ex',
            'run',
            '-ex',
            'info proc mappings',
            '--args',
        ] + dummy_cmd
        result = run(gdb_cmd, stdout=PIPE, stderr=PIPE, text=True, check=False)

        mappings = []
        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 1 and parts[0].startswith('0x'):
                mappings.append(line)

        return mappings

    def __init__(self, config: Config, output_dir: str) -> None:
        self._config = config
        self._output_dir = output_dir
        assert config.bin_native is not None  # enforced by config validation
        self._target_bin = config.bin_native
        self._template_cmd = [config.bin_native if s == "@#" else s for s in config.template_cmd]
        self._gdb_mappings = self._get_gdb_mappings(self._template_cmd,
                                                    config.afl_seed_dir,
                                                    config.tracing_entrypoint)

    def drill_down(self, pc_: int) -> None:
        """
        Drill down into a specific violation detected by the fuzzer,
        identified by its program counter (PC).
        :param pc: The program counter to investigate
        """
        self._check_required_files()

        pc = PC(pc_)
        pc_hex = hex(pc)

        # Search for the PC in the report
        with open(os.path.join(self._config.stage4_wd, "report_verbosity_3.json"), 'r') as f:
            report_data = json.load(f)
        leak_info = self._find_pc_in_report(report_data, pc_hex)

        # Populate additional fields in leak_info
        self._copy_files(leak_info)
        leak_info.spec_windows = self._find_spec_windows(leak_info)
        for spec_win in leak_info.spec_windows:
            spec_win.start_pc_gdb = self._translate_pc_to_gdb(spec_win.start_pc)
            spec_win.pc_gdb = self._translate_pc_to_gdb(spec_win.pc)
        leak_info.build_gdb_cmd()

        # Pretty print the details
        print(leak_info)

    def _check_required_files(self) -> None:
        stag3_dir: str = self._config.stage3_wd
        if not os.path.isdir(stag3_dir):
            raise FileNotFoundError(f"Stage 3 working directory not found: {stag3_dir}.")
        if not os.path.exists(os.path.join(stag3_dir, "mappings.txt")):
            raise FileNotFoundError(f"Required file 'mappings.txt' not found in {stag3_dir}.")

        report_file = os.path.join(self._config.stage4_wd, "report_verbosity_3.json")
        if not os.path.exists(report_file):
            raise FileNotFoundError(f"Report file not found: {report_file}.")

    def _find_pc_in_report(self, report_data: Dict[str, Any], pc_hex: str) -> _LeakInfo:
        # Search all clauses (seq and cond)
        for clause in ['seq', 'cond']:
            data = report_data[clause]
            # Search in both I (instruction) and D (data) leak types
            for leak_type in ['I', 'D']:
                if leak_type not in data:
                    continue
                per_type_map = data[leak_type]
                for code_line, pc_map in per_type_map.items():
                    if pc_hex in pc_map:
                        loc = pc_map[pc_hex][0]
                        leak_info = _LeakInfo(clause, leak_type, code_line, pc_hex, loc)
                        return leak_info
        assert False, f"PC {pc_hex} not found in the report."

    def _translate_pc_to_gdb(self, pc: int) -> int:
        """
        Translate a PC address from the trace to the corresponding address under gdb.

        This handles ASLR by:
        1. Finding where the module was loaded during tracing (from mappings.txt)
        2. Running a dummy gdb session to find where the module is loaded under gdb
        3. Computing the offset and translating the address

        Assumes gdb is run with 'set disable-randomization on' for consistent addressing.

        :param pc: Absolute PC address from the trace
        :return: Translated PC address for use in gdb
        """
        trace_base, module_path = self._get_trace_base(pc)
        module_basename = os.path.basename(module_path)
        gdb_base = self._get_gdb_base(module_basename)

        offset = pc - trace_base
        return gdb_base + offset

    def _get_trace_base(self, pc: int) -> Tuple[int, str]:
        """Find the trace base address and module path from mappings.txt."""
        mappings_file = os.path.join(self._config.stage3_wd, "mappings.txt")

        with open(mappings_file, "r") as f:
            modules = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.rsplit(' ', 1)
                if len(parts) != 2:
                    continue
                module_name, addr_str = parts
                start_addr = int(addr_str, 16)
                modules.append((module_name, start_addr))

            # Sort by start address descending and find module containing the PC
            modules.sort(key=lambda m: m[1], reverse=True)
            for module_name, start_addr in modules:
                if pc >= start_addr:
                    return start_addr, module_name

        assert False, f"Module for PC {pc:#x} not found in mappings.txt"

    def _get_gdb_base(self, module_basename: str) -> int:
        """Return the base address of a given module as reported by gdb."""
        for line in self._gdb_mappings:
            if module_basename in line:
                return int(line.split()[0], 16)

        assert False, f"Module {module_basename} not found in gdb mappings output"

    def _find_spec_windows(self, leak_info: _LeakInfo) -> List[_SpecWinInfo]:
        # Parse the trace file
        trace_decoder = TraceDecoder()
        raw_trace = trace_decoder.decode_trace_file(str(leak_info.trace_path))
        trace = _Trace(str(leak_info.trace_path), raw_trace)

        def at_line(line_id: int) -> Any:
            return trace.instructions['org_trace_entry_id'] == line_id

        # Find the spec level of the target line
        cur_target_id = leak_info.org_trace_line_id
        cur_spec_level = trace.instructions[at_line(cur_target_id)]['spec_level']

        # Populate the spec windows info by traversing nested speculation windows backwards
        # until we reach architectural execution
        spec_windows: List[_SpecWinInfo] = []
        while True:
            spec_win_info = _SpecWinInfo()

            # Save target (end) of the current window
            spec_win_info.trace_line_id = cur_target_id
            spec_win_info.pc = trace.instructions[at_line(cur_target_id)]['pc'][0]

            # Find start of the current window
            if cur_spec_level == 0:
                start_id = 0
            else:
                mispred_mask = trace.instructions['spec_level'] == cur_spec_level - 1
                mispred_mask &= (trace.instructions['org_trace_entry_id'] < cur_target_id)
                last_mispred_id = trace.instructions[mispred_mask][-1]['org_trace_entry_id']
                start_id = last_mispred_id + 1
            spec_win_info.start_trace_line_id = start_id
            spec_win_info.start_pc = trace.instructions[at_line(start_id)]['pc'][0]

            # Find occurrences of the target PC in the current window
            cur_win_mask = trace.instructions['org_trace_entry_id'] >= start_id
            cur_win_mask &= (trace.instructions['org_trace_entry_id'] < cur_target_id)
            cur_win_mask &= (trace.instructions['spec_level'] == cur_spec_level)
            is_target_pc = trace.instructions['pc'] == spec_win_info.pc
            spec_win_info.pc_occurrence = len(trace.instructions[cur_win_mask & is_target_pc])

            spec_windows.append(spec_win_info)
            if cur_spec_level == 0:
                break
            # Go down in the speculation hierarchy
            cur_spec_level -= 1
            cur_target_id = start_id - 1

        # Reverse to get the order from outermost (architectural) to innermost speculation window
        spec_windows.reverse()
        return spec_windows

    def _copy_files(self, leak_info: _LeakInfo) -> None:
        # Copy all relevant files into the output directory (clear if exists)
        if os.path.exists(self._output_dir):
            shutil.rmtree(self._output_dir)
        os.makedirs(self._output_dir, exist_ok=True)

        # Inputs
        input_dest = os.path.join(self._output_dir, os.path.basename(leak_info.org_input_path))
        shutil.copy2(leak_info.org_input_path, input_dest)

        ref_input = os.path.dirname(leak_info.org_input_path) + "/000.bin"
        shutil.copy2(ref_input, os.path.join(self._output_dir, "000.bin"))

        # Traces
        trace_dest = os.path.join(self._output_dir, os.path.basename(leak_info.org_trace_path))
        shutil.copy2(leak_info.org_trace_path, trace_dest)

        compressor = Compressor(self._config)
        trace_dest_ = compressor.decompress_universal(trace_dest)

        # Binary
        bin_dest = os.path.join(self._output_dir, os.path.basename(self._target_bin))
        shutil.copy2(self._target_bin, bin_dest)

        # Save the updated paths in the leak_info for further use
        leak_info.input_path = input_dest
        leak_info.trace_path = trace_dest_
        leak_info.bin_path = bin_dest
        leak_info.org_template_cmd = self._template_cmd
