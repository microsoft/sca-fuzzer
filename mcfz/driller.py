"""
File: Module responsible for helping to "drill down" into specific findings from fuzzing;
      It allows users to deeply investigate specific program points of interest.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import List, Dict, Tuple

import os
import json
import shutil

from .reporter import PC, FileName, CodeLine
from .config import Config
from .util.compressor import Compressor
from rvzr.model_dynamorio.trace_decoder import TraceDecoder
from subprocess import run, PIPE


class _LeakInfo:

    def __init__(self, leak_type: str, code_line: str, pc_hex: str, location_in_trace: str) -> None:
        self.leak_type = leak_type
        self.code_line = CodeLine(code_line)
        self.pc = PC(int(pc_hex, 16))
        trace_file, loc_id, _ = self._parse_location_in_trace(location_in_trace)
        self.org_trace_path = trace_file
        self.trace_line_id = loc_id
        self.org_input_path: FileName = self._get_input_path()

        # set later
        self._bin = FileName("")
        self.input_path: FileName = FileName('')
        self.trace_path: FileName = FileName('')
        self.org_template_cmd: List[str] = []
        self.gdb_cmd: str = ""
        self.pc_occurrence: int = 0
        self.pc_gdb: int = 0  # Translated PC address for gdb

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

    def _set_gdb_cmd(self) -> None:
        assert self.org_template_cmd, "Original template command not set."

        # Build command for target input
        modified_cmd = [self._bin] + [
            arg.replace('@@', str(self.input_path)) for arg in self.org_template_cmd[1:]
        ]
        modified_cmd_str = " ".join(modified_cmd)

        # Build gdb command for target input (pane 1)
        gdb_parts = ['gdb']
        gdb_parts.append(f'-ex "break *{self.pc_gdb:#x}"')

        # Add ignore count if PC occurs multiple times
        if self.pc_occurrence > 1:
            ignore_count = self.pc_occurrence - 1
            gdb_parts.append(f'-ex "ignore 1 {ignore_count}"')

        gdb_parts.append('-ex "run"')
        gdb_parts.append('--args ' + modified_cmd_str)
        target_gdb_cmd = " ".join(gdb_parts)

        # Build command for reference input (000.bin)
        ref_input_path = os.path.join(os.path.dirname(self.input_path), "000.bin")
        ref_cmd = [self._bin] + \
                  [arg.replace('@@', ref_input_path) for arg in self.org_template_cmd[1:]]
        ref_cmd_str = " ".join(ref_cmd)

        # Build gdb command for reference input (pane 0)
        ref_gdb_parts = ['gdb']
        ref_gdb_parts.append(f'-ex "break *{self.pc_gdb:#x}"')

        # Add ignore count if PC occurs multiple times
        if self.pc_occurrence > 1:
            ignore_count = self.pc_occurrence - 1
            ref_gdb_parts.append(f'-ex "ignore 1 {ignore_count}"')

        ref_gdb_parts.append('-ex "run"')
        ref_gdb_parts.append('--args ' + ref_cmd_str)
        ref_gdb_cmd = " ".join(ref_gdb_parts)

        # Create a bash script with the tmux command
        output_dir = os.path.dirname(self.input_path)
        script_path = os.path.join(output_dir, "debug.sh")

        script_content = f"""#!/bin/bash
# Debug script for violation at PC {self.pc:#x}
# Opens two gdb sessions side-by-side using tmux:
#   Left pane (0):  Reference input (000.bin)
#   Right pane (1): Target input ({os.path.basename(self.input_path)})

# Kill any existing session with the same name
tmux kill-session -t mysession 2>/dev/null

# Create new tmux session with two panes and labeled borders
tmux new-session -s mysession \\; \\
    set-option -g pane-border-status top \\; \\
    set-option -g pane-border-format " #{{pane_title}} " \\; \\
    split-window -h \\; \\
    select-pane -t 0 -T "000.bin" \\; \\
    select-pane -t 1 -T "{os.path.basename(self.input_path)}" \\; \\
    send-keys -t 0 '{ref_gdb_cmd}' C-m \\; \\
    send-keys -t 1 '{target_gdb_cmd}' C-m
"""

        with open(script_path, 'w') as f:
            f.write(script_content)

        # Make script executable
        os.chmod(script_path, 0o755)

        self.gdb_cmd = script_path

    def __str__(self) -> str:
        # Determine violation type description
        violation_type = f"SEQ, {self.leak_type}"
        violation_desc = "I-type" if self.leak_type == 'I' \
            else "D-type"

        # Print the details
        s = ""
        s += "=" * 80 + "\n"
        s += f"Violation Details for PC {self.pc:x}\n"
        s += "\n"
        s += f"Source Code Location:  {self.code_line}\n"
        s += f"Violation Type:        {violation_type} ({violation_desc})\n"
        s += f"Orig. Input File:      {self.org_input_path}\n"
        s += f"Orig. Trace File:      {self.org_trace_path}\n"
        s += f"  Target Trace Line:   {self.trace_line_id}\n"
        s += "=" * 80 + "\n"

        # gdb command to reproduce the bug
        s += "\n"
        s += "To reproduce with gdb (opens two sessions in tmux):\n"
        s += f"  {self.gdb_cmd}\n"

        return s


class Driller:

    def __init__(self, config: Config, output_dir: str) -> None:
        self._config = config
        self._output_dir = output_dir
        assert config.bin_native is not None  # enforced by config validation
        self._target_bin = config.bin_native
        self._template_cmd = [config.bin_native if s == "@#" else s for s in config.template_cmd]

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
        leak_info.pc_occurrence = self._find_pc_occurrence(leak_info)
        leak_info.pc_gdb = self._translate_pc_to_gdb(leak_info.pc)
        leak_info._set_gdb_cmd()

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

    def _find_pc_in_report(self, report_data: Dict, pc_hex: str) -> _LeakInfo:
        assert "seq" in report_data, "No 'seq' section in the report data."
        seq_data = report_data['seq']

        # Search in both I (instruction) and D (data) leak types
        for leak_type in ['I', 'D']:
            if leak_type not in seq_data:
                continue
            per_type_map = seq_data[leak_type]
            for code_line, pc_map in per_type_map.items():
                if pc_hex in pc_map:
                    leak_info = _LeakInfo(leak_type, code_line, pc_hex, pc_map[pc_hex][0])
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
        # Step 1: Find trace base address from mappings.txt
        mappings_file = os.path.join(self._config.stage3_wd, "mappings.txt")
        trace_base = None
        module_path = None

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

            # Sort by start address descending
            modules.sort(key=lambda m: m[1], reverse=True)

            # Find module containing the PC
            for module_name, start_addr in modules:
                if pc >= start_addr:
                    trace_base = start_addr
                    module_path = module_name
                    break

        assert module_path is not None, f"Module path for PC {pc:#x} not found in mappings.txt"
        assert trace_base is not None, f"Module for PC {pc:#x} not found in mappings.txt"

        # Step 2: Run dummy gdb session to get memory mappings under gdb
        gdb_cmd = [
            'gdb',
            '--batch',
            '-ex',
            'starti',
            '-ex',
            'info proc mappings',
            '--args',
        ] + self._template_cmd

        result = run(gdb_cmd, stdout=PIPE, stderr=PIPE, text=True)

        # Step 3: Parse gdb mappings to find gdb base address
        gdb_base = None
        module_basename = os.path.basename(module_path)

        for line in result.stdout.split('\n'):
            # Look for first occurrence of the module (should be the base address)
            if module_basename in line:
                parts = line.split()
                if len(parts) >= 1 and parts[0].startswith('0x'):
                    gdb_base = int(parts[0], 16)
                    break

        assert gdb_base is not None, \
            f"Module {module_basename} not found in gdb mappings output"

        # Step 4: Translate the PC
        offset = pc - trace_base
        gdb_pc = gdb_base + offset

        return gdb_pc

    def _find_pc_occurrence(self, leak_info: _LeakInfo) -> int:
        """
        Find which occurrence of the PC in the trace corresponds to the given trace line ID.

        This is useful because the same PC can be hit multiple times (e.g., in a loop),
        and we need to know which specific hit corresponds to the violation.

        :param leak_info: Information about the leak
        :return: The occurrence number (1-indexed) of the PC in the trace
        """
        from .reporter import _Trace

        # Parse the trace file
        trace_decoder = TraceDecoder()
        raw_trace = trace_decoder.decode_trace_file(str(leak_info.trace_path))
        trace = _Trace(str(leak_info.trace_path), raw_trace)

        # Find all instructions with the matching PC
        matching_mask = trace.instructions['pc'] == leak_info.pc
        matching_pcs = trace.instructions[matching_mask]

        # Find which occurrence has the matching trace_line_id
        for occurrence, instr in enumerate(matching_pcs, start=1):
            if instr['org_trace_entry_id'] == leak_info.trace_line_id:
                return occurrence

        assert False, "PC occurrence not found in the trace."

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
        leak_info._bin = bin_dest
        leak_info.org_template_cmd = self._template_cmd
