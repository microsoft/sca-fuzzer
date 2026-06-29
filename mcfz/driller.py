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

from dataclasses import dataclass
from typing import Any, Dict, Final, List, Tuple, Optional
from subprocess import run, PIPE

from rvzr.model_dynamorio.trace_decoder import TraceDecoder

from .leak_detector import PC, FileName
from .reporter import CodeLine
from .config import Config
from .util.compressor import Compressor
from .leak_detector import _Trace


class _GdbScriptBuilder:
    """ Encapsulates GDB command syntax and script generation for leak debugging """

    def __init__(self, ignored_funcs: Optional[List[str]] = None) -> None:
        self._commands: List[str] = []
        self._n_break: int = 0

        if ignored_funcs:
            self._declare_skip_hook()
            for func in ignored_funcs:
                self._add_skip_hook(func)

    def _declare_skip_hook(self) -> None:
        """
        Define a GDB function to skip the rest of the current function.
        This makes sure that we don't count hits to breakpoints that happen during ignored
        functions, otherwise me might be inspecting the wrong execution state.
        Note that we cannot simply use "skip" since it will continue counting hits to the
        breakpoint.
        """
        disable_output = [
            "    set logging file /dev/null", "    set logging redirect on",
            "    set logging enabled on"
        ]
        enable_output = ["     set logging enabled off", "     set logging redirect off"]

        # Define `skip_current_func` to simply reach the end of the current function
        self._commands.extend([
            "define skip_current_func",
            *disable_output,
            "    finish",
            *enable_output,
            "end",
        ])
        # Hook `skip_current_func` such that all breakpoints are disabled when executed
        self._commands.extend([
            "define hook-skip_current_func",
            "    disable",  # Disable all breakpoints
            "end",
            "",
            "define hookpost-skip_current_func",
            "    enable",  # Re-enable breakpoints
            "    continue",
            "end",
        ])
        # Declare a command to skip the given function
        self._commands.extend([
            "define skip_function",
            *disable_output,
            "    break $arg0",  # Set a breakpoint at the start of the function to skip
            "    commands",
            "        silent",
            "        skip_current_func",  # Skip the function when breakpoint is hit
            "    end",
            *enable_output,
            "end",
            ""
        ])

    def _add_skip_hook(self, func_name: str) -> None:
        """ Add a command to skip the given function by name """
        if func_name.strip():
            self._commands.append(f"skip_function {func_name.strip()}")
            self._n_break += 1

    def breakpoint(self, pc: int, temporary: bool = False) -> int:
        """ Add a breakpoint at the given PC address and return the breakpoint number """
        if temporary:
            self._commands.append(f"tbreak *{pc:#x}")
        else:
            self._commands.append(f"break *{pc:#x}")
        self._n_break += 1
        return self._n_break

    def run(self) -> None:
        """ Add a command to start program execution """
        self._commands.append("run")

    def jump(self, pc: int) -> None:
        """ Add a command to jump to the given PC address """
        self._commands.append(f"jump *{pc:#x}")

    def continue_(self) -> None:
        """ Add a command to continue program execution """
        self._commands.append("continue")

    def delete(self, bp_num: int) -> None:
        """ Add a command to delete the given breakpoint """
        self._commands.append(f"del {bp_num}")

    def ignore(self, bp_num: int, count: int) -> None:
        """ Add a command to ignore the next `count` hits of the given breakpoint """
        self._commands.append(f"ignore {bp_num} {count}")

    def shell_prompt(self, message: str) -> None:
        """ Add a shell command that prints a message and waits for user input """
        self._commands.append(
            f'shell printf "[MCFZ] {message}. Press [Enter] to continue..." && read _')

    def shell_message(self, message: str) -> None:
        """ Add a shell command that prints a message without waiting """
        self._commands.append(f'shell printf "[MCFZ] {message}\\n"')

    def write(self, path: str) -> None:
        """ Write the accumulated GDB commands to a script file """
        with open(path, 'w') as f:
            f.write("\n".join(self._commands))

    @classmethod
    def create_leak_script(cls,
                           leak_info: _LeakInfo,
                           path: str,
                           args_cmd: str,
                           fast: bool = False,
                           single_step: bool = False,
                           ignored_funcs: Optional[List[str]] = None) -> str:
        """
        Create a gdb script that reaches the violation described in leak_info,
        save it to the given path, and return the full gdb command to run it.

        :param leak_info: Information about the leak to investigate
        :param path: Path to save the gdb script
        :param args_cmd: The command (with arguments) to pass to gdb's ``--args``
        :param fast: If True, skip intermediate gdb prompts (architectural and spec window starts)
        :param single_step: If True, drop to interactive gdb at the first speculative instruction,
            with breakpoints set at all remaining points of interest
        :param ignored_funcs: List of function names to ignore (skip) during debugging
        :return: The full gdb command string (e.g., ``gdb -x script.gdb --args cmd``)
        """
        builder = cls(ignored_funcs)

        for lvl, win in enumerate(leak_info.spec_windows):
            is_first = lvl == 0
            is_last = lvl == len(leak_info.spec_windows) - 1

            # Reach start of this window
            b_num = builder.breakpoint(win.start_pc_gdb, temporary=True)
            if is_first:
                builder.run()
            else:
                builder.jump(win.start_pc_gdb)
                if single_step:
                    # Set breakpoints at all remaining POIs and drop to interactive mode
                    for remaining_win in leak_info.spec_windows[lvl:]:
                        builder.breakpoint(remaining_win.pc_gdb)
                    builder.shell_prompt(
                        f'Entered single-step mode at first speculative instruction '
                        f'(pc: {win.start_pc_gdb:#x}). '
                        f'Breakpoints set at all remaining POIs. '
                        f'Use ni/si to single-step or continue to reach next POI')
                    break

            if not fast:
                builder.shell_prompt(
                    "Reached first architectural instruction" if is_first else
                    f'Reached start of spec window (level: {lvl}, pc: {win.start_pc_gdb:#x})')

            # Reach target instruction
            b_num = builder.breakpoint(win.pc_gdb)
            if win.pc_occurrence > 0:
                builder.ignore(b_num, win.pc_occurrence)
            builder.continue_()

            msg_template = 'Reached {label} (level: {lvl}, pc: {win:#x})'
            if is_last:
                label = "leak instruction"
                builder.shell_message(msg_template.format(label=label, lvl=lvl, win=win.pc_gdb))
                continue

            label = "mispredicted instruction"
            builder.shell_prompt(msg_template.format(label=label, lvl=lvl, win=win.pc_gdb))
            builder.delete(b_num)

        builder.write(path)
        return f'gdb -x {path} --args {args_cmd}'


class _DebugScriptBuilder:
    """ Creates the debug bash script that launches tmux with side-by-side gdb sessions """

    _SCRIPT_TEMPLATE: Final[str] = """\
#!/bin/bash
# Debug script for violation at PC {pc_hex}
# Opens two gdb sessions side-by-side using tmux:
#   Left pane (0):  Reference input (000.bin)
#   Right pane (1): Target input ({input_basename})

# Kill any existing session with the same name
tmux kill-session -t mysession 2>/dev/null

# Create new tmux session with two panes and labeled borders
tmux new-session -s mysession \\; \\
    set-option -g pane-border-status top \\; \\
    set-option -g pane-border-format " #{{pane_title}} " \\; \\
    set-option -g mouse on \\; \\
    bind-key -n M-Left select-pane -L \\; \\
    bind-key -n M-Right select-pane -R \\; \\
    split-window -h \\; \\
    select-pane -t 0 -T "000.bin" \\; \\
    select-pane -t 1 -T "{input_basename}" \\; \\
    send-keys -t 0 '{ref_gdb_cmd}' C-m \\; \\
    send-keys -t 1 '{target_gdb_cmd}' C-m
"""

    @classmethod
    def build(cls,
              leak_info: _LeakInfo,
              output_dir: str,
              fast: bool = False,
              single_step: bool = False,
              ignored_funcs: Optional[List[str]] = None) -> str:
        """
        Create gdb scripts and a tmux debug launcher for investigating a leak.

        Creates two gdb scripts (for reference and target inputs) and a bash script
        that launches them side-by-side in tmux.

        :param leak_info: Information about the leak to investigate
        :param output_dir: Directory to write debug scripts into
        :param fast: If True, skip intermediate gdb prompts
        :param single_step: If True, drop to interactive gdb at first speculative instruction
        :param ignored_funcs: List of function names to ignore (skip) during debugging
        :return: Path to the generated debug.sh script
        """

        def make_gdb_cmd(input_path: str, script_name: str) -> str:
            cmd = [leak_info.bin_path] + \
                [arg.replace('@@', input_path) for arg in leak_info.org_template_cmd[1:]]
            return _GdbScriptBuilder.create_leak_script(
                leak_info,
                os.path.join(output_dir, script_name),
                " ".join(cmd),
                fast=fast,
                single_step=single_step,
                ignored_funcs=ignored_funcs)

        ref_gdb_cmd = make_gdb_cmd(os.path.join(output_dir, "000.bin"), "debug_ref.gdb")
        target_gdb_cmd = make_gdb_cmd(str(leak_info.input_path), "debug_target.gdb")

        # Write the tmux debug script
        script_path = os.path.join(output_dir, "debug.sh")
        script_content = cls._SCRIPT_TEMPLATE.format(
            pc_hex=f"{leak_info.org_pc:#x}",
            input_basename=os.path.basename(leak_info.input_path),
            ref_gdb_cmd=ref_gdb_cmd,
            target_gdb_cmd=target_gdb_cmd,
        )
        with open(script_path, 'w') as f:
            f.write(script_content)
        os.chmod(script_path, 0o755)

        return script_path


@dataclass
class _SpecWinInfo:
    """ Information about a speculation window related to a leak """
    start_pc: PC = PC(0)
    start_trace_line_id: int = 0
    start_pc_gdb: int = 0

    pc: PC = PC(0)
    trace_line_id: int = 0
    pc_gdb: int = 0
    pc_occurrence: int = 0


class _LeakInfo:

    def __init__(self, clause_type: str, leak_type: str, code_line: str, pc_hex: str,
                 trace_path: str, trace_line_id: int) -> None:
        # original info from the report
        self.clause_type = clause_type
        self.leak_type = leak_type
        self.code_line = CodeLine(code_line)
        self.org_pc = PC(int(pc_hex, 16))

        self.org_trace_path = FileName(trace_path)
        self.org_trace_line_id = int(trace_line_id)

        # spec windows info
        self.spec_windows: List[_SpecWinInfo] = []

        # set later
        self.bin_path = FileName("")
        self.input_path: FileName = FileName('')
        self.trace_path: FileName = FileName('')
        self.org_template_cmd: List[str] = []
        self.gdb_cmd: str = ""

    @property
    def org_input_path(self) -> FileName:
        """ Compute the input file path from the trace path """
        trace_dir = os.path.dirname(self.org_trace_path)
        trace_file: str = os.path.basename(self.org_trace_path)

        input_dir = trace_dir.replace('stage3', 'stage2')
        input_file = trace_file.removesuffix('.bz2').removesuffix('.gz')
        input_file = input_file.replace('.trace', '.bin')
        return FileName(os.path.join(input_dir, input_file))

    def build_gdb_cmd(self,
                      fast: bool = False,
                      single_step: bool = False,
                      ignored_funcs: Optional[List[str]] = None) -> None:
        """
        Generate a debug shell script that opens two gdb sessions in tmux.

        :param fast: If True, skip intermediate gdb prompts
        :param single_step: If True, drop to interactive gdb at first speculative instruction
        :param ignored_funcs: List of function names to ignore (skip) during debugging
        """
        assert self.org_template_cmd, "Original template command not set."
        output_dir = os.path.dirname(self.input_path)
        self.gdb_cmd = _DebugScriptBuilder.build(
            self, output_dir, fast=fast, single_step=single_step, ignored_funcs=ignored_funcs)

    def __str__(self) -> str:
        sep = "=" * 80

        lines = [
            sep,
            f"Violation Details for PC {self.org_pc:x}",
            "",
            f"Source Code Location:  {self.code_line}",
            f"Violation Type:        {self.clause_type} ({self.leak_type}-type)",
            f"Orig. Input File:      {self.org_input_path}",
            f"Orig. Trace File:      {self.org_trace_path}",
            f"  Target Trace Line:   {self.org_trace_line_id}",
            sep,
        ]

        last_lvl = len(self.spec_windows) - 1
        for lvl, win in enumerate(self.spec_windows):
            prefix = "    " * lvl
            if lvl == 0:
                lines.append(f"Architectural execution starts at pc {win.start_pc:#x}:")
            else:
                lines.append(f"{prefix}├── Start of spec window at PC {win.start_pc:#x}:")

            if lvl == last_lvl:
                lines.append(f"{prefix}└── LEAK! At line {win.trace_line_id} (PC: {win.pc:#x})")
            else:
                lines.append(f"{prefix}└── MISPREDICTION at line {win.trace_line_id} "
                             f"(PC: {win.pc:#x})")

        lines += [
            sep,
            "",
            "To reproduce with gdb (opens two sessions in tmux):",
            f"  {self.gdb_cmd}",
        ]

        return "\n".join(lines) + "\n"


class Driller:
    """ Investigates specific findings from fuzzing by drilling down into violations """

    def __init__(self,
                 config: Config,
                 output_dir: str,
                 fast: bool = False,
                 single_step: bool = False) -> None:
        self._config = config
        self._output_dir = output_dir
        self._fast = fast
        self._single_step = single_step
        assert config.bin_native is not None  # enforced by config validation
        self._target_bin = config.bin_native
        self._template_cmd = [config.bin_native if s == "@#" else s for s in config.template_cmd]

    def drill_down(self, pc: int) -> None:
        """
        Drill down into a specific violation detected by the fuzzer,
        identified by its program counter (PC).
        :param pc: The program counter to investigate
        """
        self._check_required_files()

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

        # Gather the list of ignored functions
        ignored_funcs = None
        if self._config.tracing_ignorelist and os.path.exists(self._config.tracing_ignorelist):
            with open(self._config.tracing_ignorelist, 'r') as f:
                ignored_funcs = [line.strip() for line in f if line.strip()]

        # Build the GDB command
        leak_info.build_gdb_cmd(
            fast=self._fast, single_step=self._single_step, ignored_funcs=ignored_funcs)

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
        # Search the flat list of leak records for one whose witnesses include this PC
        for leak in report_data.get("leaks", []):
            witnesses = leak.get("witnesses", {})
            if pc_hex not in witnesses:
                continue
            first = witnesses[pc_hex][0]
            code_line = f"{leak['file']}:{leak['line']}"
            return _LeakInfo(leak["clause"], leak["type"], code_line, pc_hex, first["trace"],
                             first["line"])
        raise ValueError(f"PC {pc_hex} not found in the report.")

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
        gdb_base = self._get_gdb_base(os.path.basename(module_path))
        return gdb_base + (pc - trace_base)

    def _get_trace_base(self, pc: int) -> Tuple[int, str]:
        """ Find the trace base address and module path from mappings.txt """
        mappings_file = os.path.join(self._config.stage3_wd, "mappings.txt")

        modules = []
        with open(mappings_file, "r") as f:
            for line in f:
                parts = line.strip().rsplit(' ', 1)
                if len(parts) == 2:
                    modules.append((parts[0], int(parts[1], 16)))

        # Sort by start address descending and find module containing the PC
        modules.sort(key=lambda m: m[1], reverse=True)
        for module_name, start_addr in modules:
            if pc >= start_addr:
                return start_addr, module_name

        raise RuntimeError(f"Module for PC {pc:#x} not found in mappings.txt")

    def _create_valid_driver_invocation(self) -> List[str]:
        """
        Create a valid driver invocation command by replacing the input placeholder with a real seed
        """
        first_seed = next(os.scandir(self._config.afl_seed_dir)).name
        seed_path = os.path.join(self._config.afl_seed_dir, first_seed)
        return [seed_path if s == "@@" else s for s in self._template_cmd]

    def _get_gdb_base(self, module_basename: str) -> int:
        """ Run a dummy gdb session and find the module's base address under gdb """

        dummy_cmd = self._create_valid_driver_invocation()
        gdb_cmd = [
            'gdb',
            '--batch',
            '-ex',
            f'b {self._config.tracing_entrypoint}',  # break on the entrypoint
            '-ex',
            'run',  # run the program to load all modules
            '-ex',
            'info proc mappings',
            '--args',
        ] + dummy_cmd

        result = run(gdb_cmd, stdout=PIPE, stderr=PIPE, text=True, check=False)

        for line in result.stdout.split('\n'):
            if module_basename in line:
                return int(line.split()[0], 16)

        raise RuntimeError(f"Module {module_basename} not found in gdb mappings output")

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

        ref_input = os.path.join(os.path.dirname(leak_info.org_input_path), "000.bin")
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
