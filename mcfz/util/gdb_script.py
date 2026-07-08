"""
File: GDB script generation for leak debugging; builds the gdb command scripts and the tmux
      launcher used by the driller to open side-by-side debug sessions for a violation.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import os

from typing import Final, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..driller import _LeakInfo


class GdbScriptBuilder:
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
        self._commands.append(
            f"# Skip {count} earlier hit(s) of breakpoint {bp_num} so execution stops at the")
        self._commands.append("# occurrence of this PC that actually triggers the leak")
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


class DebugScriptBuilder:
    """ Creates the debug bash script that launches tmux with side-by-side gdb sessions """

    _SCRIPT_TEMPLATE: Final[str] = """\
#!/bin/bash
# Debug script for violation at PC {pc_hex}
# Opens two gdb sessions side-by-side using tmux:
#   Left pane (0):  Reference input (000.bin)
#   Right pane (1): Target input ({input_basename})

# Kill any existing session with the same name
tmux kill-session -t {session_name} 2>/dev/null

# Create new tmux session with two panes and labeled borders
tmux new-session -s {session_name} \\; \\
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
            cmd = leak_info.driver_cmd(input_path)
            return GdbScriptBuilder.create_leak_script(
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
            session_name=f"mcfz_{leak_info.org_pc:x}",
            input_basename=os.path.basename(leak_info.input_path),
            ref_gdb_cmd=ref_gdb_cmd,
            target_gdb_cmd=target_gdb_cmd,
        )
        with open(script_path, 'w') as f:
            f.write(script_content)
        os.chmod(script_path, 0o755)

        return script_path
