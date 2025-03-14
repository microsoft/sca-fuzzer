""" File: Printing of the minimization progress

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""


class ProgressPrinter():
    """
    A simple class to print progress in the terminal.
    Used to ensure that all minimization classes
    provide a uniform output.
    """
    line_width: int = 64
    curr_width: int = 0
    offset: int = 2
    pass_id: int = 0
    progress_bar_on: bool = False

    def pass_start(self, label: str, offset: int = 2) -> None:
        """ Start a new minimization pass """
        self.pass_id += 1
        self.offset = offset
        self.curr_width = 0
        self.progress_bar_on = False
        print(f"[PASS {self.pass_id}] {label}", flush=True)

    def pass_finish(self) -> None:
        """ Finish the current minimization pass """
        print("")  # finish the line

    def pass_msg(self, msg: str) -> None:
        """ Print a message related to the current pass """
        print(" " * self.offset + "> " + msg)
        self.progress_bar_on = False

    def next(self, success: bool) -> None:
        """ Print a progress bar """
        if not self.progress_bar_on:
            print("")
            self.progress_bar_on = True

        self.curr_width += 1
        if self.curr_width > self.line_width:
            print("\n", end="", flush=True)
            self.curr_width = self.offset

        if success:
            print(".", end="", flush=True)
        else:
            print("-", end="", flush=True)

    def global_msg(self, msg: str) -> None:
        """ Print a message that is not related to the current pass """
        print(f"[INFO] {msg}")
