"""
File: Global classes that provide service to all Revizor modules

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""


from datetime import datetime

from config import CONF


class StatisticsCls:
    test_cases = 0
    num_inputs = 0
    effective_eq_classes = 0
    single_entry_eq_classes = 0
    required_priming = 0
    broken_measurements = 0
    violations = 0
    coverage = 0
    coverage_longest_uncovered = 0
    fully_covered: int = 0

    def __str__(self):
        total_clss = self.effective_eq_classes + self.single_entry_eq_classes
        effectiveness = self.effective_eq_classes / total_clss if total_clss else 0
        total_clss_per_test_case = total_clss / self.test_cases if self.test_cases else 0
        effective_clss = self.effective_eq_classes / self.test_cases if self.test_cases else 0

        s = "\n================================ Statistics ===================================\n"
        s += f"Test Cases: {self.test_cases}\n"
        s += f"Inputs per test case: {self.num_inputs}\n"
        s += "Coverage:\n"
        s += f"  Patterns: {self.coverage}\n"
        s += f"  Fully covered: {self.fully_covered}\n"
        s += f"  Longest uncovered: {self.coverage_longest_uncovered}\n"
        s += f"  Effectiveness: {effectiveness:.1f}\n"
        s += "Effectiveness: \n"
        s += f"  Total Cls: {total_clss_per_test_case:.1f}\n"
        s += f"  Effective Cls: {effective_clss:.1f}\n"
        s += f"Required priming: {self.required_priming}\n"
        s += f"Broken measurements: {self.broken_measurements}\n"
        s += f"Violations: {self.violations}\n"
        return s

    def get_brief(self):
        if self.test_cases == 0:
            return ""
        else:
            s = f"EC: {self.effective_eq_classes / self.test_cases:.1f} | "
            s += f"C: {self.coverage} | "
            s += f"I: {self.num_inputs} | "
            s += f"E: {self.effective_eq_classes / (self.effective_eq_classes + self.single_entry_eq_classes):.1f} | "
            s += f"P: {self.required_priming} | " \
                 f"BM: {self.broken_measurements} | " \
                 f"V: {self.violations} | "
            return s


STAT = StatisticsCls()


class Logger:
    one_percent_progress: float = 0.0
    progress: float = 0.0
    progress_percent: int = 0
    msg: str = ""
    line_ending: str = ""
    start_time: int = 0

    def __init__(self) -> None:
        pass

    def start_fuzzing(self, iterations: int, start_time):
        self.one_percent_progress = iterations / 100
        self.progress = 0
        self.progress_percent = 0
        self.msg = ""
        self.line_ending = '\n' if CONF.multiline_output else ''
        self.start_time = start_time
        if CONF.verbose:
            print(start_time.strftime('Starting at %H:%M:%S'))

    def start_round(self):
        if CONF.verbose:
            if STAT.test_cases > self.progress:
                self.progress += self.one_percent_progress
                self.progress_percent += 1
            msg = f"\rP: {STAT.test_cases} [{self.progress_percent}%] | "
            msg += STAT.get_brief()
            print(msg + "Normal execution            ", end=self.line_ending, flush=True)
            self.msg = msg

    def priming(self, num_violations: int):
        if CONF.verbose:
            print(self.msg + "Priming " + str(num_violations) + "       ",
                  end=self.line_ending,
                  flush=True)

    def higher_nesting(self):
        if CONF.verbose:
            print(self.msg + "Max nesting: " + str(CONF.max_nesting) + "         ",
                  end=self.line_ending,
                  flush=True)

    def finish(self):
        # new line after the progress bar
        if CONF.verbose:
            now = datetime.today()
            print("")
            print(STAT)
            print(f"Duration: {(now - self.start_time).total_seconds():.1f}")
            print(datetime.today().strftime('Finished at %H:%M:%S'))


LOGGER = Logger()
