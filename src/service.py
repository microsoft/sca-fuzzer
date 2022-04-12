"""
File: Global classes that provide service to all Revizor modules

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from datetime import datetime

from config import CONF
from typing import NoReturn

MASK_64BIT = pow(2, 64)
POW2_64 = pow(2, 64)
TWOS_COMPLEMENT_MASK_64 = pow(2, 64) - 1


class StatisticsCls:
    test_cases = 0
    num_inputs = 0
    eff_classes = 0
    single_entry_classes = 0
    required_priming = 0
    broken_measurements = 0
    violations = 0
    coverage = 0
    coverage_longest_uncovered = 0
    fully_covered: int = 0

    def __str__(self):
        total_clss = self.eff_classes + self.single_entry_classes
        effectiveness = self.eff_classes / total_clss if total_clss else 0
        total_clss_per_test_case = total_clss / self.test_cases if self.test_cases else 0
        effective_clss = self.eff_classes / self.test_cases if self.test_cases else 0

        s = "\n================================ Statistics ===================================\n"
        s += f"Test Cases: {self.test_cases}\n"
        s += f"Inputs per test case: {self.num_inputs / self.test_cases:.1f}\n"
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
            s = f"EC: {self.eff_classes / self.test_cases:.1f} | "
            s += f"C: {self.coverage} | "
            s += f"I: {self.num_inputs / self.test_cases:.1f} | "
            s += f"E: {self.eff_classes / (self.eff_classes + self.single_entry_classes):.1f} | "
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
    model_debug_mode: bool = False

    def __init__(self) -> None:
        pass

    def error(self, msg) -> NoReturn:
        print(f"ERROR: {msg}")
        exit(1)

    def waring(self, msg) -> None:
        print(f"WARNING: {msg}")

    def start_fuzzing(self, iterations: int, start_time):
        self.one_percent_progress = iterations / 100
        self.progress = 0
        self.progress_percent = 0
        self.msg = ""
        self.line_ending = '\n' if CONF.multiline_output else ''
        self.start_time = start_time
        if CONF.verbose:
            print(start_time.strftime('Starting at %H:%M:%S'))

    def start_round(self, round_id):
        if CONF.verbose > 1 and round_id and round_id % 1000 == 0:
            print(f"\nFUZZER: current duration: "
                  f"{(datetime.today() - self.start_time).total_seconds()}")

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
            print(
                self.msg + "Priming " + str(num_violations) + "       ",
                end=self.line_ending,
                flush=True)

    def nesting_increased(self):
        if CONF.verbose:
            print(
                self.msg + "Max nesting: " + str(CONF.max_nesting) + "         ",
                end=self.line_ending,
                flush=True)

    def timeout(self):
        if CONF.verbose:
            print("\nTimeout expired")

    def finish_fuzzing(self):
        # new line after the progress bar
        if CONF.verbose:
            now = datetime.today()
            print("")
            print(STAT)
            print(f"Duration: {(now - self.start_time).total_seconds():.1f}")
            print(datetime.today().strftime('Finished at %H:%M:%S'))

    def dbg_dump_traces(self, htraces, ctraces):
        if CONF.verbose == 999:
            print("")
            nprinted = 10 if len(ctraces) > 10 else len(ctraces)
            for i in range(nprinted):
                print("..............................................................")
                print(self._pretty_bitmap(ctraces[i], ctraces[i] > pow(2, 64)))
                print(self._pretty_bitmap(htraces[i]))

    def dbg_model_mem_access(self, normalized_address, val, is_store):
        if self.model_debug_mode:
            type_ = "store:" if is_store else "load: "
            print(f"  > {type_} +0x{normalized_address:x} = 0x{val:x}")

    def dbg_model_instruction(self, normalized_address, model):
        if self.model_debug_mode:
            print(f"{normalized_address:2x}: ", end="")
            model.print_state(oneline=True)

    def _pretty_bitmap(self, bits: int, merged=False):
        if not merged:
            s = f"{bits:064b}"
        else:
            s = f"{bits % MASK_64BIT:064b} [ns]\n" \
                f"{(bits >> 64) % MASK_64BIT:064b} [s]"
        s = s.replace("0", "_").replace("1", "^")
        return s

    def report_violations(self, violation, model):
        print("\n\n================================ Violations detected ==========================")
        print("  Contract trace (hash):\n")
        if violation.ctrace <= pow(2, 64):
            print(f"    {violation.ctrace:064b}")
        else:
            print(f"    {violation.ctrace % violation.mod2p64:064b} [ns]\n"
                  f"    {(violation.ctrace >> 64) % violation.mod2p64:064b} [s]\n")
        print("  Hardware traces:")
        for group in violation.htrace_groups.values():
            inputs = [violation.inputs[i] for i in group]
            if len(inputs) < 4:
                print(f"   Inputs {inputs}:")
            else:
                print(f"   Inputs {inputs[:4]} (+ {len(inputs) - 4} ):")
            print(f"    {self._pretty_bitmap(violation.htraces[group[0]])}")
        print("")

        if CONF.verbose < 2:
            return

        # print details
        for group in violation.htrace_groups.values():
            print("===========================================")
            print(f"Input: {violation.inputs[group[0]]}, {violation.original_positions[group[0]]}")
            self.model_debug_mode = True
            model.trace_test_case([violation.inputs[group[0]]], 1)
            self.model_debug_mode = False


LOGGER = Logger()


# ==================================================================================================
# Small helper functions
# ==================================================================================================
def bit_count(n):
    count = 0
    while n:
        count += n & 1
        n >>= 1
    return count


class NotSupportedException(Exception):
    pass
