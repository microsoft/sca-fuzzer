"""
File: Global classes that provide service to all Revizor modules

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from datetime import datetime

from interfaces import EquivalenceClass
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
    flaky_violations = 0
    violations = 0
    coverage = 0
    analysed_test_cases: int = 0
    spec_filter: int = 0
    observ_filter: int = 0

    def __str__(self):
        total_clss = self.eff_classes + self.single_entry_classes
        effectiveness = self.eff_classes / total_clss if total_clss else 0
        total_clss_per_test_case = total_clss / self.analysed_test_cases \
            if self.analysed_test_cases else 0
        effective_clss = self.eff_classes / self.analysed_test_cases \
            if self.analysed_test_cases else 0
        iptc = self.num_inputs / self.test_cases if self.test_cases else 0

        s = "================================ Statistics ===================================\n"
        s += f"Test Cases: {self.test_cases}\n"
        s += f"Inputs per test case: {iptc:.1f}\n"
        s += f"Required priming: {self.required_priming}\n"
        s += f"Flaky violations: {self.flaky_violations}\n"
        s += f"Violations: {self.violations}\n"
        s += "Effectiveness: \n"
        s += f"  Effectiveness: {effectiveness:.1f}\n"
        s += f"  Total Cls: {total_clss_per_test_case:.1f}\n"
        s += f"  Effective Cls: {effective_clss:.1f}\n"
        s += "Filters:"
        s += f"  Speculation Filter: {self.spec_filter}\n"
        s += f"  Observation Filter: {self.observ_filter}\n"
        return s

    def get_brief(self):
        if self.test_cases == 0:
            return ""
        else:
            if self.analysed_test_cases:
                all_cls = (self.eff_classes + self.single_entry_classes) / self.analysed_test_cases
            else:
                all_cls = 0
            s = f"AlCl:{all_cls:.1f}, "
            s += f"In:{self.num_inputs / self.test_cases:.1f}, "
            s += f"Cov:{self.coverage}, "
            s += f"Obs:{self.observ_filter}, "
            s += f"Prim:{self.required_priming}, " \
                 f"Flak:{self.flaky_violations}, " \
                 f"Viol:{self.violations}, "
            return s


STAT = StatisticsCls()


class Logger:
    """
    A global object responsible for printing stuff.

    Has the following levels of logging:
    - Error: Critical error. Prints a message and exits
    - Warning: Non-critical error. Always printed, but does not exit
    - Info: Useful info. Printed only if enabled in CONF.logging_modes
    - Debug: Detailed info. Printed if both enabled in CONF.logging_modes and if __debug__ is set.
             Enabled separately for each module.
    - Trace: Same as debug, but for the cases when the amount of printed info is huge
    """

    one_percent_progress: float = 0.0
    progress: float = 0.0
    progress_percent: int = 0
    msg: str = ""
    line_ending: str = ""
    redraw_mode: bool = True

    # info modes
    info_enabled: bool = False
    stat_enabled: bool = False

    # debugging modes
    fuzzer_debug: bool = False
    fuzzer_trace: bool = False
    model_debug: bool = False
    coverage_debug: bool = False

    def __init__(self) -> None:
        pass

    def set_logging_modes(self):
        mode_list = CONF.logging_modes
        if "info" in mode_list:
            self.info_enabled = True
        if "stat" in mode_list:
            self.stat_enabled = True
        if "fuzzer_debug" in mode_list:
            self.fuzzer_debug = True
        if "fuzzer_trace" in mode_list:
            self.fuzzer_trace = True
        if "model_debug" in mode_list:
            self.model_debug = True
        if "coverage_debug" in mode_list:
            self.coverage_debug = True

        if not __debug__:
            if self.fuzzer_debug or self.model_debug or self.coverage_debug or self.fuzzer_trace:
                self.waring("", "Debugging mode was not enabled! Remove '-O' from python arguments")

    def error(self, msg) -> NoReturn:
        if self.redraw_mode:
            print("")
        print(f"ERROR: {msg}")
        exit(1)

    def waring(self, src, msg) -> None:
        if self.redraw_mode:
            print("")
        print(f"WARNING: [{src}] {msg}")

    def info(self, src, msg, end="\n") -> None:
        if self.info_enabled:
            if self.redraw_mode:
                print("")
            print(f"INFO: [{src}] {msg}", end=end, flush=True)

    # ==============================================================================================
    # Fuzzer
    def dbg_fuzzer(self, msg) -> None:
        if __debug__:
            if self.fuzzer_debug:
                print(f"DBG: [fuzzer] {msg}")

    def fuzzer_start(self, iterations: int, start_time):
        if self.info_enabled:
            self.one_percent_progress = iterations / 100
            self.progress = 0
            self.progress_percent = 0
            self.msg = ""
            self.line_ending = '\n' if CONF.multiline_output else ''
            self.redraw_mode = False if CONF.multiline_output else True
            self.start_time = start_time
        self.info("fuzzer", start_time.strftime('Starting at %H:%M:%S'))

    def fuzzer_start_round(self, round_id):
        if __debug__ and round_id and round_id % 1000 == 0:
            self.dbg_fuzzer(
                f"Current duration: {(datetime.today() - self.start_time).total_seconds()}")

        if self.info_enabled:
            if STAT.test_cases > self.progress:
                self.progress += self.one_percent_progress
                self.progress_percent += 1
            msg = f"\rProgress: {STAT.test_cases}|{self.progress_percent}%, "
            msg += STAT.get_brief()
            print(msg + "> Normal execution              ", end=self.line_ending, flush=True)
            self.msg = msg

    def fuzzer_priming(self, num_violations: int):
        if self.info_enabled:
            print(
                self.msg + "> Priming:" + str(num_violations) + "           ",
                end=self.line_ending,
                flush=True)

    def fuzzer_nesting_increased(self):
        if self.info_enabled:
            print(
                self.msg + "> Trying max nesting:" + str(CONF.model_max_nesting) + "         ",
                end=self.line_ending,
                flush=True)

    def fuzzer_timeout(self):
        self.info("fuzzer", "\nTimeout expired")

    def fuzzer_finish(self):
        if self.info_enabled:
            now = datetime.today()
            print("")  # new line after the progress bar
            if self.stat_enabled:
                print(STAT)
            print(f"Duration: {(now - self.start_time).total_seconds():.1f}")
            print(datetime.today().strftime('Finished at %H:%M:%S'))

    def trc_fuzzer_dump_traces(self, htraces, ctraces):
        if __debug__:
            if self.fuzzer_trace:
                print("")
                nprinted = 10 if len(ctraces) > 10 else len(ctraces)
                for i in range(nprinted):
                    print("..............................................................")
                    print(self.pretty_bitmap(ctraces[i], ctraces[i] > pow(2, 64)))
                    print(self.pretty_bitmap(htraces[i]))

    def fuzzer_report_violations(self, violation: EquivalenceClass, model):
        print("\n\n================================ Violations detected ==========================")
        print("  Contract trace (hash):\n")
        if violation.ctrace <= pow(2, 64):
            print(f"    {violation.ctrace:064b}")
        else:
            print(f"    {violation.ctrace % MASK_64BIT:064b} [ns]\n"
                  f"    {(violation.ctrace >> 64) % MASK_64BIT:064b} [s]\n")
        print("  Hardware traces:")
        for htrace, measurements in violation.htrace_map.items():
            inputs = [m.input_id for m in measurements]
            if len(inputs) < 4:
                print(f"   Inputs {inputs}:")
            else:
                print(f"   Inputs {inputs[:4]} (+ {len(inputs) - 4} ):")
            print(f"    {self.pretty_bitmap(htrace)}")
        print("")

        if __debug__ and self.fuzzer_debug:
            # print details
            print("================================ Execution Trace ==============================")
            for htrace, measurements in violation.htrace_map.items():
                print("---------------------------------------------------------------------------")
                print(f"Input #{measurements[0].input_id}")
                model_debug_state = self.model_debug
                self.model_debug = True
                model.trace_test_case([measurements[0].input_], 1)
                self.model_debug = model_debug_state

    # ==============================================================================================
    # Model
    def dbg_model_mem_access(self, normalized_address, val, is_store):
        if self.model_debug:
            type_ = "store:" if is_store else "load: "
            print(f"  > {type_} +0x{normalized_address:x} = 0x{val:x}")

    def dbg_model_instruction(self, name, normalized_address, model):
        if self.model_debug:
            print(f"{normalized_address:2x}: {name}")
            model.print_state(oneline=True)

    # ==============================================================================================
    # Coverage
    def dbg_report_coverage(self, round_id, msg):
        if __debug__:
            if round_id and round_id % 100 == 0 and self.coverage_debug:
                print(f"\nDBG: [coverage] {msg}")

    # ==============================================================================================
    # Helpers
    def pretty_bitmap(self, bits: int, merged=False):
        if not merged:
            s = f"{bits:064b}"
        else:
            s = f"{bits % MASK_64BIT:064b} [ns]\n" \
                f"{(bits >> 64) % MASK_64BIT:064b} [s]"
        s = s.replace("0", "_").replace("1", "^")
        return s


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


class UnreachableCode(Exception):
    pass
