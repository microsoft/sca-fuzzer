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
        s += "Filters:\n"
        s += f"  Speculation Filter: {self.spec_filter}\n"
        s += f"  Observation Filter: {self.observ_filter}\n"
        return s

    def get_brief(self):
        if self.test_cases == 0:
            return ""
        else:
            if self.analysed_test_cases:
                all_cls = (self.eff_classes + self.single_entry_classes) / self.analysed_test_cases
                eff_cls = self.eff_classes / self.analysed_test_cases
            else:
                all_cls = 0
                eff_cls = 0
            s = f"Cls:{eff_cls:.1f}/{all_cls:.1f},"
            s += f"In:{self.num_inputs / self.test_cases:.1f},"
            s += f"Cv:{self.coverage},"
            s += f"SpF:{self.spec_filter},"
            s += f"ObF:{self.observ_filter},"
            s += f"Prm:{self.required_priming}," \
                 f"Flk:{self.flaky_violations}," \
                 f"Vio:{self.violations}"
            return s


STAT = StatisticsCls()


class Logger:
    """
    A global object responsible for printing stuff.

    Has the following levels of logging:
    - Error: Critical error. Prints a message and exits
    - Warning: Non-critical error. Always printed, but does not cause an exit
    - Info: Useful info. Printed only if enabled in CONF.logging_modes
    - Debug: Detailed info. Printed if both enabled in CONF.logging_modes and if __debug__ is set.
    """

    one_percent_progress: float = 0.0
    progress: float = 0.0
    progress_percent: int = 0
    msg: str = ""
    line_ending: str = ""
    redraw_mode: bool = True

    # info modes
    info: bool = False
    stat: bool = False

    # debugging
    dbg_timestamp: bool = False
    dbg_violation: bool = False
    dbg_traces: bool = False
    dbg_model: bool = False
    dbg_coverage: bool = False

    def __init__(self) -> None:
        pass

    def set_logging_modes(self):
        for mode in CONF.logging_modes:
            if not mode:
                continue
            if getattr(self, mode, None) is None:
                self.error(f"Unknown value '{mode}' of config variable 'logging_modes'")
            setattr(self, mode, True)

        if not __debug__:
            if self.dbg_timestamp or self.dbg_model or self.dbg_coverage or self.dbg_traces:
                self.warning(
                    "", "Current value of `logging_modes` requires debugging mode!\n"
                    "Remove '-O' from python arguments")

    def error(self, msg) -> NoReturn:
        if self.redraw_mode:
            print("")
        print(f"ERROR: {msg}")
        exit(1)

    def warning(self, src, msg) -> None:
        if self.redraw_mode:
            print("")
        print(f"WARNING: [{src}] {msg}")

    def inform(self, src, msg, end="\n") -> None:
        if self.info:
            if self.redraw_mode:
                print("")
            print(f"INFO: [{src}] {msg}", end=end, flush=True)

    def dbg(self, src, msg) -> None:
        if self.redraw_mode:
            print("")
        print(f"DBG: [{src}] {msg}")

    # ==============================================================================================
    # Fuzzer
    def fuzzer_start(self, iterations: int, start_time):
        if self.info:
            self.one_percent_progress = iterations / 100
            self.progress = 0
            self.progress_percent = 0
            self.msg = ""
            self.line_ending = '\n' if CONF.multiline_output else ''
            self.redraw_mode = False if CONF.multiline_output else True
            self.start_time = start_time
        self.inform("fuzzer", start_time.strftime('Starting at %H:%M:%S'))

    def fuzzer_start_round(self, round_id):
        if self.info:
            if STAT.test_cases > self.progress:
                self.progress += self.one_percent_progress
                self.progress_percent += 1
            msg = f"\r{STAT.test_cases:<6}({self.progress_percent:>2}%)| Stats: "
            msg += STAT.get_brief()
            print(msg + "         ", end=self.line_ending, flush=True)
            self.msg = msg

        if not __debug__:
            return

        if self.dbg_timestamp and round_id and round_id % 1000 == 0:
            self.dbg(
                "fuzzer", f"Time: {datetime.today()} | "
                f" Duration: {(datetime.today() - self.start_time).total_seconds()} seconds")

    def fuzzer_priming(self, num_violations: int):
        if self.info:
            print(
                self.msg + "> Prime  " + str(num_violations) + "           ",
                end=self.line_ending,
                flush=True)

    def fuzzer_nesting_increased(self):
        if self.info:
            print(
                self.msg + "> Nest   " + str(CONF.model_max_nesting) + "         ",
                end=self.line_ending,
                flush=True)

    def fuzzer_timeout(self):
        self.inform("fuzzer", "\nTimeout expired")

    def fuzzer_finish(self):
        if self.info:
            now = datetime.today()
            print("")  # new line after the progress bar
            if self.stat:
                print(STAT)
            print(f"Duration: {(now - self.start_time).total_seconds():.1f}")
            print(datetime.today().strftime('Finished at %H:%M:%S'))

    def trc_fuzzer_dump_traces(self, model, inputs, htraces, ctraces):
        if __debug__:
            if self.dbg_traces:
                print("\n================================ Collected Traces "
                      "=============================")

                if CONF.contract_observation_clause == 'l1d':
                    for i in range(len(htraces)):
                        if i > 100:
                            self.warning("fuzzer", "Trace output is limited to 100 traces")
                            break
                        print("    ")
                        print(f"CTr{i}: {self.pretty_bitmap(ctraces[i], ctraces[i] > pow(2, 64))}")
                        print(f"HTr{i}: {self.pretty_bitmap(htraces[i])}")
                    return

                org_debug_state = self.dbg_model
                self.dbg_model = False
                for i in range(len(htraces)):
                    if i > 100:
                        self.warning("fuzzer", "Trace output is limited to 100 traces")
                        break
                    ctrace_full = model.dbg_get_trace_detailed(inputs[i], 1)
                    print("    ")
                    print(f"CTr{i}: {ctrace_full}")
                    print(f"HTr{i}: {self.pretty_bitmap(htraces[i])}")
                self.dbg_model = org_debug_state

    def fuzzer_report_violations(self, violation: EquivalenceClass, model):
        print("\n\n================================ Violations detected ==========================")
        print("Contract trace:")
        if CONF.contract_observation_clause != 'l1d':
            print(f" {violation.ctrace} (hash)")
        else:
            if violation.ctrace <= pow(2, 64):
                print(f"    {violation.ctrace:064b}")
            else:
                print(f"    {violation.ctrace % MASK_64BIT:064b} [ns]\n"
                      f"    {(violation.ctrace >> 64) % MASK_64BIT:064b} [s]\n")
        print("Hardware traces:")
        for htrace, measurements in violation.htrace_map.items():
            inputs = [m.input_id for m in measurements]
            if len(inputs) < 4:
                print(f" Inputs {inputs}:")
            else:
                print(f" Inputs {inputs[:4]} (+ {len(inputs) - 4} ):")
            print(f"  {self.pretty_bitmap(htrace)}")
        print("")

        if not __debug__:
            return

        if self.dbg_violation:
            # print details
            print("================================ Debug Trace ==================================")
            for htrace, measurements in violation.htrace_map.items():
                print(f"                      ##### Input {measurements[0].input_id} #####")
                model_debug_state = self.dbg_model
                self.model_debug = True
                model.trace_test_case([measurements[0].input_], 1)
                self.model_debug = model_debug_state
                print("\n\n")

    # ==============================================================================================
    # Model
    def dbg_model_mem_access(self, normalized_address, value, address, size, is_store, model):
        if not __debug__:
            return

        if not self.dbg_model:
            return

        val = value if is_store else int.from_bytes(
            model.emulator.mem_read(address, size), byteorder='little')
        type_ = "store to" if is_store else "load from"
        print(f"  > {type_} +0x{normalized_address:x} value 0x{val:x}")

    def dbg_model_instruction(self, normalized_address, model):
        if not __debug__:
            return

        if not self.dbg_model:
            return

        name = model.test_case.address_map[normalized_address].name
        if model.in_speculation:
            print(f"transient 0x{normalized_address:<2x}: {name}")
        else:
            print(f"0x{normalized_address:<2x}: {name}")
        model.print_state(oneline=True)

    def dbg_model_rollback(self, address, base):
        if not __debug__:
            return

        if not self.dbg_model:
            return

        print(f"ROLLBACK to 0x{address - base:x}")

    # ==============================================================================================
    # Coverage
    def dbg_report_coverage(self, round_id, msg):
        if __debug__:
            if self.dbg_coverage and round_id and round_id % 100 == 0:
                print(f"\nDBG: [coverage] {msg}")

    # ==============================================================================================
    # Helpers
    def pretty_bitmap(self, bits: int, merged=False, offset: str = ""):
        if not merged:
            s = f"{bits:064b}"
        else:
            s = f"{bits % MASK_64BIT:064b} [ns]\n" \
                f"{offset}{(bits >> 64) % MASK_64BIT:064b} [s]"
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
