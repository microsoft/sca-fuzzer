"""
File: Global classes that provide service to all Revizor modules

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from datetime import datetime
from typing import NoReturn, Dict
from pprint import pformat
from traceback import print_stack
from .interfaces import EquivalenceClass
from .config import CONF

MASK_64BIT = pow(2, 64)
POW2_64 = pow(2, 64)
TWOS_COMPLEMENT_MASK_64 = pow(2, 64) - 1


class StatisticsCls:
    _borg_shared_state: Dict = {}

    test_cases: int = 0
    num_inputs: int = 0
    eff_classes: int = 0
    single_entry_classes: int = 0
    required_priming: int = 0
    flaky_violations: int = 0
    violations: int = 0
    coverage: int = 0
    analysed_test_cases: int = 0
    spec_filter: int = 0
    observ_filter: int = 0

    # Implementation of Borg pattern
    def __init__(self) -> None:
        self.__dict__ = self._borg_shared_state

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
        s += f"Flaky violations: {self.flaky_violations}\n"
        s += f"Required priming: {self.required_priming}\n"
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
    debug: bool = False

    # debugging specific modules
    dbg_timestamp: bool = False
    dbg_violation: bool = False
    dbg_traces: bool = False
    dbg_model: bool = False
    dbg_coverage: bool = False
    dbg_generator: bool = False

    def __init__(self) -> None:
        self.update_logging_modes()

    def update_logging_modes(self):
        for mode in CONF.logging_modes:
            if not mode:
                continue
            if getattr(self, mode, None) is None:
                self.error(f"Unknown value '{mode}' of config variable 'logging_modes'")
            setattr(self, mode, True)
            if "dbg" in mode:  # enable debug mode if any debug mode is enabled
                self.debug = True

        if not __debug__:
            if self.dbg_timestamp or self.dbg_model or self.dbg_coverage or self.dbg_traces\
               or self.dbg_generator:
                self.warning(
                    "", "Current value of `logging_modes` requires debugging mode!\n"
                    "Remove '-O' from python arguments")

    def error(self, msg: str, print_tb: bool = False) -> NoReturn:
        if self.redraw_mode:
            print("")

        if print_tb:
            print("Encountered an unrecoverable error\nTraceback:")
            print_stack()
            print("\n")

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
        if self.debug:
            if self.redraw_mode:
                print("")
            print(f"DBG: [{src}] {msg}")

    # ==============================================================================================
    # Generator
    def dbg_gen_instructions(self, instructions):
        if not __debug__:
            return

        if not self.dbg_generator:
            return

        instructions_by_category = {i.category: set() for i in instructions}
        for i in instructions:
            instructions_by_category[i.category].add(i.name)

        self.dbg("generator", "Instructions under test:")
        for k, instruction_list in instructions_by_category.items():
            print("  - " + k + ": " + pformat(sorted(instruction_list), indent=4, compact=True))
        print("")

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
            if STAT.test_cases == 0:
                msg = ""
            else:
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

    def trc_fuzzer_dump_traces(self, model, inputs, htraces, ctraces, hw_feedback):
        if __debug__:
            if self.dbg_traces:
                print("\n================================ Collected Traces "
                      "=============================")

                if CONF.contract_observation_clause == 'l1d':
                    for i in range(len(htraces)):
                        if i > 100:
                            self.warning("fuzzer", "Trace output is limited to 100 traces")
                            break
                        ctrace = ctraces[i]
                        print("    ")
                        print(f"CTr{i:<2} {pretty_trace(ctrace, ctrace > pow(2, 64), '      ')}")
                        print(f"HTr{i:<2} {pretty_trace(htraces[i])}")
                        print(f"Feedback{i}: {hw_feedback[i]}")

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
                    print(f"HTr{i}: {pretty_trace(htraces[i])}")
                    print(f"Feedback{i}: {hw_feedback[i]}")
                self.dbg_model = org_debug_state

    def fuzzer_report_violations(self, violation: EquivalenceClass, model):
        print("\n\n================================ Violations detected ==========================")
        print("Contract trace:")
        if CONF.contract_observation_clause != 'l1d':
            print(f" {violation.ctrace} (hash)")
        else:
            if violation.ctrace <= pow(2, 64):
                print(f"  {violation.ctrace:064b}")
            else:
                print(f"  {violation.ctrace % MASK_64BIT:064b} [ns]\n"
                      f"  {(violation.ctrace >> 64) % MASK_64BIT:064b} [s]\n")
        print("Hardware traces:")
        for htrace, measurements in violation.htrace_map.items():
            inputs = [m.input_id for m in measurements]
            if len(inputs) < 4:
                print(f" Inputs {inputs}:")
            else:
                print(f" Inputs {inputs[:4]} (+ {len(inputs) - 4} ):")
            print(f"  {pretty_trace(htrace)}")
        print("")

        if not __debug__:
            return

        if self.dbg_violation:
            # print details
            print("================================ Debug Trace ==================================")
            for htrace, measurements in violation.htrace_map.items():
                print(f"                      ##### Input {measurements[0].input_id} #####")
                model_debug_state = self.dbg_model
                self.dbg_model = True
                model.trace_test_case([measurements[0].input_], 1)
                self.dbg_model = model_debug_state
                print("\n\n")

    # ==============================================================================================
    # Model
    def dbg_model_header(self, input_id):
        if not __debug__:
            return

        if not self.dbg_model:
            return

        print(f"\n                     ##### Input {input_id} #####")

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

        name = model.test_case.address_map[normalized_address]
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


# ==================================================================================================
# Small helper functions
# ==================================================================================================
def bit_count(n):
    count = 0
    while n:
        count += n & 1
        n >>= 1
    return count


def pretty_trace(bits: int, merged=False, offset: str = ""):
    if not merged:
        s = f"{bits:064b}"
    else:
        s = f"{bits % MASK_64BIT:064b} [ns]\n" \
            f"{offset}{(bits >> 64) % MASK_64BIT:064b} [s]"
    s = s.replace("0", ".").replace("1", "^")
    if CONF.color:
        s = '\033[33;34m' + s[0:8] + '\033[33;32m' + s[8:16] \
            + '\033[33;34m' + s[16:24] + '\033[33;32m' + s[24:32] \
            + '\033[33;34m' + s[32:40] + '\033[33;32m' + s[40:48] \
            + '\033[33;34m' + s[48:56] + '\033[33;32m' + s[56:64] \
            + "\033[0m" + s[64:]
    return s


class NotSupportedException(Exception):
    pass


class UnreachableCode(Exception):
    pass
