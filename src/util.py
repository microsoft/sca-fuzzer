"""
File: Global classes that provide service to all Revizor modules

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import xxhash
from datetime import datetime
from typing import NoReturn, Dict, List
from pprint import pformat
from traceback import print_stack
from collections import Counter
from .interfaces import Violation, SANDBOX_CODE_SIZE, Model, HTrace
from .config import CONF

MASK_64BIT = pow(2, 64)
POW2_64 = pow(2, 64)

RED = '\033[33;31m'
GREEN = '\033[33;32m'
YELLOW = '\033[33;33m'
BLUE = '\033[33;34m'
PURPLE = '\033[33;35m'
CYAN = '\033[33;36m'
GRAY = '\033[33;37m'
COL_RESET = "\033[0m"


class StatisticsCls:
    _borg_shared_state: Dict = {}

    test_cases: int = 0
    num_inputs: int = 0
    eff_classes: int = 0
    single_entry_classes: int = 0
    violations: int = 0
    analysed_test_cases: int = 0
    executor_reruns: int = 0

    spec_filter: int = 0
    observ_filter: int = 0
    fast_path: int = 0
    fp_nesting: int = 0
    fp_taint_mistakes: int = 0
    fp_early_priming: int = 0
    fp_large_sample: int = 0
    fp_priming: int = 0

    # Implementation of Borg pattern
    def __init__(self) -> None:
        self.__dict__ = self._borg_shared_state

    def __str__(self):
        total_clss = self.eff_classes + self.single_entry_classes
        total_clss_per_test_case = total_clss / self.analysed_test_cases \
            if self.analysed_test_cases else 0
        effective_clss = self.eff_classes / self.analysed_test_cases \
            if self.analysed_test_cases else 0
        iptc = self.num_inputs / self.test_cases if self.test_cases else 0

        s = ""
        s += f"Test Cases: {self.test_cases}\n"
        s += f"Inputs per test case: {iptc:.1f}\n"
        s += f"Violations: {self.violations}\n"
        s += "Effectiveness: \n"
        s += f"  Total Cls: {total_clss_per_test_case:.1f}\n"
        s += f"  Effective Cls: {effective_clss:.1f}\n"
        s += "Discarded Test Cases:\n"
        s += f"  Speculation Filter: {self.spec_filter}\n"
        s += f"  Observation Filter: {self.observ_filter}\n"
        s += f"  Fast Path: {self.fast_path}\n"
        s += f"  Max Nesting Check: {self.fp_nesting}\n"
        s += f"  Tainting Check: {self.fp_taint_mistakes}\n"
        s += f"  Early Priming Check: {self.fp_early_priming}\n"
        s += f"  Large Sample Check: {self.fp_large_sample}\n"
        s += f"  Priming Check: {self.fp_priming}\n"
        return s

    def get_brief(self):
        if self.test_cases == 0:
            return ""
        else:
            if self.analysed_test_cases:
                all_cls = (self.eff_classes + self.single_entry_classes) // self.analysed_test_cases
                eff_cls = self.eff_classes // self.analysed_test_cases
            else:
                all_cls = 0
                eff_cls = 0
            executor_reruns = self.executor_reruns // self.num_inputs
            s = f"Cls:{eff_cls}/{all_cls},"
            s += f"In:{self.num_inputs // self.test_cases},"
            s += f"R:{executor_reruns},"
            s += f"SF:{self.spec_filter},"
            s += f"OF:{self.observ_filter},"
            s += f"Fst:{self.fast_path}," \
                 f"CN:{self.fp_nesting}," \
                 f"CT:{self.fp_taint_mistakes}," \
                 f"P1:{self.fp_early_priming}," \
                 f"CS:{self.fp_large_sample}," \
                 f"P2:{self.fp_priming}," \
                 f"V:{self.violations}"
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
    _borg_shared_state: Dict = {}

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
    dbg_dump_htraces: bool = False
    dbg_dump_ctraces: bool = False
    dbg_dump_traces_unlimited: bool = False
    dbg_executor_raw: bool = False
    dbg_model: bool = False
    dbg_coverage: bool = False
    dbg_generator: bool = False
    dbg_priming: bool = False

    def __init__(self) -> None:
        self.__dict__ = self._borg_shared_state
        if not self._borg_shared_state:
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
            if self.dbg_timestamp or self.dbg_model or self.dbg_coverage or self.dbg_dump_htraces \
               or self.dbg_dump_ctraces or self.dbg_generator or self.dbg_priming \
               or self.dbg_executor_raw:
                self.warning(
                    "", "Current value of `logging_modes` requires debugging mode!\n"
                    "Remove '-O' from python arguments")

    def error(self, msg: str, print_tb: bool = False, print_last_tb: bool = False) -> NoReturn:
        if self.redraw_mode:
            print("")

        if print_tb:
            print("Encountered an unrecoverable error\nTraceback:")
            print_stack()
            print("\n")
        elif print_last_tb:
            print("Encountered an unrecoverable error\nTraceback:")
            print_stack(limit=3)
            print("\n")

        if CONF.color:
            print(f"{RED}ERROR:{COL_RESET} {msg}")
        else:
            print(f"ERROR: {msg}")
        exit(1)

    def warning(self, src, msg) -> None:
        if self.redraw_mode:
            print("")
        if CONF.color:
            print(f"{YELLOW}WARNING:{COL_RESET} [{src}] {msg}")
        else:
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

        if not self.dbg_generator or CONF._no_generation:
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
                print(msg + "                         ", end=self.line_ending, flush=True)
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
                self.msg + f"> Priming  {num_violations}             ",
                end=self.line_ending,
                flush=True)

    def fuzzer_nesting_increased(self):
        if self.info:
            print(
                self.msg + "> Nest   " + str(CONF.model_max_nesting) + "         ",
                end=self.line_ending,
                flush=True)

    def fuzzer_slow_path(self):
        if self.info:
            print(self.msg + "> Entering slow path...", end=self.line_ending, flush=True)

    def fuzzer_timeout(self):
        self.inform("fuzzer", "\nTimeout expired")

    def fuzzer_sample_size_increase(self, sample_size):
        if self.info:
            print(
                f"{self.msg} > Increase sample size to {sample_size}",
                end=self.line_ending,
                flush=True)

    def fuzzer_finish(self):
        if self.info:
            now = datetime.today()
            print("")  # new line after the progress bar
            if self.stat:
                print("================================ Statistics ================================"
                      "===\n")
                print(STAT)
            print(f"Duration: {(now - self.start_time).total_seconds():.1f}")
            print(datetime.today().strftime('Finished at %H:%M:%S'))

    def trc_fuzzer_dump_traces(self, model: Model, inputs, htraces, reference_htraces, ctraces,
                               nesting: int):
        if not __debug__:
            return
        if not self.dbg_dump_htraces and not self.dbg_dump_ctraces:
            return
        if not htraces:  # might be empty due to tracing errors
            return

        NullTrace = frozenset({0})
        for i, htrace in enumerate(htraces):
            if htrace.raw == NullTrace and reference_htraces[i].raw != NullTrace:
                htraces[i] = reference_htraces[i]

        print("\n================================ Collected Traces =============================")

        if CONF.contract_observation_clause == 'l1d':
            for i in range(len(htraces)):
                if i > 100 and not self.dbg_dump_traces_unlimited:
                    self.warning("fuzzer", "Trace output is limited to 100 traces")
                    break
                ctrace = ctraces[i]
                print("    ")
                print(f"CTr{i:<2} {pretty_trace(ctrace, ctrace > pow(2, 64), '      ')}")
                print(f"HTr{i:<2} {pretty_htrace(htraces[i])}")
                print(f"Feedback{i}: {htraces[i].perf_counters_max}")

            return

        org_debug_state = self.dbg_model
        self.dbg_model = False
        for i in range(len(inputs)):
            if i > 100 and not self.dbg_dump_traces_unlimited:
                self.warning("fuzzer", "Trace output is limited to 100 traces")
                break
            ctrace_full = model.dbg_get_trace_detailed(inputs[i], nesting)
            print(f"- Input {i}:")
            if self.dbg_dump_ctraces:
                print(f"  CTr: {ctrace_colorize(ctrace_full) if CONF.color else ctrace_full} "
                      f"| Hash: {ctraces[i]}")
            if self.dbg_dump_htraces:
                print(f"  HTr:\n{pretty_htrace(htraces[i], offset='    ')}", end="")
            if CONF.color and htraces[i].perf_counters_max[0] > htraces[i].perf_counters_max[1]:
                print(f"  Feedback: {YELLOW}{htraces[i].perf_counters_max}{COL_RESET}")
            else:
                print(f"  Feedback: {htraces[i].perf_counters_max}")
        self.dbg_model = org_debug_state

    def dbg_fuzzer_dump_architectural_traces(self, hardware_regs: List[List[int]],
                                             model_regs: List[List[int]]) -> None:
        if not __debug__:
            return
        if not self.dbg_dump_htraces and not self.dbg_dump_ctraces:
            return

        print("\n========================== Architectural Traces ==============================")
        for i in range(len(hardware_regs)):
            if i > 100 and not self.dbg_dump_traces_unlimited:
                self.warning("fuzzer", "Trace output is limited to 100 traces")
                break
            print(f"Input {i}:")
            if self.dbg_dump_ctraces:
                print(f"  Model Registers: {model_regs[i]}")
            if self.dbg_dump_htraces:
                print(f"  HW Registers:    {hardware_regs[i]}")

    def fuzzer_report_violations(self, violation: Violation, model) -> None:
        print("\n\n================================ Violations detected ==========================")
        print("Contract trace:")
        if CONF.contract_observation_clause != 'l1d':
            print(f" {violation.ctrace} (hash)")
        else:
            # special case: L1D trace
            value = violation.ctrace.hash_
            if value <= pow(2, 64):
                # no speculative observation
                print(f"  {value:064b}")
            else:
                # contains speculative observation
                print(f"  {value % MASK_64BIT:064b} [ns]\n"
                      f"  {(value >> 64) % MASK_64BIT:064b} [s]\n")
        print("Hardware traces:")
        if len(violation.htrace_groups) == 2:
            inputs1 = [m.input_id for m in violation.htrace_groups[0]]
            inputs2 = [m.input_id for m in violation.htrace_groups[1]]
            htrace1 = violation.htrace_groups[0][0].htrace
            htrace2 = violation.htrace_groups[1][0].htrace
            print(f"  Input group 1: {inputs1}")
            print(f"  Input group 2: {inputs2}")
            print(f"{pretty_htrace_pair(htrace1, htrace2, offset='  ')}")
        else:
            for measurements in violation.htrace_groups:
                inputs = [m.input_id for m in measurements]
                htrace = measurements[0].htrace
                if len(inputs) < 4:
                    print(f" Inputs {inputs}:")
                else:
                    print(f" Inputs {inputs[:4]} (+ {len(inputs) - 4} ):")
                print(f"{pretty_htrace(htrace, offset='  ')}")
            print("")

        if not __debug__:
            return

        if self.dbg_violation:
            # print details
            print("================================ Violation Traces =============================")
            for measurements in violation.htrace_groups:
                print(f"                      ##### Input {measurements[0].input_id} #####")
                model_debug_state = self.dbg_model
                self.dbg_model = True
                model.trace_test_case([measurements[0].input_], CONF.model_max_nesting)
                self.dbg_model = model_debug_state
                print("\n\n")

    def fuzzer_report_architectural_violation(self, input_id: int, hardware_regs: List[int],
                                              model_regs: List[int]) -> None:
        regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi']
        mr_str = ""
        hr_str = ""
        for i in range(len(regs)):
            mr_str += f"{regs[i]}:{model_regs[i]:016x} "
            hr_str += f"{regs[i]}:{hardware_regs[i]:016x} "

        s = "Architectural violation detected\n"
        s += f"Input {input_id}:\n"
        s += f"  Model Registers:\n  {mr_str}\n"
        s += f"  HW Registers:   \n  {hr_str}\n"
        self.warning("fuzzer", s)

    def dbg_priming_progress(self, input_id, current_input_id):
        if not __debug__:
            return
        if not self.dbg_priming:
            return
        print(f"\nPriming #{input_id} in place of #{current_input_id}")

    def dbg_priming_fail(self, input_id, current_input_id, htrace_to_reproduce, new_htrace):
        if not __debug__:
            return
        if not self.dbg_priming:
            return

        print(f"\nPriming failed for input {input_id} in place of {current_input_id}")
        print(f"{'HTrace':64} Original|New")
        print(f"{pretty_htrace_pair(htrace_to_reproduce, new_htrace)}")

    def dbg_executor_raw_traces(self, all_traces, all_pfc):
        if not __debug__:
            return
        if not self.dbg_executor_raw:
            return

        counters = {}
        for input_id in range(len(all_traces)):
            if input_id not in counters:
                counters[input_id] = Counter()
            for m_id in range(len(all_traces[0])):
                counters[input_id][all_traces[input_id][m_id]] += 1
        print("Collected raw traces:")
        for input_id in range(len(all_traces)):
            for m_id in range(len(all_traces[0])):
                t = all_traces[input_id][m_id]
                c = counters[input_id][t]
            for t, c in sorted(counters[input_id].items()):
                print(f"{input_id:03}, {pretty_trace(t)}, {t}, {c}")

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
        if CONF.color:
            msg = f"    > {CYAN}{type_}{COL_RESET} +0x{normalized_address:x} " \
                  f"{CYAN}value {COL_RESET}0x{val:x}"
        else:
            msg = f"    > {type_} +0x{normalized_address:x} value 0x{val:x}"

        print(msg)

    def dbg_model_instruction(self, address, model):
        if not __debug__:
            return

        if not self.dbg_model:
            return

        section_offset = address - (model.code_start + model.current_actor.id_ * SANDBOX_CODE_SIZE)
        address_map = model.test_case.address_map[model.current_actor.id_]
        if section_offset not in address_map:
            return

        name = str(address_map[section_offset])
        if CONF.color:
            if model.in_speculation:
                name = YELLOW + name + COL_RESET
            else:
                name = GREEN + name + COL_RESET

        code_offset = address - model.code_start
        if model.in_speculation:
            name = f"[transient, nesting = {len(model.checkpoints)}] " + name
        name = f"0x{code_offset:<2x}: {name}"
        if code_offset == model.exit_addr - model.code_start - 1:
            name += " [test_case_exit]"

        print(name)
        model.print_state(oneline=True)

    def dbg_model_rollback(self, address, base):
        if not __debug__:
            return

        if not self.dbg_model:
            return

        msg = f"ROLLBACK to 0x{address - base:x}"
        if CONF.color:
            msg = YELLOW + msg + COL_RESET
        print(msg)

    def dbg_model_exception(self, errno, descr):
        if not __debug__:
            return

        if not self.dbg_model:
            return

        msg = f"EXCEPTION #{errno}: {descr}"
        if CONF.color:
            msg = RED + msg + COL_RESET
        print(msg)

    # ==============================================================================================
    # Coverage
    def dbg_report_coverage(self, model: Model):
        if not __debug__:
            return
        if not self.dbg_coverage:
            return

        inst_names = sorted(model.instruction_coverage.items(), key=lambda x: x[1], reverse=True)
        with open("coverage.txt", "w") as f:
            for inst_name, count in inst_names:
                f.write(f"{inst_name:<20} {count}\n")
            if not inst_names:
                f.write("    No coverage data available")


# ==================================================================================================
# Small helper functions
# ==================================================================================================
def bit_count(n):
    count = 0
    while n:
        count += n & 1
        n >>= 1
    return count


def pretty_htrace(htrace: HTrace, offset: str = ""):
    final_str = ""
    counter = Counter(htrace.raw)
    trace_distribution = sorted(counter.items(), key=lambda x: x[1], reverse=True)

    if CONF.executor_mode == "TSC":
        for t, c in trace_distribution:
            t = t & 0xFFFFFFFFFFFFFF
            final_str += f"{offset}{t} [{c}]\n"
        return final_str

    for t, c in trace_distribution:
        s = f"{t:064b}"
        s = s.replace("0", ".").replace("1", "^")
        if CONF.color:
            s = CYAN + s[0:8] + YELLOW + s[8:16] \
                + CYAN + s[16:24] + YELLOW + s[24:32] \
                + CYAN + s[32:40] + YELLOW + s[40:48] \
                + CYAN + s[48:56] + YELLOW + s[56:64] \
                + COL_RESET + s[64:]
        final_str += offset + s + f" [{c}]\n"
    return final_str


def pretty_htrace_pair(htrace1: HTrace, htrace2: HTrace, offset: str = ""):
    final_str = ""
    c1 = Counter(htrace1.raw)
    c2 = Counter(htrace2.raw)
    keys = set(c1.keys()) | set(c2.keys())
    traces = sorted(keys, key=lambda x: (c1[x] << 10000) + c2[x], reverse=True)

    if CONF.executor_mode == "TSC":
        for t in traces:
            t = t & 0xFFFFFFFFFFFFFF
            final_str += f"{offset}{t} [{c1[t]:<6} | {c2[t]:<6}]\n"
        return final_str

    for t in traces:
        s = f"{t:064b}"
        s = s.replace("0", ".").replace("1", "^")
        if CONF.color:
            s = CYAN + s[0:8] + YELLOW + s[8:16] \
                + CYAN + s[16:24] + YELLOW + s[24:32] \
                + CYAN + s[32:40] + YELLOW + s[40:48] \
                + CYAN + s[48:56] + YELLOW + s[56:64] \
                + COL_RESET + s[64:]
        final_str += offset + s + f" [{c1[t]:<6} | {c2[t]:<6}]\n"
    return final_str


def pretty_trace(bits: int, merged=False, offset: str = ""):
    if CONF.executor_mode == "TSC":
        return f"{bits}"

    if not merged:
        s = f"{bits:064b}"
    else:
        s = f"{bits % MASK_64BIT:064b} [ns]\n" \
            f"{offset}{(bits >> 64) % MASK_64BIT:064b} [s]"
    s = s.replace("0", ".").replace("1", "^")
    if CONF.color:
        s = CYAN + s[0:8] + YELLOW + s[8:16] \
            + CYAN + s[16:24] + YELLOW + s[24:32] \
            + CYAN + s[32:40] + YELLOW + s[40:48] \
            + CYAN + s[48:56] + YELLOW + s[56:64] \
            + COL_RESET + s[64:]
    return s


def ctrace_colorize(ctrace):
    res = "["
    for item in ctrace:
        res += "'"
        if "mem" in item:
            res += PURPLE + item + COL_RESET
        elif "pc" in item:
            res += item
        else:
            res += CYAN + item + COL_RESET
        res += "', "
    return res + "]"


def stable_hash_bytes(data: bytes) -> int:
    return xxhash.xxh64(data, seed=0).intdigest()


def stable_hash_intlist(data: List[int]) -> int:
    return xxhash.xxh64(str(data), seed=0).intdigest()
