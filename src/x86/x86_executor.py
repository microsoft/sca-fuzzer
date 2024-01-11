import subprocess
import os.path
import csv
import numpy as np
from collections import Counter
from typing import List, Tuple

from ..interfaces import CombinedHTrace, Input, TestCase, Executor
from ..config import CONF
from ..util import Logger


def write_to_sysfs_file(value, path: str) -> None:
    subprocess.run(f"echo -n {value} > {path}", shell=True, check=True)


def write_to_sysfs_file_bytes(value: bytes, path: str) -> None:
    with open(path, "wb") as f:
        f.write(value)


TRACE_NUM_ELEMENTS = 6


class X86Executor(Executor):
    previous_num_inputs: int = 0
    feedback: List[int]
    curr_test_case: TestCase

    def __init__(self):
        super().__init__()
        self.LOG = Logger()
        self.feedback = []

        # check the execution environment: is SMT disabled?
        smt_on = None
        try:
            out = subprocess.run("lscpu", shell=True, check=True, capture_output=True)
        except subprocess.CalledProcessError:
            self.LOG.error("Could not check if hyperthreading is enabled.\n"
                           "       Is lscpu installed?")
        for line in out.stdout.decode().split("\n"):
            if line.startswith("Thread(s) per core:"):
                if line[-1] == "1":
                    smt_on = False
                else:
                    smt_on = True
        if smt_on is None:
            self.LOG.warning("executor", "Could not check if SMT is on.")
        if smt_on:
            self.LOG.warning("executor", "SMT is on! You may experience false positives.")

        # is kernel module ready?
        if not os.path.isfile("/sys/x86_executor/trace"):
            self.LOG.error("x86 executor: kernel module not installed\n\n"
                           "Go to https://microsoft.github.io/sca-fuzzer/quick-start/ for "
                           "installation instructions.")

        # initialize the kernel module
        self.set_vendor_specific_features()
        write_to_sysfs_file(CONF.executor_warmups, '/sys/x86_executor/warmups')
        write_to_sysfs_file("1" if getattr(CONF, 'x86_executor_enable_ssbp_patch') else "0",
                            "/sys/x86_executor/enable_ssbp_patch")
        write_to_sysfs_file("1" if getattr(CONF, 'x86_executor_enable_prefetcher') else "0",
                            "/sys/x86_executor/enable_prefetcher")
        write_to_sysfs_file("1" if CONF.enable_pre_run_flush else "0",
                            "/sys/x86_executor/enable_pre_run_flush")
        write_to_sysfs_file(CONF.executor_mode, "/sys/x86_executor/measurement_mode")
        write_to_sysfs_file("1" if CONF.fuzzer == "architectural" else "0",
                            "/sys/x86_executor/enable_dbg_gpr_mode")

    def set_quick_and_dirty(self, state: bool):
        write_to_sysfs_file("1" if state else "0", "/sys/x86_executor/enable_quick_and_dirty_mode")

    def set_vendor_specific_features(self):
        pass

    def load_test_case(self, test_case: TestCase):
        self.__write_test_case(test_case)
        self.curr_test_case = test_case

    def trace_test_case(self,
                        inputs: List[Input],
                        repetitions: int = 0,
                        threshold_outliers: int = 0) -> List[CombinedHTrace]:
        # make sure it's not a dummy call
        if not inputs:
            return []
        n_measurements = len(inputs)

        if repetitions == 0:
            repetitions = CONF.executor_repetitions
            threshold_outliers = CONF.executor_max_outliers
        elif threshold_outliers == 0:
            threshold_outliers = repetitions // 10

        # Transfer inputs
        self.__write_inputs(inputs)

        # Check that the transfer was successful
        with open('/sys/x86_executor/inputs', 'r') as f:
            if f.readline() != '1\n':
                self.LOG.error("Failure loading inputs!", print_tb=True)

        # run experiments and load the results
        all_results: np.ndarray = np.ndarray(
            shape=(n_measurements, repetitions, TRACE_NUM_ELEMENTS), dtype=np.uint64)
        for rep in range(repetitions):
            # executor prints results in reverse, so we begin from the end
            input_id = n_measurements - 1
            reading_finished = False

            # executor prints results in batches, hence we have to call it several times,
            # until we find the `done` keyword in the output
            while not reading_finished:
                output = subprocess.check_output(
                    f"taskset -c {CONF.executor_taskset} cat /sys/x86_executor/trace", shell=True)
                reader = csv.reader(output.decode().split("\n"))
                for row in reader:
                    if not row:
                        continue
                    if 'done' in row:
                        reading_finished = True
                        break

                    for i in range(TRACE_NUM_ELEMENTS):
                        all_results[input_id][rep][i] = int(row[i])
                    input_id -= 1

        # simple case - no merging required
        if repetitions == 1:
            self.feedback = [r[0][1:] for r in all_results]
            return [int(r[0][0]) for r in all_results]

        if CONF.executor_mode == 'TSC':
            traces, pfc_readings = self._merge_results_tsc(all_results, n_measurements,
                                                           threshold_outliers)
        else:
            traces, pfc_readings = self._merge_results_cache(all_results, n_measurements,
                                                             threshold_outliers)
        self.feedback = pfc_readings
        return traces

    @staticmethod
    def _merge_results_cache(results, n_measurements,
                             threshold_outliers) -> Tuple[List[int], List[int]]:
        traces = [0 for _ in results]
        pfc_readings: np.ndarray = np.zeros(shape=(n_measurements, 3), dtype=np.uint64)

        # remove outliers and merge hardware traces and PFC readings
        for input_id, input_results in enumerate(results):
            counter: Counter = Counter()
            for result in input_results:
                trace = int(result[0])
                counter[trace] += 1
                if counter[trace] == threshold_outliers + 1:
                    # merge the trace if we observed it sufficiently many time
                    # (i.e., if we can conclude it's not noise)
                    traces[input_id] |= trace

                    # set the PFC reading value to the one that maximizes the first counter
                    # (normally, the first counter is the number of issued uops)
                    pfc_reading = result[1:]
                    if pfc_reading[0] > pfc_readings[input_id][0]:
                        pfc_readings[input_id][0] = pfc_reading[0]
                        pfc_readings[input_id][1] = pfc_reading[1]
                        pfc_readings[input_id][2] = pfc_reading[2]

        return traces, pfc_readings.tolist()

    @staticmethod
    def _merge_results_tsc(results, n_measurements,
                           threshold_outliers) -> Tuple[List[int], List[int]]:
        traces = [0 for _ in results]
        pfc_readings: np.ndarray = np.zeros(shape=(n_measurements, 3), dtype=np.uint64)
        tsc_mask = 0xFFFFFFFFFFF00  # mask to ignore the last 8 bits of the TSC

        for input_id, input_results in enumerate(results):
            for pfc_id in range(0, 3):
                pfc_readings[input_id][pfc_id] = max([res[pfc_id + 1] for res in input_results])

            counter: Counter = Counter()
            for result in input_results:
                trace = int(result[0]) & tsc_mask
                counter[trace] += 1
                if counter[trace] == threshold_outliers + 1:
                    traces[input_id] = max(traces[input_id], trace)

        return traces, pfc_readings.tolist()

    def read_base_addresses(self):
        with open('/sys/x86_executor/print_sandbox_base', 'r') as f:
            sandbox_base = f.readline()
        with open('/sys/x86_executor/print_code_base', 'r') as f:
            code_base = f.readline()
        return int(sandbox_base, 16), int(code_base, 16)

    def get_last_feedback(self) -> List:
        return self.feedback

    def __write_test_case(self, test_case: TestCase):
        actors = sorted(test_case.actors.values(), key=lambda a: (a.id_))

        # sanity check
        for symbol in test_case.symbol_table:
            if symbol.type_ < 0:
                self.LOG.error("attempt to use template as a test case")

        with open('/sys/x86_executor/test_case', 'wb') as f:
            # header
            f.write((len(actors)).to_bytes(8, byteorder='little'))  # n_actors
            f.write((len(test_case.symbol_table)).to_bytes(8, byteorder='little'))  # n_symbols

            # actor metadata
            for actor in actors:
                f.write((actor.id_).to_bytes(8, byteorder='little'))
                f.write((actor.mode.value).to_bytes(8, byteorder='little'))
                f.write((actor.privilege_level.value).to_bytes(8, byteorder='little'))
                f.write((actor.data_properties).to_bytes(8, byteorder='little'))
                f.write((actor.data_ept_properties).to_bytes(8, byteorder='little'))
                f.write((actor.code_properties).to_bytes(8, byteorder='little'))

            # symbol table (first functions sorted by argument, then macros sorted by actor+offset)
            function_symbols = [s for s in test_case.symbol_table if s[2] == 0]
            macro_symbols = [s for s in test_case.symbol_table if s[2] != 0]
            for aid, s_offset, s_id, arg in sorted(function_symbols, key=lambda s: s.arg):
                # print("function", s_id, aid, s_offset, arg)
                f.write((aid).to_bytes(8, byteorder='little'))
                f.write((s_offset).to_bytes(8, byteorder='little'))
                f.write((s_id).to_bytes(8, byteorder='little'))
                f.write((arg).to_bytes(8, byteorder='little'))
            for aid, s_offset, s_id, arg in sorted(macro_symbols, key=lambda s: (s.aid, s.offset)):
                # print("macro", aid, s_offset, s_id, arg)
                f.write((aid).to_bytes(8, byteorder='little'))
                f.write((s_offset).to_bytes(8, byteorder='little'))
                f.write((s_id).to_bytes(8, byteorder='little'))
                f.write((arg).to_bytes(8, byteorder='little'))

            # section metadata
            for actor in actors:
                assert actor.elf_section is not None
                # print("section\n")
                f.write((actor.id_).to_bytes(8, byteorder='little'))
                f.write((actor.elf_section.size).to_bytes(8, byteorder='little'))
                f.write((0).to_bytes(8, byteorder='little'))

            # code
            with open(test_case.obj_path, 'rb') as bin_file:
                for actor in actors:
                    bin_file.seek(actor.elf_section.offset)  # type: ignore
                    code = bin_file.read(actor.elf_section.size)  # type: ignore
                    # print(code, actor.elf_section.size)
                    f.write(code)

            # print(test_case.obj_path, f.tell())

    def __write_inputs(self, inputs: List[Input]):
        with open('/sys/x86_executor/inputs', 'wb') as f:
            # header
            f.write((len(inputs[0])).to_bytes(8, byteorder='little'))  # number of actors
            f.write((len(inputs)).to_bytes(8, byteorder='little'))  # number of inputs

            # metadata
            fragment_size = (inputs[0].data_size * 8).to_bytes(8, byteorder='little')
            for id_ in range(len(inputs[0])):
                f.write(fragment_size)  # size
                f.write((0).to_bytes(8, byteorder='little'))  # reserved

            # data
            for input_ in inputs:
                f.write(input_.tobytes())


class X86IntelExecutor(X86Executor):

    def __init__(self):
        self.LOG = Logger()
        vendor = subprocess.run(
            "grep 'vendor_id' /proc/cpuinfo", shell=True, capture_output=True).stdout.decode()
        if "Intel" not in vendor:
            self.LOG.error(
                "Attempting to run Intel executor on a non-Intel CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")
        super().__init__()

    def set_vendor_specific_features(self):
        write_to_sysfs_file("1" if "BR" in CONF._handled_faults else "0",
                            "/sys/x86_executor/enable_mpx")


class X86AMDExecutor(X86Executor):

    def __init__(self):
        self.LOG = Logger()
        vendor = subprocess.run(
            "grep 'vendor_id' /proc/cpuinfo", shell=True, capture_output=True).stdout.decode()
        if "AMD" not in vendor:
            self.LOG.error(
                "Attempting to run AMD executor on a non-AMD CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")
        super().__init__()

    def set_vendor_specific_features(self):
        pass
