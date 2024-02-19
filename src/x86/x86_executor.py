"""
File: Implementation of executor for x86 architecture
  - Interfacing with the kernel module
  - Aggregation of the results

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import subprocess
import os.path
import csv
import numpy as np
from collections import Counter
from typing import List, Set, Optional

from ..interfaces import HTrace, Input, TestCase, Executor
from ..config import CONF
from ..util import Logger


def write_to_sysfs_file(value, path: str) -> None:
    subprocess.run(f"echo -n {value} > {path}", shell=True, check=True)


def write_to_sysfs_file_bytes(value: bytes, path: str) -> None:
    with open(path, "wb") as f:
        f.write(value)


MeasurementResult = np.dtype(
    [
        ('htrace', np.uint64),
        ('pfc', np.uint64, 5),
    ],
    align=False,
)


class X86Executor(Executor):
    """
    The executor for x86 architecture. The executor interfaces with the kernel module to collect
    measurements.

    The high-level workflow is as follows:
    1. Load a test case into the kernel module (see __write_test_case).
    2. Load a set of inputs into the kernel module (see __write_inputs).
    3. Run the measurements by calling the kernel module (see _get_raw_measurements). Each
       measurement is repeated `n_reps` times.
    4. Aggregate the measurements into sets of traces (see _aggregate_measurements). The executor
       filters out the traces that appear less than `threshold_outliers * n_reps` times, and
       combines the remaining measurements into sets (one set per input).
    5. Optionally, ensure that the measurements are reproducible by collecting the results in
       several batches, and ensuring that the set of traces for each inputs converges
       (see _get_converged_traces). This function performs additional filtering by removing the
       traces that appeared in less than a half of the batches.
    """

    previous_num_inputs: int = 0
    feedback: List[List[int]]
    curr_test_case: TestCase
    ignore_list: List[int]
    __ignore_list_internal: List[int]
    enable_sticky_ignore_list: bool = False

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

        self.__ignore_list_internal = []

    def set_quick_and_dirty(self, state: bool):
        write_to_sysfs_file("1" if state else "0", "/sys/x86_executor/enable_quick_and_dirty_mode")

    def set_vendor_specific_features(self):
        pass

    def ignore_inputs(self, ignore_list: List[int]):
        """ Sets a list of inputs IDs that should be ignored by the executor.
        The executor will executed the inputs with these IDs as normal (in case they are
        necessary for priming the uarch state), but their htraces will be set to zero """
        self.ignore_list = ignore_list
        self.__ignore_list_internal = ignore_list

    def read_base_addresses(self):
        with open('/sys/x86_executor/print_sandbox_base', 'r') as f:
            sandbox_base = f.readline()
        with open('/sys/x86_executor/print_code_base', 'r') as f:
            code_base = f.readline()
        return int(sandbox_base, 16), int(code_base, 16)

    def get_last_feedback(self) -> List:
        return self.feedback

    def load_test_case(self, test_case: TestCase):
        self.__write_test_case(test_case)
        self.curr_test_case = test_case
        if not self.enable_sticky_ignore_list:
            self.ignore_list = []
        else:
            self.ignore_list = self.__ignore_list_internal

    def trace_test_case(self,
                        inputs: List[Input],
                        n_reps: int,
                        threshold_outliers: float,
                        ensure_convergence: bool = False) -> List[HTrace]:
        """ see interfaces.py:Executor for documentation """

        # make sure it's not a dummy call
        if not inputs:
            return []
        n_inputs = len(inputs)
        assert threshold_outliers > 0.0 and threshold_outliers <= 1.0

        # check that there are non-ignored inputs
        if n_inputs - len(self.ignore_list) == 0:
            self.LOG.warning("executor", "All inputs are ignored. Skipping measurements")
            self.feedback = [[0, 0, 0, 0, 0] for _ in range(n_inputs)]
            return [HTrace(frozenset({0}), hash(frozenset({0}))) for _ in range(n_inputs)]

        # Transfer inputs to the kernel module
        self.__write_inputs(inputs)

        # Check that the transfer was successful
        with open('/sys/x86_executor/inputs', 'r') as f:
            if f.readline() != '1\n':
                self.LOG.error("Failure loading inputs!", print_tb=True)

        if ensure_convergence:
            # Collection of data with convergence check
            traces = self._get_converged_traces(n_inputs, n_reps, threshold_outliers)
        else:
            # Collect data without convergence check
            raw_results = self._get_raw_measurements(n_reps, n_inputs)
            if raw_results is None:
                return []
            trace_sets = self._aggregate_measurements(raw_results, threshold_outliers, False)
            traces = [HTrace(frozenset(ts), hash(frozenset(ts))) for ts in trace_sets]

        return traces

    def _get_converged_traces(self, n_inputs, n_reps, threshold_outliers) -> List[HTrace]:
        """
        Collects measurements in several batches, and ensures that the set of traces for each input
        converges. This function performs additional filtering by removing the traces that appeared
        in less than a half of the batches.
        """
        batches: List[List[Set[int]]] = [[] for _ in range(n_inputs)]
        batch: List[Set[int]] = []

        # collect the first batch
        raw_results = self._get_raw_measurements(n_reps, n_inputs)
        if raw_results is None:
            return []
        batch = self._aggregate_measurements(raw_results, threshold_outliers)
        for input_id in range(n_inputs):
            batches[input_id].append(batch[input_id])

        # keep repeating the measurements until we stop encountering new traces
        converged = [False for _ in range(n_inputs)]
        for i in range(10):  # FIXME: make this a configuration option
            # collect the next batch
            raw_results = self._get_raw_measurements(n_reps, n_inputs)
            if raw_results is None:
                return []
            batch = self._aggregate_measurements(raw_results, threshold_outliers, True)

            # check if we found new traces for any of the inputs
            for input_id in range(n_inputs):
                batches[input_id].append(batch[input_id])
                if batch[input_id].issubset(batch[input_id]):
                    converged[input_id] = True
                else:
                    batch[input_id].update(batch[input_id])
                    converged[input_id] = False

            # stop if we found no new traces
            if all(converged):
                break

        # label the inputs that did not converge as ignored
        if not all(converged):
            self.LOG.warning("executor", "Some measurements did not converge after 10 iterations.")
            for i in range(n_inputs):
                if not converged[i] and i not in self.ignore_list:
                    self.ignore_list.append(i)
                    batches[i] = [set()]

        # filter out those sets that appeared in less than 50% of the batches
        filtered_batches: List[Set[int]] = []
        threshold = len(batches[0]) // 2 + (len(batches[0]) % 2 > 0)  # over 50%
        for input_id in range(n_inputs):
            counter: Counter = Counter()
            for trace_set in batches[input_id]:
                counter.update(trace_set)
            filtered_batches.append({k for k, v in counter.items() if v > threshold})
            # print(f"input {input_id}: {batches[input_id]} -> {filtered_batches[input_id]}")
            # print({k for k, v in counter.items() if v <= threshold})

        # convert the trace sets to HTrace objects
        traces = [HTrace(frozenset(ts), hash(frozenset(ts))) for ts in filtered_batches]
        return traces

    def _get_raw_measurements(self, n_reps: int, n_inputs: int) -> Optional[np.ndarray]:
        """
        Collects raw measurements from the kernel module.

        :param n_reps: number of repetitions for each input
        :param n_inputs: number of inputs
        """

        # Pre-allocate an array to store the results
        all_results: np.ndarray = np.ndarray(shape=(n_inputs, n_reps), dtype=MeasurementResult)

        # Run experiments and save the results
        cmd = f"taskset -c {CONF.executor_taskset} cat /sys/x86_executor/trace"
        for rep in range(n_reps):
            input_id = n_inputs - 1  # executor prints results in reverse

            # executor prints results in batches, hence we have to call it several times,
            # until we find the `done` keyword in the output
            reading_finished = False
            while not reading_finished:
                output = subprocess.check_output(cmd, shell=True)
                reader = csv.reader(output.decode().split("\n"))
                for row in reader:
                    if not row:
                        continue
                    if 'done' in row:
                        reading_finished = True
                        break

                    if input_id not in self.ignore_list:
                        all_results[input_id][rep]['htrace'] = int(row[0])
                        all_results[input_id][rep]['pfc'] = [int(x) for x in row[1:]]
                        if all_results[input_id][rep]['htrace'] == 0:
                            self.LOG.warning(
                                "executor", "Detected a kernel module error (see dmesg for details)"
                                ". Skipping this test case")
                            return None
                    else:
                        all_results[input_id][rep]['htrace'] = 0
                        all_results[input_id][rep]['pfc'] = [0, 0, 0, 0, 0]
                    input_id -= 1

        return all_results

    def _aggregate_measurements(self,
                                all_results: np.ndarray,
                                threshold_outliers: float,
                                ignore_pfc: bool = False) -> List[Set[int]]:
        """
        Aggregates the raw measurements into sets of traces. The function receives an array of
        of measurements, filters out the measurements that appear less than
        `threshold_outliers * n_reps` times, combines the remaining measurements into sets
        (one set per input), and returns the sets. The function also stores the PFC readings
        for each input.

        :param all_results: array of measurements
        :param threshold_outliers: the threshold for the number of times a trace must appear
        :param ignore_pfc: whether to ignore the PFC readings
        """

        # initialize the trace sets and PFC readings
        trace_sets: List[Set[int]] = [set() for _ in all_results]
        pfc_readings = [[0, 0, 0, 0, 0] for _ in all_results]
        n_reps = len(all_results[0])

        # mask to ignore the last 8 trace bits if in TSC mode
        trace_mask = 0xFFFFFFFFFFF00 if CONF.executor_mode == "TSC" else 0xFFFFFFFFFFFFFFFF

        count_threshold = threshold_outliers * n_reps
        for input_id, input_measurements in enumerate(all_results):
            counter: Counter = Counter()
            for result in input_measurements:
                # count the number of times each trace appears
                trace = int(result['htrace']) & trace_mask
                counter[trace] += 1

                if counter[trace] >= count_threshold:
                    trace_sets[input_id].add(trace)

                if not ignore_pfc:
                    # set the PFC reading value to the one that maximizes the first counter
                    # (normally, the first counter is the number of issued uops)
                    pfc_reading = result['pfc']
                    if pfc_reading[0] >= pfc_readings[input_id][0]:
                        pfc_readings[input_id] = pfc_reading

        if not ignore_pfc:
            self.feedback = pfc_readings

        return trace_sets

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
