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
from typing import List, Optional, Tuple

from ..interfaces import HTrace, Input, TestCase, Executor
from ..config import CONF
from ..util import Logger, STAT


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
    4. Aggregate the measurements into sets of traces (see _aggregate_measurements).
    """

    previous_num_inputs: int = 0
    feedback: List[List[int]]
    curr_test_case: TestCase
    ignore_list: List[int]

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

        # if setting of a reserved bit is requested, check if it's possible
        reserved_requested = \
            any(CONF._actors[a]['data_properties']['reserved_bit'] for a in CONF._actors) or \
            any(CONF._actors[a]['data_ept_properties']['reserved_bit'] for a in CONF._actors)
        if reserved_requested:
            physical_bits = int(
                subprocess.run(
                    "lscpu | grep 'Address sizes' | awk '{print $3}'",
                    shell=True,
                    check=True,
                    capture_output=True).stdout.decode().strip())
            if physical_bits > 51:
                self.LOG.error("executor", "Cannot set reserved bits on this CPU")

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

    def set_ignore_list(self, ignore_list: List[int]):
        """ Sets a list of inputs IDs that should be ignored by the executor.
        The executor will executed the inputs with these IDs as normal (in case they are
        necessary for priming the uarch state), but their htraces will be set to zero """
        self.ignore_list = list(ignore_list)

    def extend_ignore_list(self, ignore_list: List[int]):
        self.ignore_list.extend(ignore_list)

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
        self.ignore_list = []

    def trace_test_case(self, inputs: List[Input], n_reps: int) -> List[HTrace]:
        """ see interfaces.py:Executor for documentation """

        # make sure it's not a dummy call
        if not inputs:
            return []
        n_inputs = len(inputs)

        # skip if all inputs are ignored
        if n_inputs == len(self.ignore_list):
            self.LOG.warning("executor", "All inputs are ignored. Skipping measurements")
            self.feedback = [[0, 0, 0, 0, 0] for _ in range(n_inputs)]
            return [HTrace([0]) for _ in range(n_inputs)]

        # Transfer inputs to the kernel module
        if n_reps % 5 == 0 and len(inputs) < 1000:
            self.__write_inputs(inputs * 5)
        else:
            self.__write_inputs(inputs)

        # Check that the transfer was successful
        with open('/sys/x86_executor/inputs', 'r') as f:
            if f.readline() != '1\n':
                self.LOG.error("Failure loading inputs!", print_tb=True)

        # Collect traces
        raw_results = self._get_raw_measurements(n_reps, n_inputs)
        if raw_results is None:
            return []
        trace_lists, pfc_lists = self._aggregate_measurements(raw_results)
        traces = [HTrace(trace_list) for trace_list in trace_lists]
        self.feedback = pfc_lists
        return traces

    def _get_raw_measurements(self, n_reps: int, n_inputs: int) -> Optional[np.ndarray]:
        """
        Collects raw measurements from the kernel module.

        :param n_reps: number of repetitions for each input
        :param n_inputs: number of inputs
        """
        STAT.executor_reruns += n_reps * n_inputs

        # Pre-allocate an array to store the results
        all_results: np.ndarray = np.ndarray(shape=(n_inputs, n_reps), dtype=MeasurementResult)

        # Run experiments and save the results
        cmd = f"taskset -c {CONF.executor_taskset} cat /sys/x86_executor/trace"

        rep = 0
        while rep < n_reps:
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

                    if input_id < 0:  # we reached the end of the batch; start over
                        input_id = n_inputs - 1
                        rep += 1

                    if input_id not in self.ignore_list:
                        raw_trace = int(row[0])
                        if CONF.executor_mode == 'TSC' and CONF.fuzzer != 'architectural':
                            all_results[input_id][rep]['htrace'] = raw_trace & 0x0FFFFFFFFFFFFFF0
                        else:
                            all_results[input_id][rep]['htrace'] = raw_trace

                        all_results[input_id][rep]['pfc'] = [int(x) for x in row[1:]]
                        if raw_trace == 0 and CONF.fuzzer != 'architectural':
                            self.LOG.warning(
                                "executor", "Detected a kernel module error (see dmesg for details)"
                                ". Skipping this test case")
                            return None
                    else:
                        all_results[input_id][rep]['htrace'] = 0
                        all_results[input_id][rep]['pfc'] = [0, 0, 0, 0, 0]
                    input_id -= 1

            assert input_id == -1, f"input_id: {input_id}, rep: {rep}"
            rep += 1

        self.LOG.dbg_executor_raw_traces(all_results)
        return all_results

    def _aggregate_measurements(self,
                                raw_results: np.ndarray) -> Tuple[List[List[int]], List[List[int]]]:
        """
        Aggregates the raw measurements into lists of traces

        :param raw_results: raw measurements collected by _get_raw_measurements
        :return: a list of traces and a list of pfc readings
        """
        trace_lists = []
        pfc_lists = []

        for input_id in range(len(raw_results)):
            trace_list = []
            max_pfc1 = 0
            for rep in range(len(raw_results[input_id])):
                trace_list.append(int(raw_results[input_id][rep]['htrace']))
                if max_pfc1 < raw_results[input_id][rep]['pfc'][1]:
                    max_pfc1 = raw_results[input_id][rep]['pfc'][1]

            trace_lists.append(trace_list)
            pfc_lists.append(raw_results[input_id][rep]['pfc'])

        return trace_lists, pfc_lists

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
