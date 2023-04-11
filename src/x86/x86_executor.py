import subprocess
import os.path
import csv
import numpy as np
from collections import Counter
from typing import List

from ..interfaces import CombinedHTrace, Input, TestCase, Executor
from ..config import CONF
from ..util import Logger


def write_to_sysfs_file(value, path: str) -> None:
    subprocess.run(f"sudo bash -c 'echo -n {value} > {path}'", shell=True, check=True)


def write_to_sysfs_file_bytes(value: bytes, path: str) -> None:
    with open(path, "wb") as f:
        f.write(value)


TRACE_NUM_ELEMENTS = 6


class X86IntelExecutor(Executor):
    previous_num_inputs: int = 0
    feedback: List[int]

    def __init__(self):
        super().__init__()
        self.LOG = Logger()

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
        write_to_sysfs_file(CONF.executor_warmups, '/sys/x86_executor/warmups')
        write_to_sysfs_file("1" if CONF.x86_executor_enable_ssbp_patch else "0",
                            "/sys/x86_executor/enable_ssbp_patch")
        write_to_sysfs_file("1" if CONF.x86_executor_enable_prefetcher else "0",
                            "/sys/x86_executor/enable_prefetcher")
        write_to_sysfs_file("1" if CONF.enable_pre_run_flush else "0",
                            "/sys/x86_executor/enable_pre_run_flush")
        write_to_sysfs_file(CONF.executor_mode, "/sys/x86_executor/measurement_mode")

    def load_test_case(self, test_case: TestCase):
        masks = f"{test_case.faulty_pte.mask_set} {test_case.faulty_pte.mask_clear}"
        write_to_sysfs_file(masks, "/sys/x86_executor/faulty_pte_mask")
        with open(test_case.bin_path, "rb") as f:
            write_to_sysfs_file_bytes(f.read(), "/sys/x86_executor/test_case")

    def trace_test_case(self, inputs: List[Input], repetitions: int = 0) \
            -> List[CombinedHTrace]:
        # make sure it's not a dummy call
        if not inputs:
            return []

        if repetitions == 0:
            repetitions = CONF.executor_repetitions
            threshold_outliers = CONF.executor_max_outliers
        else:
            threshold_outliers = repetitions // 10

        # convert the inputs into a byte sequence
        byte_inputs = [i.tobytes() for i in inputs]
        byte_inputs_merged = bytes().join(byte_inputs)

        # protocol of loading inputs (must be in this order):
        # 1) Announce the number of inputs
        write_to_sysfs_file(str(len(inputs)), "/sys/x86_executor/n_inputs")
        # 2) Load the inputs
        write_to_sysfs_file_bytes(byte_inputs_merged, "/sys/x86_executor/inputs")
        # 3) Check that the load was successful
        with open('/sys/x86_executor/inputs', 'r') as f:
            if f.readline() != '1\n':
                self.LOG.error("Failure loading inputs!", print_tb=True)

        # run experiments and load the results
        all_results: np.ndarray = np.ndarray(
            shape=(len(inputs), repetitions, TRACE_NUM_ELEMENTS), dtype=np.uint64)
        for rep in range(repetitions):
            # executor prints results in reverse, so we begin from the end
            input_id = len(inputs) - 1
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

        traces = [0 for _ in inputs]
        pfc_readings: np.ndarray = np.zeros(shape=(len(inputs), 3), dtype=int)

        # merge the results of repeated measurements
        for input_id, input_results in enumerate(all_results):
            # find the max value of each perf counter for each input
            for pfc_id in range(0, 3):
                pfc_readings[input_id][pfc_id] = max([res[pfc_id + 1] for res in input_results])

            # remove outliers and merge hardware traces
            counter: Counter = Counter()
            for result in input_results:
                trace = int(result[0])
                counter[trace] += 1
                if counter[trace] == threshold_outliers + 1:
                    # merge the trace if we observed it sufficiently many time
                    # (i.e., if we can conclude it's not noise)
                    traces[input_id] |= trace
        self.feedback = pfc_readings.tolist()

        return traces

    def read_base_addresses(self):
        with open('/sys/x86_executor/print_sandbox_base', 'r') as f:
            sandbox_base = f.readline()
        with open('/sys/x86_executor/print_code_base', 'r') as f:
            code_base = f.readline()
        return int(sandbox_base, 16), int(code_base, 16)

    def get_last_feedback(self) -> List:
        return self.feedback
