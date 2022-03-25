"""
File: Executor Interface

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import subprocess
import os.path
import csv
from collections import Counter
from typing import List
from interfaces import CombinedHTrace, HTrace, Input, TestCase, Executor

from helpers import write_to_pseudo_file, write_to_pseudo_file_bytes
from config import CONF

PFCReading = int


class X86Intel(Executor):
    previous_num_inputs: int = 0

    def __init__(self):
        super().__init__()
        write_to_pseudo_file(CONF.warmups, '/sys/x86-executor/warmups')
        write_to_pseudo_file("1" if CONF.enable_ssbp_patch else "0",
                             "/sys/x86-executor/enable_ssbp_patch")
        write_to_pseudo_file("1" if CONF.enable_pre_run_flush else "0",
                             "/sys/x86-executor/enable_pre_run_flush")
        write_to_pseudo_file("1" if CONF.enable_assist_page else "0",
                             "/sys/x86-executor/enable_mds")
        write_to_pseudo_file(CONF.attack_variant, "/sys/x86-executor/measurement_mode")

    def load_test_case(self, test_case: TestCase):
        write_to_pseudo_file(test_case.bin_path, "/sys/x86-executor/code")

    def trace_test_case(self, inputs: List[Input], num_measurements: int = 0) \
            -> List[CombinedHTrace]:
        # make sure it's not a dummy call
        if not inputs:
            return []

        # is kernel module ready?
        if not os.path.isfile("/proc/x86-executor"):
            print("Error: x86 Intel Executor: kernel module not loaded")

        if num_measurements == 0:
            num_measurements = CONF.num_measurements

        # convert the inputs into a byte sequence
        byte_inputs = [i.tobytes() for i in inputs]
        byte_inputs_merged = bytes().join(byte_inputs)

        # protocol of loading inputs (must be in this order):
        # 1) Announce the number of inputs
        write_to_pseudo_file(str(len(inputs)), "/sys/x86-executor/n_inputs")
        # 2) Load the inputs
        write_to_pseudo_file_bytes(byte_inputs_merged, "/sys/x86-executor/inputs")
        # 3) Check that the load was successful
        with open('/sys/x86-executor/n_inputs', 'r') as f:
            if f.readline() == '0\n':
                print("Failure loading inputs!")
                raise Exception()

        traces: List[List[HTrace]] = [[] for _ in inputs]
        pfc_readings: List[List] = [[[], [], []] for _ in inputs]
        for _ in range(num_measurements):
            # measure
            subprocess.run(
                f"taskset -c {CONF.measurement_cpu} cat /proc/x86-executor "
                "| sudo tee measurement.txt >/dev/null",
                shell=True,
                check=True)

            # fetch the results
            with open('measurement.txt', "r") as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames or 'CACHE_MAP' not in reader.fieldnames:
                    raise Exception("Error: Hardware Trace was not produced.")

                for i, row in enumerate(reader):
                    trace: HTrace = int(row['CACHE_MAP'])
                    if CONF.ignore_first_cache_line:
                        trace &= 9223372036854775807
                    traces[i].append(trace)

                    pfc_readings[i][0].append(int(row['pfc1']))
                    pfc_readings[i][1].append(int(row['pfc2']))
                    pfc_readings[i][2].append(int(row['pfc3']))

        if num_measurements == 1:
            if self.coverage:
                self.coverage.executor_hook([[r[0][0], r[1][0], r[2][0]] for r in pfc_readings])
            return [t[0] for t in traces]

        # remove outliers and merge
        merged_traces = [0 for _ in inputs]
        for i, trace_list in enumerate(traces):
            num_occurrences: Counter = Counter()
            for trace in trace_list:
                num_occurrences[trace] += 1
                # print(pretty_bitmap(trace))
                if num_occurrences[trace] <= CONF.max_outliers:
                    # if we see too few occurrences of this specific htrace,
                    # it might be noise, ignore it for now
                    continue
                elif num_occurrences[trace] == CONF.max_outliers + 1:
                    # otherwise, merge it
                    merged_traces[i] |= trace

        # same for PFC readings, except select max. values instead of merging
        filtered_pfc_readings = [[0, 0, 0] for _ in inputs]
        for i, reading_lists in enumerate(pfc_readings):
            num_occurrences = Counter()

            for reading in reading_lists[0]:
                num_occurrences[reading] += 1
                if num_occurrences[reading] <= CONF.max_outliers * 2:
                    # if we see too few occurrences of this specific htrace,
                    # it might be noise, ignore it for now
                    continue
                elif num_occurrences[reading] == CONF.max_outliers * 2 + 1:
                    # otherwise, update max
                    filtered_pfc_readings[i][0] = max(filtered_pfc_readings[i][0], reading)

        if self.coverage:
            self.coverage.executor_hook(filtered_pfc_readings)

        return merged_traces

    def read_base_addresses(self):
        with open('/sys/x86-executor/print_sandbox_base', 'r') as f:
            sandbox_base = f.readline()
        with open('/sys/x86-executor/print_code_base', 'r') as f:
            code_base = f.readline()
        return int(sandbox_base, 16), int(code_base, 16)


def get_executor() -> Executor:
    options = {
        'x86-intel': X86Intel,
    }
    if CONF.executor not in options:
        print("Error: unknown executor in config.py")
        exit(1)
    return options[CONF.executor]()
