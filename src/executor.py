"""
File: Executor Interface

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from abc import ABC, abstractmethod
from collections import Counter
import subprocess
import os.path

from helpers import assemble, load_measurement, write_to_pseudo_file, write_to_pseudo_file_bytes
from custom_types import List, Tuple, CombinedHTrace
from config import CONF


class Executor(ABC):
    coverage = None

    @abstractmethod
    def load_test_case(self, test_case_asm: str):
        pass

    @abstractmethod
    def trace_test_case(self, inputs: List[int], num_measurements: int = 0) -> List[CombinedHTrace]:
        pass

    @abstractmethod
    def read_base_addresses(self) -> Tuple[int, int, int]:
        pass

    def set_coverage(self, coverage):
        self.coverage = coverage


class X86Intel(Executor):
    previous_num_inputs: int = 0

    def __init__(self):
        write_to_pseudo_file(CONF.warmups, '/sys/x86-executor/warmups')
        write_to_pseudo_file("1" if CONF.enable_ssbp_patch else "0",
                             "/sys/x86-executor/enable_ssbp_patch")
        write_to_pseudo_file("1" if CONF.enable_pre_run_flush else "0",
                             "/sys/x86-executor/enable_pre_run_flush")
        write_to_pseudo_file("1" if CONF.enable_mds else "0",
                             "/sys/x86-executor/enable_mds")
        write_to_pseudo_file(CONF.attack_variant, "/sys/x86-executor/measurement_mode")

    def load_test_case(self, test_case_asm: str):
        assemble(test_case_asm, 'generated.o')
        write_to_pseudo_file("generated.o", "/sys/x86-executor/code")

    def trace_test_case(self, inputs: List[int], num_measurements: int = 0,
                        max_outliers: int = 0) -> List[CombinedHTrace]:
        # is kernel module ready?
        if not os.path.isfile("/proc/x86-executor"):
            print("Error: x86 Intel Executor: kernel module not loaded")

        if num_measurements == 0:
            num_measurements = CONF.num_measurements
        if max_outliers == 0:
            max_outliers = CONF.max_outliers

        # set entropy
        input_mask = pow(2, (CONF.prng_entropy_bits % 33)) - 1
        write_to_pseudo_file(input_mask, '/sys/x86-executor/input_mask')

        # convert the inputs into a byte sequence
        qword_inputs = [i.to_bytes(8, byteorder='little') for i in inputs]
        byte_inputs = bytes().join(qword_inputs)

        # protocol of loading inputs (must be in this order):
        # 1) Announce the number of inputs
        write_to_pseudo_file(str(len(inputs)), "/sys/x86-executor/n_inputs")
        # 2) Load the inputs
        write_to_pseudo_file_bytes(byte_inputs, "/sys/x86-executor/inputs")
        # 3) Check that the load was successful
        with open('/sys/x86-executor/n_inputs', 'r') as f:
            if f.readline() == '0\n':
                print("Failure loading inputs!")
                raise Exception()

        traces = [[] for _ in inputs]
        for _ in range(num_measurements):
            # measure
            subprocess.run(f"taskset -c {CONF.measurement_cpu} cat /proc/x86-executor "
                           "| sudo tee measurement.txt >/dev/null",
                           shell=True, check=True)
            # fetch the results
            for i, trace in enumerate(load_measurement('measurement.txt')):
                traces[i].append(trace)

        if num_measurements == 1:
            return [t[0] for t in traces]

        # remove outliers and merge
        merged_traces = [0 for _ in inputs]
        for i, trace_list in enumerate(traces):
            num_occurrences = Counter()
            for trace in trace_list:
                num_occurrences[trace] += 1
                # print(pretty_bitmap(trace))
                if num_occurrences[trace] <= max_outliers:
                    # if we see too few occurrences of this specific htrace,
                    # it might be noise, ignore it for now
                    continue
                elif num_occurrences[trace] == max_outliers + 1:
                    # otherwise, merge it
                    merged_traces[i] |= trace

            if CONF.self_test_mode:
                if merged_traces[i] == 0:
                    print(f"Useless HW traces: {trace_list}")

        return merged_traces

    def read_base_addresses(self):
        with open('/sys/x86-executor/print_sandbox_base', 'r') as f:
            sandbox_base = f.readline()
        with open('/sys/x86-executor/print_stack_base', 'r') as f:
            stack_base = f.readline()
        with open('/sys/x86-executor/print_code_base', 'r') as f:
            code_base = f.readline()
        return int(sandbox_base, 16), int(stack_base, 16), int(code_base, 16)


def get_executor() -> Executor:
    options = {
        'x86-intel': X86Intel,
    }
    if CONF.executor not in options:
        print("Error: unknown executor in config.py")
        exit(1)
    return options[CONF.executor]()
