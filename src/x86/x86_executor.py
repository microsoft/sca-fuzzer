"""
File: Implementation of executor for x86 architecture
  - Interfacing with the kernel module
  - Aggregation of the results

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import subprocess
import os.path
import numpy as np
from typing import List, Tuple, Set, Generator

from ..interfaces import HTrace, Input, TestCase, Executor, HardwareTracingError
from ..config import CONF
from ..util import Logger, STAT
from .x86_target_desc import X86TargetDesc


# ==================================================================================================
# Helper functions
# ==================================================================================================
def km_write(value, path: str) -> None:
    subprocess.run(f"echo -n {value} > {path}", shell=True, check=True)


def km_write_bytes(value: bytes, path: str) -> None:
    with open(path, "wb") as f:
        f.write(value)


def is_smt_enabled() -> bool:
    """
    Check if SMT is enabled on the current CPU.

    :return: True if SMT is enabled, False otherwise
    """
    try:
        out = subprocess.run("lscpu", shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError:
        LOG = Logger()
        LOG.warning("executor", "Could not check if SMT is enabled. Is lscpu installed?")
        return True
    for line in out.stdout.decode().split("\n"):
        if line.startswith("Thread(s) per core:"):
            if line[-1] == "1":
                return False
            else:
                return True
    return True


def can_set_reserved() -> bool:
    """
    Check if setting reserved bits is possible on the current CPU.
    :return: True if it's possible, False otherwise
    """
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
            return False
    return True


def is_kernel_module_installed() -> bool:
    return os.path.isfile("/sys/x86_executor/trace")


def configure_kernel_module() -> None:
    km_write(CONF.executor_warmups, '/sys/x86_executor/warmups')
    km_write("1" if getattr(CONF, 'x86_executor_enable_ssbp_patch') else "0",
             "/sys/x86_executor/enable_ssbp_patch")
    km_write("1" if getattr(CONF, 'x86_executor_enable_prefetcher') else "0",
             "/sys/x86_executor/enable_prefetcher")
    km_write("1" if CONF.enable_pre_run_flush else "0", "/sys/x86_executor/enable_pre_run_flush")
    km_write(CONF.executor_mode, "/sys/x86_executor/measurement_mode")
    km_write("1" if getattr(CONF, 'x86_enable_hpa_gpa_collisions') else "0",
             "/sys/x86_executor/enable_hpa_gpa_collisions")


def read_trace(
        n_reps: int,
        n_inputs: int,
        enable_warnings: bool = True) -> Generator[Tuple[int, int, int, List[int]], None, None]:
    """
    Generator function that reads the traces from the kernel module.
    The generator handles the batched output of the kernel module and yields the traces one by one.
    The traces are read in reverse order.

    Example:
    Assume the kernel module output for n_reps=2 and n_inputs=2 is:
    ```
    htrace1, pfc1..5
    htrace0, pfc1..5
    done
    htrace1, pfc1..5
    htrace0, pfc1..5
    done
    ```
    then the generator will yield the following tuples:
    ```
    (0, 1, htrace1, [pfc1..5])
    (0, 0, htrace0, [pfc1..5])
    (1, 1, htrace1, [pfc1..5])
    (1, 0, htrace0, [pfc1..5])
    ```

    :param n_reps: number of repetitions of the measurements
    :param n_inputs: number of inputs
    :param enable_warnings: if True, the function will print warnings if the kernel module output is
           malformed or if it returns an error
    :return: a generator that yields a tuple (repetition, input_id, htrace, [pfc1, ..., pfc5])
    :raises HardwareTracingError: if the kernel module output is malformed
    """
    if n_inputs <= 0:
        return
    LOG = Logger()

    rep_id = 0
    last_input_id = n_inputs - 1
    while rep_id < n_reps:
        input_id: int = last_input_id
        reading_finished: bool = False
        while not reading_finished:
            # read the next batch of traces from the kernel module
            output = subprocess.check_output(
                f"taskset -c {CONF.executor_taskset} cat /sys/x86_executor/trace", shell=True)
            lines = output.decode().split("\n")

            # parse the output
            for line in lines:
                # print(rep_id, input_id, line)
                # skip empty lines
                if not line:
                    continue

                # we reached the end of the batch? read the next batch
                if 'done' in line:
                    reading_finished = True
                    break

                # transform the line into a sequence of ints
                line_words = line.split(",")
                line_ints = [int(x) for x in line_words]

                # if the line width is unexpected, it's an error
                if len(line_words) != 6:
                    if enable_warnings:
                        LOG.warning("executor", f"Unexpected line width: {len(line_words)}")
                    rewind_km_output_to_end()
                    raise HardwareTracingError()

                # if the hardware trace is zero, it's an error
                if line_ints[0] == 0:
                    if enable_warnings:
                        LOG.warning("executor", "Kernel module error; see dmesg for details")
                    rewind_km_output_to_end()
                    raise HardwareTracingError()

                # yield the trace
                yield rep_id, input_id, line_ints[0], line_ints[1:]

                # move to next input
                input_id -= 1
                if input_id < 0:
                    # if we reached the end of a repetition, restart the input counter
                    input_id = last_input_id
                    rep_id += 1
        assert input_id == last_input_id, f"input_id: {input_id}, rep_id: {rep_id}"
    return


def rewind_km_output_to_end():
    """
    Read to the end of the kernel module output, until the 'done' line.
    """
    while True:
        output = subprocess.check_output(
            f"taskset -c {CONF.executor_taskset} cat /sys/x86_executor/trace", shell=True)
        if 'done' in output.decode():
            break


# ==================================================================================================
# Main executor class
# ==================================================================================================
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
    curr_test_case: TestCase
    ignore_list: Set[int]

    def __init__(self, enable_mismatch_check_mode: bool = False):
        super().__init__(enable_mismatch_check_mode)
        self.LOG = Logger()
        self.target_desc = X86TargetDesc()
        self.ignore_list = set()

        # Check the execution environment:
        if is_smt_enabled() and not enable_mismatch_check_mode:
            self.LOG.warning("executor", "SMT is on! You may experience false positives.")
        if not can_set_reserved():
            self.LOG.error("executor: Cannot set reserved bits on this CPU")

        # Initialize the kernel module
        if not is_kernel_module_installed():
            self.LOG.error("x86 executor: kernel module not installed\n\n"
                           "Go to https://microsoft.github.io/sca-fuzzer/quick-start/ for "
                           "installation instructions.")
        configure_kernel_module()
        self.set_vendor_specific_features()

    def set_vendor_specific_features(self):
        pass  # override in vendor-specific executors

    # ==============================================================================================
    # Interface: Quick and Dirty Mode
    def set_quick_and_dirty(self, state: bool):
        """
        Enable or disable the quick and dirty mode in the executor. In this mode, the executor
        will skip some of the stabilization phases, which will make the measurements faster but
        less reliable.

        :param state: True to enable the quick and dirty mode, False to disable it
        """
        km_write("1" if state else "0", "/sys/x86_executor/enable_quick_and_dirty_mode")

    # ==============================================================================================
    # Interface: Ignore List
    def set_ignore_list(self, ignore_list: List[int]):
        """
        Sets a list of inputs IDs that should be ignored by the executor.
        The executor will executed the inputs with these IDs as normal (in case they are
        necessary for priming the uarch state), but their htraces will be set to zero

        :param ignore_list: a list of input IDs to ignore
        """
        self.ignore_list = set(ignore_list)

    def extend_ignore_list(self, ignore_list: List[int]):
        """
        Add a list of new inputs IDs to the current ignore list.

        :param ignore_list: a list of input IDs to add to the ignore list
        """
        self.ignore_list.update(ignore_list)

    # ==============================================================================================
    # Interface: Base Addresses
    def read_base_addresses(self):
        """
        Read the base addresses of the code and the sandbox from the kernel module.
        This function is used to synchronize the memory layout between the executor and the model
        :return: a tuple (sandbox_base, code_base)
        """

        with open('/sys/x86_executor/print_sandbox_base', 'r') as f:
            sandbox_base = f.readline()
        with open('/sys/x86_executor/print_code_base', 'r') as f:
            code_base = f.readline()
        return int(sandbox_base, 16), int(code_base, 16)

    # ==============================================================================================
    # Interface: Test Case Loading
    def load_test_case(self, test_case: TestCase):
        """
        Load a test case into the executor.
        This function must be called before calling `trace_test_case`.

        This function also sets the mismatch check mode in the kernel module if requested.
        The flag has to be set before loading the test case because the kernel module links
        the test case code with different measurement functions based on this flag.

        :param test_case: the test case object to load
        """
        # enable mismatch check mode if requested
        km_write("1" if self.mismatch_check_mode else "0", "/sys/x86_executor/enable_dbg_gpr_mode")

        # write the test case to the kernel module
        self.__write_test_case(test_case)
        self.curr_test_case = test_case

        # reset the ignore list; as we are testing a new program now, the old ignore list is not
        # relevant anymore
        self.ignore_list = set()

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

    # ==============================================================================================
    # Interface: Test Case Tracing
    def trace_test_case(self, inputs: List[Input], n_reps: int) -> List[HTrace]:
        """
        Call the executor kernel module to collect the hardware traces for
        the test case (previously loaded with `load_test_case`) and the given inputs.

        :param inputs: list of inputs to be used for the test case
        :param n_reps: number of times to repeat each measurement
        :return: a list of HTrace objects, one for each input
        :raises HardwareTracingError: if the kernel module output is malformed
        """
        # Skip if it's a dummy call
        if not inputs:
            return []

        # Skip if all inputs are ignored
        if len(inputs) <= len(self.ignore_list):
            self.LOG.warning("executor", "All inputs are ignored. Skipping measurements")
            null_trace = HTrace.get_null()
            return [null_trace for _ in range(len(inputs))]

        # Store statistics
        n_inputs = len(inputs)
        STAT.executor_reruns += n_reps * n_inputs

        # Transfer inputs to the kernel module
        # TODO: that's a quick-and-dirty optimization to reduce the number of KM calls;
        # it should be rewritten
        if n_reps % 5 == 0 and n_inputs < 1000:
            self.__write_inputs(inputs * 5)
        else:
            self.__write_inputs(inputs)

        # Call the kernel module and read traces
        # Note: read_trace may raise HardwareTracingError, which will be propagated to the caller
        all_traces: np.ndarray = np.ndarray(shape=(n_inputs, n_reps), dtype=np.uint64)
        all_pfc: np.ndarray = np.ndarray(shape=(n_inputs, n_reps, 5), dtype=np.uint64)
        enable_warnings = not self.mismatch_check_mode
        for rid, iid, htrace, pfc_list in read_trace(n_reps, n_inputs, enable_warnings):
            all_traces[iid][rid] = htrace
            all_pfc[iid][rid] = pfc_list
        self.LOG.dbg_executor_raw_traces(all_traces, all_pfc)

        # Post-process the results and check for errors
        if not self.mismatch_check_mode:  # no need to post-process in mismatch check mode
            for input_id in range(n_inputs):
                for rep_id in range(n_reps):
                    # Zero-out traces for ignored inputs
                    if input_id in self.ignore_list:
                        all_traces[input_id][rep_id] = 0
                        continue

                    # When using TSC mode, we need to mask the lower 4 bits of the trace
                    if CONF.executor_mode == 'TSC':
                        all_traces[input_id][rep_id] &= 0x0FFFFFFFFFFFFFF0

        # Aggregate measurements into HTrace objects
        traces = []
        for input_id in range(n_inputs):
            trace_list = list(all_traces[input_id])
            perf_counters = all_pfc[input_id]
            traces.append(HTrace(trace_list=trace_list, perf_counters=perf_counters))
        return traces

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

        # Check that the transfer was successful
        with open('/sys/x86_executor/inputs', 'r') as f:
            if f.readline() != '1\n':
                self.LOG.error("Failure loading inputs!", print_tb=True)


# ==================================================================================================
# Vendor-specific executors
# ==================================================================================================
class X86IntelExecutor(X86Executor):

    def __init__(self, *args):
        super().__init__(*args)
        if self.target_desc.cpu_desc.vendor != "Intel":
            self.LOG.error(
                "Attempting to run Intel executor on a non-Intel CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")

    def set_vendor_specific_features(self):
        km_write("1" if "BR" in CONF._handled_faults else "0", "/sys/x86_executor/enable_mpx")


class X86AMDExecutor(X86Executor):

    def __init__(self, *args):
        super().__init__(*args)
        if self.target_desc.cpu_desc.vendor != "AMD":
            self.LOG.error(
                "Attempting to run AMD executor on a non-AMD CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")

    def set_vendor_specific_features(self):
        pass
