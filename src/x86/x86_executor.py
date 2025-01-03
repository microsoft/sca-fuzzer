"""
File: Implementation of executor for x86 architecture
  - Interfacing with the kernel module
  - Aggregation of the results

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import subprocess
import sys
import os.path
from typing import List, Tuple, Set, Generator, Optional, Final

import numpy as np
import numpy.typing as npt

from ..executor import Executor
from ..traces import HTrace, RawHTraceSample, HTraceType
from ..tc_components.test_case_data import InputData
from ..tc_components.test_case_code import TestCaseProgram
from ..config import CONF, ConfigException
from ..logs import ExecutorLogger, warning, error
from ..stats import FuzzingStats
from ..sandbox import BaseAddrTuple
from ..target_desc import Vendor
from .x86_target_desc import X86TargetDesc

KMOutputLine = Tuple[int, int, int, int, int, int]
ReadingsArray = npt.NDArray[np.void]

STAT = FuzzingStats()


# ==================================================================================================
# Helper functions
# ==================================================================================================
def _km_write(value: str, path: str) -> None:
    subprocess.run(f"echo -n {value} > {path}", shell=True, check=True)


def _is_smt_enabled() -> bool:
    """
    Check if SMT is enabled on the current CPU.

    :return: True if SMT is enabled, False otherwise
    """
    try:
        out = subprocess.run("lscpu", shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError:
        warning("executor", "Could not check if SMT is enabled. Is lscpu installed?")
        return True
    for line in out.stdout.decode().split("\n"):
        if line.startswith("Thread(s) per core:"):
            if line[-1] == "1":
                return False
            return True
    return True


def _can_set_reserved() -> bool:
    """
    Check if setting reserved bits is possible on the current CPU.
    :return: True if it's possible, False otherwise
    """
    actors_conf = CONF.get_actors_conf()
    reserved_requested = \
        any(actors_conf[a]['data_properties']['reserved_bit'] for a in actors_conf) or \
        any(actors_conf[a]['data_ept_properties']['reserved_bit'] for a in actors_conf)
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


def _is_kernel_module_installed() -> bool:
    return os.path.isfile("/sys/x86_executor/trace")


def _configure_kernel_module() -> None:
    _km_write(str(CONF.executor_warmups), '/sys/x86_executor/warmups')
    _km_write("1" if getattr(CONF, 'x86_executor_enable_ssbp_patch') else "0",
              "/sys/x86_executor/enable_ssbp_patch")
    _km_write("1" if getattr(CONF, 'x86_executor_enable_prefetcher') else "0",
              "/sys/x86_executor/enable_prefetcher")
    _km_write("1" if CONF.enable_pre_run_flush else "0", "/sys/x86_executor/enable_pre_run_flush")
    _km_write(CONF.executor_mode, "/sys/x86_executor/measurement_mode")
    _km_write("1" if getattr(CONF, 'x86_enable_hpa_gpa_collisions') else "0",
              "/sys/x86_executor/enable_hpa_gpa_collisions")


def _read_trace(
        n_reps: int,
        n_inputs: int,
        arch_mode: bool = False) -> Generator[Tuple[int, int, KMOutputLine], None, None]:
    """
    ProgramGenerator function that reads and parses the output of the kernel module.
    The generator handles the batched output of the kernel module and yields the traces one by one.
    The traces are read in reverse order.

    Example:
    Assume the kernel module output for n_reps=2 and n_inputs=2 is:
    ```
    htrace1, pfc0, .., pfc4
    htrace0, pfc0, .., pfc4
    done
    htrace1, pfc0, .., pfc4
    htrace0, pfc0, .., pfc4
    done
    ```
    then the generator will yield the following tuples:
    ```
    (0, 1, [htrace1, pfc0, .., pfc4])
    (0, 0, [htrace0, pfc0, .., pfc4])
    (1, 1, [htrace1, pfc0, .., pfc4])
    (1, 0, [htrace0, pfc0, .., pfc4])
    ```

    :param n_reps: number of repetitions of the measurements
    :param n_inputs: number of inputs
    :param arch_mode: if True, the kernel module is in architecture mode
    :return: a generator that yields a tuple (repetition, input_id, htrace, [pfc1, ..., pfc5])
    :raises IOError: if the kernel module output is malformed
    """
    if n_inputs <= 0:
        return

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
                line_ints = tuple(int(x) for x in line.split(","))

                # if the line width is unexpected, it's an error
                if len(line_ints) != 6:
                    warning("executor", f"Unexpected line width: {len(line_ints)}")
                    _rewind_km_output_to_end()
                    raise IOError()

                # if the hardware trace is zero, it's an error (except for arch mode)
                if line_ints[0] == 0 and not arch_mode:
                    warning("executor", "Kernel module error; see dmesg for details")
                    _rewind_km_output_to_end()
                    raise IOError()

                # yield the trace
                yield rep_id, input_id, line_ints

                # move to next input
                input_id -= 1
                if input_id < 0:
                    # if we reached the end of a repetition, restart the input counter
                    input_id = last_input_id
                    rep_id += 1
        assert input_id == last_input_id, f"input_id: {input_id}, rep_id: {rep_id}"
    return


def _rewind_km_output_to_end() -> None:
    """
    Read to the end of the kernel module output, until the 'done' line.
    """
    while True:
        output = subprocess.check_output(
            f"taskset -c {CONF.executor_taskset} cat /sys/x86_executor/trace", shell=True)
        if 'done' in output.decode():
            break


# ==================================================================================================
# Public: Implementation of the executor for x86 architecture
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

    _curr_test_case: Optional[TestCaseProgram] = None
    _ignore_list: Set[int]
    _log: Final[ExecutorLogger]
    _vendor: Vendor
    _TSC_MASK: Final[np.uint64] = np.uint64(0x0FFFFFFFFFFFFFF0)

    def __init__(self, enable_mismatch_check_mode: bool = False, skip_setup: bool = False):
        super().__init__(enable_mismatch_check_mode)
        self._vendor = X86TargetDesc.get_vendor()
        self._ignore_list = set()
        self._log = ExecutorLogger()

        if skip_setup:
            warning("executor", "Executor starting without setting up the kernel module")
            return

        # Check the execution environment:
        if _is_smt_enabled() and not enable_mismatch_check_mode:
            warning("executor", "SMT is on! You may experience false positives.")
        if not _can_set_reserved():
            raise ConfigException("Cannot set reserved bits on this CPU")

        # Initialize the kernel module
        if not _is_kernel_module_installed():
            print("x86 executor: kernel module not installed\n\n"
                  "Go to https://microsoft.github.io/sca-fuzzer/quick-start/ for "
                  "installation instructions.")
            sys.exit(1)
        _configure_kernel_module()
        self._set_vendor_specific_features()

    def _set_vendor_specific_features(self) -> None:
        pass  # override in vendor-specific executors

    # ==============================================================================================
    # Public Interface: Test Case Loading and Tracing
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        Load a test case into the executor.
        This function must be called before calling `trace_test_case`.

        This function also sets the mismatch check mode in the kernel module if requested.
        The flag has to be set before loading the test case because the kernel module links
        the test case code with different measurement functions based on this flag.

        :param test_case: the test case object to load
        """
        # enable mismatch check mode if requested
        _km_write("1" if self._enable_mismatch_check_mode else "0",
                  "/sys/x86_executor/enable_dbg_gpr_mode")

        # write the test case to the kernel module
        self._write_test_case(test_case)
        self._curr_test_case = test_case

        # reset the ignore list; as we are testing a new program now, the old ignore list is not
        # relevant anymore
        self._ignore_list = set()

    def trace_test_case(self, inputs: List[InputData], n_reps: int) -> List[HTrace]:
        """
        Call the executor kernel module to collect the hardware traces for
        the test case (previously loaded with `load_test_case`) and the given inputs.

        :param inputs: list of inputs to be used for the test case
        :param n_reps: number of times to repeat each measurement
        :return: a list of HTrace objects, one for each input
        :raises IOError: if the kernel module output is malformed
        """
        # Skip if it's a dummy call
        if not inputs:
            return []
        n_inputs = len(inputs)

        # Skip if all inputs are ignored
        if n_inputs <= len(self._ignore_list):
            warning("executor", "All inputs are ignored. Skipping measurements")
            return [HTrace.empty_trace() for _ in range(n_inputs)]

        # Store statistics
        STAT.executor_reruns += n_reps * n_inputs

        # Transfer inputs to the kernel module
        # TODO: that's a quick-and-dirty optimization to reduce the number of KM calls;
        # it should be rewritten
        input_sequence = inputs if n_reps % 5 != 0 or n_inputs >= 1000 else inputs * 5
        self._write_inputs(input_sequence)

        # Call the kernel module and read traces
        all_readings: ReadingsArray = np.ndarray(shape=(n_inputs, n_reps), dtype=RawHTraceSample)
        for rep_id, input_id, readings in \
                _read_trace(n_reps, n_inputs, arch_mode=self._enable_mismatch_check_mode):
            all_readings[input_id][rep_id] = readings

        # Post-process results and return a list of HTrace objects
        traces = self._raw_readings_to_traces(all_readings, n_inputs)
        self._log.dbg_dump_raw_traces(traces)
        return traces

    # ==============================================================================================
    # Public Interface: Base Addresses
    def read_base_addresses(self) -> BaseAddrTuple:
        """
        Read the base addresses of the code and the sandbox from the kernel module.
        This function is used to synchronize the memory layout between the executor and the model
        :return: a tuple (data_start, code_start)
        """

        with open('/sys/x86_executor/print_data_base', 'r') as f:
            data_start = f.readline()
        with open('/sys/x86_executor/print_code_base', 'r') as f:
            code_start = f.readline()
        return int(data_start, 16), int(code_start, 16)

    # ==============================================================================================
    # Public Interface: Ignore List
    def set_ignore_list(self, ignore_list: List[int]) -> None:
        """
        Sets a list of inputs IDs that should be ignored by the executor.
        The executor will executed the inputs with these IDs as normal (in case they are
        necessary for priming the uarch state), but their htraces will be set to zero

        :param ignore_list: a list of input IDs to ignore
        """
        self._ignore_list = set(ignore_list)

    def extend_ignore_list(self, ignore_list: List[int]) -> None:
        """
        Add a list of new inputs IDs to the current ignore list.

        :param ignore_list: a list of input IDs to add to the ignore list
        """
        self._ignore_list.update(ignore_list)

    # ==============================================================================================
    # Public Interface: Quick and Dirty Mode
    def set_quick_and_dirty(self, state: bool) -> None:
        """
        Enable or disable the quick and dirty mode in the executor. In this mode, the executor
        will skip some of the stabilization phases, which will make the measurements faster but
        less reliable.

        :param state: True to enable the quick and dirty mode, False to disable it
        """
        _km_write("1" if state else "0", "/sys/x86_executor/enable_quick_and_dirty_mode")

    # ----------------------------------------------------------------------------------------------
    # Private Methods
    def _write_test_case(self, test_case: TestCaseProgram) -> None:
        """ Transfer the test case code to the kernel module """
        # Format: must match with `executor/test_case_parser.c`
        # - header: number of actors, number of symbols
        # - actor metadata: actor id, mode, privilege level, data properties, data ept properties
        # - symbol table
        # - section metadata table: section id, section size, reserved 8 bytes
        # - section code (for each actor)

        actors = test_case.get_actors(sorted_=True)
        test_case_obj = test_case.get_obj()
        symbol_table = test_case_obj.symbol_table()

        # sanity check
        if any(symbol.type_ < 0 for symbol in symbol_table):
            error("attempt to use template as a test case")

        with open('/sys/x86_executor/test_case', 'wb') as f:
            # header
            f.write((len(actors)).to_bytes(8, byteorder='little'))  # n_actors
            f.write((len(symbol_table)).to_bytes(8, byteorder='little'))  # n_symbols

            # actor metadata
            for actor in actors:
                f.write((actor.get_id()).to_bytes(8, byteorder='little'))
                f.write((actor.mode.value).to_bytes(8, byteorder='little'))
                f.write((actor.privilege_level.value).to_bytes(8, byteorder='little'))
                f.write((actor.data_properties).to_bytes(8, byteorder='little'))
                f.write((actor.data_ept_properties).to_bytes(8, byteorder='little'))
                f.write((0).to_bytes(8, byteorder='little'))  # unused

            # symbol table (first functions sorted by argument, then macros sorted by actor+offset)
            function_symbols = [s for s in symbol_table if s[2] == 0]
            macro_symbols = [s for s in symbol_table if s[2] != 0]
            for aid, s_offset, s_id, arg in sorted(function_symbols, key=lambda s: s.arg):
                # print("function", s_id, aid, s_offset, arg)
                f.write((aid).to_bytes(8, byteorder='little'))
                f.write((s_offset).to_bytes(8, byteorder='little'))
                f.write((s_id).to_bytes(8, byteorder='little'))
                f.write((arg).to_bytes(8, byteorder='little'))
            for aid, s_offset, s_id, arg in sorted(macro_symbols, key=lambda s: (s.sid, s.offset)):
                # print("macro", aid, s_offset, s_id, arg)
                f.write((aid).to_bytes(8, byteorder='little'))
                f.write((s_offset).to_bytes(8, byteorder='little'))
                f.write((s_id).to_bytes(8, byteorder='little'))
                f.write((arg).to_bytes(8, byteorder='little'))

            # section metadata
            for actor in actors:
                section_data = actor.code_section().get_elf_data()
                # print("section\n")
                f.write((section_data["id"]).to_bytes(8, byteorder='little'))
                f.write((section_data["size"]).to_bytes(8, byteorder='little'))
                f.write((0).to_bytes(8, byteorder='little'))

            # code
            with open(test_case_obj.obj_path, 'rb') as bin_file:
                for actor in actors:
                    section_data = actor.code_section().get_elf_data()
                    bin_file.seek(section_data["offset"])  # type: ignore
                    # print(code, section.size)
                    f.write(bin_file.read(section_data["size"]))

            # print(test_case.obj_path, f.tell())

    def _write_inputs(self, inputs: List[InputData]) -> None:
        """ Transfer the inputs to the kernel module """
        # Format: must match with `executor/input_parser.c`
        # - header: number of actors, number of inputs
        # - metadata: size of data per actor for each input + reserved 8 bytes
        # - data: data for each input
        with open('/sys/x86_executor/inputs', 'wb') as f:
            # header
            f.write((len(inputs[0])).to_bytes(8, byteorder='little'))  # number of actors
            f.write((len(inputs)).to_bytes(8, byteorder='little'))  # number of inputs

            # metadata
            data_size_per_actor_bytes = InputData.data_size_per_actor()
            for _ in range(len(inputs[0])):
                f.write((data_size_per_actor_bytes).to_bytes(8, byteorder='little'))  # size
                f.write((0).to_bytes(8, byteorder='little'))  # reserved

            # data
            for input_ in inputs:
                f.write(input_.tobytes())

        # Check that the transfer was successful
        with open('/sys/x86_executor/inputs', 'r') as f:
            if f.readline() != '1\n':
                raise IOError("Error writing inputs to the kernel module")

    def _identify_trace_type(self) -> HTraceType:
        """ Identify the type of the traces based on the configuration """
        if self._enable_mismatch_check_mode:
            return "reg"
        if CONF.executor_mode == 'TSC':
            return "tsc"
        return "cache"

    def _raw_readings_to_traces(self, all_readings: ReadingsArray, n_inputs: int) -> List[HTrace]:
        """ Convert the raw readings into HTrace objects and perform post-processing if needed """
        traces = []
        trace_type = self._identify_trace_type()
        for input_id in range(n_inputs):
            raw = all_readings[input_id]

            # No post-processing in mismatch check mode
            if self._enable_mismatch_check_mode:
                traces.append(HTrace(raw, trace_type))
                continue

            # Zero-out traces for ignored inputs
            if input_id in self._ignore_list:
                traces.append(HTrace.invalid_trace(trace_type))
                continue

            # When using TSC mode, we need to mask the lower 4 bits of the trace
            if CONF.executor_mode == 'TSC':
                raw['trace'] &= self._TSC_MASK

            traces.append(HTrace(raw, trace_type))
        return traces


# ==================================================================================================
# Vendor-specific executors
# ==================================================================================================
class X86IntelExecutor(X86Executor):
    """ Intel-specific implementation of the executor """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        super().__init__(enable_mismatch_check_mode)
        if self._vendor != "Intel":
            raise ConfigException(
                "Attempting to run Intel executor on a non-Intel CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")

    def _set_vendor_specific_features(self) -> None:
        handled_faults = CONF._handled_faults  # pylint: disable=protected-access  # FIXME
        _km_write("1" if "BR" in handled_faults else "0", "/sys/x86_executor/enable_mpx")


class X86AMDExecutor(X86Executor):
    """ AMD-specific implementation of the executor """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        super().__init__(enable_mismatch_check_mode)
        if self._vendor != "AMD":
            raise ConfigException(
                "Attempting to run AMD executor on a non-AMD CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")

    def _set_vendor_specific_features(self) -> None:
        pass
