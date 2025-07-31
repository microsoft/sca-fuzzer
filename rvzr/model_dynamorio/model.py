"""
File: DynamoRIO-based backend to the contract model.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import os
import tempfile
from subprocess import check_output, CalledProcessError, STDOUT
from typing import List, Tuple, Optional, TYPE_CHECKING, Final, Any

from .trace_decoder import TraceDecoder, TraceEntryType, DebugTraceEntryType

from ..model import Model
from ..sandbox import BaseAddrTuple, SandboxLayout
from ..traces import CTrace, CTraceEntry
from ..tc_components.test_case_data import save_input_sequence_as_rdbf
from ..config import CONF

if TYPE_CHECKING:
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_data import InputData, InputTaint

_DRRUN_TRACING_FLAGS: Final[str] = " --instrumented-func test_case_entry "
_ADAPTER_PATH: Final[str] = "~/.local/dynamorio/adapter"
_DRRUN_CMD: Final[str] = "~/.local/dynamorio/drrun -c ~/.local/dynamorio/libdr_model.so " \
    " {flags} -- {binary} {args}"


class DynamoRIOModel(Model):
    """
    Adapter class that connects the DynamoRIO backend to the rest of Revizor.
    """
    _obs_clause_name: Optional[str] = None
    _exec_clause_name: Optional[str] = None

    _installation_checked: bool = False  # flag to avoid checking DR installation multiple times

    _test_case: Optional[TestCaseProgram] = None  # the current test case
    _rcbf_file: Optional[str] = None  # tmp file storing the current test case in RCBF format
    _rdbf_file: Optional[str] = None  # tmp file storing the current input sequence in RDBF format

    _trace_file: str = ""
    _dbg_trace_file: str = ""
    poison_value: int = 0  # If this value is != 0, it will be returned on speculative faulty loads

    # ----------------------------------------------------------------------------------------------
    # Constructor/Destructor
    def __init__(self,
                 bases: BaseAddrTuple,
                 *args: Any,
                 enable_mismatch_check_mode: bool = False) -> None:
        # NOTE: the `bases` argument is not used as DynamoRIO backend does not allow
        #       for customization of the memory layout
        self._enable_mismatch_check_mode = enable_mismatch_check_mode
        self.is_speculative = True  # may be changed by configure_clauses
        self.poison_value = 0  # may be changed later

        with tempfile.NamedTemporaryFile("wb", delete=False) as trace_f:
            self._trace_file = trace_f.name
        with tempfile.NamedTemporaryFile("wb", delete=False) as dbg_trace_f:
            self._dbg_trace_file = dbg_trace_f.name

    def __del__(self) -> None:
        if self._rcbf_file is not None and os.path.exists(self._rcbf_file):
            os.unlink(self._rcbf_file)
        if self._rdbf_file is not None and os.path.exists(self._rdbf_file):
            os.unlink(self._rdbf_file)

    # ----------------------------------------------------------------------------------------------
    # Public Interfaces
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """
        Prepare the test case to be traced by the DynamoRIO backend.
        This means creating a binary in the RCBF format so that it can be parsed by the backend.
        :param test_case: the test case to load
        :return: None
        """
        self._test_case = test_case

        # remove the previous RCBF file if it exists and create a new one
        if self._rcbf_file is not None and os.path.exists(self._rcbf_file):
            os.unlink(self._rcbf_file)
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            self._rcbf_file = f.name

        # store the test case in the RCBF format
        test_case.get_obj().save_rcbf(self._rcbf_file)

    def trace_test_case(self, inputs: List[InputData], nesting: int) -> List[CTrace]:
        """
        Execute the test case with the given inputs on DR backend and return the traces
        :param inputs: input sequence to trace
        :param nesting: maximum nesting level to emulated in the model
        :return: list of contract traces, one per input
        """
        # Just ignore sandbox addresses
        trace, _, _ = self._trace_test_case_with_addr(inputs, nesting)
        return trace

    def trace_test_case_with_taints(self, inputs: List[InputData],
                                    nesting: int) -> Tuple[List[CTrace], List[InputTaint]]:
        # remove the previous RDBF file if it exists
        if self._rdbf_file is not None and os.path.exists(self._rdbf_file):
            os.unlink(self._rdbf_file)

        # create a temporary file and store the input sequence in it in the RDBF format
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            self._rdbf_file = f.name
        save_input_sequence_as_rdbf(inputs, self._rdbf_file)
        raise NotImplementedError("trace_test_case_with_taints")
        # return []

    def report_coverage(self, path: str) -> None:
        raise NotImplementedError()

    def configure_clauses(self, obs_clause_name: str, exec_clause_name: str) -> None:
        """
        Configure the backend to use the given observation and execution clauses.
        Also check if the given clauses are supported.
        :param obs_clause_name: the name of the observation clause
        :param exec_clause_name: the name of the execution clause
        :return: None
        :raises: ValueError if the given clauses are not supported
        """
        assert self._obs_clause_name is None and self._exec_clause_name is None, \
            "Cannot reconfigure the observation and execution clauses"

        # ensure that the DynamoRIO backend is installed
        self._check_if_installed()

        # check if the contract is supported
        if obs_clause_name not in self.get_supported_obs_clauses(False):
            raise ValueError(f"Unsupported observation clause {obs_clause_name}")
        self._obs_clause_name = obs_clause_name

        if exec_clause_name not in self.get_supported_exec_clauses(False):
            raise ValueError(f"Unsupported execution clause {exec_clause_name}")
        self._exec_clause_name = exec_clause_name

        if exec_clause_name in ["seq", "no_speculation"]:
            self.is_speculative = False

    @classmethod
    def get_supported_obs_clauses(cls, check_installation: bool = True) -> List[str]:
        """
        Get the list of supported observation clauses.
        :return: list of supported observation clauses
        :raises: FileNotFoundError if the DynamoRIO backend is not installed
        """
        if check_installation:
            cls._check_if_installed()
        cmd = _DRRUN_CMD.format(flags="--list-tracers", binary="echo", args="''")
        output = check_output(cmd, shell=True).decode("utf-8")
        return output.split("\n")[:-1]

    @classmethod
    def get_supported_exec_clauses(cls, check_installation: bool = True) -> List[str]:
        """
        Get the list of supported execution clauses.
        :return: list of supported execution clauses
        :raises: FileNotFoundError if the DynamoRIO backend is not installed
        """
        if check_installation:
            cls._check_if_installed()
        cmd = _DRRUN_CMD.format(flags="--list-speculators", binary="echo", args="''")
        output = check_output(cmd, shell=True).decode("utf-8")
        return output.split("\n")[:-1]

    # ----------------------------------------------------------------------------------------------
    # Private Methods
    @classmethod
    def _check_if_installed(cls) -> None:
        """
        Ensure that the DynamoRIO backend is installed.
        :return: None
        :raises: FileNotFoundError if the DynamoRIO backend is not installed
        """
        if not cls._installation_checked:  # check only once
            cmd = _DRRUN_CMD.format(flags="--trace-output /dev/null", binary="ls", args="/dev/null")
            try:
                output = check_output(cmd, shell=True, stderr=STDOUT).decode("utf-8")
            except (FileNotFoundError, CalledProcessError):
                output = ""
            if '/dev/null' not in output:
                raise FileNotFoundError("DynamoRIO backend is not installed\n\n\n"
                                        "Please follow the instructions in "
                                        "https://microsoft.github.io/sca-fuzzer/quick-start/")
            cls._installation_checked = True

    def _construct_drrun_cmd(self) -> str:
        """ Construct the command to call the DynamoRIO backend
        with the given test case and input sequence.
        """
        flags = _DRRUN_TRACING_FLAGS + \
            f" --tracer {self._obs_clause_name}" + \
            f" --speculator {self._exec_clause_name}" + \
            f" --max-nesting {CONF.model_max_nesting}" + \
            f" --max-spec-window {CONF.model_max_spec_window}" \
            f" --trace-output {self._trace_file}"
        if self._enable_mismatch_check_mode:
            flags += f" --log-level 1 --debug-trace-output {self._dbg_trace_file}"
        if self.poison_value != 0:
            flags += f" --poison-value {self.poison_value}"

        binary = _ADAPTER_PATH
        args = f"{self._rcbf_file} {self._rdbf_file}"
        cmd = _DRRUN_CMD.format(flags=flags, binary=binary, args=args)
        # print(cmd)
        return cmd

    def _clean_trace_files(self) -> None:
        # Truncate trace files if they exist, or create new if they don't
        with open(self._trace_file, 'wb') as tf:
            tf.truncate()
        with open(self._dbg_trace_file, 'wb') as dbg_tf:
            dbg_tf.truncate()

    def _trace_test_case_with_addr(self, inputs: List[InputData],
                                   nesting: int) -> Tuple[List[CTrace], int, int]:
        """
        Execute the test case with the given inputs on DR backend and return the traces
        and the sandbox addresses.
        :param inputs: input sequence to trace
        :param nesting: maximum nesting level to emulated in the model
        :return: list of contract traces, one per input, and the addresses of the sandbox
        """
        assert nesting != 1, "Nesting is not yet supported by the DynamoRIO backend"

        assert self._test_case is not None, "No test case was loaded"
        if len(inputs) == 0:
            return [], 0, 0

        # remove the previous RDBF file if it exists and create a new one
        if self._rdbf_file is not None and os.path.exists(self._rdbf_file):
            os.unlink(self._rdbf_file)
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            self._rdbf_file = f.name

        # store the input sequence
        save_input_sequence_as_rdbf(inputs, self._rdbf_file)

        # call the backend
        self._clean_trace_files()
        cmd = self._construct_drrun_cmd()
        output = check_output(cmd, shell=True)
        assert len(output) >= 16, "No traces were generated"

        # the first two entries in the output are used to create a representation of the sandbox
        code_base_addr = int.from_bytes(output[:8], byteorder="little")
        data_base_addr = int.from_bytes(output[8:16], byteorder="little")
        self.layout = SandboxLayout((data_base_addr, code_base_addr), self._test_case.n_actors())

        # read traces from the trace files
        reader = _TraceReader(self.layout, self._test_case)
        traces, dbg_traces = reader.decode_traces(self._trace_file, self._dbg_trace_file)
        assert len(traces) == len(inputs), "Mismatch between the number of inputs and traces"
        self._clean_trace_files()

        if self._enable_mismatch_check_mode:
            # In this mode, the contract trace is the register values at the end of the test case
            arch_traces = [CTrace(t.get_typed()[-6:]) for t in dbg_traces]
            return arch_traces, code_base_addr, data_base_addr

        return traces, code_base_addr, data_base_addr


class _TraceReader:
    """
    Local class responsible for reading traces produced by DynamoRIO backend,
    removing irrelevant information from them, and converting them to the
    format that is expected by the contract model.
    """

    def __init__(self, layout: SandboxLayout, test_case: TestCaseProgram) -> None:
        self._layout = layout
        self._test_case = test_case
        self._decoder = TraceDecoder()

    def decode_traces(self, trace_path: str, dbg_path: str) -> Tuple[List[CTrace], List[CTrace]]:
        """
        Read the traces produced by the DynamoRIO backend and return them in the format
        that is expected by the contract model.
        :return: contract traces and debug traces
        """
        traces: List[CTrace] = []
        dbg_traces: List[CTrace] = []

        # iterate over the binary trace and parse the entries
        raw_traces = self._decoder.decode_trace_file(trace_path)
        for raw_trace in raw_traces:
            converted = self._raw_to_ctrace(raw_trace)
            if converted:
                traces.append(converted)

        # do the same for debug traces
        raw_dbg_traces = self._decoder.decode_debug_trace_file(dbg_path)
        for raw_dbg_trace in raw_dbg_traces:
            converted = self._raw_dbg_to_ctrace(raw_dbg_trace)
            if converted:
                dbg_traces.append(converted)

        # trim non relevant entries
        traces = self._trim_traces(traces)
        if dbg_traces:
            dbg_traces = self._trim_dbg_traces(traces, dbg_traces)

        return traces, dbg_traces

    def _raw_to_ctrace(self, raw_trace: list[Any]) -> CTrace:
        trace: List[CTraceEntry] = []

        for entry in raw_trace:
            type_ = TraceEntryType(entry.type)
            if type_ in (TraceEntryType.ENTRY_READ, TraceEntryType.ENTRY_WRITE):
                val = self._layout.data_addr_to_offset(entry.addr)
                trace.append(CTraceEntry(type_="mem", value=val))
            elif type_ == TraceEntryType.ENTRY_PC:
                val = self._layout.code_addr_to_offset(entry.addr)
                trace.append(CTraceEntry(type_="pc", value=val))
            elif type_ == TraceEntryType.ENTRY_IND:
                val = self._layout.code_addr_to_offset(entry.addr)
                trace.append(CTraceEntry(type_="ind", value=val))

        return CTrace(trace)

    def _raw_dbg_to_ctrace(self, raw_dbg_trace: list[Any]) -> CTrace:
        trace: List[CTraceEntry] = []

        for entry in raw_dbg_trace:
            type_ = DebugTraceEntryType(entry.type)
            if type_ == DebugTraceEntryType.ENTRY_REG_DUMP:
                val = self._layout.code_addr_to_offset(entry.regs.pc)
                trace.append(CTraceEntry(type_="pc", value=val))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xax))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xbx))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xcx))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xdx))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xsi))
                trace.append(CTraceEntry(type_="reg", value=entry.regs.xdi))

        return CTrace(trace)

    def _trim_traces(self, traces: List[CTrace]) -> List[CTrace]:
        """
        Remove trace entries for the instructions before the start of the test case
        and after the exit. Those entries are accidental artifacts of the tracing process
        with DynamoRIO backend, and are irrelevant for the contract verification.
        :return: the traces with the irrelevant entries removed
        """
        # find the address of the enter and exit instructions
        enter_offset = 0  # always zero by convention
        exit_addr = self._layout.get_exit_addr(self._test_case)
        exit_offset = self._layout.code_addr_to_offset(exit_addr)

        # filter out entries where the pc is not in the range of the test case
        # (i.e. before the entry or after the exit)
        new_traces = []
        for trace in traces:
            new_entries = []
            in_range = False
            for entry in trace.get_typed():
                # relevant entries are those that appear after the entry instruction and
                # before the exit instruction;
                # NOTE: it does not imply enter_offset < pc < exit_offset, because we may have
                # code beyond exit_offset when we have multiple actors (i.e., sections)
                if entry.type_ == "pc" and entry.value == enter_offset:
                    in_range = True
                    continue
                if entry.type_ == "pc" and entry.value == exit_offset:
                    in_range = False
                    continue

                # correct for re-entries due to rollbacks after speculative execution.
                # the rollback address in such cases is always within the first section,
                # so a simple range check actually suffices here
                if not in_range and entry.type_ == "pc" \
                   and enter_offset < entry.value < exit_offset:
                    in_range = True

                if in_range:
                    new_entries.append(entry)

            new_traces.append(CTrace(new_entries))

        return new_traces

    def _trim_dbg_traces(self, trimmed_ctraces: List[CTrace],
                         dbg_traces: List[CTrace]) -> List[CTrace]:
        """
        Remove the debug traces that do not correspond to the contract traces.
        :param trimmed_traces: contract traces with the irrelevant entries removed
        :param dbg_traces: debug traces to process
        :return: debug traces that correspond to the contract traces
        """
        assert len(trimmed_ctraces) == len(dbg_traces), "Mismatch between the number of traces"
        new_dbg_traces = []

        for i, dbg_trace in enumerate(dbg_traces):
            # get a list of PC offsets that are present in the contract trace
            pc_offsets = []
            for entry in trimmed_ctraces[i].get_typed():
                if entry.type_ == "pc":
                    pc_offsets.append(entry.value)

            # create a new debug trace that contains only the entries in pc_offsets
            new_dbg_trace = []
            for j, entry in enumerate(dbg_trace.get_typed()):
                if entry.type_ != "pc":
                    continue
                if entry.value in pc_offsets:
                    new_dbg_trace.extend(dbg_trace.get_typed()[j:j + 7])

            new_dbg_traces.append(CTrace(new_dbg_trace))

        return new_dbg_traces
