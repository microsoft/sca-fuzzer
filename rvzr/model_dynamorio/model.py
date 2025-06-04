"""
File: DynamoRIO-based backend to the contract model.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import os
import tempfile
from subprocess import check_output, CalledProcessError, STDOUT
from typing import List, Tuple, Optional, TYPE_CHECKING, Final, Any, Dict, Literal

from ..model import Model
from ..sandbox import BaseAddrTuple, SandboxLayout
from ..traces import CTrace, CTraceEntry
from ..tc_components.test_case_data import save_input_sequence_as_rdbf
from ..config import CONF

if TYPE_CHECKING:
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_data import InputData, InputTaint


_DRRUN_TRACING_FLAGS: Final[str] = " --enable-bin-output" + \
    " --instrumented-func test_case_entry"
_ADAPTER_PATH: Final[str] = "~/.local/dynamorio/adapter"
_DRRUN_CMD: Final[str] = "~/.local/dynamorio/drrun " \
    "-c ~/.local/dynamorio/libdr_model.so {flags} -- {binary} {args}"

_TraceType = Literal["eot", "pc", "mem"]
_DbgTraceType = Literal["eot", "pc", "mem", "reg"]

_TRACE_ENTRY_SIZE: Final[int] = 16
_TRACE_ID_TO_NAME: Final[Dict[int, _TraceType]] = {0: "eot", 1: "pc", 2: "mem", 3: "mem"}
_NORMAL_TRACE_MARKER: Final[str] = "T"

_DBG_TRACE_ENTRY_SIZE: Final[int] = 64
_DBG_TRACE_ID_TO_NAME: Final[Dict[int, _DbgTraceType]] = {0: "eot", 1: "reg", 2: "mem", 3: "mem"}
_DEBUG_TRACE_MARKER: Final[str] = "D"

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
        assert self._test_case is not None, "No test case was loaded"
        if len(inputs) == 0:
            return []

        # remove the previous RDBF file if it exists and create a new one
        if self._rdbf_file is not None and os.path.exists(self._rdbf_file):
            os.unlink(self._rdbf_file)
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            self._rdbf_file = f.name

        # store the input sequence
        save_input_sequence_as_rdbf(inputs, self._rdbf_file)

        # call the backend
        cmd = self._construct_drrun_cmd()
        output = check_output(cmd, shell=True)
        assert len(output) >= 16, "No traces were generated"

        # the first two entries in the output are used to create a representation of the sandbox
        code_base_addr = int.from_bytes(output[:8], byteorder="little")
        data_base_addr = int.from_bytes(output[8:16], byteorder="little")
        self.layout = SandboxLayout((data_base_addr, code_base_addr), self._test_case.n_actors())

        # the remainder of the output is raw traces; parse it and remove irrelevant entries
        reader = _TraceReader(self.layout, self._test_case)
        traces, dbg_traces = reader.decode_traces(output[16:])
        assert len(traces) == len(inputs), "Mismatch between the number of inputs and traces"

        if self._enable_mismatch_check_mode:
            # In this mode, the contract trace is the register values at the end of the test case
            arch_traces = [CTrace(t.get_typed()[-6:]) for t in dbg_traces]
            return arch_traces

        return traces

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
            cmd = _DRRUN_CMD.format(flags="", binary="ls", args="/dev/null")
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
            f" --max-spec-window {CONF.model_max_spec_window}"
        if self._enable_mismatch_check_mode:
            flags += " --enable-debug-trace"
        binary = _ADAPTER_PATH
        args = f"{self._rcbf_file} {self._rdbf_file}"
        cmd = _DRRUN_CMD.format(flags=flags, binary=binary, args=args)
        # print(cmd)
        return cmd


class _TraceReader:
    """
    Local class responsible for reading traces produced by DynamoRIO backend,
    removing irrelevant information from them, and converting them to the
    format that is expected by the contract model.
    """

    def __init__(self, layout: SandboxLayout, test_case: TestCaseProgram) -> None:
        self._layout = layout
        self._test_case = test_case

    def decode_traces(self, dr_output: bytes) -> Tuple[List[CTrace], List[CTrace]]:
        """
        Read the traces produced by the DynamoRIO backend and return them in the format
        that is expected by the contract model.
        :return: contract traces and debug traces
        """
        traces: List[CTrace] = []
        dbg_traces: List[CTrace] = []

        # iterate over the binary and parse the entries
        i = 0
        while i < len(dr_output):
            trace_type = dr_output[i:i+1].decode("utf-8")
            i += 1

            if trace_type == _NORMAL_TRACE_MARKER:
                trace, increment = self._decode_trace(dr_output[i:])
                traces.append(trace)
                i += increment

            elif trace_type == _DEBUG_TRACE_MARKER:
                # In addition to the debug trace, there might also be a debug trace
                trace, increment = self._decode_dbg_trace(dr_output[i:])
                dbg_traces.append(trace)
                i += increment

            else:
                raise ValueError(f"Unexpected trace type found: {trace_type}")

        traces = self._trim_traces(traces)
        if dbg_traces:
            dbg_traces = self._trim_dbg_traces(traces, dbg_traces)

        return traces, dbg_traces

    def _decode_trace(self, bin_traces: bytes) -> Tuple[CTrace, int]:
        """
        Decode the next trace in the binary, according to this format:
            - entry: <type: uint64_t> <addr: uint64_t> <size: uint64_t>
            ... (repeated for N entries)
            - exit: <EOT: uint64_t> <0: uint64_t> <0: uint64_t>
        :param bin_traces: the compressed output of the DynamoRIO backend
        :return: decoded trace + the number of bytes consumed
        """
        trace: List[CTraceEntry] = []
        type_: _TraceType
        i = 0
        while i < len(bin_traces):
            type_ = self._decode_next_entry_type(bin_traces, i)

            if type_ == "eot":
                i += _TRACE_ENTRY_SIZE
                break

            val = int.from_bytes(bin_traces[i:i + 8], byteorder="little")
            # NOTE: size is unused

            if type_ == "mem":
                val = self._layout.data_addr_to_offset(val)
                trace.append(CTraceEntry(type_=type_, value=val))
                i += _TRACE_ENTRY_SIZE
                continue
            if type_ == "pc":
                val = self._layout.code_addr_to_offset(val)
                trace.append(CTraceEntry(type_=type_, value=val))
                i += _TRACE_ENTRY_SIZE
                continue

        assert type_ == "eot", "Reached the end of the binary without finding the EOT"
        return CTrace(trace), i

    def _decode_dbg_trace(self, bin_traces: bytes) -> Tuple[CTrace, int]:
        """ Decode the first debug trace in the binary, according to this format:
            - dbg_entry: <type: uint64_t> <xax: uint64_t> <xbx: uint64_t> <xcx: uint64_t>
                        <xdx: uint64_t> <xsi: uint64_t> <xdi: uint64_t> <pc: uint64_t>
            ... (repeated for N entries)
            - dbg_exit: <EOT: uint64_t> <0: uint64_t> <0: uint64_t>
        :param bin_traces: the compressed output of the DynamoRIO backend
        :return: decoded debug trace + the number of bytes consumed
        """
        trace: List[CTraceEntry] = []
        type_: _DbgTraceType
        i = 0
        while i < len(bin_traces):
            type_ = self._decode_next_dbg_entry_type(bin_traces, i)
            if type_ not in _DBG_TRACE_ID_TO_NAME.values():
                raise ValueError(f"Unexpected entry type in debug trace: {type_}")

            if type_ == "eot":
                i += _DBG_TRACE_ENTRY_SIZE
                break

            if type_ == "reg":
                val = int.from_bytes(bin_traces[i + 56:i + 64], byteorder="little")
                val = self._layout.code_addr_to_offset(val)
                trace.append(CTraceEntry(type_="pc", value=val))
                val = int.from_bytes(bin_traces[i + 8:i + 16], byteorder="little")
                trace.append(CTraceEntry(type_=type_, value=val))
                val = int.from_bytes(bin_traces[i + 16:i + 24], byteorder="little")
                trace.append(CTraceEntry(type_=type_, value=val))
                val = int.from_bytes(bin_traces[i + 24:i + 32], byteorder="little")
                trace.append(CTraceEntry(type_=type_, value=val))
                val = int.from_bytes(bin_traces[i + 32:i + 40], byteorder="little")
                trace.append(CTraceEntry(type_=type_, value=val))
                val = int.from_bytes(bin_traces[i + 40:i + 48], byteorder="little")
                trace.append(CTraceEntry(type_=type_, value=val))
                val = int.from_bytes(bin_traces[i + 48:i + 56], byteorder="little")
                trace.append(CTraceEntry(type_=type_, value=val))
                i += _DBG_TRACE_ENTRY_SIZE
                continue

            i += _DBG_TRACE_ENTRY_SIZE

        assert type_ == "eot", "Reached the end of the binary without finding the EOT"
        return CTrace(trace), i

    def _decode_next_entry_type(self, bin_traces: bytes, cursor: int) -> _TraceType:
        """ Decode the entry type and return the type and the number of bytes consumed """
        type_id = int.from_bytes(bin_traces[cursor + 12:cursor + 13], byteorder="little")
        if type_id not in _TRACE_ID_TO_NAME:
            raise ValueError(f"Unknown trace type ID: {type_id}")
        type_ = _TRACE_ID_TO_NAME[type_id]
        # print(type_)
        return type_

    def _decode_next_dbg_entry_type(self, bin_traces: bytes, cursor: int) -> _TraceType:
        """ Decode the entry type and return the type and the number of bytes consumed """
        type_id = int.from_bytes(bin_traces[cursor:cursor + 1], byteorder="little")
        if type_id not in _DBG_TRACE_ID_TO_NAME:
            raise ValueError(f"Unknown trace type ID: {type_id}")
        type_ = _DBG_TRACE_ID_TO_NAME[type_id]
        # print(type_)
        return type_

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
