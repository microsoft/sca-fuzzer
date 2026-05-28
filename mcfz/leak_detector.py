"""
File: Module responsible for parsing contract traces and detecting leaks
      (violations of the non-interference property).

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import os

from typing import (TYPE_CHECKING, Any, List, Tuple, Dict, Iterator, NewType, Literal, Final,
                    cast, get_args, Optional)
from typing_extensions import TypeAlias

import numpy as np
from numpy.typing import NDArray
from tqdm import tqdm

from rvzr.model_dynamorio.trace_decoder import TraceDecoder, TraceEntryType, TraceEntryArray
from .util.compressor import Compressor
from .util.logger import Logger
from .util.worker_pool import send_to_worker_pool

if TYPE_CHECKING:
    from .config import Config

# ==================================================================================================
# Local type definitions
# ==================================================================================================
PC = NewType('PC', int)
""" Program Counter, used to identify instructions in the trace. """

FilePath = str
""" String representing a path """

TraceFileName = NewType('TraceFileName', str)
""" Name of the trace file, used to link leaks back the trace file they were found in. """

LeakType = Literal['I', 'D']
""" Type of the leak:
    'I' for instruction leaks (e.g., secret dependent branch),
    'D' for data leaks (e.g., secret dependent memory access).
"""

ClauseType = Literal['seq', 'cond']
""" Type of the leak:
    'seq' for architectural leaks (happen under SEQ execution clause),
    'cond' for speculative leaks under the COND execution clause.
"""

TraceEntryId = NewType('TraceEntryId', int)
""" Entry ID in the original (raw) trace file, used to locate the leak. """

LeakyInstrDType: Final[np.dtype[np.void]] = np.dtype([
    ('pc', np.uint64),
    ('leak_type', 'U1'),  # 'I' or 'D' as single Unicode character
    ('target_trace_entry_id', np.int64),
    ('ref_trace_entry_id', np.int64),
    ('spec_level', np.uint8),
])
""" Numpy dtype for a leaky instruction:
    * pc: the program counter (PC) of the instruction,
    * leak_type: the type of the leak ('I' or 'D'),
    * target_trace_entry_id: entry ID in the target trace file,
    * ref_trace_entry_id: entry ID in the reference trace file.
"""

LeakyInstrArray: TypeAlias = NDArray[np.void]
""" Array of leaky instructions with dtype LeakyInstrDType. """

InstrArray: TypeAlias = NDArray[np.void]
""" Structured numpy array of decoded trace instructions. """

IndexArray: TypeAlias = NDArray[np.signedinteger[Any]]
""" Numpy array of integer indices. """

LinesInTracePair = NewType('LinesInTracePair', str)
""" A string representing a location of a leak in a trace pair.
    It is in the format "trace_file_name:line_number_in_trace:line_number_in_reference",
    where:
    * trace_file_name is the name of the trace file where
        the leak was found,
    * line_number_in_trace is the line number in the trace file where
        the leak was found,
    * line_number_in_reference is the line number in the reference trace file
        (000.trace, which is the same for all leaks).
"""

LeakageMap = Dict[
    ClauseType,
    Dict[
        LeakType,
        Dict[
            PC,
            List[LinesInTracePair],
        ],
    ]
]
""" Map of leaks found in the traces, indexed by leak type and PC.
    The value is a list of trace file names where the leak was found.
"""

DirName = str
FileName = str
WorkDirMap = Dict[DirName, List[FileName]]

# ==================================================================================================
# Classes representing parsed traces and their elements
# ==================================================================================================
TracedInstructionDType: Final[np.dtype[np.void]] = np.dtype([
    ('pc', np.uint64),  # PC of the instruction
    ('spec_level', np.uint8),  # Level of nested speculation (0 = architectural)
    ('mem_accesses_offset', np.int32),  # Offset in the mem_accesses array
    ('num_mem_accesses', np.int16),  # Number of memory accesses
    ('org_trace_entry_id', np.int32),  # Entry ID in the original (raw) trace
])
TracedInstruction: TypeAlias = np.void


class _Trace:
    """
    A trace of a contract execution, containing a list of instructions executed
    during the execution and their memory accesses.
    """
    file_name: Final[TraceFileName]

    def __init__(self, file_name: str, raw_trace: TraceEntryArray) -> None:
        """
        This function processes the flat trace array and splits it up into instructions and
        memory accesses, while keeping track of the original entry IDs to enable leak localization.

        E.g., if the raw trace contains entries like this (type, addr):
        [(PC, 0x100), (READ, 0x200), (WRITE, 0x300), (PC, 0x110), (READ, 0x400)]

        The resulting trace attributes will be:
        instructions (ndarray of dtype TracedInstructionDType)
            = [(0x100, 0, 2, 0), (0x110, 2, 1, 3)]
        mem_accesses (ndarray of dtype np.uint64)
            = [0x200, 0x300, 0x400]
        """

        self.file_name = TraceFileName(file_name)

        # Count the number of instructions to identify array size
        counts = np.bincount(raw_trace['type'], minlength=6)
        num_instructions = counts[TraceEntryType.ENTRY_PC]
        assert num_instructions < 2 ** 31, \
            "Too many instructions for int32 offsets; trace parsing would need adjustment"

        # Pre-allocate instruction array; mem_accesses is assigned directly below
        self.instructions = np.zeros(num_instructions, dtype=TracedInstructionDType)

        # Process memory accesses first, then free is_mem before building the PC
        # arrays, so that the two N-byte boolean masks never coexist in memory.
        is_mem = ((raw_trace['type'] == TraceEntryType.ENTRY_READ)
                  | (raw_trace['type'] == TraceEntryType.ENTRY_WRITE)
                  | (raw_trace['type'] == TraceEntryType.ENTRY_IND))

        self.mem_accesses = raw_trace['addr'][is_mem]
        assert self.mem_accesses.size < 2 ** 31, \
            "Too many memory accesses for int32 offsets; trace parsing would need adjustment"

        # Build a running count of memory accesses at each raw-trace position.
        mem_cumcount = np.cumsum(is_mem, dtype=np.int32)
        del is_mem  # free N-byte boolean array

        # Extract PC indices and addresses, then free the boolean mask
        is_pc = raw_trace['type'] == TraceEntryType.ENTRY_PC
        pc_indices = np.flatnonzero(is_pc)
        self.instructions['pc'] = raw_trace['addr'][is_pc]
        self.instructions['spec_level'] = raw_trace['spec_level'][is_pc]
        del is_pc  # free N-byte boolean array

        self.instructions['org_trace_entry_id'] = pc_indices

        # For each PC, the cumulative count at that position equals the number
        # of memory accesses strictly before it (PC and mem types are disjoint).
        self.instructions['mem_accesses_offset'] = mem_cumcount[pc_indices]
        del mem_cumcount, pc_indices  # free cumcount (4N) and pc indices (8P)

        # num_mem_accesses = next_offset - current_offset (in-place, avoids concatenation)
        offsets = self.instructions['mem_accesses_offset']
        self.instructions['num_mem_accesses'][:-1] = offsets[1:] - offsets[:-1]
        self.instructions['num_mem_accesses'][-1] = len(self.mem_accesses) - offsets[-1]

    @classmethod
    def empty(cls) -> _Trace:
        """ Create an empty trace instance. """
        trace = cls.__new__(cls)
        trace.instructions = np.zeros(0, dtype=TracedInstructionDType)
        trace.mem_accesses = np.zeros(0, dtype=np.uint64)
        return trace

    def __len__(self) -> int:
        return len(self.instructions)

    def __iter__(self) -> Iterator[np.void]:
        return iter(self.instructions)

    def __getitem__(self, item: int) -> np.void:
        return cast(np.void, self.instructions[item])


class _ChoppedTrace:
    """
    A trace of the execution divided into subtraces, each corresponding to a (nested) speculation
    level. Subtraces are built lazily on iteration so that only one _Trace segment is live at a
    time; the previous segment is freed before the next one is constructed.
    """
    _file_name: TraceFileName
    _raw_trace: TraceEntryArray
    _boundaries: IndexArray

    def __init__(self, file_name: str, raw_trace: TraceEntryArray) -> None:
        self._file_name = TraceFileName(file_name)
        self._raw_trace = raw_trace

        if len(raw_trace) == 0:
            self._boundaries = np.empty(0, dtype=np.intp)
            return

        # Compute segment boundaries: one boundary pair per contiguous run of the same spec_level.
        spec_levels = raw_trace['spec_level']
        change_points = np.flatnonzero(np.diff(spec_levels)) + 1
        self._boundaries = np.concatenate([[0], change_points, [len(raw_trace)]])

    @classmethod
    def empty(cls) -> _ChoppedTrace:
        """ Create an empty trace instance. """
        trace = cls.__new__(cls)
        trace._file_name = TraceFileName('')
        trace._boundaries = np.empty(0, dtype=np.intp)
        return trace

    def __len__(self) -> int:
        return max(0, len(self._boundaries) - 1)

    def __iter__(self) -> Iterator[_Trace]:
        for i in range(len(self._boundaries) - 1):
            start = int(self._boundaries[i])
            end = int(self._boundaries[i + 1])
            segment = self._raw_trace[start:end]

            # Segments with no PC entries carry no instructions; skip them.
            if not np.any(segment['type'] == TraceEntryType.ENTRY_PC):
                continue

            trace = _Trace(self._file_name, segment)
            # _Trace stores segment-relative indices; make them absolute so that
            # leak localization (LinesInTracePair) can reference the original file.
            trace.instructions['org_trace_entry_id'] += start
            yield trace

# ==================================================================================================
# Trace parsing and leakage analysis
# ==================================================================================================
class _LeakDetectionWorker:
    """
    Service class responsible for analyzing a group of traces that share the same reference
    trace (000.trace), that is traces for public-equivalent inputs.

    NOTE: this class is split from the main _LeakDetector class to enable multiprocessing.
    """

    def __init__(self, config: Config) -> None:
        self.trace_decoder = TraceDecoder()
        self._compressor = Compressor(config)
        self._logger = Logger("LeakDetectionWorker")

    def identify_all_leaks_in_group(
            self, trace_files: List[FileName]) -> List[Tuple[LeakyInstrArray, str]]:
        """
        Identify all leaks in a group of traces that share the same reference trace.
        Returns a list of tuples (leaky_instructions, source), where:
        - leaky_instructions is an array of leaky instructions found in the group,
        - source is a string describing the source of the leak (e.g., trace file name).
        """
        all_leaks: List[Tuple[LeakyInstrArray, str]] = []

        # # Find and parse the reference trace (000.trace) for this group of traces.
        try:
            reference_trace_file = self._find_reference_trace(trace_files)
        except ValueError as e:
            self._logger.warning(str(e) + " Skipping this set of traces.")
            return []
        reference_trace = self._parse_trace_file(reference_trace_file)
        if len(reference_trace) == 0:
            return []  # gracefully handle corrupted/missing traces

        # Analyze each trace in the group against the reference trace and collect leaks
        for trace_file in trace_files:
            trace = self._parse_trace_file(trace_file)
            if len(trace) == 0:
                continue  # gracefully handle corrupted/missing traces

            leaky_instructions = self._identify_leaks(reference_trace, trace)
            if leaky_instructions.size == 0:
                continue

            all_leaks.append((leaky_instructions, trace_file))
        return all_leaks

    def _find_reference_trace(self, trace_files: List[FileName]) -> FileName:
        """ Find the reference trace file (000.trace) in the given list of trace files. """
        # Normally the reference trace is the first in the list, but we check to be sure
        for trace_file in trace_files:
            if os.path.basename(trace_file).startswith("000.trace"):
                return trace_file
        raise ValueError(
            f"Reference trace file (000.trace) not found in the given list. {trace_files}")

    def _parse_trace_file(self, trace_file: str) -> _ChoppedTrace:
        if not os.path.isfile(trace_file):
            self._logger.warning(f"File {trace_file} not found.\n    "
                                 "Either tracing failed or is incomplete. Skipping")
            return _ChoppedTrace.empty()

        # If the file is not compressed, parse it directly
        if trace_file.endswith(".trace"):
            raw_trace = self.trace_decoder.decode_trace_file(trace_file)
            try:
                trace = _ChoppedTrace(trace_file, raw_trace)
                return trace
            except IndexError:
                print(f"Trace {trace_file} is likely corrupted! (len: {len(raw_trace)})")
                return _ChoppedTrace.empty()

        # If the file is compressed, decompress and parse it
        if trace_file.endswith(".gz") or trace_file.endswith(".bz2"):
            decompressed_file = self._compressor.decompress_universal(trace_file, keep=True)
            raw_trace = self.trace_decoder.decode_trace_file(decompressed_file)
            trace = _ChoppedTrace(trace_file, raw_trace)
            os.remove(decompressed_file)
            return trace

        raise ValueError(f"Unsupported trace file format: {trace_file}")

    def _identify_leaks(self, ref_trace: _ChoppedTrace,
                        target_trace: _ChoppedTrace) -> LeakyInstrArray:
        """
        Check traces for violations of the non-interference property.

        Compares two execution traces and identifies:
        - I-type leaks: PC divergence (secret-dependent control flow)
        - D-type leaks: Memory access divergence (secret-dependent data access)

        FIXME: Rewind to merge point not implemented; stops at first I-type leak.
        """
        all_leaks: List[LeakyInstrArray] = []
        cur_level = 0
        i_leak_level = None
        prev_level = 0
        last_insts = {0: None}

        # Inspect each chunk of the trace
        for ref_sub, tgt_sub in zip(ref_trace, target_trace):
            cur_level = int(ref_sub.instructions['spec_level'][0])

            # If we have found an I-Leak ...
            if i_leak_level is not None:
                # ... skip this chunk if it's affected by the I-Leak
                if cur_level >= i_leak_level:
                    continue
                # ... keep looking for violations if we exited the I-Leak's window
                else:
                    i_leak_level = None

            # Get the relevant preceding instruction
            if cur_level >= prev_level:
                last_inst = last_insts.setdefault(prev_level, None)
            else:
                last_inst = last_insts.setdefault(cur_level, None)
            prev_level = cur_level
            last_insts[cur_level] = ref_sub.instructions[-1]

            # Check for violations (D-Leaks and I-Leaks)
            leaks = self._identify_leaks_in_subtrace(ref_sub, tgt_sub, last_inst)
            if leaks.size == 0:
                continue
            all_leaks.append(leaks)
            #  Handle I-Leaks
            if np.any(leaks['leak_type'] == 'I'):
                # If the I-Leak is architectural, stop here
                # TODO: implement resume point
                if cur_level == 0:
                    break
                else:
                    i_leak_level = cur_level

        if not all_leaks:
            return np.array([], dtype=LeakyInstrDType)
        return np.concatenate(all_leaks) if len(all_leaks) > 1 else all_leaks[0]

    def _identify_leaks_in_subtrace(self, ref_trace: _Trace, target_trace: _Trace,
                                    last_ref: Optional[TracedInstruction]) -> LeakyInstrArray:
        """
        Check a pair of subtraces that contain instructions of the same speculation level
        for non-interference violations.
        """
        end_id = min(len(ref_trace), len(target_trace))
        if end_id == 0:
            return np.array([], dtype=LeakyInstrDType)

        ref_instr = ref_trace.instructions[:end_id]
        tgt_instr = target_trace.instructions[:end_id]

        # Detect I-type leak (PC divergence)
        i_leak, analysis_end = self._find_i_type_leak(ref_instr, tgt_instr, end_id, last_ref)
        if analysis_end == 0:
            return i_leak

        # Detect D-type leaks (memory access divergence)
        d_leaks = self._find_d_type_leaks(ref_trace, target_trace, ref_instr[:analysis_end],
                                          tgt_instr[:analysis_end])

        # Combine I-type and D-type leaks
        non_empty = [a for a in [d_leaks, i_leak] if len(a) > 0]
        if not non_empty:
            return np.array([], dtype=LeakyInstrDType)
        return np.concatenate(non_empty) if len(non_empty) > 1 else non_empty[0]

    def _find_i_type_leak(self, ref_instr: InstrArray, tgt_instr: InstrArray, end_id: int,
                          last_ref: Optional[TracedInstruction]) -> Tuple[LeakyInstrArray, int]:
        """ Find first I-type leak (PC divergence) and return analysis boundary. """
        pc_mismatch = ref_instr['pc'] != tgt_instr['pc']
        if not pc_mismatch.any():
            return np.array([], dtype=LeakyInstrDType), end_id

        # The instruction before divergence caused the branch
        first_diverge = int(np.argmax(pc_mismatch))
        if first_diverge > 0:
            prev = ref_instr[first_diverge - 1]
        elif last_ref is not None:
            prev = last_ref  # Previous instruction is from another speculative window
        else:
            return np.array([], dtype=LeakyInstrDType), 0  # No previous instruction to blame

        leak = np.array([(prev['pc'], 'I', prev['org_trace_entry_id'], prev['org_trace_entry_id'],
                          prev['spec_level'])], dtype=LeakyInstrDType)
        return leak, first_diverge

    def _find_d_type_leaks(self, ref_trace: _Trace, target_trace: _Trace, ref_instr: InstrArray,
                           tgt_instr: InstrArray) -> LeakyInstrArray:
        """ Find all D-type leaks (memory access divergence) in the given pair of traces. """
        # Find indices of instructions with memory access differences
        # This can be done fast using numpy bulk operations if the memory access structures match
        fast_path_possible = (
            np.array_equal(ref_instr['mem_accesses_offset'], tgt_instr['mem_accesses_offset'])
            and np.array_equal(ref_instr['num_mem_accesses'], tgt_instr['num_mem_accesses']))
        if fast_path_possible:
            indices = self._find_d_leaks_bulk(ref_trace, target_trace, ref_instr)
        else:
            print("WARNING: slow path for D-leak detection not implemented\nSkipping")
            indices = self._find_insts_with_different_accesses(ref_instr, tgt_instr)

        if len(indices) == 0:
            return np.array([], dtype=LeakyInstrDType)

        # Build LeakyInstrArray for D-type leaks from instruction indices
        leaks = np.empty(len(indices), dtype=LeakyInstrDType)
        leaks['pc'] = tgt_instr['pc'][indices]
        leaks['leak_type'] = 'D'
        leaks['target_trace_entry_id'] = tgt_instr['org_trace_entry_id'][indices]
        leaks['ref_trace_entry_id'] = ref_instr['org_trace_entry_id'][indices]
        leaks['spec_level'] = ref_instr['spec_level'][indices]
        return leaks

    def _find_insts_with_different_accesses(self, ref_instr: InstrArray,
                                            tgt_instr: InstrArray) -> IndexArray:
        # Find instructions that have a different number of accesses
        mem_mismatch = ref_instr['num_mem_accesses'] != tgt_instr['num_mem_accesses']
        return np.flatnonzero(mem_mismatch)

    def _find_d_leaks_bulk(self, ref_trace: _Trace, target_trace: _Trace,
                           ref_instr: InstrArray) -> IndexArray:
        """Find D-leaks via bulk memory comparison (same structure fast path)"""
        mem_end = ref_instr[-1]['mem_accesses_offset'] + ref_instr[-1]['num_mem_accesses']
        mem_diff = ref_trace.mem_accesses[:mem_end] != target_trace.mem_accesses[:mem_end]

        if not mem_diff.any():
            return np.array([], dtype=np.intp)

        # Map differing memory indices back to instruction indices via searchsorted
        diff_indices = np.flatnonzero(mem_diff)
        instr_boundaries = ref_instr['mem_accesses_offset'] + ref_instr['num_mem_accesses']
        leak_indices = np.unique(np.searchsorted(instr_boundaries, diff_indices, side='right'))

        # Filter to valid range with non-zero memory accesses
        valid = (leak_indices < len(ref_instr)) & (ref_instr['num_mem_accesses'][leak_indices] > 0)
        return leak_indices[valid]

def _analyse_group_worker(args: Tuple[Config, List[FileName]]) \
        -> Tuple[List[Tuple[LeakyInstrArray, str]], int]:
    """
    Worker function for multiprocessing: analyzes a group of traces and returns the leaks found
    along with the number of traces analyzed (for progress tracking).
    """
    config, trace_files = args
    group_analyser = _LeakDetectionWorker(config)
    leaks = group_analyser.identify_all_leaks_in_group(trace_files)
    return leaks, len(trace_files)


class LeakDetector:
    """
    Class responsible for checking the collected contract traces for violations of the
    non-interference property.
    """

    def __init__(self, config: Config) -> None:
        if not os.path.isdir(config.stage3_wd):
            raise FileNotFoundError(
                f"Stage 3 working directory '{config.stage3_wd}' does not exist.")
        if not os.listdir(config.stage3_wd):
            raise FileNotFoundError(f"Stage 3 working directory '{config.stage3_wd}' is empty.")

        self._logger = Logger("Analyser")
        self._config = config

    def build_leakage_map(self, stage3_dir: str, num_groups: int) -> LeakageMap:
        """
        Analyse all leaks stored in the given directory after a completed fuzzing campaign.
        """
        leakage_map: LeakageMap = {}
        stage3_dir_map = self._get_directory_map(stage3_dir)

        # Initialize a progress bar to track the progress of the analysis
        progress_bar = tqdm(
            total=sum(len(trace_files) for trace_files in stage3_dir_map.values()),
            colour='green',
        )

        # Prepare the list of work items for multiprocessing:
        # a tuple of (config, trace_files) for each group of traces.
        all_groups = list(stage3_dir_map.values())
        if num_groups > 0:
            self._logger.info(
                f"Processing only the first {num_groups} groups of traces as requested.")
            all_groups = all_groups[:num_groups]
        work_items = ((self._config, trace_files) for trace_files in all_groups)

        def _on_result(result: Tuple[List[Tuple[LeakyInstrArray, str]], int]) -> None:
            all_leaks, num_files = result
            progress_bar.update(num_files)
            self._update_global_map(leakage_map, all_leaks)

        send_to_worker_pool(
            task=_analyse_group_worker,
            work_items=work_items,
            num_workers=self._config.num_workers_detector,
            on_complete=_on_result,
        )

        progress_bar.close()
        return leakage_map

    def _get_directory_map(self, stage3_dir: str) -> WorkDirMap:
        """
        Build a map of the working directory that will serve as a todo-list for the analysis.
        This map contains - as keys - all subdirectories in the Stage3 directory that contain
        trace files. The value for each key is a list of trace files in that subdirectory. The
        trace files are produced during the tracing stage, and may or may not be compressed.
        """
        dir_map: WorkDirMap = {}
        subdirs = os.listdir(stage3_dir)
        for subdir in subdirs:
            subdir_full = os.path.join(stage3_dir, subdir)
            if not os.path.isdir(subdir_full):
                continue

            file_list = []
            files_in_dir = set(os.listdir(subdir_full))
            for file_ in files_in_dir:
                # check if the file is a trace file
                # skip all those that are not
                if not file_.endswith(".trace") and \
                   not file_.endswith(".trace.gz") and \
                   not file_.endswith(".trace.bz2"):
                    continue
                # skip uncompressed trace files when a compressed version also exists;
                # decompressing the .gz/.bz2 would otherwise delete the .trace entry
                if file_.endswith(".trace") and \
                   (file_ + ".gz" in files_in_dir or file_ + ".bz2" in files_in_dir):
                    continue
                trace_path = os.path.join(subdir_full, file_)
                file_list.append(trace_path)
            if file_list:
                dir_map[subdir_full] = file_list
        return dir_map

    def _update_global_map(self, leakage_map: LeakageMap, all_leaks: List[Tuple[LeakyInstrArray,
                                                                                str]]) -> None:
        """
        Update the global leakage map with all leaks collected from a group of traces.
        """
        for leaky_instructions, source in all_leaks:
            for leaky_instr in leaky_instructions:
                # Unpack the leaky instruction from numpy structured array
                leak_type: LeakType = leaky_instr['leak_type']
                clauseType: ClauseType = 'seq' if leaky_instr['spec_level'] == 0 else 'cond'
                pc = PC(int(leaky_instr['pc']))
                ref_entry_id = int(leaky_instr['ref_trace_entry_id'])
                tgt_entry_id = int(leaky_instr['target_trace_entry_id'])

                per_type_map = leakage_map.setdefault(clauseType, {}).setdefault(leak_type, {})

                # Create a new leakage location and append it to the map
                leakage_location = LinesInTracePair(f"{source}:{tgt_entry_id}:{ref_entry_id}")
                per_type_map.setdefault(pc, []).append(leakage_location)
