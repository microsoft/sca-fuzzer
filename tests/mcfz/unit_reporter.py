"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=missing-function-docstring  # justification: test conventions
# pylint: disable=missing-class-docstring  # justification: test conventions
# pylint: disable=protected-access  # justification: tests inspect internal state

import os
import tempfile
import unittest
from unittest.mock import MagicMock
from typing import List, Any

import numpy as np
from mcfz.leak_detector import _LeakDetectionWorker, _Trace, _ChoppedTrace
from mcfz.reporter import _ReportPrinter
from rvzr.model_dynamorio.trace_decoder import TraceEntryType, TraceEntryDType


def _make_test_config() -> MagicMock:
    """Create a minimal mock Config for testing (num_workers=1)."""
    config = MagicMock()
    config.num_workers = 1
    config.compression_tool = "bzip2"
    return config


def _t(entries: List[Any]) -> np.ndarray:
    """ Shorthand: build a trace-entry array from a list of tuples """
    return np.array(entries, dtype=TraceEntryDType)


class TestReporter(unittest.TestCase):

    def test_trace_parsing(self) -> None:
        # Create a temporary trace file for testing
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.trace', delete=False) as f:
            temp_trace_path = f.name

            # Write the trace marker (b'T' for trace + 7 bytes padding)
            f.write(b'T')
            f.write(b'\x00' * 7)

            # Create one entry of each possible type (except EOT)
            # The order we'll use: PC, READ, WRITE, EXCEPTION, IND, EOT
            test_entries = np.array(
                [
                    (0x1000, 4, 0, TraceEntryType.ENTRY_PC),  # PC entry
                    (0x2000, 8, 0, TraceEntryType.ENTRY_READ),  # READ entry
                    (0x3000, 8, 0, TraceEntryType.ENTRY_WRITE),  # WRITE entry
                    # EXCEPTION entry
                    (0x4000, 0, 0, TraceEntryType.ENTRY_EXCEPTION),
                    (0x5000, 8, 0, TraceEntryType.ENTRY_IND),  # IND entry
                    (0x0000, 0, 0, TraceEntryType.ENTRY_EOT),  # EOT entry
                ],
                dtype=TraceEntryDType)

            # Write the entries to the file
            test_entries.tofile(f)

        try:
            analyzer = _LeakDetectionWorker(_make_test_config())

            # Call analyzer._parse_trace_file with the temporary file path
            chopped_trace = analyzer._parse_trace_file(temp_trace_path)

            # Verify that the returned _Trace object contains all expected entries.
            # All entries here share spec_level=0, so there is exactly one subtrace.
            traces = list(chopped_trace)
            self.assertEqual(len(traces), 1)
            subtrace = traces[0]

            # Check that we have the expected number of instructions (only PC entries)
            self.assertEqual(len(subtrace.instructions), 1)

            # Check that the PC entry is correct
            self.assertEqual(subtrace.instructions[0]['pc'], 0x1000)

            # Check that we have the expected number of memory accesses
            # (READ, WRITE, IND entries)
            self.assertEqual(len(subtrace.mem_accesses), 3)

            # Check that memory accesses are in the right order
            self.assertEqual(subtrace.mem_accesses[0], 0x2000)  # READ
            self.assertEqual(subtrace.mem_accesses[1], 0x3000)  # WRITE
            self.assertEqual(subtrace.mem_accesses[2], 0x5000)  # IND
        except Exception as e:  # pylint: disable=broad-exception-caught
            # justification: any failure while parsing should fail the test with a clear message
            self.fail(f"Trace parsing raised an exception: {e}")

        finally:
            # Clean up the temporary file
            os.remove(temp_trace_path)

    def test_find_i_type_leak(self) -> None:
        # Test detection of I-type leaks
        analyzer = _LeakDetectionWorker(_make_test_config())

        # Case 1: No divergence
        trace1 = _Trace("", _t([
            (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
        ]))
        trace2 = _Trace("", _t([
            (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
        ]))
        end_id = len(trace1)
        leak, first_divergence = analyzer._find_i_type_leak(trace1.instructions,
                                                            trace2.instructions, end_id, None)
        self.assertEqual(len(leak), 0)
        self.assertEqual(first_divergence, end_id)

        # Case 2: Divergence at fist instruction
        trace1 = _Trace("", _t([
            (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
        ]))
        trace2 = _Trace("", _t([
            (0x2000, 4, 0, TraceEntryType.ENTRY_PC),
        ]))
        end_id = len(trace1)
        leak, first_divergence = analyzer._find_i_type_leak(trace1.instructions,
                                                            trace2.instructions, end_id, None)
        self.assertEqual(len(leak), 0)
        self.assertEqual(first_divergence, 0)

        # Case 3: Divergence at a later instruction
        trace1 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x1004, 4, 0, TraceEntryType.ENTRY_PC),
            ]))
        trace2 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x1008, 4, 0, TraceEntryType.ENTRY_PC),
            ]))
        end_id = len(trace1)
        leak, first_divergence = analyzer._find_i_type_leak(trace1.instructions,
                                                            trace2.instructions, end_id, None)
        self.assertEqual(leak[0]['pc'], 0x1000)
        self.assertEqual(first_divergence, 1)

    def test_find_d_leaks_bulk(self) -> None:
        # Test detection of D-type leaks in bulk
        analyzer = _LeakDetectionWorker(_make_test_config())

        # Case 1: No leaks
        trace1 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2000, 8, 0, TraceEntryType.ENTRY_READ),
            ]))
        trace2 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2000, 8, 0, TraceEntryType.ENTRY_READ),
            ]))
        indices = analyzer._find_d_leaks_bulk(trace1, trace2, trace1.instructions)
        self.assertEqual(len(indices), 0)

        # Case 2: One leak on the first mem. access
        trace1 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2000, 8, 0, TraceEntryType.ENTRY_READ),
            ]))
        trace2 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x3000, 8, 0, TraceEntryType.ENTRY_READ),
            ]))
        indices = analyzer._find_d_leaks_bulk(trace1, trace2, trace1.instructions)
        self.assertEqual(len(indices), 1)
        self.assertEqual(indices[0], 0)

        # Case 2: One leak on a later mem. access
        trace1 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2000, 8, 0, TraceEntryType.ENTRY_READ),
                (0x2000, 8, 0, TraceEntryType.ENTRY_WRITE),
            ]))
        trace2 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2000, 8, 0, TraceEntryType.ENTRY_READ),
                (0x3000, 8, 0, TraceEntryType.ENTRY_WRITE),
            ]))
        indices = analyzer._find_d_leaks_bulk(trace1, trace2, trace1.instructions)
        self.assertEqual(len(indices), 1)
        self.assertEqual(indices[0], 0)

        # Case 3: Multiple leaks
        trace1 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2000, 8, 0, TraceEntryType.ENTRY_READ),
                (0x1004, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2000, 8, 0, TraceEntryType.ENTRY_WRITE),
            ]))
        trace2 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2001, 8, 0, TraceEntryType.ENTRY_READ),
                (0x1004, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2001, 8, 0, TraceEntryType.ENTRY_WRITE),
            ]))
        indices = analyzer._find_d_leaks_bulk(trace1, trace2, trace1.instructions)
        self.assertEqual(len(indices), 2)
        self.assertEqual(indices[0], 0)
        self.assertEqual(indices[1], 1)

    def test_find_d_type_leaks(self) -> None:
        # Test detection of D-type leaks
        # NOTE: this test assumes that the d-leak detection uses the fast path and
        # _find_d_leaks_bulk is correct (already tested above)
        analyzer = _LeakDetectionWorker(_make_test_config())

        # Case 1: No leaks
        trace1 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2000, 8, 0, TraceEntryType.ENTRY_READ),
            ]))
        trace2 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2000, 8, 0, TraceEntryType.ENTRY_READ),
            ]))
        leaks = analyzer._find_d_type_leaks(trace1, trace2, trace1.instructions,
                                            trace2.instructions)
        self.assertEqual(len(leaks), 0)

        # Case 2: One leak
        trace1 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2000, 8, 0, TraceEntryType.ENTRY_READ),
            ]))
        trace2 = _Trace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x3000, 8, 0, TraceEntryType.ENTRY_READ),
            ]))
        leaks = analyzer._find_d_type_leaks(trace1, trace2, trace1.instructions,
                                            trace2.instructions)
        self.assertEqual(len(leaks), 1)
        self.assertEqual(leaks[0]['pc'], 0x1000)

    def test_identify_leaks(self) -> None:
        #  Test combined leak identification
        # NOTE: this test assumes that both i-type and d-type leak
        # detection methods are correct (already tested above)
        analyzer = _LeakDetectionWorker(_make_test_config())

        # Case: Both i-type and d-type leaks (all entries at spec_level=0 → single subtrace)
        trace1 = _ChoppedTrace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2000, 8, 0, TraceEntryType.ENTRY_READ),
                (0x1004, 4, 0, TraceEntryType.ENTRY_PC),
                (0x1008, 4, 0, TraceEntryType.ENTRY_PC),
            ]))
        trace2 = _ChoppedTrace(
            "",
            _t([
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2001, 8, 0, TraceEntryType.ENTRY_READ),
                (0x1004, 4, 0, TraceEntryType.ENTRY_PC),
                (0x100a, 4, 0, TraceEntryType.ENTRY_PC),
            ]))
        leaks = analyzer._identify_leaks(trace1, trace2)
        self.assertEqual(len(leaks), 2)
        self.assertEqual(leaks[0]['leak_type'], 'D')
        self.assertEqual(leaks[0]['pc'], 0x1000)
        self.assertEqual(leaks[1]['leak_type'], 'I')
        self.assertEqual(leaks[1]['pc'], 0x1004)

    def test_identify_leaks_with_speculative_window(self) -> None:
        # Trace structure (ARCH = spec_level 0, SPEC = spec_level 1):
        #
        #   1 ARCH  no leak
        #   2 ARCH  no leak
        #   3 ARCH  D-Leak (reported)          ← READ addr differs
        #   4 SPEC  no leak
        #   5 SPEC  no leak
        #   6 ARCH  no leak
        #   7 ARCH  I-Leak (reported)          ← next PC differs
        #   8 ARCH  diverging instruction
        #   9 ARCH  D-Leak NOT reported        ← beyond I-Leak's analysis boundary
        #  10 SPEC  no leak
        #  11 SPEC  no leak
        #  12 SPEC  D-Leak NOT reported        ← subtrace skipped (arch-level I-Leak)
        analyzer = _LeakDetectionWorker(_make_test_config())

        ref = _ChoppedTrace(
            "ref",
            _t([
                # subtrace 1: spec_level=0
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x1004, 4, 0, TraceEntryType.ENTRY_PC),
                (0x2001, 8, 0, TraceEntryType.ENTRY_READ),  # READ for ARCH 2 (D-Leak)
                (0x1008, 4, 0, TraceEntryType.ENTRY_PC),
                # subtrace 2: spec_level=1
                (0x100d, 4, 1, TraceEntryType.ENTRY_PC),  # First instruction from window
                (0x1010, 4, 1, TraceEntryType.ENTRY_PC),
                # subtrace 3: spec_level=0
                (0x3004, 4, 0, TraceEntryType.ENTRY_PC),  # First instr when resuming from spec
                (0x1014, 4, 0, TraceEntryType.ENTRY_PC),
                (0xdead, 4, 0, TraceEntryType.ENTRY_PC),  # not reported
                # subtrace 5: spec_level=1
                (0x1028, 4, 1, TraceEntryType.ENTRY_PC),
                (0x102c, 4, 1, TraceEntryType.ENTRY_PC),
                (0x4001, 8, 1, TraceEntryType.ENTRY_READ),  # READ for SPEC 12 (not reported)
            ]))
        tgt = _ChoppedTrace(
            "tgt",
            _t([
                # subtrace 1: spec_level=0
                (0x1000, 4, 0, TraceEntryType.ENTRY_PC),
                (0x1004, 4, 0, TraceEntryType.ENTRY_PC),
                (0xdead, 8, 0, TraceEntryType.ENTRY_READ),  # READ for ARCH 2 (D-Leak)
                (0x1008, 4, 0, TraceEntryType.ENTRY_PC),
                # subtrace 2: spec_level=1
                (0x100c, 4, 1, TraceEntryType.ENTRY_PC),  # First instruction from window
                (0x1010, 4, 1, TraceEntryType.ENTRY_PC),
                # subtrace 3: spec_level=0
                (0x3008, 4, 0, TraceEntryType.ENTRY_PC),  # First instr when resuming from spec
                (0x1014, 4, 0, TraceEntryType.ENTRY_PC),
                (0xbeef, 4, 0, TraceEntryType.ENTRY_PC),  # not reported
                # subtrace 5: spec_level=1
                (0x1028, 4, 1, TraceEntryType.ENTRY_PC),
                (0x102c, 4, 1, TraceEntryType.ENTRY_PC),
                (0x4001, 8, 1, TraceEntryType.ENTRY_READ),  # READ for SPEC 12 (not reported)
            ]))

        leaks = analyzer._identify_leaks(ref, tgt)

        self.assertEqual(len(leaks), 3)
        self.assertEqual(leaks[0]['leak_type'], 'D')
        self.assertEqual(leaks[0]['pc'], 0x1004)  # D-Leak blames same instruction
        self.assertEqual(leaks[0]['spec_level'], 0)

        self.assertEqual(leaks[1]['leak_type'], 'I')
        self.assertEqual(leaks[1]['pc'], 0x1008)  # I-Leak blames previous instruction
        self.assertEqual(leaks[1]['spec_level'], 0)

        self.assertEqual(leaks[2]['leak_type'], 'I')
        self.assertEqual(leaks[2]['pc'], 0x1008)  # I-Leak blames previous instruction
        self.assertEqual(leaks[2]['spec_level'], 0)


class TestAllowlistMatching(unittest.TestCase):

    def _check(self, code_line: str, entry: str) -> bool:
        """Helper: check if code_line is allowlisted by a single-entry allowlist."""
        printer = object.__new__(_ReportPrinter)
        return printer._is_allowlisted(code_line, {entry})

    def test_exact_match(self) -> None:
        self.assertTrue(self._check("filename.c:123", "filename.c:123"))

    def test_full_path_match(self) -> None:
        self.assertTrue(self._check("/path/to/filename.c:123", "filename.c:123"))

    def test_partial_path_match(self) -> None:
        self.assertTrue(self._check("/path/to/lib/file.c:42", "lib/file.c:42"))

    def test_no_false_positive_different_filename(self) -> None:
        # 'file.c:123' must not match 'otherfile.c:123'
        self.assertFalse(self._check("/path/to/otherfile.c:123", "file.c:123"))

    def test_no_false_positive_different_line(self) -> None:
        self.assertFalse(self._check("/path/to/filename.c:456", "filename.c:123"))

    def test_full_absolute_path_entry(self) -> None:
        self.assertTrue(
            self._check("/full/path/to/some/file.c:34232", "/full/path/to/some/file.c:34232"))

    def test_no_match_unrelated_path(self) -> None:
        self.assertFalse(self._check("/path/to/somefile.c:123", "otherfile.c:123"))

    def test_filter_allowlist_vrb1(self) -> None:
        allowlist = {'somefile.c:123'}
        printer = object.__new__(_ReportPrinter)
        result = printer._is_allowlisted('somefile.c:123', allowlist)
        self.assertTrue(result)
        result = printer._is_allowlisted('/other/path/keep.c:1', allowlist)
        self.assertFalse(result)

    def test_filter_allowlist_removes_suffix_match(self) -> None:
        # Allowlist entry 'somefile.c:123' should remove '/path/to/somefile.c:123'
        allowlist = {'somefile.c:123'}
        printer = object.__new__(_ReportPrinter)
        self.assertTrue(printer._is_allowlisted('/path/to/somefile.c:123', allowlist))
        self.assertFalse(printer._is_allowlisted('/path/to/somefile.c:456', allowlist))
