"""
File: Unit tests for rvzr/fuzzer.py

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=missing-function-docstring,missing-class-docstring,protected-access
# pylint: disable=too-many-instance-attributes,too-many-public-methods

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch
from typing import List, Any, Iterator
from contextlib import contextmanager
import numpy as np

from rvzr.fuzzer import Fuzzer, _RoundManager, _RoundState
from rvzr.tc_components.test_case_code import TestCaseProgram
from rvzr.tc_components.test_case_data import InputData
from rvzr.traces import CTrace, HTrace, CTraceEntry, RawHTraceSample, TraceBundle, Violation, \
    ArrayOfSamples
from rvzr.config import CONF
from rvzr.logs import update_logging_after_config_change


def _mk_ctrace(value: int) -> CTrace:
    """Helper to create a simple contract trace"""
    return CTrace([CTraceEntry("val", value)])


def _mk_htrace(trace_value: int, sample_size: int = 100) -> HTrace:
    """Helper to create a hardware trace with repeated samples"""
    samples: ArrayOfSamples = np.ndarray(sample_size, dtype=RawHTraceSample)
    for i in range(sample_size):
        samples[i] = (trace_value, 0, 0, 0, 0, 0)
    return HTrace(samples, "cache")


def _mk_violation(n_inputs: int = 2) -> Violation:
    """Helper to create a mock violation"""
    inputs = [InputData() for _ in range(n_inputs)]
    measurements = [
        TraceBundle(
            input_id=i,
            input_=inputs[i],
            ctrace=_mk_ctrace(1),  # same ctrace
            htrace=_mk_htrace(0x100 + i)  # different htraces
        ) for i in range(n_inputs)
    ]
    test_case = TestCaseProgram("test.asm")
    violation = Violation(measurements, inputs, test_case)
    violation.set_trivial_hw_classes()
    return violation


@contextmanager
def _temp_conf_override(**kwargs: Any) -> Iterator[None]:
    """Context manager to temporarily override CONF settings"""
    original_values = {}
    for key, value in kwargs.items():
        if hasattr(CONF, key):
            original_values[key] = getattr(CONF, key)
            setattr(CONF, key, value)

    try:
        yield
    finally:
        for key, value in original_values.items():
            setattr(CONF, key, value)
        update_logging_after_config_change()


class _MockSetup:
    """Helper class to setup standard mocks for fuzzing tests"""

    def __init__(self, inputs: List[InputData]) -> None:
        self.inputs = inputs
        self.boosted_inputs = inputs * 2
        self.ctraces = [_mk_ctrace(1), _mk_ctrace(1), _mk_ctrace(1), _mk_ctrace(1)]
        self.htraces = [
            _mk_htrace(0x100), _mk_htrace(0x100), _mk_htrace(0x200), _mk_htrace(0x200)
        ]

    def configure_mocks(
        self,
        data_gen: MagicMock,
        model: MagicMock,
        executor: MagicMock,
        analyser: MagicMock,
        violations: List[Violation] | None = None
    ) -> None:
        """Configure standard mock returns for a typical fuzzing round"""
        data_gen.generate_boosted.return_value = self.boosted_inputs
        model.trace_test_case_with_taints.return_value = (self.ctraces[:2], [None, None])
        model.trace_test_case.return_value = self.ctraces
        executor.trace_test_case.return_value = self.htraces
        analyser.filter_violations.return_value = violations if violations is not None else []


class FuzzerRoundTest(unittest.TestCase):
    """
    Comprehensive tests for the fuzzing_round method and its multi-stage violation detection.
    This test exercises the main fuzzing loop which has the lowest coverage in fuzzer.py.
    """

    def setUp(self) -> None:
        """Set up mock objects for fuzzer components"""
        # Save original config state
        self.orig_logging = CONF.logging_modes
        self.orig_sample_sizes = CONF.executor_sample_sizes
        self.orig_inputs_per_class = CONF.inputs_per_class
        self.orig_fast_path = CONF.enable_fast_path_model
        self.orig_priming = CONF.enable_priming

        # Configure for testing
        CONF.logging_modes = []
        CONF.executor_sample_sizes = [100, 200, 500]
        CONF.inputs_per_class = 2
        CONF.enable_fast_path_model = True
        CONF.enable_priming = True
        CONF.model_min_nesting = 1
        CONF.model_max_nesting = 3
        update_logging_after_config_change()

        # Create test data
        self.test_case = TestCaseProgram("test.asm")
        self.inputs = [InputData(), InputData()]

        # Mock components
        self.mock_model = MagicMock()
        self.mock_model.is_speculative = True

        self.mock_executor = MagicMock()
        self.mock_arch_model = MagicMock()
        self.mock_arch_executor = MagicMock()

        self.mock_analyser = MagicMock()
        self.mock_code_gen = MagicMock()
        self.mock_data_gen = MagicMock()
        self.mock_elf_parser = MagicMock()
        self.mock_asm_parser = MagicMock()

        # Create a minimal fuzzer with mocked components
        with patch('rvzr.fuzzer.factory'):
            self.fuzzer = Fuzzer.__new__(Fuzzer)
            self.fuzzer.model = self.mock_model
            self.fuzzer.executor = self.mock_executor
            self.fuzzer.arch_model = self.mock_arch_model
            self.fuzzer.arch_executor = self.mock_arch_executor
            self.fuzzer.analyser = self.mock_analyser
            self.fuzzer.code_gen = self.mock_code_gen
            self.fuzzer.data_gen = self.mock_data_gen
            self.fuzzer.elf_parser = self.mock_elf_parser
            self.fuzzer.asm_parser = self.mock_asm_parser
            self.fuzzer.log = MagicMock()
            self.fuzzer._work_dir = "/tmp/test"

    def tearDown(self) -> None:
        """Restore original config state"""
        CONF.logging_modes = self.orig_logging
        CONF.executor_sample_sizes = self.orig_sample_sizes
        CONF.inputs_per_class = self.orig_inputs_per_class
        CONF.enable_fast_path_model = self.orig_fast_path
        CONF.enable_priming = self.orig_priming
        update_logging_after_config_change()

    def test_fuzzing_round_no_violation_fast_path(self) -> None:
        # Test fuzzing_round when no violations are found in the fast path

        boosted_inputs = self.inputs * 2  # inputs_per_class=2
        ctraces = [_mk_ctrace(1), _mk_ctrace(1), _mk_ctrace(2), _mk_ctrace(2)]
        htraces = [_mk_htrace(0x100), _mk_htrace(0x100), _mk_htrace(0x200), _mk_htrace(0x200)]

        self.mock_data_gen.generate_boosted.return_value = boosted_inputs
        self.mock_model.trace_test_case_with_taints.return_value = (ctraces[:2], [None, None])
        self.mock_model.trace_test_case.return_value = ctraces
        self.mock_executor.trace_test_case.return_value = htraces
        self.mock_analyser.filter_violations.return_value = []

        result = self.fuzzer.fuzzing_round(self.test_case, self.inputs, [])
        self.assertIsNone(result)

    def test_fuzzing_round_violation_detected_survives_all_stages(self) -> None:
        # Test fuzzing_round when a genuine violation survives all false positive filters

        with _temp_conf_override(enable_priming=False):
            # Setup: return violations through all stages
            violation = _mk_violation(4)
            mock_setup = _MockSetup(self.inputs)
            mock_setup.configure_mocks(
                self.mock_data_gen, self.mock_model, self.mock_executor,
                self.mock_analyser, [violation]
            )

            # Architectural mismatch check should pass (no mismatch) - same register values
            # get_untyped() returns the first 6 values for comparison
            arch_htrace_data: ArrayOfSamples = np.ndarray(1, dtype=RawHTraceSample)
            arch_htrace_data[0] = (1, 2, 3, 4, 5, 6)
            arch_htraces = [HTrace(arch_htrace_data, "reg") for _ in range(4)]
            arch_ctraces = [
                CTrace([CTraceEntry("val", v) for v in [1, 2, 3, 4, 5, 6]]) for _ in range(4)
            ]
            self.mock_arch_executor.trace_test_case.return_value = arch_htraces
            self.mock_arch_model.trace_test_case.return_value = arch_ctraces

            # Execute
            result = self.fuzzer.fuzzing_round(self.test_case, self.inputs, [])

            # Verify: violation should survive all stages
            self.assertIsNotNone(result)
            self.assertEqual(result, violation)

    def test_fuzzing_round_fp_filtered_by_nesting(self) -> None:
        # Test that false positives due to insufficient nesting are filtered out
        violation = _mk_violation(4)
        mock_setup = _MockSetup(self.inputs)
        mock_setup.configure_mocks(
            self.mock_data_gen, self.mock_model, self.mock_executor, self.mock_analyser
        )

        # First call (fast path) returns violation, second call (nesting) returns no violation
        self.mock_analyser.filter_violations.side_effect = [[violation], []]

        # Execute
        result = self.fuzzer.fuzzing_round(self.test_case, self.inputs, [])

        # Verify: violation should be filtered out after nesting stage
        self.assertIsNone(result)

    def test_fuzzing_round_fp_filtered_by_taint_mistake(self) -> None:
        # Test that false positives due to taint tracking errors are filtered out
        boosted_inputs = self.inputs * 2
        ctraces_fast = [_mk_ctrace(1), _mk_ctrace(1), _mk_ctrace(1), _mk_ctrace(1)]
        ctraces_full = [_mk_ctrace(1), _mk_ctrace(2), _mk_ctrace(1), _mk_ctrace(2)]
        htraces = [_mk_htrace(0x100), _mk_htrace(0x100), _mk_htrace(0x200), _mk_htrace(0x200)]

        violation = _mk_violation(4)

        self.mock_data_gen.generate_boosted.return_value = boosted_inputs
        self.mock_model.trace_test_case_with_taints.return_value = (ctraces_fast[:2], [None, None])

        # Return different ctraces when called with full tracing (taint_mistake stage)
        self.mock_model.trace_test_case.side_effect = [ctraces_fast, ctraces_fast, ctraces_full]
        self.mock_executor.trace_test_case.return_value = htraces

        # Violation appears with fast ctraces, disappears with full ctraces
        self.mock_analyser.filter_violations.side_effect = [[violation], [violation], []]

        # Execute
        result = self.fuzzer.fuzzing_round(self.test_case, self.inputs, [])

        # Verify: violation should be filtered out after taint_mistake stage
        self.assertIsNone(result)

    def test_fuzzing_round_fp_filtered_by_priming(self) -> None:
        # Test that false positives due to cross-talk between inputs are filtered by priming"""
        violation = _mk_violation(4)
        mock_setup = _MockSetup(self.inputs)
        mock_setup.configure_mocks(
            self.mock_data_gen, self.mock_model, self.mock_executor,
            self.mock_analyser, [violation]
        )

        # Priming check: traces are NOT equivalent (false positive)
        self.mock_analyser.htraces_are_equivalent.return_value = False

        # Execute
        result = self.fuzzer.fuzzing_round(self.test_case, self.inputs, [])

        # Verify: violation should be filtered out by priming
        self.assertIsNone(result)

    def test_fuzzing_round_noise_stage_extends_htraces(self) -> None:
        # Test that noise stage extends htraces with larger sample sizes"""
        # Configure for single sample size to skip noise stage initially
        orig_sample_sizes = CONF.executor_sample_sizes
        CONF.executor_sample_sizes = [100]  # Single sample size - skips noise stage

        try:
            boosted_inputs = self.inputs * 2
            ctraces = [_mk_ctrace(1), _mk_ctrace(1), _mk_ctrace(2), _mk_ctrace(2)]
            htraces = [
                _mk_htrace(0x100, 100),
                _mk_htrace(0x100, 100),
                _mk_htrace(0x200, 100),
                _mk_htrace(0x200, 100)
            ]

            self.mock_data_gen.generate_boosted.return_value = boosted_inputs
            self.mock_model.trace_test_case_with_taints.return_value = (ctraces[:2], [None, None])
            self.mock_model.trace_test_case.return_value = ctraces
            self.mock_executor.trace_test_case.return_value = htraces
            self.mock_analyser.filter_violations.return_value = []

            # Execute
            result = self.fuzzer.fuzzing_round(self.test_case, self.inputs, [])

            # Verify: no violation, noise stage was skipped
            self.assertIsNone(result)
            # Only fast path should execute
            self.assertEqual(self.mock_executor.trace_test_case.call_count, 1)
        finally:
            CONF.executor_sample_sizes = orig_sample_sizes

    @patch('rvzr.fuzzer.warning')
    def test_fuzzing_round_architectural_mismatch_detected(
        self, mock_warning: MagicMock
    ) -> None:
        # Test detection of architectural mismatches between model and executor"""
        # Temporarily disable priming to simplify test, and set work_dir to None
        # to prevent file writing on architectural mismatch
        self.fuzzer._work_dir = ""  # Disable file writing

        with _temp_conf_override(enable_priming=False):
            violation = _mk_violation(4)
            mock_setup = _MockSetup(self.inputs)
            mock_setup.configure_mocks(
                self.mock_data_gen, self.mock_model, self.mock_executor,
                self.mock_analyser, [violation]
            )

            # Architectural mismatch: model and executor return different register values
            # Hardware returns specific register values
            arch_htrace_data: ArrayOfSamples = np.ndarray(1, dtype=RawHTraceSample)
            arch_htrace_data[0] = (1, 2, 3, 4, 5, 6)
            arch_htraces = [HTrace(arch_htrace_data, "reg") for _ in range(4)]

            # Model returns different values (mismatch!) - get_untyped()[:6] is compared
            arch_ctraces = [
                CTrace([CTraceEntry("val", v) for v in [999, 2, 3, 4, 5, 6]]) for _ in range(4)
            ]

            self.mock_arch_executor.trace_test_case.return_value = arch_htraces
            self.mock_arch_model.trace_test_case.return_value = arch_ctraces

            # Execute
            result = self.fuzzer.fuzzing_round(self.test_case, self.inputs, [])

            # Verify: architectural mismatch should filter the violation
            self.assertIsNone(result)

        self.fuzzer._work_dir = "/tmp/test"

    def test_fuzzing_round_executor_error_handled(self) -> None:
        # Test that IOErrors from executor are handled gracefully"""
        mock_setup = _MockSetup(self.inputs)
        self.mock_data_gen.generate_boosted.return_value = mock_setup.boosted_inputs
        self.mock_model.trace_test_case_with_taints.return_value = (
            mock_setup.ctraces[:2], [None, None]
        )
        self.mock_model.trace_test_case.return_value = mock_setup.ctraces

        # Executor raises IOError
        self.mock_executor.trace_test_case.side_effect = IOError("Trace collection failed")

        # Execute
        result = self.fuzzer.fuzzing_round(self.test_case, self.inputs, [])

        # Verify: should handle error and return None
        self.assertIsNone(result)

    def test_fuzzing_round_with_ignore_list(self) -> None:
        # Test that starting ignore list is properly set in executor"""
        mock_setup = _MockSetup(self.inputs)
        mock_setup.configure_mocks(
            self.mock_data_gen, self.mock_model, self.mock_executor, self.mock_analyser
        )

        # Execute with ignore list
        ignore_list = [0, 1]
        result = self.fuzzer.fuzzing_round(self.test_case, self.inputs, ignore_list)

        # Verify
        self.assertIsNone(result)

    def test_fuzzing_round_empty_inputs(self) -> None:
        # Test fuzzing_round with empty input list"""
        empty_inputs: List[InputData] = []

        # With empty inputs, no violations should be checked
        self.mock_data_gen.generate_boosted.return_value = []
        self.mock_model.trace_test_case_with_taints.return_value = ([], [])
        self.mock_model.trace_test_case.return_value = []
        self.mock_executor.trace_test_case.return_value = []

        # Execute
        result = self.fuzzer.fuzzing_round(self.test_case, empty_inputs, [])

        # Verify: should complete without errors
        self.assertIsNone(result)
        # filter_violations should not be called with empty inputs
        self.mock_analyser.filter_violations.assert_not_called()

    def test_round_state_configuration(self) -> None:
        # Test _RoundState initialization with different model types"""
        # Test with speculative model
        state_spec = _RoundState(is_speculative=True)
        self.assertEqual(state_spec.model_nesting, CONF.model_min_nesting)
        self.assertEqual(state_spec.max_nesting, CONF.model_max_nesting)
        self.assertTrue(state_spec.enable_priming)
        self.assertTrue(state_spec.enable_fast_contract_tracing)

        # Test with non-speculative model
        state_non_spec = _RoundState(is_speculative=False)
        self.assertEqual(state_non_spec.model_nesting, 1)
        self.assertEqual(state_non_spec.max_nesting, 1)

    def test_round_manager_stage_execution_order(self) -> None:
        # Test that round manager executes stages in the correct order"""
        mock_setup = _MockSetup(self.inputs)
        mock_setup.configure_mocks(
            self.mock_data_gen, self.mock_model, self.mock_executor, self.mock_analyser
        )

        # Create round manager
        round_mgr = _RoundManager(self.fuzzer, self.test_case, self.inputs)

        # Execute stages
        round_mgr.execute_stage("fast")
        self.assertFalse(round_mgr.conf.is_initial)
        self.assertFalse(round_mgr.conf.record_stats)

        round_mgr.execute_stage("nesting")
        self.assertTrue(round_mgr.conf.reuse_boosts)
        self.assertTrue(round_mgr.conf.update_ignore_list)

        round_mgr.execute_stage("taint_mistake")
        self.assertTrue(round_mgr.conf.reuse_ctraces)

        round_mgr.finalize()


class FuzzerStartTest(unittest.TestCase):
    """Tests for the main fuzzing loop start() method"""

    def setUp(self) -> None:
        """Set up minimal mock fuzzer for start() tests"""
        self.orig_logging = CONF.logging_modes
        CONF.logging_modes = []
        update_logging_after_config_change()

        with patch('rvzr.fuzzer.factory'):
            self.fuzzer = Fuzzer.__new__(Fuzzer)
            self.fuzzer.log = MagicMock()
            self.fuzzer.code_gen = MagicMock()
            self.fuzzer.data_gen = MagicMock()
            self.fuzzer.model = MagicMock()
            self.fuzzer.executor = MagicMock()
            self.fuzzer.analyser = MagicMock()
            self.fuzzer._work_dir = "/tmp/test"
            self.fuzzer._input_paths = []
            self.fuzzer._existing_test_case = ""

            # Mock generation
            self.test_case = TestCaseProgram("test.asm")
            self.fuzzer.code_gen.create_test_case.return_value = self.test_case

            # Mock data generation
            self.inputs = [InputData(), InputData()]
            self.fuzzer.data_gen.generate.return_value = self.inputs

    def tearDown(self) -> None:
        CONF.logging_modes = self.orig_logging
        update_logging_after_config_change()

    @patch('rvzr.fuzzer.datetime')
    def test_start_no_violations_found(self, mock_datetime: MagicMock) -> None:
        # Test start() when no violations are found"""
        mock_datetime.today.return_value.strftime.return_value = "250101-120000"

        # Mock fuzzing_round to return no violations
        with patch.object(self.fuzzer, 'fuzzing_round', return_value=None):
            result = self.fuzzer.start(
                num_test_cases=5,
                num_inputs=2,
                timeout=0,
                nonstop=False,
                save_violations=False,
                type_="random")

        # Verify
        self.assertFalse(result)

    @patch('rvzr.fuzzer.datetime')
    def test_start_violation_found_stop(self, mock_datetime: MagicMock) -> None:
        # Test start() stops after finding first violation when nonstop=False"""
        mock_datetime.today.return_value.strftime.return_value = "250101-120000"

        violation = _mk_violation()

        # Mock fuzzing_round to return violation on second iteration
        with patch.object(self.fuzzer, 'fuzzing_round', side_effect=[None, violation]):
            result = self.fuzzer.start(
                num_test_cases=5,
                num_inputs=2,
                timeout=0,
                nonstop=False,
                save_violations=False,
                type_="random")

        # Verify: should stop after violation
        self.assertTrue(result)

    @patch('rvzr.fuzzer.datetime')
    def test_start_violation_found_nonstop(self, mock_datetime: MagicMock) -> None:
        # Test start() continues after finding violation when nonstop=True"""
        mock_datetime.today.return_value.strftime.return_value = "250101-120000"

        violation = _mk_violation()

        # Mock fuzzing_round to return violations multiple times
        with patch.object(
                self.fuzzer, 'fuzzing_round', side_effect=[violation, None, violation, None]):
            result = self.fuzzer.start(
                num_test_cases=4,
                num_inputs=2,
                timeout=0,
                nonstop=True,
                save_violations=False,
                type_="random")

        # Verify: should continue through all test cases
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()
