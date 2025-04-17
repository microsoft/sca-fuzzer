"""
File: Collection of unit tests for DynamoRIO backend adaptor.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=too-many-arguments
# pylint: disable=too-few-public-methods
# pylint: disable=too-many-public-methods
# pylint: disable=protected-access
# pylint: disable=missing-function-docstring

import unittest
from typing import List, Optional
# from unittest.mock import MagicMock
from pathlib import Path

from rvzr.model_dynamorio.model import DynamoRIOModel

from rvzr.tc_components.test_case_data import InputData
from rvzr.factory import get_model
from rvzr.config import CONF, ConfigException
from rvzr.logs import update_logging_after_config_change

from .model_common import Inst, InstList, get_default_input

TEST_PATH = Path(__file__).resolve()
TEST_DIR = TEST_PATH.parent

# base addresses for calculating expected contract traces
DATA_BASE = 0x1000000
CODE_BASE = 0x8000
MAIN_OFFSET = 0x1000
FAULTY_OFFSET = 0x2000

ASM_NOP = InstList([
    Inst("xor rax, rax", 3, 0, 0),
])

ASM_BRANCH_AND_LOAD = InstList([
    Inst("xor rax, rax", 3, 0, 0),
    Inst("jz .l1", 2, 0, 0),
    Inst(".l0:", 0, 0, 0),
    Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
    Inst(".l1:", 0, 0, 0),
])

ASM_BRANCH_AND_STORE = InstList([
    Inst("xor rax, rax", 3, 0, 0),
    Inst("jz .l1", 2, 0, 0),
    Inst(".l0:", 0, 0, 0),
    Inst("mov qword ptr [r14], 1", 7, MAIN_OFFSET + 0, 1),
    Inst(".l1:", 0, 0, 0),
    Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
])

ASM_BRANCH_NESTED = InstList([
    Inst("xor rax, rax", 3, 0, 0),
    Inst("jz .l2", 2, 0, 0),
    Inst(".l0:", 0, 0, 0),
    Inst("mov qword ptr [r14], 1", 7, MAIN_OFFSET + 0, 1),
    Inst("jz .l2", 2, 0, 0),
    Inst(".l1:", 0, 0, 0),
    Inst("mov qword ptr [r14], 2", 7, MAIN_OFFSET + 0, 1),
    Inst("mov rbx, 1", 7, 0, 0),
    Inst(".l2:", 0, 0, 0),
    Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
])


class X86DRModelTest(unittest.TestCase):
    """
    A suite of tests for the x86 DynamoRIO model.
    """
    _prev_obs_clause: Optional[str] = None
    _prev_exec_clause: Optional[List[str]] = None
    _prev_backend: Optional[str] = None

    @classmethod
    def setUpClass(cls) -> None:
        # make sure that the change in the configuration does not impact the other tests
        CONF._no_generation = True
        CONF.logging_modes = []
        update_logging_after_config_change()

    def _skip_if_not_installed(self) -> None:
        try:
            DynamoRIOModel._check_if_installed()
        except FileNotFoundError:
            self.skipTest("DynamoRIO is not installed")

    def _save_conf(self) -> None:
        self._prev_obs_clause = CONF.contract_observation_clause
        self._prev_exec_clause = CONF.contract_execution_clause
        self._prev_backend = CONF.model_backend

    def _restore_conf(self) -> None:
        assert self._prev_obs_clause is not None and \
               self._prev_exec_clause is not None and \
               self._prev_backend is not None
        CONF.contract_observation_clause = self._prev_obs_clause
        CONF.contract_execution_clause = self._prev_exec_clause
        CONF.model_backend = self._prev_backend

    def _set_clauses(self, obs_clause: str, exec_clause: List[str]) -> None:
        CONF.contract_observation_clause = obs_clause
        CONF.contract_execution_clause = exec_clause
        CONF.model_backend = "dynamorio"

    def test_clause_configuration(self) -> None:
        self._skip_if_not_installed()
        self._save_conf()

        # Set new clauses (valid)
        self._set_clauses("ct", ["seq"])

        # Create a model instance
        model = get_model((DATA_BASE, CODE_BASE))
        self.assertIsInstance(model, DynamoRIOModel)
        assert isinstance(model, DynamoRIOModel)  # this is only to make mypy happy
        self.assertEqual(model._obs_clause_name, "ct")
        self.assertEqual(model._exec_clause_name, "seq")

        # Set new clauses (invalid)
        self._set_clauses("invalid", ["seq"])
        with self.assertRaises(ConfigException) as e:
            _ = get_model((DATA_BASE, CODE_BASE))
        self.assertIn("unsupported observation clause", str(e.exception))
        self.assertIn("- ct", str(e.exception))

        self._set_clauses("ct", ["invalid"])
        with self.assertRaises(ConfigException) as e:
            _ = get_model((DATA_BASE, CODE_BASE))
        self.assertIn("unsupported execution clause", str(e.exception))
        self.assertIn("- seq", str(e.exception))

        # Set new clauses (invalid, alt interface)
        model = DynamoRIOModel((DATA_BASE, CODE_BASE))
        with self.assertRaises(ValueError):
            model.configure_clauses("invalid", "seq")
        with self.assertRaises(ValueError):
            model.configure_clauses("ct", "invalid")

        self._restore_conf()

    def test_load_test_case(self) -> None:
        self._skip_if_not_installed()
        self._save_conf()
        self._set_clauses("ct", ["seq"])

        model = get_model((DATA_BASE, CODE_BASE))
        tc = ASM_NOP.to_test_case()
        model.load_test_case(tc)
        assert isinstance(model, DynamoRIOModel)  # this is only to make mypy happy

        # Check that a temporary file was created and that it contains the test case
        self.assertIsNotNone(model._rcbf_file)
        assert model._rcbf_file is not None
        with open(model._rcbf_file, "rb") as f:
            rcbf_data = f.read()
        self.assertNotEqual(len(rcbf_data), 0)

        self._restore_conf()

    def test_tc_dispatch(self) -> None:
        # Check that the tracing functions create RDBF and RCBF files
        self._skip_if_not_installed()
        self._save_conf()
        self._set_clauses("ct", ["seq"])

        model = get_model((DATA_BASE, CODE_BASE))
        assert isinstance(model, DynamoRIOModel)
        tc = ASM_NOP.to_test_case()
        model.load_test_case(tc)
        _ = model.trace_test_case([InputData()], 0)

        # RDBF
        self.assertIsNotNone(model._rdbf_file)
        assert model._rdbf_file is not None
        with open(model._rdbf_file, "rb") as f:
            rdbf_data = f.read()
        self.assertNotEqual(len(rdbf_data), 0)
        # FIXME: the next two statements should be a part of test_case_data tests
        self.assertEqual(rdbf_data[0], 1)  # number of actors
        self.assertEqual(rdbf_data[8], 1)  # number of inputs

        # RCBF
        self.assertIsNotNone(model._rcbf_file)
        assert model._rcbf_file is not None
        with open(model._rcbf_file, "rb") as f:
            rcbf_data = f.read()
        self.assertEqual(rcbf_data[0], 1)  # number of actors

        # Check that loading another test case with a different input overwrites the files
        tc = ASM_BRANCH_AND_LOAD.to_test_case()
        input_ = InputData()
        input_[0]["main"][0] = 42
        model.load_test_case(tc)
        _ = model.trace_test_case([input_], 0)

        with open(model._rcbf_file, "rb") as f:
            rcbf_data2 = f.read()
        self.assertNotEqual(len(rcbf_data2), 0)
        self.assertNotEqual(rcbf_data, rcbf_data2)

        with open(model._rdbf_file, "rb") as f:
            rdbf_data2 = f.read()
        self.assertNotEqual(len(rdbf_data2), 0)
        self.assertNotEqual(rdbf_data, rdbf_data2)

        self._restore_conf()

    def test_no_trace(self) -> None:
        # Check that tracing with no inputs returns an empty list
        self._skip_if_not_installed()
        self._save_conf()
        self._set_clauses("ct", ["seq"])

        model = get_model((DATA_BASE, CODE_BASE))
        tc = ASM_NOP.to_test_case()
        model.load_test_case(tc)
        assert isinstance(model, DynamoRIOModel)

        ctraces = model.trace_test_case([], 0)
        self.assertEqual(len(ctraces), 0)

        self._restore_conf()

    def test_ct_seq(self) -> None:
        # Check that the tracing functions create RDBF and RCBF files
        self._skip_if_not_installed()
        self._save_conf()
        self._set_clauses("ct", ["seq"])

        model = get_model((DATA_BASE, CODE_BASE))
        assert isinstance(model, DynamoRIOModel)
        instructions = ASM_BRANCH_AND_LOAD
        tc = instructions.to_test_case()
        model.load_test_case(tc)

        input_ = get_default_input()
        ctraces = model.trace_test_case([input_], 0)
        self.assertEqual(len(ctraces), 1)

        expected_trace: List[int] = []

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[5].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_mismatch_check_mode(self) -> None:
        self._skip_if_not_installed()
        self._save_conf()
        self._set_clauses("ct", ["seq"])

        model = get_model((DATA_BASE, CODE_BASE), enable_mismatch_check_mode=True)
        tc = ASM_NOP.to_test_case()
        model.load_test_case(tc)

        input_ = InputData()
        input_[0]['gpr'][0] = 1
        input_[0]['gpr'][1] = 2
        input_[0]['gpr'][2] = 3
        input_[0]['gpr'][3] = 4
        input_[0]['gpr'][4] = 5
        input_[0]['gpr'][5] = 6
        traces = model.trace_test_case([input_], 0)
        reg_values = traces[0].get_untyped()
        self.assertEqual(len(reg_values), 6)
        self.assertEqual(reg_values[0], 0)
        self.assertEqual(reg_values[1], 2)
        self.assertEqual(reg_values[2], 3)
        self.assertEqual(reg_values[3], 4)
        self.assertEqual(reg_values[4], 5)

        self._restore_conf()

    def test_checkpoint_rollback_registers(self) -> None:
        self._skip_if_not_installed()
        self._save_conf()
        self._set_clauses("ct", ["cond"])

        model = get_model((DATA_BASE, CODE_BASE), enable_mismatch_check_mode=True)
        assert isinstance(model, DynamoRIOModel)
        instructions = ASM_BRANCH_AND_LOAD
        tc = instructions.to_test_case()
        model.load_test_case(tc)

        input_ = InputData()
        traces = model.trace_test_case([input_], 0)
        reg_values = traces[0].get_untyped()
        self.assertEqual(len(reg_values), 6)
        self.assertEqual(reg_values[0], 0)

        self._restore_conf()

    def test_checkpoint_rollback_memory(self) -> None:
        self._skip_if_not_installed()
        self._save_conf()
        self._set_clauses("ct", ["cond"])

        model = get_model((DATA_BASE, CODE_BASE), enable_mismatch_check_mode=True)
        assert isinstance(model, DynamoRIOModel)
        instructions = ASM_BRANCH_AND_STORE
        tc = instructions.to_test_case()
        model.load_test_case(tc)

        input_ = InputData()
        input_[0]['main'][0] = 0x42
        traces = model.trace_test_case([input_], 0)
        reg_values = traces[0].get_untyped()
        self.assertEqual(len(reg_values), 6)
        self.assertEqual(reg_values[0], 0x42)

        self._restore_conf()

    def test_checkpoint_rollback_nested(self) -> None:
        self._skip_if_not_installed()
        self._save_conf()
        self._set_clauses("ct", ["cond"])

        model = get_model((DATA_BASE, CODE_BASE), enable_mismatch_check_mode=True)
        assert isinstance(model, DynamoRIOModel)
        instructions = ASM_BRANCH_NESTED
        tc = instructions.to_test_case()
        model.load_test_case(tc)

        input_ = InputData()
        input_[0]['main'][0] = 0x42
        input_[0]['gpr'][1] = 0x1
        traces = model.trace_test_case([input_], 0)
        reg_values = traces[0].get_untyped()
        self.assertEqual(len(reg_values), 6)
        self.assertEqual(reg_values[0], 0x42)
        self.assertEqual(reg_values[1], 1)

        self._restore_conf()

    def test_ct_cond(self) -> None:
        self._skip_if_not_installed()
        self._save_conf()
        self._set_clauses("ct", ["cond"])

        model = get_model((DATA_BASE, CODE_BASE))
        assert isinstance(model, DynamoRIOModel)
        instructions = ASM_BRANCH_NESTED
        tc = instructions.to_test_case()
        model.load_test_case(tc)

        input_ = get_default_input()
        ctraces = model.trace_test_case([input_], 0)
        self.assertEqual(len(ctraces), 1)

        expected_trace: List[int] = []

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[3].pc_offset)  # first misprediction
        expected_trace.append(instructions[3].mem_address)
        expected_trace.append(instructions[4].pc_offset)
        expected_trace.append(instructions[6].pc_offset)  # second misprediction
        expected_trace.append(instructions[6].mem_address)
        expected_trace.append(instructions[7].pc_offset)
        expected_trace.append(instructions[9].pc_offset)
        expected_trace.append(instructions[9].mem_address)
        expected_trace.append(instructions[10].pc_offset)  # first rollback
        expected_trace.append(instructions[9].pc_offset)
        expected_trace.append(instructions[9].mem_address)
        expected_trace.append(instructions[10].pc_offset)  # second rollback
        expected_trace.append(instructions[9].pc_offset)
        expected_trace.append(instructions[9].mem_address)
        expected_trace.append(instructions[10].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)
