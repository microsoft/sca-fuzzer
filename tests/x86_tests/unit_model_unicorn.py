"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=too-many-arguments
# pylint: disable=too-few-public-methods

import unittest
from typing import List, Optional, Type
from copy import deepcopy

from src.model_unicorn import model as uc_model
from src.model_unicorn import tracer as uc_tracer
from src.model_unicorn.speculator_abc import UnicornSpeculator
from src.model_unicorn.interpreter import X86ExtraInterpreter
from src.model_unicorn.speculators_basic import SeqSpeculator, X86CondSpeculator, \
    StoreBpasSpeculator
from src.model_unicorn.speculators_fault import X86UnicornNull, X86UnicornNullAssist, \
    X86Meltdown, X86UnicornDEH

from src.tc_components.test_case_data import InputData
from src.traces import CTrace
from src.x86.x86_target_desc import X86TargetDesc
from src.config import CONF, Conf
from src.logs import update_logging_after_config_change

from .model_common import Inst, InstList, get_default_input, \
    MAIN_OFFSET, FAULTY_OFFSET, MEM_DEFAULT_VALUE, \
    REG_DEFAULT_VALUE, MEM_FAULTY_DEFAULT_VALUE, RSP_DEFAULT_VALUE, CODE_BASE, MEM_BASE

ASM_BRANCH_AND_LOAD = InstList([
    Inst("xor rax, rax", 3, 0, 0),
    Inst("jnz .l1", 2, 0, 0),
    Inst(".l0:", 0, 0, 0),
    Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
    Inst(".l1:", 0, 0, 0),
])

ASM_DOUBLE_BRANCH = InstList([
    Inst("xor rax, rax", 3, 0, 0),
    Inst("jnz .l1", 2, 0, 0),
    Inst(".l0:", 0, 0, 0),
    Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
    Inst("jmp .l3", 2, 0, 0),
    Inst(".l1:", 0, 0, 0),
    Inst("xor rbx, rbx", 3, 0, 0),
    Inst("jnz .l3", 2, 0, 0),
    Inst(".l2:", 0, 0, 0),
    Inst("mov rbx, qword ptr [r14]", 3, MAIN_OFFSET + 0, 2),
    Inst(".l3:", 0, 0, 0),
])

ASM_STORE_AND_LOAD = InstList([
    Inst("mov qword ptr [r14], 42", 3, MAIN_OFFSET + 0, 42),
    Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 42),
])

ASM_STORE_AND_LOAD_AND_LOAD = InstList([
    Inst("mov qword ptr [r14], 42", 7, MAIN_OFFSET + 0, 42),
    Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 42),
    Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + 42, 0),
])

ASM_FENCE = InstList([
    Inst("xor rax, rax", 3, 0, 0),
    Inst("jz .l1", 2, 0, 0),
    Inst(".l0:", 0, 0, 0),
    Inst("mov rax, qword ptr [r14]", 3, MAIN_OFFSET + 0, 1),
    Inst("lfence", 2, 0, 0),
    Inst("mov rax, qword ptr [r14 + 2]", 5, MAIN_OFFSET + 2, 2),
    Inst(".l1:", 0, 0, 0),
])

ASM_FAULTY_ACCESS = InstList([
    Inst("mov rax, qword ptr [r14 + 0x1000]", 7, FAULTY_OFFSET, 0),
    Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + 3, 0),
    Inst("mov rbx, qword ptr [r14 + rbx]", 4, MAIN_OFFSET + REG_DEFAULT_VALUE, 0),
])

ASM_DIV_ZERO = InstList([
    Inst("div rbx", 3, 0, 0),
    Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + 0, 0),
])

ASM_DIV_ZERO2 = InstList([
    Inst("div rbx", 3, 0, 0),
    Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + 0, 0),
    Inst("mov rax, qword ptr [r14 + rax]", 4, MAIN_OFFSET + 0, 0),
])

PF_MASK = 0xfffffffffffffffe


class X86ModelTest(unittest.TestCase):  # pylint: disable=too-many-public-methods
    """
    A suite of tests for the x86 Unicorn-based models
    """

    prev_conf: Optional[Conf]

    @classmethod
    def setUpClass(cls) -> None:
        # make sure that the change in the configuration does not impact the other tests
        cls.prev_conf = deepcopy(CONF)
        CONF.instruction_set = "x86-64"
        CONF.model_backend = 'unicorn'
        CONF.data_generator_seed = 10  # default
        CONF._no_generation = True  # pylint: disable=protected-access
        CONF.logging_modes = []
        update_logging_after_config_change()

    @classmethod
    def tearDownClass(cls) -> None:
        global CONF  # pylint: disable=global-statement
        assert cls.prev_conf is not None
        CONF = cls.prev_conf

    @staticmethod
    def _init_model(speculator_cls: Type[UnicornSpeculator],
                    tracer_class: Type[uc_tracer.UnicornTracer],
                    arch_mode: bool = False) -> uc_model.X86UnicornModel:
        # Initialize a model with the given tracer and return it
        model_ = uc_model.X86UnicornModel(
            bases=(MEM_BASE, CODE_BASE),
            target_desc=X86TargetDesc(),
            speculator_cls=speculator_cls,
            tracer_cls=tracer_class,
            interpreter_cls=X86ExtraInterpreter,
            enable_mismatch_check_mode=arch_mode)
        return model_

    def _get_traces(self,
                    model: uc_model.UnicornModel,
                    instr_list: InstList,
                    inputs: List[InputData],
                    nesting: int = 1,
                    pte_mask: int = 0) -> List[CTrace]:
        tc = instr_list.to_test_case()
        tc.find_actor(name="main").data_properties = pte_mask  # type: ignore
        # Note: the type is ignored because we assign a value to a Final property;
        # this is done for testing purposes only, so it's ok to ignore the type here

        model.load_test_case(tc)
        ctraces = model.trace_test_case(inputs, nesting)
        return ctraces

    @staticmethod
    def _get_default_ct_trace() -> List[int]:
        trace: List[int] = []
        return trace

    def test_l1d_seq(self) -> None:
        # Test L1DTracer with SeqSpeculator
        model = self._init_model(SeqSpeculator, uc_tracer.L1DTracer)
        instructions = ASM_BRANCH_AND_LOAD
        ctraces = self._get_traces(model, instructions, [InputData()])
        self.assertEqual(ctraces[0].get_untyped(), [instructions[3].mem_address])
        self.assertEqual(str(ctraces[0]), "^" + "." * 63)

    def test_ct_seq(self) -> None:
        # Test CTTracer with SeqSpeculator
        model = self._init_model(SeqSpeculator, uc_tracer.CTTracer)
        instructions = ASM_BRANCH_AND_LOAD
        input_ = get_default_input()
        ctraces = self._get_traces(model, instructions, [input_])
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[3].pc_offset)
        expected_trace.append(instructions[3].mem_address)
        expected_trace.append(instructions[5].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_ct_arch_mode(self) -> None:
        # Test CTTracer with SeqSpeculator in the architectural mode
        model = self._init_model(SeqSpeculator, uc_tracer.CTTracer, True)
        instructions = ASM_STORE_AND_LOAD
        input_ = get_default_input()
        ctraces = self._get_traces(model, instructions, [input_])
        full_trace = ctraces[0].get_untyped()

        expected_trace = [
            instructions[1].mem_value,
            REG_DEFAULT_VALUE,
            REG_DEFAULT_VALUE,
            REG_DEFAULT_VALUE,
            REG_DEFAULT_VALUE,
            REG_DEFAULT_VALUE,
        ]
        self.assertEqual(full_trace, expected_trace)

    def test_arch_seq(self) -> None:
        # Test ArchTracer with SeqSpeculator
        model = self._init_model(SeqSpeculator, uc_tracer.ArchTracer)
        instructions = ASM_BRANCH_AND_LOAD
        input_ = get_default_input()
        ctraces = self._get_traces(model, instructions, [input_])
        expected_trace = self._get_default_ct_trace()

        expected_trace = [
            REG_DEFAULT_VALUE, REG_DEFAULT_VALUE, REG_DEFAULT_VALUE, REG_DEFAULT_VALUE,
            REG_DEFAULT_VALUE, REG_DEFAULT_VALUE, REG_DEFAULT_VALUE
        ] + expected_trace

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[3].pc_offset)
        expected_trace.append(instructions[3].mem_value)
        expected_trace.append(instructions[3].mem_address)
        expected_trace.append(instructions[5].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_ct_cond(self) -> None:
        model = self._init_model(X86CondSpeculator, uc_tracer.CTTracer)
        instructions = ASM_BRANCH_AND_LOAD
        input_ = get_default_input()
        ctraces = self._get_traces(model, instructions, [input_])
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[5].pc_offset)
        expected_trace.append(instructions[3].pc_offset)
        expected_trace.append(instructions[3].mem_address)
        expected_trace.append(instructions[5].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_ct_cond_double(self) -> None:
        model = self._init_model(X86CondSpeculator, uc_tracer.CTTracer)
        instructions = ASM_DOUBLE_BRANCH
        input_ = get_default_input()
        ctraces = self._get_traces(model, instructions, [input_], nesting=2)
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[5].pc_offset)
        expected_trace.append(instructions[7].pc_offset)
        expected_trace.append(instructions[10].pc_offset)
        expected_trace.append(instructions[9].pc_offset)
        expected_trace.append(instructions[9].mem_address)
        expected_trace.append(instructions[10].pc_offset)
        expected_trace.append(instructions[3].pc_offset)
        expected_trace.append(instructions[3].mem_address)
        expected_trace.append(instructions[4].pc_offset)
        expected_trace.append(instructions[10].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_ct_bpas(self) -> None:
        model = self._init_model(StoreBpasSpeculator, uc_tracer.CTTracer)
        instructions = ASM_STORE_AND_LOAD_AND_LOAD
        input_ = get_default_input()
        ctraces = self._get_traces(model, instructions, [input_])
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)

        # speculative
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[1].mem_address)
        rax = MEM_DEFAULT_VALUE
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(MAIN_OFFSET + rax)
        expected_trace.append(instructions[3].pc_offset)

        # after rollback
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[1].mem_address)
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(instructions[2].mem_address)
        expected_trace.append(instructions[3].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_rollback_on_fence(self) -> None:
        model = self._init_model(X86CondSpeculator, uc_tracer.CTTracer)
        instructions = ASM_FENCE
        input_ = get_default_input()
        ctraces = self._get_traces(model, instructions, [input_])
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[3].pc_offset)
        expected_trace.append(instructions[3].mem_address)
        expected_trace.append(instructions[4].pc_offset)
        expected_trace.append(instructions[7].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_fault_handling(self) -> None:
        # Test the fault handling mechanism
        model = self._init_model(SeqSpeculator, uc_tracer.CTTracer)
        model._handled_faults.update([12, 13])
        instructions = ASM_FAULTY_ACCESS
        input_ = get_default_input()
        ctraces = self._get_traces(model, instructions, [input_], pte_mask=PF_MASK)
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_ct_deh(self) -> None:
        # Test X86UnicornDEH with CTTracer
        model = self._init_model(X86UnicornDEH, uc_tracer.CTTracer)
        model._handled_faults.update([12, 13])
        instructions = ASM_FAULTY_ACCESS
        input_ = get_default_input()
        ctraces = self._get_traces(model, instructions, [input_], pte_mask=PF_MASK)
        expected_trace = self._get_default_ct_trace()

        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(instructions[2].mem_address)
        expected_trace.append(instructions[3].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_ct_nullinj_assist(self) -> None:
        # Test X86UnicornNullAssist with CTTracer
        model = self._init_model(X86UnicornNullAssist, uc_tracer.CTTracer)
        model._handled_faults.update([12, 13])
        instructions = ASM_FAULTY_ACCESS
        input_ = get_default_input()
        ctraces = self._get_traces(model, instructions, [input_], pte_mask=PF_MASK)
        expected_trace = self._get_default_ct_trace()

        # fault
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)

        # re-execute with changed permissions and inject zero into rax
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        rax = 0

        # execute with speculative rax
        expected_trace.append(instructions[1].pc_offset)  # traced twice due to a quirk in Unicorn
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(MAIN_OFFSET + rax)
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(instructions[2].mem_address)
        expected_trace.append(instructions[3].pc_offset)

        # rollback and re-execute without a fault
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(instructions[1].mem_address)
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(instructions[2].mem_address)
        expected_trace.append(instructions[3].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_ct_nullinj_term(self) -> None:
        # Test X86UnicornNull with CTTracer
        model = self._init_model(X86UnicornNull, uc_tracer.CTTracer)
        model._handled_faults.update([12, 13])
        instructions = ASM_FAULTY_ACCESS
        input_ = get_default_input()
        ctraces = self._get_traces(model, instructions, [input_], pte_mask=PF_MASK)
        expected_trace = self._get_default_ct_trace()

        # fault
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)

        # re-execute with changed permissions and inject zero into rax
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        rax = 0

        # execute with speculative rax
        expected_trace.append(instructions[1].pc_offset)  # traced twice due to a quirk in Unicorn
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(MAIN_OFFSET + rax)
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(instructions[2].mem_address)
        expected_trace.append(instructions[3].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    def test_ct_meltdown(self) -> None:
        # Test X86Meltdown with CTTracer
        model = self._init_model(X86Meltdown, uc_tracer.CTTracer)
        model._handled_faults.update([12, 13])
        instructions = ASM_FAULTY_ACCESS
        input_ = get_default_input()
        ctraces = self._get_traces(model, instructions, [input_], pte_mask=PF_MASK)
        expected_trace = self._get_default_ct_trace()

        # fault
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        expected_trace.append(RSP_DEFAULT_VALUE)

        # re-execute with changed permissions and inject zero into rax
        expected_trace.append(instructions[0].pc_offset)
        expected_trace.append(instructions[0].mem_address)
        rax = MEM_FAULTY_DEFAULT_VALUE

        # execute with speculative rax
        expected_trace.append(instructions[1].pc_offset)
        expected_trace.append(MAIN_OFFSET + rax)
        expected_trace.append(instructions[2].pc_offset)
        expected_trace.append(instructions[2].mem_address)
        expected_trace.append(instructions[3].pc_offset)

        self.assertEqual(ctraces[0].get_untyped(), expected_trace)

    @unittest.skip("No longer maintained")
    def test_ct_vsops(self) -> None:
        # Test x86UnicornVspecOpsDIV with CTTracer
        pass

    @unittest.skip("No longer maintained")
    def test_ct_vsall(self) -> None:
        # Test x86UnicornVspecAllDIV with CTTracer
        pass


if __name__ == '__main__':
    unittest.main()
