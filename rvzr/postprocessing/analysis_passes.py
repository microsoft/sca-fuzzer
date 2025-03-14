""" File: Collection of minimization passes that analyse the test case without modifying it.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import TYPE_CHECKING, List

from ..model_unicorn import model as uc_model, speculators_basic as uc_speculator, \
    tracer as uc_tracer, interpreter as uc_interpreter
from ..sandbox import CodeArea
from ..arch.x86.target_desc import X86TargetDesc

from .instruction_passes import BaseInstructionMinimizationPass

if TYPE_CHECKING:
    from ..traces import Violation
    from ..tc_components.test_case_data import InputData
    from ..tc_components.test_case_code import TestCaseProgram


class AddViolationCommentsPass(BaseInstructionMinimizationPass):
    """
    An instrumentation pass that iterates over the test case and adds comments
    with the memory addresses of the loads and stores that caused the violation.
    """
    name = "Violation Comment Insertion"
    violation: Violation

    def set_violation(self, violation: Violation) -> None:
        self.violation = violation

    def run(self, test_case: TestCaseProgram, inputs: List[InputData]) -> TestCaseProgram:
        # pylint: disable=too-many-locals
        # pylint: disable=too-many-branches
        # FIXME: this function was written in a hurry and needs to be refactored

        # reproduce the violation to get violating input IDs
        v_inputs = [m.input_ for m in self.violation.measurements[:2]]
        v_input_ids = [m.input_id for m in self.violation.measurements[:2]]

        # create a model that will collect PC and memory traces
        data_start, code_start = 0x2000000, 0x1000000
        model = uc_model.X86UnicornModel((data_start, code_start), X86TargetDesc(),
                                         uc_speculator.SeqSpeculator, uc_tracer.CTTracer,
                                         uc_interpreter.X86ExtraInterpreter)

        # collect traces
        model.tracer.enable_tracing = True  # start tracing from the very beginning
        model.load_test_case(test_case)
        ctraces_obj = model.trace_test_case(v_inputs, 30)
        ctraces: List[List[int]] = [t.get_untyped() for t in ctraces_obj]

        # select loads and stores form the traces
        ctrace_maps = []
        for ctrace in ctraces:
            ctrace_map = {}
            for v1, v2, v3 in zip(ctrace, ctrace[1:], ctrace[2:]):
                if v2 >= data_start > v1 >= code_start:
                    pc = v1 - code_start
                    ld_addr = v2 - data_start
                    st_addr = v3 - data_start if v3 >= data_start else 0
                    ctrace_map[pc] = (ld_addr, st_addr)
            ctrace_maps.append(ctrace_map)

        # get the contents of the asm file
        lines = []
        with open(test_case.asm_path(), "r") as f:
            lines = list(enumerate(f))

        # to simplify the next step, get a dictionary mapping assembly lines to PCs
        line_num_to_pc = {}
        instruction_map = test_case.get_obj().instruction_map()
        for actor_id in instruction_map:
            actor_start_pc = self._fuzzer.model.layout.get_code_addr(CodeArea.MAIN, actor_id)
            for inst in instruction_map[actor_id].values():
                pc = actor_start_pc + inst.section_offset()
                line_num = inst.line_num()
                if line_num != 0:
                    line_num_to_pc[line_num] = pc

        # add a comment with the load/store addresses to the assembly
        with open(test_case.asm_path(), 'w') as f:
            for i, line in lines:
                f.write(line)
                if i not in line_num_to_pc:
                    continue
                pc = line_num_to_pc[i]
                if pc not in ctrace_maps[0] or pc not in ctrace_maps[1]:
                    continue

                ld, st, cl, of = [0, 0], [0, 0], [0, 0], [0, 0]
                iid = v_input_ids
                for i in range(2):
                    ld[i], st[i] = ctrace_maps[i][pc]
                    cl[i] = (ld[i] % 0x1000) // 64
                    of[i] = (ld[i] % 0x1000) % 64

                if st[0] != 0 or st[1] != 0:
                    f.write(
                        f"# mem access: [{iid[0]}] {hex(ld[0])}-{hex(st[0])} CL {cl[0]}:{of[0]} | "
                        f"[{iid[1]}] {hex(ld[1])}-{hex(st[1])} CL {cl[1]}:{of[1]}\n")
                else:
                    f.write(f"# mem access: [{iid[0]}] {hex(ld[0])} CL {cl[0]}:{of[0]} | "
                            f"[{iid[1]}] {hex(ld[1])} CL {cl[1]}:{of[1]}\n")

                if st[0] == 0xff8 or st[1] == 0xff8:
                    f.write("# exception?\n")

        return test_case

    def modify_instruction(self, _: List[str], __: int) -> List[str]:
        return []  # unused

    def verify_modification(self, _: TestCaseProgram, __: List[InputData]) -> bool:
        return True  # unused
