"""
File: Various helper functions used by multiple parts of the project

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from enum import IntEnum
from typing import Dict, Set, List, Optional

from .isa_loader import InstructionSet
from .interfaces import Coverage, EquivalenceClass, TestCase, Executor, Model, Analyser, \
    ExecutionTrace, TracedInstruction, Instruction, RegisterOperand, OT
from .x86.x86_generator import X86TargetDesc
from .util import STAT


# ==================================================================================================
# Coverage Disabled
# ==================================================================================================
class NoCoverage(Coverage):
    """
    A dummy class with empty functions.
    Used when fuzzing without coverage
    """

    def load_test_case(self, test_case):
        pass

    def generator_hook(self, feedback):
        pass

    def model_hook(self, feedback):
        pass

    def executor_hook(self, feedback):
        pass

    def analyser_hook(self, feedback):
        pass

    def get(self) -> int:
        return 0


# ==================================================================================================
# DependentPairCoverage
# ==================================================================================================
class DT(IntEnum):  # Dependency Type
    REG_GPR = 1
    REG_FLAGS = 2
    MEM_LL = 4
    MEM_LS = 5
    MEM_SL = 6
    MEM_SS = 7
    CONTROL_DIRECT = 8
    CONTROL_COND = 9


class DependentPairCoverage(Coverage):
    """ Coverage of pairs of instructions with a data or control-flow dependency """
    coverage: Dict[DT, Set[int]]
    max_coverage: Dict[DT, int]
    execution_traces: List[ExecutionTrace]
    test_case: TestCase

    def __init__(self, instruction_set: InstructionSet, executor: Executor, model: Model,
                 analyser: Analyser):
        super().__init__(instruction_set, executor, model, analyser)
        self.coverage = {k: set() for k in DT}
        self.max_coverage = {}
        self._calculate_max_coverage()

    def _update_coverage(self, effective_traces: List[ExecutionTrace]) -> None:
        """ The main function of this class - calculates coverage based on the collected traces """

        # get rid of instrumentation in the traces
        # - collect the addresses of instrumentation instructions
        instrumentation_addresses = []
        for addr, instr in self.test_case.address_map.items():
            if instr.is_instrumentation:
                instrumentation_addresses.append(addr)
        # - remove those addresses from traces
        filtered_traces = []
        for trace in effective_traces:
            filtered_trace = [t for t in trace if t.i_address not in instrumentation_addresses]
            filtered_traces.append(filtered_trace)
        effective_traces = filtered_traces

        # process all pairs of the executed instructions
        addr1: TracedInstruction
        addr2: TracedInstruction
        for trace in effective_traces:
            for addr1, addr2 in zip(trace, trace[1:]):
                instr1 = self.test_case.address_map[addr1.i_address]
                instr2 = self.test_case.address_map[addr2.i_address]

                type_: Optional[DT]
                key = hash(self._get_instruction_key(instr1) + self._get_instruction_key(instr2))

                # control flow dependency
                if instr1.control_flow:
                    type_ = DT.CONTROL_DIRECT if instr1.category == "BASE-UNCOND_BR" \
                        else DT.CONTROL_COND
                    self.coverage[type_].add(key)

                # potential memory dependency
                if addr1.accesses and addr2.accesses:
                    types = self._search_memory_dependency(addr1, addr2)
                    for type_ in types:
                        self.coverage[type_].add(key)

                # potential reg dependency
                if self._search_reg_dependency(instr1, instr2):
                    self.coverage[DT.REG_GPR].add(key)
                if self._search_flag_dependency(instr1, instr2):
                    self.coverage[DT.REG_FLAGS].add(key)

    def _calculate_max_coverage(self):
        all_, reg_src, reg_dest, flags_src, flags_dest, mem_src, mem_dest, control_cond = (0,) * 8
        control_direct = 1

        for inst in self.instruction_set.instructions:
            all_ += 1

            reg_ops = [r for r in inst.operands + inst.implicit_operands if r.type == OT.REG]
            if any(reg.src for reg in reg_ops):
                reg_src += 1
            if any(reg.dest for reg in reg_ops):
                reg_dest += 1

            flag_ops = [r for r in inst.operands + inst.implicit_operands if r.type == OT.FLAGS]
            if flag_ops:
                has_src, has_dest = False, False
                for v in flag_ops[0].values:
                    if 'r' in v:
                        has_src = True
                    if 'w' in v:
                        has_dest = True
                if has_src:
                    flags_src += 1
                if has_dest:
                    flags_dest += 1

            if inst.has_write:
                mem_dest += 1
            if [r for r in inst.operands + inst.implicit_operands if r.type == OT.MEM and r.src]:
                mem_src += 1

            if inst.control_flow:
                if inst.category == "BASE-UNCOND_BR":
                    control_direct += 1
                else:
                    control_cond += 1

        self.max_coverage[DT.REG_GPR] = reg_src * (reg_dest + mem_src + mem_dest)
        self.max_coverage[DT.REG_FLAGS] = flags_src * flags_dest
        self.max_coverage[DT.MEM_LL] = mem_src * mem_src
        self.max_coverage[DT.MEM_LS] = mem_src * mem_dest
        self.max_coverage[DT.MEM_SL] = mem_dest * mem_src
        self.max_coverage[DT.MEM_SS] = mem_dest * mem_dest
        self.max_coverage[DT.CONTROL_DIRECT] = control_direct * all_
        self.max_coverage[DT.CONTROL_COND] = control_cond * all_

    def get(self) -> int:
        return sum([len(c) for c in self.coverage.values()])

    def get_brief(self):
        flags = (len(self.coverage[DT.REG_FLAGS]) / self.max_coverage[DT.REG_FLAGS]) * 100
        grp = (len(self.coverage[DT.REG_GPR]) / self.max_coverage[DT.REG_GPR]) * 100
        ll = (len(self.coverage[DT.MEM_LL]) / self.max_coverage[DT.MEM_LL]) * 100
        ls = (len(self.coverage[DT.MEM_LS]) / self.max_coverage[DT.MEM_LS]) * 100
        sl = (len(self.coverage[DT.MEM_SL]) / self.max_coverage[DT.MEM_SL]) * 100
        ss = (len(self.coverage[DT.MEM_SS]) / self.max_coverage[DT.MEM_SS]) * 100
        cond = (len(self.coverage[DT.CONTROL_COND]) / self.max_coverage[DT.CONTROL_COND]) * 100
        dire = (len(self.coverage[DT.CONTROL_DIRECT]) / self.max_coverage[DT.CONTROL_DIRECT]) * 100
        return f"{flags:.2f}, {grp:.2f}, {ll:.2f}, {ls:.2f}," \
               f" {sl:.2f}, {ss:.2f}, {cond:.2f}, {dire:.2f}"

    def load_test_case(self, test_case: TestCase):
        self.test_case = test_case

    def model_hook(self, execution_traces: List[ExecutionTrace]):
        self.execution_traces = execution_traces

    def analyser_hook(self, classes: List[EquivalenceClass]):
        # ignore those traces that belong to ineffective classes
        effective_traces = []
        for eq_cls in classes:
            if len(eq_cls) > 1:
                member_input_id = eq_cls.measurements[0].input_id
                effective_traces.append(self.execution_traces[member_input_id])
        if not effective_traces:
            return

        # we're done with this test case and are ready to collect coverage
        self._update_coverage(effective_traces)
        STAT.coverage = self.get()
        return

    def executor_hook(self, _):
        pass

    def _get_instruction_key(self, instruction: Instruction) -> str:
        key = instruction.name
        for op in instruction.get_all_operands():
            key += "-" + str(op.width) + str(op.type)
        return key

    def _search_memory_dependency(self, traced_instr1: TracedInstruction,
                                  traced_instr2: TracedInstruction) -> List[DT]:
        read_addresses1 = []
        write_addresses1 = []
        for addr in traced_instr1.accesses:
            if addr.is_store:
                write_addresses1.append(addr.m_address)
            else:
                read_addresses1.append(addr.m_address)

        read_addresses2 = []
        write_addresses2 = []
        for addr in traced_instr2.accesses:
            if addr.is_store:
                read_addresses2.append(addr.m_address)
            else:
                write_addresses2.append(addr.m_address)

        types = []
        if any(i in read_addresses2 for i in read_addresses1):
            types.append(DT.MEM_LL)

        if any(i in write_addresses2 for i in read_addresses1):
            types.append(DT.MEM_LS)

        if any(i in read_addresses2 for i in write_addresses1):
            types.append(DT.MEM_SL)

        if any(i in write_addresses2 for i in write_addresses1):
            types.append(DT.MEM_SS)

        return types

    def _search_reg_dependency(self, inst1: Instruction, inst2: Instruction) -> Optional[DT]:
        # normal register dependencies
        dest_regs = [
            r.value for r in inst1.get_dest_operands(True) if isinstance(r, RegisterOperand)
        ]
        src_regs = [r.value for r in inst2.get_src_operands(True) if isinstance(r, RegisterOperand)]
        dest_regs = [X86TargetDesc.gpr_normalized[r] for r in dest_regs]
        src_regs = [X86TargetDesc.gpr_normalized[r] for r in src_regs]
        for r in dest_regs:
            if r in src_regs:
                return DT.REG_GPR

        # address dependency
        mem_operands = [m.value for m in inst2.get_mem_operands()]
        for r in dest_regs:
            for mem in mem_operands:
                if r in mem:
                    return DT.REG_GPR

        return None

    def _search_flag_dependency(self, instr1: Instruction, instr2: Instruction) -> Optional[DT]:
        flags1 = instr1.get_flags_operand()
        flags2 = instr2.get_flags_operand()
        if flags1 and flags2 and flags2.is_dependent(flags1):
            return DT.REG_FLAGS

        return None

    def _dbg_print_coverage_by_type(self):
        print("")
        for k in self.coverage:
            size = len(self.coverage[k])
            ratio = (size / self.max_coverage[k]) * 100
            print(f"- {str(k)}: {size} [{ratio:.3}%]")
