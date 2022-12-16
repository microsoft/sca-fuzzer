"""
File: x86-specific model implementation

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import re
import copy
import numpy as np
from typing import Tuple, Dict, List, Set

import unicorn.x86_const as ucc
from unicorn import Uc, UC_MEM_WRITE, UC_ARCH_X86, UC_MODE_64, UC_PROT_READ, UC_PROT_NONE

from interfaces import Input, FlagsOperand, RegisterOperand, MemoryOperand, TestCase
from model import UnicornModel, UnicornSpec, UnicornSeq, UnicornBpas, BaseTaintTracker
from x86.x86_target_desc import X86UnicornTargetDesc, X86TargetDesc
from service import UnreachableCode

FLAGS_CF = 0b000000000001
FLAGS_PF = 0b000000000100
FLAGS_AF = 0b000000010000
FLAGS_ZF = 0b000001000000
FLAGS_SF = 0b000010000000
FLAGS_OF = 0b100000000000


class X86UnicornModel(UnicornModel):
    """
    Base class that serves as main interface.
    Loads inputs and executes the test case on x86
    """
    
    input_hash: int = 0

    def __init__(self, sandbox_base, code_start):
        self.target_desc = X86UnicornTargetDesc()
        self.architecture = (UC_ARCH_X86, UC_MODE_64)
        self.rw_fault_mask = (1 << X86TargetDesc.pte_bits["PRESENT"][0]) + \
            (1 << X86TargetDesc.pte_bits["ACCESSED"][0])
        self.write_fault_mask = (1 << X86TargetDesc.pte_bits["RW"][0]) + \
            (1 << X86TargetDesc.pte_bits["DIRTY"][0])

        super().__init__(sandbox_base, code_start)

    def load_test_case(self, test_case: TestCase) -> None:
        # check which permissions have to be set on the pages
        self.rw_protect = bool((0xffffffffffffffff ^ test_case.faulty_pte.mask_clear)
                               & self.rw_fault_mask)
        self.write_protect = bool((0xffffffffffffffff ^ test_case.faulty_pte.mask_clear)
                                  & self.write_fault_mask)
        return super().load_test_case(test_case)

    def _load_input(self, input_: Input):
        """
        Set registers and stack before starting the emulation
        """        
        self.input_hash = hash(input_)
        
        # Set memory:
        # - initialize overflows with zeroes
        self.emulator.mem_write(self.lower_overflow_base, self.overflow_region_values)
        self.emulator.mem_write(self.upper_overflow_base, self.overflow_region_values)

        # - sandbox pages
        self.emulator.mem_write(self.sandbox_base, input_.get_memory().tobytes())

        # Set values in registers
        regs = self.target_desc.registers
        flags = self.target_desc.flags_register
        reg_init_address = self.sandbox_base + self.MAIN_REGION_SIZE + self.FAULTY_REGION_SIZE
        for i, value in enumerate(input_.get_registers()):
            if regs[i] == flags:
                value = (value & np.uint64(2263)) | np.uint64(2)  # type: ignore
            self.emulator.reg_write(regs[i], value)

            # executor uses the lower bytes of the upper_overflow_region to initialize registers
            # we need to match it in the model
            self.emulator.mem_write(reg_init_address, value.tobytes())
            reg_init_address += 8
        self.emulator.mem_write(reg_init_address,
                                self.stack_base.to_bytes(8, byteorder='little', signed=False))

        if self.rw_protect:
            self.emulator.mem_protect(self.sandbox_base + self.MAIN_REGION_SIZE,
                                      self.FAULTY_REGION_SIZE, UC_PROT_NONE)
        elif self.write_protect:
            self.emulator.mem_protect(self.sandbox_base + self.MAIN_REGION_SIZE,
                                      self.FAULTY_REGION_SIZE, UC_PROT_READ)

        self.emulator.reg_write(ucc.UC_X86_REG_RSP, self.stack_base)
        self.emulator.reg_write(ucc.UC_X86_REG_RBP, self.stack_base)
        self.emulator.reg_write(ucc.UC_X86_REG_R14, self.sandbox_base)

    def print_state(self, oneline: bool = False):

        def compressed(val: int):
            if val >= self.sandbox_base and val <= self.sandbox_base + 12288:
                return f"+0x{val - self.sandbox_base:<15x}"
            elif val >= self.sandbox_base - self.OVERFLOW_REGION_SIZE and val < self.sandbox_base:
                return f"+0x{val - self.sandbox_base:<15x}"
            else:
                return f"0x{val:<15x}"

        emulator = self.emulator
        rax = compressed(emulator.reg_read(ucc.UC_X86_REG_RAX))
        rbx = compressed(emulator.reg_read(ucc.UC_X86_REG_RBX))
        rcx = compressed(emulator.reg_read(ucc.UC_X86_REG_RCX))
        rdx = compressed(emulator.reg_read(ucc.UC_X86_REG_RDX))
        rsi = compressed(emulator.reg_read(ucc.UC_X86_REG_RSI))
        rdi = compressed(emulator.reg_read(ucc.UC_X86_REG_RDI))

        if not oneline:
            print("\n\nRegisters:")
            print(f"RAX: {rax}")
            print(f"RBX: {rbx}")
            print(f"RCX: {rcx}")
            print(f"RDX: {rdx}")
            print(f"RSI: {rsi}")
            print(f"RDI: {rdi}")
        else:
            print(f"  rax={rax} "
                  f"rbx={rbx} "
                  f"rcx={rcx} \n"
                  f"  rdx={rdx} "
                  f"rsi={rsi} "
                  f"rdi={rdi} \n"
                  f"  fl={emulator.reg_read(ucc.UC_X86_REG_EFLAGS):012b}")


# ==================================================================================================
# Implementation of Execution Clauses
# ==================================================================================================
class X86UnicornSeq(UnicornSeq, X86UnicornModel):
    pass


class X86UnicornSpec(UnicornSpec, X86UnicornModel):
    pass


class X86UnicornCond(X86UnicornSpec):
    """
    Contract for conditional branch mispredicitons.
    Forces all cond. branches to speculatively go into a wrong target
    """

    jumps = {
        # c - the byte code of the instruction
        # f - the value of EFLAGS
        0x70: lambda c, f, r: (c[1:], f & FLAGS_OF != 0, False),  # JO
        0x71: lambda c, f, r: (c[1:], f & FLAGS_OF == 0, False),  # JNO
        0x72: lambda c, f, r: (c[1:], f & FLAGS_CF != 0, False),  # JB
        0x73: lambda c, f, r: (c[1:], f & FLAGS_CF == 0, False),  # JAE
        0x74: lambda c, f, r: (c[1:], f & FLAGS_ZF != 0, False),  # JZ
        0x75: lambda c, f, r: (c[1:], f & FLAGS_ZF == 0, False),  # JNZ
        0x76: lambda c, f, r: (c[1:], f & FLAGS_CF != 0 or f & FLAGS_ZF != 0, False),  # JNA
        0x77: lambda c, f, r: (c[1:], f & FLAGS_CF == 0 and f & FLAGS_ZF == 0, False),  # JNBE
        0x78: lambda c, f, r: (c[1:], f & FLAGS_SF != 0, False),  # JS
        0x79: lambda c, f, r: (c[1:], f & FLAGS_SF == 0, False),  # JNS
        0x7A: lambda c, f, r: (c[1:], f & FLAGS_PF != 0, False),  # JP
        0x7B: lambda c, f, r: (c[1:], f & FLAGS_PF == 0, False),  # JPO
        0x7C: lambda c, f, r: (c[1:], (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),  # JNGE
        0x7D: lambda c, f, r: (c[1:], (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),  # JNL
        0x7E: lambda c, f, r:
        (c[1:], f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),
        0x7F: lambda c, f, r:
        (c[1:], f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),
        0xE0: lambda c, f, r: (c[1:], r != 1 and (f & FLAGS_ZF == 0), True),  # LOOPNE
        0xE1: lambda c, f, r: (c[1:], r != 1 and (f & FLAGS_ZF != 0), True),  # LOOPE
        0xE2: lambda c, f, r: (c[1:], r != 1, True),  # LOOP
        0xE3: lambda c, f, r: (c[1:], r == 0, False),  # J*CXZ
        0x0F: lambda c, f, r:
        X86UnicornCond.multibyte_jmp.get(c[1], (lambda _, __, ___: ([0], False, False)))(c, f, r)
    }  # yapf: disable

    multibyte_jmp: Dict = {
        0x80: lambda c, f, r: (c[2:], f & FLAGS_OF != 0, False),  # JO
        0x81: lambda c, f, r: (c[2:], f & FLAGS_OF == 0, False),  # JNO
        0x82: lambda c, f, r: (c[2:], f & FLAGS_CF != 0, False),  # JB
        0x83: lambda c, f, r: (c[2:], f & FLAGS_CF == 0, False),  # JAE
        0x84: lambda c, f, r: (c[2:], f & FLAGS_ZF != 0, False),  # JE
        0x85: lambda c, f, r: (c[2:], f & FLAGS_ZF == 0, False),  # JNE
        0x86: lambda c, f, r: (c[2:], f & FLAGS_CF != 0 or f & FLAGS_ZF != 0, False),  # JBE
        0x87: lambda c, f, r: (c[2:], f & FLAGS_CF == 0 and f & FLAGS_ZF == 0, False),  # JA
        0x88: lambda c, f, r: (c[2:], f & FLAGS_SF != 0, False),  # JS
        0x89: lambda c, f, r: (c[2:], f & FLAGS_SF == 0, False),  # JNS
        0x8A: lambda c, f, r: (c[2:], f & FLAGS_PF != 0, False),  # JP
        0x8B: lambda c, f, r: (c[2:], f & FLAGS_PF == 0, False),  # JPO
        0x8C: lambda c, f, r: (c[2:], (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),  # JNGE
        0x8D: lambda c, f, r: (c[2:], (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),  # JNL
        0x8E: lambda c, f, r:
        (c[2:], f & FLAGS_ZF != 0 or (f & FLAGS_SF == 0) != (f & FLAGS_OF == 0), False),
        0x8F: lambda c, f, r:
        (c[2:], f & FLAGS_ZF == 0 and (f & FLAGS_SF == 0) == (f & FLAGS_OF == 0), False),
    }  # yapf: disable

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model: UnicornModel) -> None:
        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return

        # if the instruction is undefined, Unicorn will return a huge value as size
        # skip those
        if size > 15:  # 15 bytes is max instr size on Intel
            return

        # decode the instruction
        code = emulator.mem_read(address, size)
        flags = emulator.reg_read(ucc.UC_X86_REG_EFLAGS)
        rcx = emulator.reg_read(ucc.UC_X86_REG_RCX)
        target, will_jump, is_loop = X86UnicornCond.decode(code, flags, rcx)

        # not a a cond. jump? ignore
        if not target:
            return

        # LOOP instructions must also decrement RCX
        if is_loop:
            emulator.reg_write(ucc.UC_X86_REG_RCX, rcx - 1)

        # Take a checkpoint
        next_instr = address + size + target if will_jump else address + size
        model.checkpoint(emulator, next_instr)

        # Simulate misprediction
        if will_jump:
            emulator.reg_write(ucc.UC_X86_REG_RIP, address + size)
        else:
            emulator.reg_write(ucc.UC_X86_REG_RIP, address + size + target)

    @staticmethod
    def decode(code: bytearray, flags: int, rcx: int) -> Tuple[int, bool, bool]:
        """
        Decodes the instruction encoded in `code` and, if it's a conditional jump,
        returns its expected target, whether it will jump to the target (based
        on the `flags` value), and whether it is a LOOP instruction
        """
        calculate_target = X86UnicornCond.jumps.get(code[0], (lambda _, __, ___:
                                                              ([0], False, False)))
        target, will_jump, is_loop = calculate_target(code, flags, rcx)
        if len(target) == 1:
            return target[0], will_jump, is_loop
        return int.from_bytes(target, byteorder='little'), will_jump, is_loop

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model):
        pass  # cond does not need to speculate mem accesses


class X86UnicornBpas(UnicornBpas, X86UnicornModel):
    pass


class X86UnicornCondBpas(X86UnicornSpec):

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model):
        X86UnicornBpas.speculate_mem_access(emulator, access, address, size, value, model)

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        X86UnicornCond.speculate_instruction(emulator, address, size, model)
        X86UnicornBpas.speculate_instruction(emulator, address, size, model)


class X86FaultModelAbstract(X86UnicornSpec):
    relevant_faults: Set[int]
    curr_instruction_addr: int = 0
    next_instruction_addr: int = 0

    def __init__(self, *args):
        super().__init__(*args)
        self.relevant_faults = set()

    def fault_triggers_speculation(self, errno: int) -> bool:
        # we speculate only on a subset of faults
        if errno not in self.relevant_faults:
            return False

        # reached max spec. window? skip
        if len(self.checkpoints) >= self.nesting:
            return False
        return True

    @staticmethod
    def trace_instruction(emulator, address, size, model: UnicornModel) -> None:
        assert isinstance(model, X86FaultModelAbstract)
        model.curr_instruction_addr = address
        model.next_instruction_addr = address + size
        X86UnicornSpec.trace_instruction(emulator, address, size, model)


class X86UnicornNull(X86FaultModelAbstract):
    """
    Contract describing zero injection on faults
    """
    curr_load: Tuple[int, int]
    pending_restore_protection: bool = False

    def __init__(self, *args):
        super().__init__(*args)
        self.relevant_faults.update([12, 13])

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        assert isinstance(model, X86UnicornNull)
        # restore permissions after speculation - we might have nested injections
        if address != model.curr_instruction_addr and model.pending_restore_protection:
            model.pending_restore_protection = False
            if model.rw_protect:
                model.emulator.mem_protect(model.sandbox_base + model.MAIN_REGION_SIZE,
                                           model.FAULTY_REGION_SIZE, UC_PROT_NONE)
            elif model.write_protect:
                model.emulator.mem_protect(model.sandbox_base + model.MAIN_REGION_SIZE,
                                           model.FAULTY_REGION_SIZE, UC_PROT_READ)

        # store the address for checkpointing (see speculate_fault)
        model.curr_instruction_addr = address
        model.curr_load = (0, 0)

    @staticmethod
    def speculate_mem_access(emulator, access, address, size, value, model):
        assert isinstance(model, X86UnicornNull)
        # save load address for zero injection
        if access != UC_MEM_WRITE:
            model.curr_load = (address, size)

    def speculate_fault(self, errno: int) -> int:
        if not self.fault_triggers_speculation(errno):
            return 0

        # store a checkpoint
        self.checkpoint(self.emulator, self.get_rollback_address())

        # inject zero in loads
        address, size = self.curr_load
        if address != 0:
            # log old value before injecting zero value
            self.store_logs[-1].append((address, self.emulator.mem_read(address, 8)))

            # inject zeros
            self.emulator.mem_write(address, bytes([0 for _ in range(size)]))

        # repeat the instruction
        self.pending_restore_protection = True
        self.emulator.mem_protect(self.sandbox_base + self.MAIN_REGION_SIZE,
                                  self.FAULTY_REGION_SIZE)
        return self.curr_instruction_addr

    def rollback(self) -> int:
        self.emulator.mem_protect(self.sandbox_base + self.MAIN_REGION_SIZE,
                                  self.FAULTY_REGION_SIZE)
        return super().rollback()

    def get_rollback_address(self) -> int:
        """ This function exists so that we can overwrite the rollback in subclasses """
        return self.curr_instruction_addr


class X86UnicornNullTerminating(X86UnicornNull):

    def get_rollback_address(self) -> int:
        return self.code_end


class X86UnicornOOO(X86FaultModelAbstract):
    """
    Contract for out-of-order handling of faults
    """
    dependencies: Set[str]
    dependency_checkpoints: List[Set[str]]
    curr_is_dependent: bool = False

    def __init__(self, *args):
        super().__init__(*args)
        self.relevant_faults.update([6, 12, 13, 21])
        self.dependencies = set()
        self.dependency_checkpoints = []

    def speculate_fault(self, errno: int) -> int:
        if not self.fault_triggers_speculation(errno):
            return 0

        # start speculation
        # we set the rollback address to the end of the testcase
        # because faults are terminating execution
        self.checkpoint(self.emulator, self.code_end)

        # add destinations to the dependency list
        for op in self.current_instruction.get_dest_operands(True):
            if isinstance(op, RegisterOperand):
                self.dependencies.add(X86TargetDesc.gpr_normalized[op.value])
            elif isinstance(op, FlagsOperand):
                for flag in op.get_write_flags():
                    self.dependencies.add(flag)

        # speculatively skip the faulting instruction
        if self.next_instruction_addr >= self.code_end:
            return 0  # no need for speculation if we're at the end
        else:
            return self.next_instruction_addr

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        """
        Track instruction dependencies to skip those instructions that are dependent
        on a faulting instruction
        """
        assert isinstance(model, X86UnicornOOO)

        # reset flag
        model.curr_is_dependent = False

        # track dependencies only after faults
        if not model.in_speculation or not model.dependencies:
            return

        # check if the instruction should be skipped due to a dependency on a faulting instr
        reg_src_operands = []
        reg_dest_operands = []
        address_regs = []
        for op in model.current_instruction.get_all_operands():
            if isinstance(op, RegisterOperand):
                if op.src:
                    reg_src_operands.append(X86TargetDesc.gpr_normalized[op.value])
                if op.dest:
                    reg_dest_operands.append(X86TargetDesc.gpr_normalized[op.value])
            elif isinstance(op, MemoryOperand):
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in X86TargetDesc.gpr_normalized:
                        normalized = X86TargetDesc.gpr_normalized[sub_op]
                        reg_src_operands.append(normalized)
                        address_regs.append(normalized)
            elif isinstance(op, FlagsOperand):
                reg_src_operands.extend(op.get_read_flags())
                reg_dest_operands.extend(op.get_write_flags())

        is_dependent = False
        is_dependent_addr = False
        for reg in reg_src_operands:
            if reg in model.dependencies:
                is_dependent = True
                break
        for reg in address_regs:
            if reg in model.dependencies:
                is_dependent_addr = True

        # remove overwritten values from dependencies
        old_dependencies = list(model.dependencies)  # type cast to force copy
        for reg in reg_dest_operands:
            if reg not in reg_src_operands and reg in model.dependencies:
                model.dependencies.remove(reg)

        if not is_dependent:
            return

        # update dependencies
        for reg in reg_dest_operands:
            model.dependencies.add(reg)

        # special case - exchange instruction swaps dependencies
        if "XCHG" in model.current_instruction.name:
            ops = model.current_instruction.get_reg_operands()
            if len(ops) == 2:
                op1, op2 = [X86TargetDesc.gpr_normalized[op.value] for op in ops]
                if op1 in old_dependencies and op2 not in old_dependencies:
                    model.dependencies.remove(op1)
                elif op1 not in old_dependencies and op2 in old_dependencies:
                    model.dependencies.remove(op2)

        # special case - many memory operations are implemented as two uops,
        # and one of them could be expected even if the other is data-dependent
        # we approximate it by simply not skipping the dependent stores
        if model.current_instruction.has_mem_operand() and not is_dependent_addr:
            return

        # skip the dependent instruction
        model.curr_is_dependent = True

    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, model) -> None:
        if not model.curr_is_dependent:
            X86FaultModelAbstract.trace_mem_access(emulator, access, address, size, value, model)

    def checkpoint(self, emulator: Uc, next_instruction):
        self.dependency_checkpoints.append(copy.copy(self.dependencies))
        return super().checkpoint(emulator, next_instruction)

    def rollback(self) -> int:
        self.dependencies = self.dependency_checkpoints.pop()
        return super().rollback()


class X86UnicornVSPECUnknown(X86FaultModelAbstract):
    """
    Contract for value speculation with unknown values
    """
    reg_taints: Dict
    flag_taints: Dict
    address_taints: Dict
    reg_taints_checkpoints: List[Dict]
    curr_observation: set()

    def __init__(self, *args):
        super().__init__(*args)
        # DIV exceptions only for now
        self.relevant_faults.update([21])
        self.reg_taints = dict()
        self.flag_taints = dict()
        self.address_taints = dict()
        self.reg_taints_checkpoints = []

    def speculate_fault(self, errno: int) -> int:
        if not self.fault_triggers_speculation(errno):
            return 0

        # start speculation
        # we set the rollback address to the end of the testcase
        # because faults are terminating execution
        self.checkpoint(self.emulator, self.code_end)

        # collect source and destination operands for initial tainting        
        reg_src_operands = []
        reg_dest_operands = []
        
        for op in self.current_instruction.get_all_operands():
            if isinstance(op, RegisterOperand):
                if op.src:
                    reg_src_operands.append(X86TargetDesc.gpr_normalized[op.value])
                if op.dest:
                    reg_dest_operands.append(X86TargetDesc.gpr_normalized[op.value])
            elif isinstance(op, MemoryOperand):
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in X86TargetDesc.gpr_normalized:
                        normalized = X86TargetDesc.gpr_normalized[sub_op]
                        reg_src_operands.append(normalized)
            elif isinstance(op, FlagsOperand):
                reg_src_operands.extend(op.get_read_flags())
                reg_dest_operands.extend(op.get_write_flags())                
        
        # self.reg_taints['A'] = {111}     
        # self.reg_taints['D'] = {111}
        # collect value of all source operands
        source_values = set()
        for reg in reg_src_operands:
            reg_id = X86UnicornTargetDesc.reg_decode[reg]
            reg_value = self.emulator.reg_read(reg_id)
            source_values.add(reg_value)
        
        # taint destination registers with taints
        for reg in reg_dest_operands:
            self.reg_taints[reg] = source_values
         
        # speculatively skip the faulting instruction
        if self.next_instruction_addr >= self.code_end:
            return 0  # no need for speculation if we're at the end
        else:
            return self.next_instruction_addr

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        """
        Track how taints move through system and produce correct observations.
        """
        assert isinstance(model, X86UnicornVSPECUnknown)

        # reset flag
        model.curr_observation = set()
        # print('current taints:', model.reg_taints)
        # track dependencies only after faults
        if not model.in_speculation or not model.reg_taints:
            return

        # assemble source and destination operands of instruction
        # code duplication, with method speculate_fault(), could me moved in
        #    into separate method at some point
        reg_src_operands = []
        reg_dest_operands = []
        # if the instruction accesses the memory, these registers are used in the address
        address_regs = []
        for op in model.current_instruction.get_all_operands():
            if isinstance(op, RegisterOperand):
                if op.src:
                    reg_src_operands.append(X86TargetDesc.gpr_normalized[op.value])
                if op.dest:
                    reg_dest_operands.append(X86TargetDesc.gpr_normalized[op.value])
            elif isinstance(op, MemoryOperand):
                for sub_op in re.split(r'\+|-|\*| ', op.value):
                    if sub_op and sub_op in X86TargetDesc.gpr_normalized:
                        normalized = X86TargetDesc.gpr_normalized[sub_op]
                        reg_src_operands.append(normalized)
                        address_regs.append(normalized)
            elif isinstance(op, FlagsOperand):
                reg_src_operands.extend(op.get_read_flags())
                reg_dest_operands.extend(op.get_write_flags())                
        
        # print('source operands:', reg_src_operands)
        # print('destination operands:', reg_dest_operands)
              
        # if source operands are not tainted, possible taint from destination operands 
        #   can be removed and control flow is returned
        # print('intersection: ', reg_src_operands & model.reg_taints.keys())
        if not (reg_src_operands & model.reg_taints.keys()):
            for reg in reg_dest_operands:
                if reg in model.reg_taints:
                    del model.reg_taints[reg]
            return
        
        # check if instruction attempted load from tainted value
        tainted_address_regs = {reg for reg in address_regs if reg in model.reg_taints}
        if model.current_instruction.has_read() and tainted_address_regs:
            # record observation of load as union of all taints in address
            for reg in tainted_address_regs:
                model.curr_observation = model.curr_observation | (model.reg_taints[reg])
            # taint destination operands with replacement taint, to be replaced
            # with hash of entire architecture meaning that destination could
            # not contain anything
            for reg in reg_dest_operands:
                model.reg_taints[reg] = {model.input_hash}
                # print('full input hash:', model.input_hash)
            return
        
        # if model.current_instruction.has_write() and tainted_address_regs:
            ## to be implemented

        # if not a memory operation, propagate taints
        source_taints = set()
        for reg in reg_src_operands:
            # if register is tainted, then value is unknown, so add taint to set
            #   else, add value of register to taint set
            if reg in model.reg_taints:
                source_taints = source_taints | model.reg_taints[reg]
            else:
                reg_id = X86UnicornTargetDesc.reg_decode[reg]
                reg_value = model.emulator.reg_read(reg_id)
                source_taints.add(reg_value)
        
        # taint destination registers with new taints
        #   old taint can be overwritten
        for reg in reg_dest_operands:
            model.reg_taints[reg] = source_taints
            
    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, model) -> None:
        assert isinstance(model, X86UnicornVSPECUnknown)
        # print('memory access, curr observation:', model.curr_observation)
        if model.curr_observation:
            # print('speculative memory access, curr observation:', model.curr_observation)
            # do not access memory, just add memory access to observations
            # print('current taints:', model.reg_taints)            
            observation_list = list(model.curr_observation)
            observation_list.sort()
            observation_hash = hash(tuple(observation_list))
            # print('memory access with observation:', model.curr_observation)
            # observation_hash =  model.curr_observation.pop()
            # print('hash:', observation_hash)
            model.tracer.observe_mem_access(access, observation_hash, size, 1, model)
            # model.tracer.trace.append(model.sandbox_base + model.default_taint)
        else:
            X86FaultModelAbstract.trace_mem_access(emulator, access, address, size, value, model)

    def checkpoint(self, emulator: Uc, next_instruction):
        self.reg_taints_checkpoints.append(copy.copy(self.reg_taints))
        return super().checkpoint(emulator, next_instruction)

    def rollback(self) -> int:
        self.reg_taints = self.reg_taints_checkpoints.pop()
        return super().rollback()


class X86UnicornDivZero(X86FaultModelAbstract):
    injected_value: int = 0

    def __init__(self, *args):
        super().__init__(*args)
        self.relevant_faults.add(21)

    def speculate_fault(self, errno: int) -> int:
        if not self.fault_triggers_speculation(errno):
            return 0

        if self.current_instruction.name not in ["DIV", "IDIV"]:
            return super().speculate_fault(errno)

        # start speculation
        self.checkpoint(self.emulator, self.code_end)

        # inject zero into both destination operands of division
        self.emulator.reg_write(ucc.UC_X86_REG_RAX, 0)
        self.emulator.reg_write(ucc.UC_X86_REG_RDX, 0)

        return self.next_instruction_addr


class X86UnicornDivOverflow(X86FaultModelAbstract):
    div_value: int = 0

    def __init__(self, *args):
        super().__init__(*args)
        self.relevant_faults.add(21)

    def speculate_fault(self, errno: int) -> int:
        if not self.fault_triggers_speculation(errno):
            return 0

        if self.current_instruction.name not in ["DIV", "IDIV"]:
            return super().speculate_fault(errno)

        # get division arguments
        assert len(self.current_instruction.operands) == 1
        assert self.current_instruction.operands[0].src
        divider = self.current_instruction.operands[0]
        if isinstance(divider, RegisterOperand):
            uc_id = X86UnicornTargetDesc.reg_str_to_constant[divider.value]
            value = self.emulator.reg_read(uc_id)
        elif isinstance(divider, MemoryOperand):
            value = self.div_value
        else:
            raise UnreachableCode()

        # skip div by zero exceptions
        if value == 0:
            return super().speculate_fault(errno)

        # start speculation
        self.checkpoint(self.emulator, self.code_end)

        if self.current_instruction.name == "DIV":
            # set carry flag
            # flags = self.emulator.reg_read(ucc.UC_X86_REG_EFLAGS)
            # self.emulator.reg_write(ucc.UC_X86_REG_EFLAGS, flags | FLAGS_CF)

            # execute division with trimming
            width = divider.width
            if width == 64:
                a = self.emulator.reg_read(ucc.UC_X86_REG_RAX)
                d = self.emulator.reg_read(ucc.UC_X86_REG_RDX)
                trimmed_result = (((d << 64) + a) // value) % 0xffffffffffffffff
                self.emulator.reg_write(ucc.UC_X86_REG_RAX, trimmed_result)
                self.emulator.reg_write(ucc.UC_X86_REG_RDX, ((d << 64) + a) % value)
                return self.next_instruction_addr
            if width == 32:
                a = self.emulator.reg_read(ucc.UC_X86_REG_EAX)
                d = self.emulator.reg_read(ucc.UC_X86_REG_EDX)
                trimmed_result = (((d << 32) + a) // value) #0xffffffff% 
                #print(hex(a), hex(d), trimmed_result, 6070540370 % 0xffffffff)
                trimmed_remainder = (((d << 32) + a) % value) # % 0xffffffff
                # self.emulator.reg_write(ucc.UC_X86_REG_RDX, 0)
                # print(trimmed_remainder)
                self.emulator.reg_write(ucc.UC_X86_REG_RAX, trimmed_result)
                self.emulator.reg_write(ucc.UC_X86_REG_RDX, 0)
                return self.next_instruction_addr
            if width == 16:
                a = self.emulator.reg_read(ucc.UC_X86_REG_AX)
                d = self.emulator.reg_read(ucc.UC_X86_REG_DX)
                trimmed_result = (((d << 16) + a) // value) #% 0xffff
                self.emulator.reg_write(ucc.UC_X86_REG_RAX, trimmed_result)
                self.emulator.reg_write(ucc.UC_X86_REG_RDX, ((d << 16) + a) % value)
                return self.next_instruction_addr
            if width == 8:
                a = self.emulator.reg_read(ucc.UC_X86_REG_AX)
                trimmed_result = (a // value) % 0xff
                trimmed_remainder = (a % value) % 0xff
                # self.emulator.reg_write(ucc.UC_X86_REG_AX, 0)
                self.emulator.reg_write(ucc.UC_X86_REG_AH, trimmed_remainder)
                self.emulator.reg_write(ucc.UC_X86_REG_AL, trimmed_result)
                return self.next_instruction_addr
            raise UnreachableCode()
        else:  # IDIV
            raise UnreachableCode()

    @staticmethod
    def trace_mem_access(emulator: Uc, access, address: int, size, value, model):
        model.div_value = int.from_bytes(emulator.mem_read(address, size), "little")
        X86FaultModelAbstract.trace_mem_access(emulator, access, address, size, value, model)


class X86Meltdown(X86FaultModelAbstract):
    """
    Loads from the faulty region speculatively return the in-memory value
    """

    def __init__(self, *args):
        super().__init__(*args)
        self.relevant_faults.update([12, 13])

    def speculate_fault(self, errno: int) -> int:
        self.curr_instruction_addr
        if not self.fault_triggers_speculation(errno):
            return 0

        # store a checkpoint
        self.checkpoint(self.emulator, self.code_end)

        # remove protection
        self.emulator.mem_protect(self.sandbox_base + self.MAIN_REGION_SIZE,
                                  self.FAULTY_REGION_SIZE)

        return self.curr_instruction_addr


class X86CondMeltdown(X86Meltdown, X86UnicornCond):
    pass


class X86FaultSkip(X86FaultModelAbstract):
    """
    As Meltdown but we skip the faulty load.
    """

    def __init__(self, *args):
        super().__init__(*args)
        self.relevant_faults.update([12, 13])

    def speculate_fault(self, errno: int) -> int:
        if not self.fault_triggers_speculation(errno):
            return 0

        # store a checkpoint
        self.checkpoint(self.emulator, self.code_end)

        # remove protection
        self.emulator.mem_protect(self.sandbox_base + self.MAIN_REGION_SIZE,
                                  self.FAULTY_REGION_SIZE)

        # speculatively skip the faulting instruction
        if self.next_instruction_addr >= self.code_end:
            return 0  # no need for speculation if we're at the end
        else:
            return self.next_instruction_addr


class X86NonCanonicalAddress(X86FaultModelAbstract):
    """
     Load from non-canonical addresss
    """
    fault_inst_addr: int

    def __init__(self, *args):
        super().__init__(*args)
        self.relevant_faults.update([6])

    def speculate_fault(self, errno: int) -> int:
        if not self.fault_triggers_speculation(errno):
            return 0

        self.checkpoint(self.emulator, self.code_end)
        self.last_faulty_addr = self.curr_instruction_addr
        return self.curr_instruction_addr

    @staticmethod
    def speculate_instruction(emulator: Uc, address, size, model) -> None:
        assert isinstance(model, X86NonCanonicalAddress)

        if not model.in_speculation or model.last_faulty_addr != address:
            return

        for mem_op in model.current_instruction.get_mem_operands():
            registers = re.split(r'\+|-|\*| ', mem_op.value)
            if len(registers) > 1:
                continue
            uc_reg = X86UnicornTargetDesc.reg_str_to_constant[registers[0]]
            low = 0x00007fffffffffff
            high = 0xffff800000000000
            address = model.emulator.reg_read(uc_reg)  # load address
            if address > low and address < high:
                canonical = address ^ 0x1000000000000
                model.emulator.reg_write(uc_reg, canonical)

                return  # Continue execution with canonical address
        return


# ==================================================================================================
# Taint tracker
# ==================================================================================================
class X86TaintTracker(BaseTaintTracker):
    # ISA-specific fields
    _registers = [
        ucc.UC_X86_REG_RAX, ucc.UC_X86_REG_RBX, ucc.UC_X86_REG_RCX, ucc.UC_X86_REG_RDX,
        ucc.UC_X86_REG_RSI, ucc.UC_X86_REG_RDI, ucc.UC_X86_REG_EFLAGS
    ]

    def __init__(self, initial_observations, sandbox_base=0):
        super().__init__(initial_observations, sandbox_base=sandbox_base)

        # ISA-specific field setup
        self.target_desc = X86TargetDesc()
        self.unicorn_target_desc = X86UnicornTargetDesc()
