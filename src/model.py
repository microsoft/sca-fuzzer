"""
File: Model Interface and its implementations

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from abc import ABC, abstractmethod
import os
from unicorn import *
from unicorn.x86_const import *

from config import CONF
from custom_types import List, Tuple, CTrace
from helpers import assemble, pretty_bitmap
from executor import X86Intel

POW32 = pow(2, 32)


class Model(ABC):
    coverage = None
    RUNTIME_R_SIZE = 1024 * 1024
    CODE_SIZE = 4 * 1024
    RSP_OFFSET = RUNTIME_R_SIZE // 2
    RBP_OFFSET = RUNTIME_R_SIZE // 2
    R14_OFFSET = RUNTIME_R_SIZE // 2

    def __init__(self, sandbox_base, stack_base, code_base):
        self.sandbox_base: int = sandbox_base
        self.stack_base: int = stack_base
        self.code_base: int = code_base
        self.rsp_init = stack_base + self.RSP_OFFSET
        self.rbp_init = stack_base + self.RBP_OFFSET
        self.r14_init = sandbox_base + self.R14_OFFSET

    @abstractmethod
    def load_test_case(self, test_case_asm: str) -> None:
        pass

    @abstractmethod
    def trace_test_case(self, inputs: List[int], nesting: int, debug: bool = False) -> List[CTrace]:
        pass

    def set_coverage(self, coverage):
        self.coverage = coverage


# =============================================================================
# Unicorn-based predictors
# =============================================================================
UC_FLAGS_CF = 0b000000000001
UC_FLAGS_PF = 0b000000000100
UC_FLAGS_AF = 0b000000010000
UC_FLAGS_ZF = 0b000001000000
UC_FLAGS_SF = 0b000010000000
UC_FLAGS_OF = 0b100000000000


class X86UnicornTracer(ABC):
    """
    A superclass that encodes the attacker capabilities
    """
    trace: List[int]
    coverage_trace: List[Tuple[bool, int]]

    def __init__(self):
        self.trace = []

    def reset_trace(self) -> None:
        self.trace = []
        self.coverage_trace = []

    def get_trace(self) -> CTrace:
        return hash(tuple(self.trace))

    def get_coverage_trace(self):
        return self.coverage_trace

    def trace_mem_access(self, access, address: int, size: int, value: int) -> None:
        if not model.in_speculation:
            self.coverage_trace.append((False, address - model.r14_init))
            if model.debug:
                if access == UC_MEM_READ:
                    val = int.from_bytes(model.emulator.mem_read(address, size), byteorder='little')
                    print(f"  > read: +0x{address - model.r14_init:x} = 0x{val:x}")
                else:
                    print(f"  > write: +0x{address - model.r14_init:x} = 0x{value:x}")

    def trace_code(self, address: int, size: int) -> None:
        if not model.in_speculation:
            self.coverage_trace.append((True, address - model.code_base))
            if model.debug:
                print(f"{address - model.code_base:2x}: ", end="")
                model.print_state(oneline=True)


class L1DTracer(X86UnicornTracer):
    def reset_trace(self):
        self.trace = [0, 0]
        self.coverage_trace = []

    def trace_mem_access(self, access, address, size, value):
        page_offset = (address & 4032) >> 6  # 4032 = 0b111111000000
        cache_set_index = 9223372036854775808 >> page_offset
        if model.in_speculation:
            self.trace[1] |= cache_set_index
        else:
            self.trace[0] |= cache_set_index
        # print(f"{cache_set_index:064b}")
        super(L1DTracer, self).trace_mem_access(access, address, size, value)

    def trace_code(self, address: int, size: int):
        super(L1DTracer, self).trace_code(address, size)

    def get_trace(self) -> CTrace:
        if CONF.ignore_first_cache_line:
            self.trace[0] &= 9223372036854775807
            self.trace[1] &= 9223372036854775807
        return (self.trace[1] << 64) + self.trace[0]


class PCTracer(X86UnicornTracer):
    def trace_mem_access(self, access, address, size, value):
        super(PCTracer, self).trace_mem_access(access, address, size, value)

    def trace_code(self, address: int, size: int):
        self.trace.append(address)
        super(PCTracer, self).trace_code(address, size)


class MemoryTracer(X86UnicornTracer):
    def trace_mem_access(self, access, address, size, value):
        self.trace.append(address)
        super(MemoryTracer, self).trace_mem_access(access, address, size, value)

    def trace_code(self, address: int, size: int):
        super(MemoryTracer, self).trace_code(address, size)


class CTTracer(X86UnicornTracer):

    def trace_mem_access(self, access, address, size, value):
        self.trace.append(address)
        super(CTTracer, self).trace_mem_access(access, address, size, value)

    def trace_code(self, address: int, size: int):
        self.trace.append(address)
        super(CTTracer, self).trace_code(address, size)


class CTNonSpecStoreTracer(X86UnicornTracer):
    def trace_mem_access(self, access, address, size, value):
        if not model.in_speculation:  # all non-spec mem accesses
            self.trace.append(address)
        if access == UC_MEM_READ:  # and speculative loads
            self.trace.append(address)
        super(CTNonSpecStoreTracer, self).trace_mem_access(access, address, size, value)

    def trace_code(self, address: int, size: int):
        self.trace.append(address)
        super(CTNonSpecStoreTracer, self).trace_code(address, size)


class ArchTracer(X86UnicornTracer):
    def reset_trace(self):
        self.trace = [
            model.emulator.reg_read(UC_X86_REG_RAX),
            model.emulator.reg_read(UC_X86_REG_RBX),
            model.emulator.reg_read(UC_X86_REG_RCX),
            model.emulator.reg_read(UC_X86_REG_RDX),
            model.emulator.reg_read(UC_X86_REG_EFLAGS),
        ]
        self.coverage_trace = []

    def trace_mem_access(self, access, address, size, value):
        if access == UC_MEM_READ:
            val = int.from_bytes(model.emulator.mem_read(address, size), byteorder='little')
            self.trace.append(val)
        self.trace.append(address)
        super(ArchTracer, self).trace_mem_access(access, address, size, value)

    def trace_code(self, address: int, size: int):
        self.trace.append(address)
        super(ArchTracer, self).trace_code(address, size)


class X86UnicornModel(Model):
    """
    Base class for all Unicorn-based models.
    Serves as an adapter between Unicorn and our fuzzer.
    """
    code: bytes
    emulator: Uc
    in_speculation: bool = False
    speculation_window: int = 0
    checkpoints: List
    store_logs: List
    previous_store: Tuple[int, int, int, int]
    tracer: X86UnicornTracer
    nesting: int = 0
    debug: bool = False

    def load_test_case(self, test_case_asm: str) -> None:
        # create a binary
        assemble(test_case_asm, 'tmp.o')

        # read the binary
        with open('tmp.o', 'rb') as f:
            self.code = f.read()

        # initialize emulator in x86-64 mode
        emulator = Uc(UC_ARCH_X86, UC_MODE_64)

        try:
            # map 3 memory regions for this emulation, 1 MB each
            # it is in line with the nanoBench memory layout
            emulator.mem_map(self.stack_base, self.RUNTIME_R_SIZE)
            emulator.mem_map(self.sandbox_base, self.RUNTIME_R_SIZE)
            emulator.mem_map(self.code_base, self.CODE_SIZE)

            # point our utility regs into it the middle of the corresponding regions
            emulator.reg_write(UC_X86_REG_RBP, self.rbp_init)
            emulator.reg_write(UC_X86_REG_RSP, self.rsp_init)
            emulator.reg_write(UC_X86_REG_R14, self.r14_init)

            # write machine code to be emulated to memory
            emulator.mem_write(self.code_base, self.code)

            # initialize machine registers
            emulator.reg_write(UC_X86_REG_RAX, 0x0)
            emulator.reg_write(UC_X86_REG_RBX, 0x0)
            emulator.reg_write(UC_X86_REG_RCX, 0x0)
            emulator.reg_write(UC_X86_REG_RDX, 0x0)
            emulator.reg_write(UC_X86_REG_RSI, 0x0)
            emulator.reg_write(UC_X86_REG_R8, 0x0)
            emulator.reg_write(UC_X86_REG_R9, 0x0)
            emulator.reg_write(UC_X86_REG_R10, 0x0)
            emulator.reg_write(UC_X86_REG_R11, 0x0)
            emulator.reg_write(UC_X86_REG_R12, 0x0)
            emulator.reg_write(UC_X86_REG_R13, 0x0)
            emulator.reg_write(UC_X86_REG_R15, 0x0)

            emulator.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.trace_mem_access)
            emulator.hook_add(UC_HOOK_CODE, self.trace_code)

            self.emulator = emulator

        except UcError as e:
            print("Model error [load_test_case]: %s" % e)
            raise e

    def trace_test_case(self, inputs: List[int], nesting, debug: bool = False) -> List[CTrace]:
        self.nesting = nesting
        self.debug = debug

        traces = []
        coverage_traces = []
        for i, input_ in enumerate(inputs):
            try:
                self.reset_emulator(input_)
                self.tracer.reset_trace()
                self.emulator.emu_start(self.code_base, self.code_base + len(self.code),
                                        timeout=10000)
            except UcError as e:
                if not self.in_speculation:
                    self.print_state(self.emulator)
                    print("Model error [trace_test_case]: %s" % e)
                    raise e

            # if we use one of the SPEC contracts, we might have some residual simulations
            # that did not reach the spec. window by the end of simulation. Those need
            # to be rolled back
            while self.in_speculation:
                try:
                    self.rollback()
                except UcError:
                    continue

            # store the results
            traces.append(self.tracer.get_trace())
            coverage_traces.append(self.tracer.get_coverage_trace())

        if self.coverage:
            self.coverage.model_hook(coverage_traces)

        return traces

    def reset_emulator(self, seed):
        self.checkpoints = []
        self.in_speculation = False
        self.speculation_window = 0

        self.emulator.reg_write(UC_X86_REG_RSP, self.rsp_init)
        self.emulator.reg_write(UC_X86_REG_RBP, self.rbp_init)
        self.emulator.reg_write(UC_X86_REG_R14, self.r14_init)

        # Values in assist page
        input_mask = pow(2, (CONF.prng_entropy_bits % 33)) - 1
        random_value = seed
        for i in range(0, 4096, 4):
            random_value = ((random_value * 2891336453) % POW32 + 12345) % POW32
            masked_rvalue = (random_value ^ (random_value >> 16)) & input_mask
            masked_rvalue = masked_rvalue << 6
            self.emulator.mem_write(self.r14_init + 4096 + i,
                                    masked_rvalue.to_bytes(4, byteorder='little'))

        # Values in sandbox memory
        for i in range(0, 4096, 4):
            random_value = ((random_value * 2891336453) % POW32 + 12345) % POW32
            masked_rvalue = (random_value ^ (random_value >> 16)) & input_mask
            masked_rvalue = masked_rvalue << 6
            self.emulator.mem_write(self.r14_init + i,
                                    masked_rvalue.to_bytes(4, byteorder='little'))

        # Values in registers
        for reg in [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
                    UC_X86_REG_R9, UC_X86_REG_R10]:
            random_value = ((random_value * 2891336453) % POW32 + 12345) % POW32
            masked_rvalue = (random_value ^ (random_value >> 16)) & input_mask
            masked_rvalue = masked_rvalue << 6
            self.emulator.reg_write(reg, masked_rvalue)

        # FLAGS
        random_value = ((random_value * 2891336453) % POW32 + 12345) % POW32
        self.emulator.reg_write(UC_X86_REG_EFLAGS, (random_value & 2263) | 2)

        self.emulator.reg_write(UC_X86_REG_RDI, random_value)

    def print_state(self, oneline: bool = False):
        def compressed(val: str):
            return f"0x{val:<8x}" if val < self.r14_init else f"+0x{val - self.r14_init:<7x}"

        emulator = self.emulator
        rax = compressed(emulator.reg_read(UC_X86_REG_RAX))
        rbx = compressed(emulator.reg_read(UC_X86_REG_RBX))
        rcx = compressed(emulator.reg_read(UC_X86_REG_RCX))
        rdx = compressed(emulator.reg_read(UC_X86_REG_RDX))
        rsi = compressed(emulator.reg_read(UC_X86_REG_RSI))
        rdi = compressed(emulator.reg_read(UC_X86_REG_RDI))

        if not oneline:
            print("\n\nRegisters:")
            print(f"RAX: {rax}")
            print(f"RBX: {rbx}")
            print(f"RCX: {rcx}")
            print(f"RDX: {rdx}")
            print(f"RSI: {rsi}")
            print(f"RDI: {rdi}")
        else:
            print(f"rax={rax},"
                  f"rbx={rbx},"
                  f"rcx={rcx},"
                  f"rdx={rdx}")

    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, user_data):
        pass  # Implemented by subclasses

    @staticmethod
    def trace_code(emulator: Uc, address, size, user_data) -> None:
        pass  # Implemented by subclasses

    @staticmethod
    def checkpoint(emulator, next_instruction):
        pass  # Implemented by subclasses

    def rollback(self):
        pass  # Implemented by subclasses


# Note: unfortunately, Unicorn does not have an object-oriented API.
# We instead have to replace `self` with a global variable `model`.
model: X86UnicornModel


class X86UnicornSeq(X86UnicornModel):
    """
    A simple, in-order contract.
    The only thing it does is tracing.
    No manipulation of the control or data flow.
    """

    @staticmethod
    def trace_mem_access(emulator, access, address: int, size, value, user_data):
        global model
        model.tracer.trace_mem_access(access, address, size, value)

    @staticmethod
    def trace_code(emulator: Uc, address, size, user_data):
        global model
        model.tracer.trace_code(address, size)


class X86UnicornSpec(X86UnicornModel):
    """
    Intermediary class for all speculative contracts.
    Tracks speculative stores
    """

    def __init__(self, *args):
        self.checkpoints = []
        self.store_logs = []
        self.previous_store = (0, 0, 0, 0)
        super(X86UnicornSpec, self).__init__(*args)

    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, user_data):
        # when in speculation, log all changes to memory
        global model
        if access == UC_MEM_WRITE and model.store_logs:
            model.store_logs[-1].append((address, emulator.mem_read(address, 8)))

        model.tracer.trace_mem_access(access, address, size, value)

    @staticmethod
    def trace_code(emulator: Uc, address, size, user_data):
        global model
        model.speculation_window += 1

        if model.in_speculation:
            # rollback on a serializing instruction (lfence, sfence, mfence)
            if emulator.mem_read(address, size) in [b'\x0F\xAE\xE8', b'\x0F\xAE\xF8',
                                                    b'\x0F\xAE\xF0']:
                emulator.emu_stop()

            # and on expired speculation window
            if model.speculation_window > CONF.max_speculation_window:
                emulator.emu_stop()

        model.tracer.trace_code(address, size)

    @staticmethod
    def checkpoint(emulator, next_instruction):
        global model
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        context = emulator.context_save()
        spec_window = model.speculation_window
        model.checkpoints.append((context, next_instruction, flags, spec_window))
        model.store_logs.append([])
        model.in_speculation = True

    def rollback(self):
        global model

        # restore register values
        state, next_instr, flags, spec_window = model.checkpoints.pop()
        if not model.checkpoints:
            model.in_speculation = False

        self.emulator.context_restore(state)
        model.speculation_window = spec_window

        # rollback memory changes
        mem_changes = model.store_logs.pop()
        while mem_changes:
            addr, val = mem_changes.pop()
            self.emulator.mem_write(addr, bytes(val))

        # if there are any pending speculative store bypasses, cancel them
        model.previous_store = (0, 0, 0, 0)

        # restore the flags last, to avoid corruption by other operations
        self.emulator.reg_write(UC_X86_REG_EFLAGS, flags)

        # restart without misprediction
        self.emulator.emu_start(next_instr, self.code_base + len(self.code),
                                timeout=10000)


class X86UnicornCond(X86UnicornSpec):
    """
    Contract for conditional branch mispredicitons.
    Forces all cond. branches to speculatively go into a wrong target
    """

    jumps = {
        # c - the byte code of the instruction
        # f - the value of EFLAGS
        0x70: lambda c, f: (c[1:], f & UC_FLAGS_OF != 0),  # JO
        0x71: lambda c, f: (c[1:], f & UC_FLAGS_OF == 0),  # JNO
        0x72: lambda c, f: (c[1:], f & UC_FLAGS_CF != 0),  # JB
        0x73: lambda c, f: (c[1:], f & UC_FLAGS_CF == 0),  # JAE
        0x74: lambda c, f: (c[1:], f & UC_FLAGS_ZF != 0),  # JZ
        0x75: lambda c, f: (c[1:], f & UC_FLAGS_ZF == 0),  # JNZ
        0x76: lambda c, f: (c[1:], f & UC_FLAGS_CF != 0 or f & UC_FLAGS_ZF != 0),  # JNA
        0x77: lambda c, f: (c[1:], f & UC_FLAGS_CF == 0 and f & UC_FLAGS_ZF == 0),  # JNBE
        0x78: lambda c, f: (c[1:], f & UC_FLAGS_SF != 0),  # JS
        0x79: lambda c, f: (c[1:], f & UC_FLAGS_SF == 0),  # JNS
        0x7A: lambda c, f: (c[1:], f & UC_FLAGS_PF != 0),  # JP
        0x7B: lambda c, f: (c[1:], f & UC_FLAGS_PF == 0),  # JPO
        0x7C: lambda c, f: (c[1:], (f & UC_FLAGS_SF == 0) != (f & UC_FLAGS_OF == 0)),  # JNGE
        0x7D: lambda c, f: (c[1:], (f & UC_FLAGS_SF == 0) == (f & UC_FLAGS_OF == 0)),  # JNL
        0x7E: lambda c, f:
        (c[1:], f & UC_FLAGS_ZF != 0 or (f & UC_FLAGS_SF == 0) != (f & UC_FLAGS_OF == 0)),
        0x7F: lambda c, f:
        (c[1:], f & UC_FLAGS_ZF == 0 and (f & UC_FLAGS_SF == 0) == (f & UC_FLAGS_OF == 0)),
        0xE3: lambda c, f: ([0], True),  # J*CXZ - not yet supported
        0x0F: lambda c, f:
        X86UnicornCond.multibyte_jmp.get(c[1], (lambda _, __: ([0], False)))(c, f)
    }

    multibyte_jmp = {
        0x80: lambda c, f: (c[2:], f & UC_FLAGS_OF != 0),  # JO
        0x81: lambda c, f: (c[2:], f & UC_FLAGS_OF == 0),  # JNO
        0x82: lambda c, f: (c[2:], f & UC_FLAGS_CF != 0),  # JB
        0x83: lambda c, f: (c[2:], f & UC_FLAGS_CF == 0),  # JAE
        0x84: lambda c, f: (c[2:], f & UC_FLAGS_ZF != 0),  # JE
        0x85: lambda c, f: (c[2:], f & UC_FLAGS_ZF == 0),  # JNE
        0x86: lambda c, f: (c[2:], f & UC_FLAGS_CF != 0 or f & UC_FLAGS_ZF != 0),  # JBE
        0x87: lambda c, f: (c[2:], f & UC_FLAGS_CF == 0 and f & UC_FLAGS_ZF == 0),  # JA
        0x88: lambda c, f: (c[2:], f & UC_FLAGS_SF != 0),  # JS
        0x89: lambda c, f: (c[2:], f & UC_FLAGS_SF == 0),  # JNS
        0x8A: lambda c, f: (c[2:], f & UC_FLAGS_PF != 0),  # JP
        0x8B: lambda c, f: (c[2:], f & UC_FLAGS_PF == 0),  # JPO
        0x8C: lambda c, f: (c[2:], (f & UC_FLAGS_SF == 0) != (f & UC_FLAGS_OF == 0)),  # JNGE
        0x8D: lambda c, f: (c[2:], (f & UC_FLAGS_SF == 0) == (f & UC_FLAGS_OF == 0)),  # JNL
        0x8E: lambda c, f:
        (c[2:], f & UC_FLAGS_ZF != 0 or (f & UC_FLAGS_SF == 0) != (f & UC_FLAGS_OF == 0)),
        0x8F: lambda c, f:
        (c[2:], f & UC_FLAGS_ZF == 0 and (f & UC_FLAGS_SF == 0) == (f & UC_FLAGS_OF == 0)),
    }

    @staticmethod
    def trace_code(emulator: Uc, address, size, user_data):
        global model
        X86UnicornSpec.trace_code(emulator, address, size, user_data)

        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return True

        # decode the instruction
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        code = emulator.mem_read(address, size)
        target, will_jump = X86UnicornCond.decode(code, flags)

        # not a a cond. jump? ignore
        if not target:
            return True

        # Take a checkpoint
        next_instr = address + size + target if will_jump else address + size
        model.checkpoint(emulator, next_instr)

        # Simulate misprediction
        if will_jump:
            emulator.reg_write(UC_X86_REG_RIP, address + size)
        else:
            emulator.reg_write(UC_X86_REG_RIP, address + size + target)
        return True

    @staticmethod
    def decode(code: bytearray, flags: int) -> (int, bool):
        """
        Decodes the instruction encoded in `code` and, if it's a conditional jump,
        returns its expected target and whether it will jump to the target, based
        on the `flags` value.
        """
        calculate_target = X86UnicornCond.jumps.get(code[0], (lambda _, __: ([0], False)))
        target, will_jump = calculate_target(code, flags)
        if len(target) == 1:
            return target[0], will_jump
        return int.from_bytes(target, byteorder='little'), will_jump


class X86UnicornBpas(X86UnicornSpec):
    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, user_data):
        """
        Since Unicorn does not have post-instruction hooks,
        I have to implement it in a dirty way:
        Save the information about the write here, but execute the all the
        contract logic in a hook before the next instruction (see trace_code)
        """
        global model
        if access == UC_MEM_WRITE:
            rip = emulator.reg_read(UC_X86_REG_RIP)
            opcode = emulator.mem_read(rip, 1)[0]
            if opcode not in [0xE8, 0xFF, 0x9A]:  # ignore CALL instructions
                model.previous_store = (address, size, emulator.mem_read(address, size), value)

        X86UnicornSpec.trace_mem_access(emulator, access, address, size, value, user_data)

    @staticmethod
    def trace_code(emulator: Uc, address, size, user_data):
        global model
        X86UnicornSpec.trace_code(emulator, address, size, user_data)

        # reached max spec. window? skip
        if len(model.checkpoints) >= model.nesting:
            return True

        if model.previous_store[0]:
            store_addr = model.previous_store[0]
            old_value = bytes(model.previous_store[2])
            new_is_signed = model.previous_store[3] < 0
            new_value = (model.previous_store[3]). \
                to_bytes(model.previous_store[1], byteorder='little', signed=new_is_signed)

            # store a checkpoint
            model.checkpoint(emulator, address)

            # cancel the previous store but preserve its value
            emulator.mem_write(store_addr, old_value)
            model.store_logs[-1].append((store_addr, new_value))
        model.previous_store = (0, 0, 0, 0)
        return True


class X86UnicornCondBpas(X86UnicornSpec):
    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, user_data):
        X86UnicornBpas.trace_mem_access(emulator, access, address, size, value, user_data)

    @staticmethod
    def trace_code(emulator: Uc, address, size, user_data):
        X86UnicornCond.trace_code(emulator, address, size, user_data)
        X86UnicornBpas.trace_code(emulator, address, size, user_data)


# =============================================================================
# Serialization-based predictors
# =============================================================================
class X86SerializingModel(Model):
    def __init__(self, *args):
        self.executor = X86Intel()
        super(X86SerializingModel, self).__init__(*args)

    def load_test_case(self, test_case_asm: str):
        """ Add an LFENCE after every instruction in the test case """
        with open(test_case_asm, 'r') as f:
            with open('serial.asm', 'w') as serial:
                for line in f:
                    if line:
                        serial.write(line + "LFENCE\n")
        self.executor.load_test_case('serial.asm')
        os.remove('serial.asm')

    def trace_test_case(self, inputs: List[int], nesting, debug: bool = False) -> List[CTrace]:
        traces = self.executor.trace_test_case(inputs, num_measurements=1, max_outliers=0)
        return traces


def get_model(bases) -> Model:
    global model
    if CONF.model == 'x86-unicorn':
        # functional part of the contract
        if "cond" in CONF.contract_execution_mode and "bpas" in CONF.contract_execution_mode:
            model = X86UnicornCondBpas(bases[0], bases[1], bases[2])
        elif "cond" in CONF.contract_execution_mode:
            model = X86UnicornCond(bases[0], bases[1], bases[2])
        elif "bpas" in CONF.contract_execution_mode:
            model = X86UnicornBpas(bases[0], bases[1], bases[2])
        elif "seq" in CONF.contract_execution_mode:
            model = X86UnicornSeq(bases[0], bases[1], bases[2])
        else:
            print("Error: unknown value of `contract_execution_mode` configuration option")
            exit(1)

        # observational part of the contract
        if CONF.contract_observation_mode == "l1d":
            model.tracer = L1DTracer()
        elif CONF.contract_observation_mode == 'pc':
            model.tracer = PCTracer()
        elif CONF.contract_observation_mode == 'memory':
            model.tracer = MemoryTracer()
        elif CONF.contract_observation_mode == 'ct':
            model.tracer = CTTracer()
        elif CONF.contract_observation_mode == 'ct-nonspecstore':
            model.tracer = CTNonSpecStoreTracer()
        elif CONF.contract_observation_mode == 'arch':
            model.tracer = ArchTracer()
        else:
            print("Error: unknown value of `contract_observation_mode` configuration option")
            exit(1)

        return model
    elif CONF.model == 'x86-serializing':
        return X86SerializingModel(bases[0], bases[1], bases[2])
    else:
        print("Error: unknown value of `model` configuration option")
        exit(1)
