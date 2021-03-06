"""
File: Model Interface and its implementations

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
    def trace_test_case(self, inputs: List[int]) -> List[CTrace]:
        pass


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

    def __init__(self):
        self.trace = []

    def reset_trace(self) -> None:
        self.trace = []

    def get_trace(self) -> CTrace:
        return hash(tuple(self.trace))

    @abstractmethod
    def trace_mem_access(self, address: int, size: int, value: int) -> None:
        pass

    @abstractmethod
    def trace_code(self, address: int, size: int) -> None:
        pass


class L1DTracer(X86UnicornTracer):
    def reset_trace(self):
        self.trace = [0, 0]

    def trace_mem_access(self, address, size, value):
        page_offset = address & 4095
        cache_set_index = 9223372036854775808 >> (page_offset >> 6)
        if model.checkpoints:
            self.trace[1] |= cache_set_index
        else:
            self.trace[0] |= cache_set_index
        # print(f"{cache_set_index:064b}")

    def trace_code(self, address: int, size: int):
        pass

    def get_trace(self) -> CTrace:
        if CONF.ignore_first_cache_line:
            self.trace[0] &= 9223372036854775807
            self.trace[1] &= 9223372036854775807
        return (self.trace[1] << 64) + self.trace[0]


class MemoryTracer(X86UnicornTracer):
    def trace_mem_access(self, address, size, value):
        self.trace.append(address)

    def trace_code(self, address: int, size: int):
        pass


class CTTracer(X86UnicornTracer):

    def trace_mem_access(self, address, size, value):
        self.trace.append(address)

    def trace_code(self, address: int, size: int):
        self.trace.append(address)


class X86UnicornModel(Model):
    """
    Base class for all Unicorn-based models.
    Serves as an adapter between Unicorn and our fuzzer.
    """
    code: bytes
    emulator: Uc
    checkpoints: List
    store_logs: List
    previous_store: Tuple[int, int, int, int]
    tracer: X86UnicornTracer

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

    def trace_test_case(self, inputs: List[int]) -> List[CTrace]:
        traces = []
        for i, input_ in enumerate(inputs):
            self.tracer.reset_trace()
            try:
                self.reset_emulator(input_)
                self.emulator.emu_start(self.code_base, self.code_base + len(self.code),
                                        timeout=10000)
            except UcError as e:
                if not self.checkpoints:
                    self._print_state(self.emulator)
                    print("Model error [trace_test_case]: %s" % e)
                    raise e

            # if we use one of the SPEC contracts, we might have some residual simulations
            # that did not reach the spec. window by the end of simulation. Those need
            # to be rolled back
            while self.checkpoints:
                try:
                    self.rollback()
                except UcError:
                    continue

            # store the results
            traces.append(self.tracer.get_trace())
        return traces

    def reset_emulator(self, seed):
        self.checkpoints = []

        self.emulator.reg_write(UC_X86_REG_RSP, self.rsp_init)
        self.emulator.reg_write(UC_X86_REG_RBP, self.rbp_init)
        self.emulator.reg_write(UC_X86_REG_R14, self.r14_init)

        random_value = seed
        random_value = ((random_value * 2891336453) % POW32 + 12345) % POW32
        for i in range(0, 4096, 64):
            self.emulator.mem_write(self.r14_init + i, random_value.to_bytes(8, byteorder='little'))
        self.emulator.reg_write(UC_X86_REG_RDI, random_value)

        # MDS assist page
        if CONF.enable_mds:
            zero_bytes = (0).to_bytes(8, byteorder='little')
            for i in range(0, 4096, 64):
                self.emulator.mem_write(self.r14_init + 4096 + i, zero_bytes)

    @staticmethod
    def _print_state(emulator: Uc):
        print("\n\nRegisters:")
        print(f"RAX: {emulator.reg_read(UC_X86_REG_RAX)}")
        print(f"RBX: {emulator.reg_read(UC_X86_REG_RBX)}")
        print(f"RCX: {emulator.reg_read(UC_X86_REG_RCX)}")
        print(f"RDX: {emulator.reg_read(UC_X86_REG_RDX)}")
        print(f"RSI: {emulator.reg_read(UC_X86_REG_RSI)}")
        print(f"RDI: {emulator.reg_read(UC_X86_REG_RDI)}")

    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, user_data):
        pass  # Implemented by subclasses

    @staticmethod
    def trace_code(emulator: Uc, address, size, user_data):
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
        model.tracer.trace_mem_access(address, size, value)

    @staticmethod
    def trace_code(emulator: Uc, address, size, user_data):
        global model
        model.tracer.trace_code(address, size)


class X86UnicornSpec(X86UnicornSeq):
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

        X86UnicornSeq.trace_mem_access(emulator, access, address, size, value, user_data)

    @staticmethod
    def checkpoint(emulator, next_instruction):
        global model
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        context = emulator.context_save()
        model.checkpoints.append((context, next_instruction, flags))
        model.store_logs.append([])

    def rollback(self):
        global model

        # restore register values
        state, next_instr, flags = model.checkpoints.pop()
        self.emulator.context_restore(state)
        self.emulator.reg_write(UC_X86_REG_EFLAGS, flags)

        # rollback memory changes
        mem_changes = model.store_logs.pop()
        while mem_changes:
            addr, val = mem_changes.pop()
            self.emulator.mem_write(addr, bytes(val))

        # if there are any pending speculative store bypasses, cancel them
        model.previous_store = (0, 0, 0, 0)

        # restart without misprediction
        self.emulator.emu_start(next_instr, self.code_base + len(self.code),
                                timeout=10000)


class X86UnicornCB(X86UnicornSpec):
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
        0x0F: lambda c, f: X86UnicornCB.multibyte_jmp.get(c[1], (lambda _, __: ([0], False)))(c, f)
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
        if len(model.checkpoints) >= CONF.max_nesting:
            return

        # decode the instruction
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        code = emulator.mem_read(address, size)
        target, will_jump = X86UnicornCB.decode(code, flags)

        # not a a cond. jump? ignore
        if not target:
            return

        # Take a checkpoint
        next_instr = address + size + target if will_jump else address + size
        model.checkpoint(emulator, next_instr)

        # Simulate misprediction
        if will_jump:
            emulator.reg_write(UC_X86_REG_RIP, address + size)
        else:
            emulator.reg_write(UC_X86_REG_RIP, address + size + target)

    @staticmethod
    def decode(code: bytearray, flags: int) -> (int, bool):
        """
        Decodes the instruction encoded in `code` and, if it's a conditional jump,
        returns its expected target and whether it will jump to the target, based
        on the `flags` value.
        """
        calculate_target = X86UnicornCB.jumps.get(code[0], (lambda _, __: ([0], False)))
        target, will_jump = calculate_target(code, flags)
        if len(target) == 1:
            return target[0], will_jump
        return int.from_bytes(target, byteorder='little'), will_jump


class X86UnicornSBP(X86UnicornSpec):
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

        # reached max spec. window? skip
        if len(model.checkpoints) >= CONF.max_nesting:
            return

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


class X86UnicornCbSbp(X86UnicornSpec):
    @staticmethod
    def trace_mem_access(emulator, access, address, size, value, user_data):
        X86UnicornSBP.trace_mem_access(emulator, access, address, size, value, user_data)

    @staticmethod
    def trace_code(emulator: Uc, address, size, user_data):
        X86UnicornCB.trace_code(emulator, address, size, user_data)
        X86UnicornSBP.trace_code(emulator, address, size, user_data)


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

    def trace_test_case(self, inputs: List[int]) -> List[CTrace]:
        traces = self.executor.trace_test_case(inputs, num_measurements=1, max_outliers=0)
        return traces


def get_model(bases) -> Model:
    global model
    if CONF.model == 'x86-unicorn':
        # functional part of the contract
        if "cb" in CONF.contracts and "sbp" in CONF.contracts:
            model = X86UnicornCbSbp(bases[0], bases[1], bases[2])
        elif "cb" in CONF.contracts:
            model = X86UnicornCB(bases[0], bases[1], bases[2])
        elif "sbp" in CONF.contracts:
            model = X86UnicornSBP(bases[0], bases[1], bases[2])
        elif "seq" in CONF.contracts:
            model = X86UnicornSeq(bases[0], bases[1], bases[2])
        else:
            print("Error: unknown value of `contracts` configuration option")
            exit(1)

        # observational part of the contract
        if CONF.attacker_capability == "l1d":
            model.tracer = L1DTracer()
        elif CONF.attacker_capability == 'memory':
            model.tracer = MemoryTracer()
        elif CONF.attacker_capability == 'ct':
            model.tracer = CTTracer()
        else:
            print("Error: unknown value of `attacker_capability` configuration option")
            exit(1)

        return model
    elif CONF.model == 'x86-serializing':
        return X86SerializingModel(bases[0], bases[1], bases[2])
    else:
        print("Error: unknown value of `model` configuration option")
        exit(1)
