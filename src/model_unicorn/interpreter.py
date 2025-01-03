"""
File: Abstract interface and architecture-specific implementation of the extra interpreter logic.

      The extra interpreter is a component that provides additional interpretation
      logic over the one provided by Unicorn.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Tuple, Dict, Callable, Set, Optional, List, Final

from unicorn import UC_ERR_NOMEM, UcError, UC_ERR_EXCEPTION, UC_MEM_WRITE, UC_ERR_INSN_INVALID
import unicorn.x86_const as x86ucc  # type: ignore  # no type hints available

from ..tc_components.actor import ActorMode, ActorPL, Actor
from ..sandbox import CodeArea, DataArea
from ..logs import warning

if TYPE_CHECKING:
    from .model import UnicornModel
    from .execution_context import ModelExecutionState
    from ..target_desc import TargetDesc, UnicornTargetDesc
    from ..tc_components.instruction import Instruction
    from ..tc_components.test_case_code import TestCaseProgram
    from ..tc_components.test_case_binary import SymbolTableEntry
    from ..tc_components.test_case_data import InputData

CRITICAL_ERROR = UC_ERR_NOMEM  # the model never handles this error, hence it will always crash


# ==================================================================================================
# Public Interface
# ==================================================================================================
class ExtraInterpreter(ABC):
    """
    Wrapper class that implements extra interpretation logic over the one provided by Unicorn.
    This, for example, includes the interpretation of macros and emulation of CPU modes.

    This class provides a generic interface, which is instantiated by the ISA-specific subclasses.
    """
    _model: Final[UnicornModel]
    _target_desc: Final[TargetDesc]
    _uc_target_desc: Final[UnicornTargetDesc]

    def __init__(self, target_desc: TargetDesc, model: UnicornModel):
        self._target_desc = target_desc
        self._model = model
        self._uc_target_desc = target_desc.uc_target_desc

    @abstractmethod
    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """ Load the test case into the interpreter """

    @abstractmethod
    def load_input(self, input_: InputData) -> None:
        """ Load the input into the interpreter """

    def interpret_instruction(self, address: int, state: ModelExecutionState) -> None:
        """ Interpret the current instruction (stored in state.current_instruction) """
        instruction = state.current_instruction

        if instruction.name == "macro":
            self._interpret_macro(instruction, address)

        # emulate invalid opcode for certain instructions when executed in VM guest mode
        if state.current_actor.mode == ActorMode.GUEST:
            self._emulate_vm_execution(address)
        elif state.current_actor.privilege_level == ActorPL.USER:
            self._emulate_userspace_execution(address)

    def interpret_mem_access(self, address: int) -> None:
        """ Interpret the given memory access """
        # FIXME: move to x86
        # emulate page faults
        if self._model.state.current_actor.privilege_level == ActorPL.USER:
            target_actor = self._model.layout.data_addr_to_actor_id(address)
            if target_actor != self._model.state.current_actor.get_id():
                self._model.do_soft_fault(12)

    @abstractmethod
    def _interpret_macro(self, macro: Instruction, pc: int) -> None:
        """ Emulate execution of a macro instruction """

    @abstractmethod
    def _emulate_vm_execution(self, address: int) -> None:
        """ Emulate the execution of an instruction in VM guest mode """

    @abstractmethod
    def _emulate_userspace_execution(self, address: int) -> None:
        """ Emulate the execution of an instruction in userspace mode """


class X86ExtraInterpreter(ExtraInterpreter):
    """ ExtraInterpreter implementation for the x86 architecture """

    _macro_interpreter: _X86MacroInterpreter
    _vm_interpreter: _X86VMInterpreter
    _userspace_interpreter: _X86UserspaceInterpreter
    _fault_interpreter: _X86FaultInterpreter

    def __init__(self, target_desc: TargetDesc, model: UnicornModel):
        super().__init__(target_desc, model)
        self._macro_interpreter = _X86MacroInterpreter(model, target_desc)
        self._vm_interpreter = _X86VMInterpreter(model, target_desc)
        self._userspace_interpreter = _X86UserspaceInterpreter(model, target_desc)
        self._fault_interpreter = _X86FaultInterpreter(model, target_desc)

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        self._macro_interpreter.load_test_case(test_case)
        self._fault_interpreter.load_test_case(test_case)
        self._vm_interpreter.reset()
        self._userspace_interpreter.reset()

    def load_input(self, input_: InputData) -> None:
        self._fault_interpreter.load_input(input_)

    def _interpret_macro(self, macro: Instruction, pc: int) -> None:
        self._macro_interpreter.interpret(macro, pc)

    def _emulate_vm_execution(self, address: int) -> None:
        self._vm_interpreter.interpret(self._model.state.current_instruction, address)

    def _emulate_userspace_execution(self, address: int) -> None:
        self._userspace_interpreter.interpret(self._model.state.current_instruction, address)


# ==================================================================================================
# Private: Macro Interpretation
# ==================================================================================================

_MacroCallback = Callable[[int, int, int, int], None]


class _X86MacroInterpreter:
    """ Implements the interpretation of x86-specific macros """
    _model: UnicornModel
    _uc_target_desc: UnicornTargetDesc
    _test_case: Optional[TestCaseProgram] = None

    _curr_targets: Dict[str, int] = {
        "h2g": 0,
        "g2h": 0,
        "k2u": 0,
        "u2k": 0,
    }

    _function_table: List[SymbolTableEntry]
    _macro_table: List[SymbolTableEntry]
    _sid_to_actor: Dict[int, Actor]
    _pseudo_lstar: int

    def __init__(self, model: UnicornModel, target_desc: TargetDesc):
        self._model = model
        self._uc_target_desc = target_desc.uc_target_desc
        self._function_table = []
        self._macro_table = []

        self._is_amd = target_desc.cpu_desc.vendor == "AMD"

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """ Load the test case into the interpreter """
        self._test_case = test_case
        test_case_obj = test_case.get_obj()
        symbol_table = test_case_obj.symbol_table()

        self._function_table = [sym for sym in symbol_table if sym.type_ == 0]
        self._function_table.sort(key=lambda s: [s.arg])
        self._macro_table = [sym for sym in symbol_table if sym.type_ != 0]
        self._sid_to_actor = {actor.get_id(): actor for actor in test_case.get_actors()}
        self._pseudo_lstar = self._model.state.exit_addr

    def interpret(self, macro: Instruction, pc: int) -> None:
        """
        Interpret the given macro instruction and execute the corresponding logic on the model
        """

        macros: Dict[str, _MacroCallback] = {
            "measurement_start": self._macro_measurement_start,
            "measurement_end": self._macro_measurement_end,
            "switch": self._macro_switch,
            "switch_k2u": self._macro_switch_k2u,
            "switch_u2k": self._macro_switch_u2k,
            "set_k2u_target": self._macro_set_k2u_target,
            "set_u2k_target": self._macro_set_u2k_target,
            "switch_h2g": self._macro_switch_h2g,
            "switch_g2h": self._macro_switch_g2h,
            "set_h2g_target": self._macro_set_h2g_target,
            "set_g2h_target": self._macro_set_g2h_target,
            "landing_k2u": self._macro_landing_k2u,
            "landing_u2k": self._macro_landing_u2k,
            "landing_h2g": self._macro_landing_h2g,
            "landing_g2h": self._macro_landing_g2h,
            "fault_handler": lambda *_: None,
            "set_data_permissions": self._macro_set_data_permissions,
        }

        actor_id = self._model.state.current_actor.get_id()
        macro_start = self._model.layout.get_code_addr(CodeArea.MAIN, actor_id)
        macro_offset = pc - macro_start
        macro_args = self._get_macro_args(actor_id, macro_offset)

        interpreter_func = macros[macro.operands[0].value.lower()[1:]]
        interpreter_func(*macro_args)

    def _get_macro_args(self, section_id: int, section_offset: int) -> Tuple[int, int, int, int]:
        # find the macro entry in the symbol table
        for symbol in self._macro_table:
            if symbol.sid == section_id and symbol.offset == section_offset:
                args = symbol.arg
                return args & 0xFFFF, (args >> 16) & 0xFFFF, (args >> 32) & 0xFFFF, \
                    (args >> 48) & 0xFFFF
        warning("get_macro_args", "macro not found in symbol table")
        raise UcError(CRITICAL_ERROR)

    def _find_function_by_id(self, function_id: int) -> SymbolTableEntry:
        if function_id < 0 or function_id >= len(self._function_table):
            warning("find_function_by_id", "function not found in symbol table")
            raise UcError(CRITICAL_ERROR)
        return self._function_table[function_id]

    def _macro_measurement_start(self, _: int, __: int, ___: int, ____: int) -> None:
        if not self._model.speculator.in_speculation():
            self._model.tracer.enable_tracing = True

    def _macro_measurement_end(self, _: int, __: int, ___: int, ____: int) -> None:
        if not self._model.speculator.in_speculation():
            self._model.tracer.enable_tracing = False

    def _macro_switch(self, section_id: int, function_id: int, _: int, __: int) -> None:
        """
        Switch the active actor, update data area base and SP,
          and jump to the corresponding function address
        """
        model = self._model
        layout = model.layout

        # PC update
        section_addr = layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        model.emulator.reg_write(self._uc_target_desc.pc_register, function_addr)

        # data area base and SP update
        new_base = layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(self._uc_target_desc.sp_register, new_sp)

        # actor update
        model.state.current_actor = self._sid_to_actor[section_id]

    def _macro_set_k2u_target(self, section_id: int, function_id: int, _: int, __: int) -> None:
        """
        Decode arguments and store destination into _curr_target
        """
        section_addr = self._model.layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        self._curr_targets["k2u"] = function_addr

    def _macro_switch_k2u(self, section_id: int, _: int, __: int, ___: int) -> None:
        """ Read the destination from _curr_target and jump to it;
        also update data area base and SP """
        model = self._model
        layout = model.layout

        # PC update
        model.emulator.reg_write(self._uc_target_desc.pc_register, self._curr_targets["k2u"])

        # side effects
        # flags = model.emulator.reg_read(x86ucc.UC_X86_REG_EFLAGS)
        # rsp = model.emulator.reg_read(x86ucc.UC_X86_REG_RSP)
        # model.emulator.mem_write(rsp - 8, flags.to_bytes(8, byteorder='little'))  # type: ignore

        # data area base and SP update
        new_base = layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(x86ucc.UC_X86_REG_RSP, new_sp)

        # actor update
        model.state.current_actor = self._sid_to_actor[section_id]

    def _macro_set_u2k_target(self, section_id: int, function_id: int, _: int, __: int) -> None:
        """ Set LSTAR to the target address if in kernel mode; otherwise, throw an exception """
        if self._model.state.current_actor.privilege_level != ActorPL.KERNEL:
            self._model.do_soft_fault(UC_ERR_EXCEPTION)
            return
        model = self._model

        # update LSTAR
        section_addr = model.layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        self._pseudo_lstar = function_addr

    def _macro_switch_u2k(self, section_id: int, _: int, __: int, ___: int) -> None:
        """ Switch the active actor, update data area base and SP, and jump to
            the _pseudo_lstar
        """
        model = self._model

        # PC update
        model.emulator.reg_write(self._uc_target_desc.pc_register, self._pseudo_lstar)

        # data area base and SP update
        new_base = model.layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = model.layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(x86ucc.UC_X86_REG_RSP, new_sp)

        # actor update
        model.state.current_actor = self._sid_to_actor[section_id]

    def _macro_switch_h2g(self, section_id: int, _: int, __: int, ___: int) -> None:
        model = self._model

        # PC update
        model.emulator.reg_write(self._uc_target_desc.pc_register, self._curr_targets["h2g"])

        # data area base and SP update
        new_base = model.layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = model.layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(x86ucc.UC_X86_REG_RSP, new_sp)

        # reset flags
        model.emulator.reg_write(x86ucc.UC_X86_REG_EFLAGS, 0b10)

        # actor update
        model.state.current_actor = self._sid_to_actor[section_id]

        # AMD VMRUN clobbers RAX; we model it as a zero write to RAX
        if self._is_amd:
            model.emulator.reg_write(x86ucc.UC_X86_REG_RAX, 0)

    def _macro_switch_g2h(self, section_id: int, _: int, __: int, ___: int) -> None:
        model = self._model

        # PC update
        model.emulator.reg_write(self._uc_target_desc.pc_register, self._curr_targets["g2h"])

        # data area base and SP update
        new_base = model.layout.get_data_addr(DataArea.MAIN, section_id)
        new_sp = model.layout.get_data_addr(DataArea.RSP_INIT, section_id)
        model.emulator.reg_write(self._uc_target_desc.actor_base_register, new_base)
        model.emulator.reg_write(x86ucc.UC_X86_REG_RSP, new_sp)

        # actor update
        model.state.current_actor = self._sid_to_actor[section_id]

        # AMD VMEXIT clobbers RAX; we model it as a zero write to RAX
        if self._is_amd:
            model.emulator.reg_write(x86ucc.UC_X86_REG_RAX, 0)

    def _macro_set_h2g_target(self, section_id: int, function_id: int, _: int, __: int) -> None:
        section_addr = self._model.layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        self._curr_targets["h2g"] = function_addr

    def _macro_set_g2h_target(self, section_id: int, function_id: int, _: int, __: int) -> None:
        section_addr = self._model.layout.get_code_addr(CodeArea.MAIN, section_id)
        function_symbol = self._find_function_by_id(function_id)
        function_addr = section_addr + function_symbol.offset
        self._curr_targets["g2h"] = function_addr

    def _macro_landing_k2u(self, _: int, __: int, ___: int, ____: int) -> None:
        """ Landing for the k2u switch """
        self._model.emulator.reg_write(x86ucc.UC_X86_REG_RCX, 0)

    def _macro_landing_u2k(self, _: int, __: int, ___: int, ____: int) -> None:
        """ Landing for the u2k switch """
        self._model.emulator.reg_write(x86ucc.UC_X86_REG_RCX, 0)

    def _macro_landing_h2g(self, _: int, __: int, ___: int, ____: int) -> None:
        """ Landing for the h2g switch """

    def _macro_landing_g2h(self, _: int, __: int, ___: int, ____: int) -> None:
        """ Landing for the g2h switch """

    def _macro_set_data_permissions(self, actor_id: int, must_set: int, must_clear: int,
                                    _: int) -> None:
        """ Manual setting of data permissions for the actor """


# ==================================================================================================
# Private: VM mode and Userspace Emulation
# ==================================================================================================
class _X86VMInterpreter:
    """ Adds the ability to emulate VM guest execution to the Unicorn emulator """

    safe_address_cache: Set[int]
    always_exit_instructions: Set[str] = {
        "cpuid", "getsec", "xgetbv", "xsetbv", "xrstors", "xsaves", "invd", "invept", "invvpid",
        "vmptrld", "vmptrst", "vmclear", "vmxon", "vmxoff", "vmlaunch", "vmresume", "vmcall",
        "vmfunc", "hlt", "invlpg", "invpcid", "lgdt", "lidt", "lldt", "ltr", "sgdt", "sidt", "sldt",
        "str", "loadiwkey", "monitor", "mwait", "rdpmc", "rdrand", "rdseed", "rdtsc", "rdtscp",
        "rsm", "tpause", "umwait", "vmread", "vmwrite", "wbinvd", "wbnoinvd", "wrmsr", "fxsave",
        "fxsave64", "in", "ins", "insb", "insw", "insd", "out", "outs", "outsb", "outsw", "outsd",
        "pause", "rdmsr", "swapgs"
    }
    always_exiting_registers = ["cr0", "cr3", "cr8", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"]

    def __init__(self, model: UnicornModel, target_desc: TargetDesc) -> None:
        self._model = model
        self._uc_target_desc = target_desc.uc_target_desc
        self.safe_address_cache = set()

    def reset(self) -> None:
        """ Reset the state of the interpreter; MUST be called for every new test case """
        self.safe_address_cache.clear()

    def interpret(self, inst: Instruction, address: int) -> None:
        """ Interpret the given instruction """

        if address in self.safe_address_cache:
            return
        stripped_name = inst.name.split()[-1]

        # always-exiting instruction
        if stripped_name in self.always_exit_instructions:
            # make sure that the memory accesses get exposed
            if inst.has_mem_operand(True):
                ops = inst.get_mem_operands(True)
                for op in ops:
                    words = op.value.split("+")
                    for word in words:
                        reg = self._uc_target_desc.reg_str_to_constant.get(word.lower(), 0)
                        if reg:
                            value = int(self._model.emulator.reg_read(reg))  # type: ignore
                            self._model.tracer.observe_mem_access(UC_MEM_WRITE, value, 8, 0)
            self._model.do_soft_fault(UC_ERR_INSN_INVALID)
            return

        # conditional exit
        if stripped_name == "mov":
            if not self._emulate_move(inst, address):
                return

        # safe instruction
        self.safe_address_cache.add(address)

    def _emulate_move(self, inst: Instruction, _: int) -> bool:
        for operand in inst.operands:
            if operand.value in self.always_exiting_registers:
                self._model.do_soft_fault(UC_ERR_INSN_INVALID)
                return False
        return True


class _X86UserspaceInterpreter(_X86VMInterpreter):
    """
    Adds the ability to emulate user-space execution to the Unicorn emulator.
    """
    always_exit_instructions: Set[str] = {
        "cpuid", "rdmsr", "wrmsr", "rdtsc", "rdtscp", "clac", "stac", "clgi", "stgi", "clts", "htl",
        "invd", "invlpg", "invlpga", "invlpgb", "invpcid", "lgdt", "lldt", "lidt", "ltr", "sgdt",
        "sidt", "sldt", "str", "psmash", "pvalidate", "rmpadjust", "rmpquery", "rmpupdate",
        "skinit", "sysretq", "sysexitq", "tlbsync", "vmmcall", "vmload", "vmsave", "vmrun",
        "wbinvd", "wbnoinvd", "smsw", "lmsw", "rdfsbase", "rdgsbase", "wrfsbase", "wrgsbase",
        "swapgs", "vmclear", "vmlaunch", "vmptrld", "vmptrst", "vmread", "vmresume", "vmwrite",
        "vmxoff", "invvpid", "getsec", "loadiwkey", "pconfig", "encls", "enclv", "hlt", "xgetbv",
        "xsetbv"
    }
    always_exiting_registers = [
        "cr0", "cr2", "cr3", "cr8", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"
    ]


# ==================================================================================================
# Private: Fault Handling and Permissions
# ==================================================================================================

class _X86FaultInterpreter:
    """ Class that handles page faults and permissions in the emulator """
    _model: UnicornModel
    _target_desc: TargetDesc
    _uc_target_desc: UnicornTargetDesc
    _test_case: Optional[TestCaseProgram] = None

    fault_masks: Dict[str, int]
    rw_forbidden: Dict[int, bool]
    w_forbidden: Dict[int, bool]

    def __init__(self, model: UnicornModel, target_desc: TargetDesc):
        self._model = model
        self._target_desc = target_desc
        self._uc_target_desc = target_desc.uc_target_desc
        self._create_fault_masks()

    def load_test_case(self, test_case: TestCaseProgram) -> None:
        """ Load the test case into the interpreter """
        self._test_case = test_case
        self.rw_forbidden = {}
        self.w_forbidden = {}
        for actor in test_case.get_actors(sorted_=True):
            aid = actor.get_id()

            pte: int = actor.data_properties
            inverse_pte = 0xffffffffffffffff ^ pte
            self.rw_forbidden[aid] = bool(self.fault_masks["pt_rw_must_set"] & inverse_pte) | \
                bool(self.fault_masks["pt_rw_must_clear"] & pte)
            self.w_forbidden[aid] = bool(self.fault_masks["pt_w_must_set"] & inverse_pte)

            if actor.mode == ActorMode.GUEST:
                epte: int = actor.data_ept_properties
                inverse_epte = 0xffffffffffffffff ^ epte
                self.rw_forbidden[aid] |= \
                    bool(self.fault_masks["ept_rw_must_set"] & inverse_epte) | \
                    bool(self.fault_masks["ept_rw_must_clear"] & epte)
                self.w_forbidden[aid] |= bool(self.fault_masks["ept_w_must_set"] & inverse_epte)

    def load_input(self, _: InputData) -> None:
        """ Load the input into the interpreter """
        assert self._test_case is not None
        # Set memory permissions
        for actor_id in range(self._test_case.n_actors()):
            if self.rw_forbidden[actor_id]:
                self._model.set_faulty_area_rw(actor_id, False, False)
            elif self.w_forbidden[actor_id]:
                self._model.set_faulty_area_rw(actor_id, True, False)

    def _create_fault_masks(self) -> None:
        self.fault_masks = {
            "pt_rw_must_set": 0,
            "pt_rw_must_clear": 0,
            "pt_w_must_set": 0,
            "ept_rw_must_set": 0,
            "ept_rw_must_clear": 0,
            "ept_w_must_set": 0,
        }

        bit_desc = {
            "pt_rw_must_set": ["present", "accessed"],
            "pt_rw_must_clear": ["user", "reserved_bit"],
            "pt_w_must_set": ["writable", "dirty"],
            "ept_rw_must_set": ["present", "accessed"],
            "ept_rw_must_clear": ["user", "reserved_bit"],
            "ept_w_must_set": ["writable", "dirty"],
        }

        for key in self.fault_masks:
            if key.startswith("pt"):
                for bit in bit_desc[key]:
                    self.fault_masks[key] |= 1 << self._target_desc.pte_bits[bit][0]
            else:
                for bit in bit_desc[key]:
                    self.fault_masks[key] |= 1 << self._target_desc.epte_bits[bit][0]
