"""
File: x86 implementation of the test case generator

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import abc
import math
import re
import random
from copy import deepcopy
from typing import List, Dict, Set, Optional

from ..isa_loader import InstructionSet
from ..interfaces import TestCase, Operand, RegisterOperand, FlagsOperand, MemoryOperand, \
    ImmediateOperand, AgenOperand, OT, Instruction, BasicBlock, InstructionSpec, \
    MAIN_AREA_SIZE, FAULTY_AREA_SIZE, SANDBOX_DATA_SIZE, Function, ActorPL, PAGE_SIZE, \
    GeneratorException
from ..generator import ConfigurableGenerator, RandomGenerator, Pass, Printer
from ..config import CONF
from .x86_target_desc import X86TargetDesc
from .x86_elf_parser import X86ElfParser


class FaultFilter:

    def __init__(self) -> None:
        self.div_by_zero: bool = 'div-by-zero' in CONF.generator_faults_allowlist
        self.div_overflow: bool = 'div-overflow' in CONF.generator_faults_allowlist
        self.non_canonical_access: bool = 'non-canonical-access' in CONF.generator_faults_allowlist
        self.u2k_access: bool = 'user-to-kernel-access' in CONF.generator_faults_allowlist


class X86Generator(ConfigurableGenerator, abc.ABC):
    faults: FaultFilter
    target_desc: X86TargetDesc

    def __init__(self, instruction_set: InstructionSet, seed: int):
        super(X86Generator, self).__init__(instruction_set, seed)
        self.target_desc = X86TargetDesc()
        self.elf_parser = X86ElfParser(self.target_desc)
        self.faults = FaultFilter()

        # configure instrumentation passes
        self.passes = [
            X86PatchUndefinedFlagsPass(self.instruction_set, self),
            X86SandboxPass(self.target_desc, self.faults),
            X86PatchUndefinedResultPass(),
        ]
        if self.faults.non_canonical_access:
            self.passes.append(X86NonCanonicalAddressPass())
        if self.faults.u2k_access:
            self.passes.append(X86U2KAccessPass())  # must be after X86SandboxPass
        self.passes.append(X86PatchOpcodesPass())
        self.printer = X86Printer(self.target_desc)

    def get_return_instruction(self) -> Instruction:
        return Instruction("ret", False, "", True)

    def get_unconditional_jump_instruction(self) -> Instruction:
        return Instruction("jmp", False, "UNCOND_BR", True)

    def get_elf_data(self, test_case: TestCase, obj_file: str) -> None:
        self.elf_parser.parse(test_case, obj_file)


class X86lfencePass(Pass):

    def run_on_test_case(self, test_case: TestCase) -> None:
        for func in test_case.functions:
            for bb in func:
                insertion_points = []
                for instr in bb:
                    # make a copy to avoid infinite insertions
                    insertion_points.append(instr)

                for instr in insertion_points:
                    bb.insert_after(instr, Instruction("lfence", True))


class X86NonCanonicalAddressPass(Pass):

    def run_on_test_case(self, test_case: TestCase) -> None:
        for func in test_case.functions:
            for bb in func:
                memory_instructions = []
                for instr in bb:
                    if instr.is_instrumentation or instr.is_from_template:
                        continue
                    if instr.name in ["div", "idiv"]:
                        # Instrumentation is difficult to combine
                        continue
                    if instr.has_mem_operand(True):
                        memory_instructions.append(instr)

                # Collect src operands
                for instr in memory_instructions:
                    n = len(memory_instructions)
                    rand_bool = random.randint(0, n) == 0
                    if not rand_bool:
                        continue

                    src_operands = []
                    for o in instr.get_src_operands():
                        if isinstance(o, RegisterOperand):
                            src_operands.append(o)

                    mem_operands = instr.get_mem_operands()
                    implicit_mem_operands = instr.get_implicit_mem_operands()
                    if mem_operands and not implicit_mem_operands:
                        assert len(mem_operands) == 1, f"Unexpected instruction format {instr.name}"
                        mem_operand: Operand = mem_operands[0]
                        registers = mem_operand.value

                        masks_list = ["rax", "rbx"]
                        mask_reg = masks_list[0]
                        # Do not overwrite offset register with mask
                        for operands in src_operands:
                            op_regs = re.split(r'\+|-|\*| ', operands.value)
                            for reg in op_regs:
                                if X86TargetDesc.reg_normalized[mask_reg] == \
                                   X86TargetDesc.reg_normalized[reg]:
                                    mask_reg = masks_list[1]

                        offset_list = ["rcx", "rdx"]
                        offset_reg = offset_list[0]
                        # Do not reuse destination register
                        for op in instr.get_all_operands():
                            if not isinstance(op, RegisterOperand):
                                continue
                            if X86TargetDesc.reg_normalized[offset_reg] == \
                               X86TargetDesc.reg_normalized[op.value]:
                                offset_reg = offset_list[1]

                        mask = hex((random.getrandbits(16) << 48))
                        lea = Instruction("lea", True) \
                            .add_op(RegisterOperand(offset_reg, 64, False, True)) \
                            .add_op(MemoryOperand(registers, 64, True, False))
                        bb.insert_before(instr, lea)
                        mov = Instruction("mov", True) \
                            .add_op(RegisterOperand(mask_reg, 64, True, True)) \
                            .add_op(ImmediateOperand(mask, 64))
                        bb.insert_before(instr, mov)
                        mask = Instruction("xor", True) \
                            .add_op(RegisterOperand(offset_reg, 64, True, True)) \
                            .add_op(RegisterOperand(mask_reg, 64, True, False))
                        bb.insert_before(instr, mask)
                        for idx, op in enumerate(instr.operands):
                            if op == mem_operand:
                                old_op = instr.operands[idx]
                                addr_op = MemoryOperand(offset_reg, old_op.get_width(), old_op.src,
                                                        old_op.dest)
                                instr.operands[idx] = addr_op

                    # Make sure #GP only once. Otherwise Unicorn keeps raising an exception
                    # when rolling back to the end of the code
                    return


class X86U2KAccessPass(Pass):
    """ A pass that selects a random memory access instruction in a user actor and replaces it
    with an access to the kernel actor's data (actor 0). """

    def run_on_test_case(self, test_case: TestCase) -> None:
        for func in test_case.functions:
            if func.owner.privilege_level != ActorPL.USER:
                continue

            to_instrument: List[Instruction] = []
            for bb in func:
                for instr in bb:
                    if instr.is_instrumentation or instr.is_from_template:
                        continue
                    if instr.name in ["div", "idiv"]:
                        # Instrumentation is difficult to combine
                        continue
                    if instr.has_mem_operand(False):
                        to_instrument.append(instr)

                for instr in to_instrument:
                    self.instrument(instr, bb, func.owner.id_)

    def instrument(self, instr: Instruction, parent: BasicBlock, owner_id) -> None:
        probability = 1 / CONF.avg_mem_accesses
        if random.random() > probability:
            return

        # select operand to patch
        mem_operands: List[MemoryOperand] = instr.get_mem_operands()
        if len(mem_operands) == 1:
            mem_operand = mem_operands[0]
        else:
            mem_operand = random.choice(mem_operands)

        # subtract kernel offset
        kernel_offset = owner_id * SANDBOX_DATA_SIZE - MAIN_AREA_SIZE  # select kernel FAULTY_AREA
        mem_operand.value += " - " + str(kernel_offset)

        # patch instrumentation added by X86SandboxPass so that it targets only one page
        previous_instr = instr.previous
        while previous_instr and previous_instr.is_instrumentation:
            for op in previous_instr.operands:
                if not isinstance(op, ImmediateOperand):
                    continue
                mask_value = int(op.value, base=0)
                if mask_value > PAGE_SIZE:
                    mask_value %= PAGE_SIZE
                op.value = bin(mask_value)
            previous_instr = previous_instr.previous


class X86SandboxPass(Pass):
    mask_3bits = "0b111"
    bit_test_names = ["bt", "btc", "btr", "bts", "lock bt", "lock btc", "lock btr", "lock bts"]

    def __init__(self, target_desc: X86TargetDesc, faults: FaultFilter):
        super().__init__()
        self.target_desc = target_desc
        self.faults = faults

        input_memory_size = MAIN_AREA_SIZE + FAULTY_AREA_SIZE
        mask_size = int(math.log(input_memory_size, 2))
        self.sandbox_address_mask = "0b" + "1" * mask_size

    def run_on_test_case(self, test_case: TestCase) -> None:
        for func in test_case.functions:
            for bb in func:
                # collect all instructions that require sandboxing
                memory_instructions = []
                divisions = []
                bit_tests = []
                repeated_instructions = []
                corrupted_cf = []
                enclu = []
                for inst in bb:
                    if inst.is_instrumentation or inst.is_from_template:
                        continue

                    if inst.has_mem_operand(True):
                        memory_instructions.append(inst)
                    if inst.name in ["div", "rex div", "idiv", "rex idiv"]:
                        divisions.append(inst)
                    elif inst.name in self.bit_test_names:
                        bit_tests.append(inst)
                    elif "rep" in inst.name:
                        repeated_instructions.append(inst)
                    elif inst.category == "BASE-ROTATE" or inst.category == "BASE-SHIFT":
                        corrupted_cf.append(inst)
                    elif inst.name == "enclu":
                        enclu.append(inst)

                # sandbox them
                for inst in memory_instructions:
                    self.sandbox_memory_access(inst, bb)

                for inst in divisions:  # must be after memory accesses
                    self.sandbox_division(inst, bb, func.owner.name)

                for inst in bit_tests:
                    self.sandbox_bit_test(inst, bb)

                for inst in repeated_instructions:
                    self.sandbox_repeated_instruction(inst, bb)

                for inst in corrupted_cf:
                    self.sandbox_corrupted_cf(inst, bb)

                for inst in enclu:
                    self.sandbox_enclu(inst, bb)

    def sandbox_memory_access(self, instr: Instruction, parent: BasicBlock):
        """ Force the memory accesses into the page starting from R14 """
        mem_operands = instr.get_mem_operands()
        implicit_mem_operands = instr.get_implicit_mem_operands()
        mask = self.sandbox_address_mask
        if "SSE" in instr.category \
           and "movup" not in instr.name \
           and "movdqu" not in instr.name \
           and "lddqu" not in instr.name:
            mask = mask[:-4] + "0" * 4
        if CONF.x86_generator_align_locks:  # type: ignore
            if "lock" in instr.name or instr.name == "xchg":
                mask = mask[:-3] + "0" * 3

        if mem_operands and not implicit_mem_operands:
            assert len(mem_operands) == 1, \
                f"Instructions with multiple memory accesses are not yet supported: {instr.name}"
            mem_operand: Operand = mem_operands[0]
            address_reg = mem_operand.value
            imm_width = mem_operand.width if mem_operand.width <= 32 else 32
            apply_mask = Instruction("and", True) \
                .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                .add_op(ImmediateOperand(mask, imm_width)) \
                .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
            parent.insert_before(instr, apply_mask)
            instr.get_mem_operands()[0].value = "r14 + " + address_reg
            return

        mem_operands = implicit_mem_operands
        if mem_operands:
            # deduplicate operands
            uniq_operands: Dict[str, MemoryOperand] = {}
            for o in mem_operands:
                if o.value not in uniq_operands:
                    uniq_operands[o.value] = o

            # instrument each operand to sandbox the memory accesses
            for address_reg, mem_operand in uniq_operands.items():
                imm_width = mem_operand.width if mem_operand.width <= 32 else 32
                assert address_reg in self.target_desc.registers[64], \
                    f"Unexpected address register {address_reg} used in {instr}"
                apply_mask = Instruction("and", True) \
                    .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                    .add_op(ImmediateOperand(mask, imm_width)) \
                    .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
                parent.insert_before(instr, apply_mask)

                add_base = Instruction("add", True) \
                    .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                    .add_op(RegisterOperand("r14", 64, True, False)) \
                    .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
                parent.insert_before(instr, add_base)

                # restore the original register value
                remove_base = Instruction("sub", True) \
                    .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                    .add_op(RegisterOperand("r14", 64, True, False)) \
                    .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
                parent.insert_after(instr, remove_base)
            return

        raise GeneratorException("Attempt to sandbox an instruction without memory operands")

    def sandbox_division(self, inst: Instruction, parent: BasicBlock, owner_name: str):
        """
        In the experiments where division errors are not permitted, we prevent them
        through code instrumentation.
        Specifically, we may need to prevent two types of faults:
        - division by zero
        - division overflow (i.e., quotient is larger than the destination register)

        To prevent div by zero we OR the divider with a non-zero value:
            divisor = divisor | 1

        The mechanism for preventing div overflows depends on the division type:
        * for unsigned division, we first mask the upper half of the dividend with the divisor,
        which makes the quotient at most one bit larger then the destination, and then shift
        the result by one, thus compensating for the last one overflow bit.
            D = (D & divisor) >> 1
        * for signed division, we make set its lower bits to 0b10000, which ensures that
        all positive divider values are larger or equal to 15, and all negative values
        are smaller or equal to -15.
            divisor[0:3] = 0b1000
        We further constraint the division by clearing the sign bit of the dividend.
        Under these two constraints, an overflow is possible only when the dividend
        is larger  or equal to (15 << div_size, e.g., for 32-bit division 15 * (2 ** 32)).
        Since, the dividend is a combination of two registers (D << div_size + A),
        an overflow happens when D is larger or equal to 15. We ensure that it does not
        happen by masking the upper bits of D:
            D = D & 0b11

        There are also two corner cases:
            1) The divisor is D. This case is impossible to resolve, as far as I can tell,
            because our instrumentation would have to modify both the divisor and the dividend
            at the same time. We just give up in this case and delete the instruction.
            2) 8-bit division, when the divisor is the AX register alone.
            Here the instrumentation becomes too complicated, so we simply set AX to 1.

        This instrumentation has a side effect of reducing the entropy of the division operands:
        For unsigned division:
            * entropy of the divisor is reduced by 1 bit
            * entropy of D is reduced by (divisor_value_size + 1) bits
        For signed division:
            * entropy of the divisor is reduced by 4 bits
            * entropy of D is reduced by (division_size - 2) bits (i.e., the resulting
              entropy of D is 2 bits, with the sign bit cleared)
        """
        # Determine what type of fault is allowed
        actor_blocklist = CONF._actors[owner_name]["fault_blocklist"]
        enable_div_by_zero = self.faults.div_by_zero & ("div-by-zero" not in actor_blocklist)
        enable_div_overflow = self.faults.div_overflow & ("div-overflow" not in actor_blocklist)

        # Copy div source operand as we may need to modify it
        divisor = deepcopy(inst.operands[0])
        size = divisor.width

        # This option prevents triggering of Zero Division Injection in the tests
        if size == 64 and CONF.x86_disable_div64:  # type: ignore
            parent.delete(inst)
            return

        # Prevent div by zero
        if not enable_div_by_zero:
            if "idiv" not in inst.name or enable_div_overflow:
                # for unsigned division and signed divisions with overflow permitted,
                # it is sufficient to OR the divisor with 1 to prevent div by zero
                instrumentation = Instruction("or", True) \
                    .add_op(divisor) \
                    .add_op(ImmediateOperand("1", 8)) \
                    .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
                parent.insert_before(inst, instrumentation)
                divisor.dest = True
            else:
                # for signed divisions with overflows forbidden,
                # we need to modify the divisor to make it both non-zero
                # and large enough to avoid overflows.
                # We have two cases here, positive and negative divider values:

                # For positive dividers, we OR the divisor with 0b10000 to make sure
                # that the divider is at least 15
                # (the value 15 comes from the instrumentation below, where
                # we make the dividend at most `4 << div_size - 1`)
                instrumentation = Instruction("or", True) \
                    .add_op(divisor) \
                    .add_op(ImmediateOperand("0b1000", 8)) \
                    .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
                parent.insert_before(inst, instrumentation)
                divisor.dest = True

                # For negative dividers, we clear the lower 4 bits of the divider,
                # thus making the value at most -15. To this end, we AND
                # the lower 8 bits of the divider bit a bit mask 0b11110000
                divider_8_bit = deepcopy(divisor)
                divider_8_bit.width = 8
                if isinstance(divisor, RegisterOperand):
                    reg_normalized = self.target_desc.reg_normalized[divisor.value]
                    reg_8_bit = self.target_desc.reg_denormalized[reg_normalized][8]
                    divider_8_bit.value = reg_8_bit
                instrumentation = Instruction("and", True) \
                    .add_op(divider_8_bit) \
                    .add_op(ImmediateOperand("0b11111000", 8)) \
                    .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
                parent.insert_before(inst, instrumentation)

        if enable_div_overflow:
            return
        # Prevent div overflows:

        # Check for the cases that are impossible to instrument:
        # - division by D register
        # - division by a memory value with the RDX offset
        # - division where AX is both the dividend and the offset in memory
        if divisor.value in ["rdx", "edx", "dx", "dh", "dl"] \
           or "rdx" in divisor.value \
           or ("rax" in divisor.value and size == 8):
            parent.delete(inst)
            return

        # Special case: dividend in AX
        # instrumentation: ax = 1
        if size == 8:
            instrumentation = Instruction("mov", True).\
                add_op(RegisterOperand("ax", 16, False, True)).\
                add_op(ImmediateOperand("1", 16))
            parent.insert_before(inst, instrumentation)
            return

        # Normal case
        d_register = {64: "rdx", 32: "edx", 16: "dx"}[size]

        # signed div
        if "idiv" in inst.name:
            # it's extremely hard to prevent overflows with large signed divisions
            # that's why we simplify the case by assigning zero to the upper bits of the dividend
            # instrumentation, thus making the dividend at most `4 << div_size - 1`
            # D = D & 3
            instrumentation = Instruction("and", True) \
                .add_op(RegisterOperand(d_register, size, True, True)) \
                .add_op(ImmediateOperand("0b11", 8)) \
                .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
            parent.insert_before(inst, instrumentation)

        # unsigned div
        else:
            # instrumentation:
            # D = (D & divisor) >> 1  # ensure that D is always smaller than the divisor
            instrumentation = Instruction("and", True) \
                .add_op(RegisterOperand(d_register, size, True, True)) \
                .add_op(divisor) \
                .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
            parent.insert_before(inst, instrumentation)
            divisor.dest = True

            instrumentation = Instruction("shr", True) \
                .add_op(RegisterOperand(d_register, size, True, True)) \
                .add_op(ImmediateOperand("1", 8)) \
                .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "undef"]), True)
            parent.insert_before(inst, instrumentation)

    def sandbox_bit_test(self, inst: Instruction, parent: BasicBlock):
        """
        The address accessed by a BT* instruction is based on both of its operands.
        `sandbox_memory_access` take care of the first operand.
        This function ensures that the offset is always within a byte.
        """
        address = inst.operands[0]
        if isinstance(address, RegisterOperand):
            # this is a version that does not access memory
            # no need for sandboxing
            return

        offset = deepcopy(inst.operands[1])
        if isinstance(offset, ImmediateOperand):
            # The offset is an immediate
            # Simply replace it with a smaller value
            offset.value = str(random.randint(0, 7))
            return

        # The offset is in a register
        # Mask its upper bits to reduce the stored value to at most 7
        if address.value != offset.value:
            apply_mask = Instruction("and", True) \
                .add_op(offset) \
                .add_op(ImmediateOperand(self.mask_3bits, 8)) \
                .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
            parent.insert_before(inst, apply_mask)
            offset.dest = True
            return

        # Special case: offset and address use the same register
        # Sandboxing is impossible. Give up
        parent.delete(inst)

    def sandbox_repeated_instruction(self, inst: Instruction, parent: BasicBlock):
        apply_mask = Instruction("and", True) \
            .add_op(RegisterOperand("rcx", 64, True, True)) \
            .add_op(ImmediateOperand("0xff", 8)) \
            .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
        add_base = Instruction("add", True) \
            .add_op(RegisterOperand("rcx", 64, True, True)) \
            .add_op(ImmediateOperand("1", 1)) \
            .add_op(FlagsOperand(["w", "w", "w", "w", "w", "", "", "", "w"]), True)
        parent.insert_before(inst, apply_mask)
        parent.insert_before(inst, add_base)

    def sandbox_corrupted_cf(self, inst: Instruction, parent: BasicBlock):
        set_cf = Instruction("stc", True) \
            .add_op(FlagsOperand(["w", "", "", "", "", "", "", "", ""]), True)
        parent.insert_after(inst, set_cf)

    def sandbox_enclu(self, inst: Instruction, parent: BasicBlock):
        options = [
            "0",  # ereport
            "1",  # egetkey
            "4",  # eexit
            "5",  # eaccept
            "6",  # emodpe
            "7",  # eacceptcopy
        ]
        set_rax = Instruction("mov", True) \
            .add_op(RegisterOperand("eax", 32, True, True)) \
            .add_op(ImmediateOperand(random.choice(options), 1))
        parent.insert_before(inst, set_rax)

    @staticmethod
    def requires_sandbox(inst: InstructionSpec):
        if inst.has_mem_operand:
            return True
        if inst.name in ["div", "rex div"]:
            return True
        if inst.name in ["bt", "btc", "btr", "bts", "lock bt", "lock btc", "lock btr", "lock bts"]:
            return True
        if inst.category in ["BASE-SHIFT", "BASE-ROTATE"]:
            return True
        return False


class X86PatchUndefinedFlagsPass(Pass):
    """
    Some instructions have undefined effect on FLAGS (e.g., SHL may or may not overwrite OF).
    This causes a mismatch between Model execution and Executor, if the undefined behavior
    is implemented differently. It leads to false positives.
    To prevent them, we analyse the test cases in search for the cases where an instruction
    with undefined flags is followed by an instruction that uses this flag. We then
    insert another random instruction in-between, such that this
    instruction overwrites the undefined flag.

    I.e., we replace
        SHL eax, eax  // undefined OF
        JNO .label    // uses OF
    with
        SHL eax, eax
        ADD ebx, ecx  // random instruction that overwrites OF
        JNO .label
    """
    patch_candidates: List[InstructionSpec]

    def __init__(self, instruction_set: InstructionSet, generator: ConfigurableGenerator):
        super().__init__()
        self.instruction_set = instruction_set
        self.generator = generator

        self.patch_candidates = []
        for instruction_spec in instruction_set.instructions:
            # we don't want to change the control flow
            if instruction_spec.control_flow:
                continue

            # check if the instruction is safe to use on its own
            if X86SandboxPass.requires_sandbox(instruction_spec):
                continue

            # check if it overwrites flags and if creates new dependencies
            has_read = False
            has_write = False
            for op in instruction_spec.operands + instruction_spec.implicit_operands:
                if op.type == OT.FLAGS:
                    for f in op.values:
                        if f in ['r', 'r/w', 'r/cw']:
                            has_read = True
                        elif f in ['w']:
                            has_write = True
            if not has_read and has_write:
                self.patch_candidates.append(instruction_spec)

    def run_on_test_case(self, test_case: TestCase) -> None:
        for func in test_case.functions:
            for bb in func:
                # get a list of all instructions in the BB
                all_instructions: List[Instruction] = []
                for inst in bb:
                    all_instructions.append(inst)
                if len(bb.terminators) == 2:  # include conditional terminators
                    all_instructions.append(bb.terminators[0])

                # keep track of the FLAGS dependencies as we iterate over instructions
                flags_to_set: Set[str] = set()

                # walk the list in inverse order
                while all_instructions:
                    inst = all_instructions.pop()
                    if inst.is_from_template:
                        continue

                    flags: Optional[FlagsOperand] = inst.get_flags_operand()
                    if not flags:
                        continue

                    # fix undefined flags by adding another instruction in-between
                    undef_flags = [i for i in flags.get_undef_flags() if i in flags_to_set]
                    if undef_flags:
                        patches = self.find_flags_patch(undef_flags, flags_to_set)
                        for patch in patches:
                            bb.insert_after(inst, patch)
                            patch.is_instrumentation = True
                            # remove the flags overwritten by the patch
                            for f in patch.get_flags_operand().get_write_flags():  # type: ignore
                                flags_to_set.discard(f)

                    # remove the flags overwritten by the instruction
                    for f in flags.get_write_flags():
                        flags_to_set.discard(f)

                    # add new flag dependencies
                    for f in flags.get_read_flags():
                        flags_to_set.add(f)

                # make sure that we do not have undefined flags when we enter the BB
                if flags_to_set:
                    # find a place to insert the patches
                    inst = bb.get_first()
                    while inst:
                        if inst.name != "macro":
                            break
                        inst = inst.next
                    if not inst:
                        self.LOG.error("X86PatchUndefinedFlagsPass: No place to insert a patch")

                    patches = self.find_flags_patch(list(flags_to_set), flags_to_set)
                    for patch in patches:
                        bb.insert_before(inst, patch)
                        patch.is_instrumentation = True

    def find_flags_patch(self, undef_flags, flags_to_set) -> List[Instruction]:
        """
        Find an instruction sequence that would overwrite a list of flags

        :param undef_flags: list of undefined flags that have to be overwritten
            by the patch instructions
        :param flags_to_set: list of flags that will be read by one of the following instructions,
            and thus should not be set to the undef state by the patch. This should be always
            a superset of or the same as undef_flags.
        :return: list of instructions that overwrite the undefined flags
        """
        org_undef = deepcopy(undef_flags)
        patches: List[Instruction] = []
        for instruction_spec in self.patch_candidates:
            patch = self.generator.generate_instruction(instruction_spec)
            patch_flags = patch.get_flags_operand()
            assert patch_flags
            new_undef_flags = [
                i for i in patch_flags.get_undef_flags()
                if i not in undef_flags and i in flags_to_set
            ]
            not_patched_flags = [i for i in undef_flags if i not in patch_flags.get_write_flags()]

            if not new_undef_flags and not_patched_flags != undef_flags:
                patches.append(patch)
                undef_flags = not_patched_flags
                if not undef_flags:
                    break

        if undef_flags:
            raise GeneratorException("Could not find an instruction to patch flags.\n"
                                     f"  Initial flags to be patched: {org_undef}\n"
                                     f"  Flags for which a patch was not found: {undef_flags}")

        return patches


class X86PatchUndefinedResultPass(Pass):

    def run_on_test_case(self, test_case: TestCase) -> None:
        for func in test_case.functions:
            for bb in func:
                # collect all instructions that require patching
                bit_scan = []
                for inst in bb:
                    if inst.is_instrumentation or inst.is_from_template:
                        continue
                    if inst.name in ["bsf", "bsr"]:
                        bit_scan.append(inst)

                # patch them
                for inst in bit_scan:
                    self.patch_bit_scan(inst, bb)

    @staticmethod
    def patch_bit_scan(inst: Instruction, parent: BasicBlock):
        """
        Bit Scan instructions give an undefined result when the source operand is zero.
        To avoid it, set the most significant bit.
        """
        source = deepcopy(inst.operands[1])  # copy because we may modify it
        mask = bin(1 << (source.width - 1))
        mask_size = source.width
        if source.width in [64, 32]:
            mask = "0b1000000000000000000000000000000"
            mask_size = 32
        apply_mask = Instruction("or", True) \
            .add_op(source) \
            .add_op(ImmediateOperand(mask, mask_size)) \
            .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
        parent.insert_before(inst, apply_mask)
        source.dest = True


class X86PatchOpcodesPass(Pass):
    """
    Replaces assembly instructions with their opcodes.
    This is necessary to test instruction with multiple opcodes and
    the instruction that are not supported/not permitted by the standard
    assembler.
    """
    opcodes: Dict[str, List[str]] = {
        "ud2": [
            # UD2 instruction
            "0x0f, 0x0b",

            # invalid in 64-bit mode;
            # all the following opcodes are padded
            # with NOP to prevent misinterpretation by objdump
            "0x06, 0x90",  # 32-bit encoding of PUSH
            "0x07, 0x90",  # 32-bit encoding of POP
            "0x0e, 0x90",  # alternative 32-bit encoding of PUSH
            "0x16, 0x90",  # alternative 32-bit encoding of PUSH
            "0x17, 0x90",  # alternative 32-bit encoding of POP
            "0x1e, 0x90",  # alternative 32-bit encoding of PUSH
            "0x1f, 0x90",  # alternative 32-bit encoding of POP
            "0x27, 0x90",  # DAA
            "0x2f, 0x90",  # DAS
            "0x37, 0x90",  # AAA
            "0x3f, 0x90",  # AAS
            "0x60, 0x90",  # PUSHA
            "0x61, 0x90",  # POPA
            "0x62, 0x90",  # BOUND
            "0x82, 0x90",  # 32-bit aliases for logical instructions
            "0x9a, 0x90",  # 32-bit encoding of CALLF
            "0xc4, 0x90",  # LES
            "0xd4, 0x90",  # AAM
            "0xd5, 0x90",  # AAD
            "0xd6, 0x90",  # reserved
            "0xea, 0x90",  # 32-bit encoding of JMPF
        ],
        "int1": ["0xf1"]
    }

    def run_on_test_case(self, test_case: TestCase) -> None:
        for func in test_case.functions:
            for bb in func:
                # collect all UD instructions
                to_patch = []
                for inst in bb:
                    if inst.is_instrumentation or inst.is_from_template:
                        continue
                    if inst.name in self.opcodes.keys():
                        to_patch.append(inst)

                # patch them
                for inst in to_patch:
                    self.replace_opcode(inst, bb)

    def replace_opcode(self, inst: Instruction, _: BasicBlock):
        opcode_options = self.opcodes[inst.name]
        opcode = random.choice(opcode_options)
        inst.name = ".byte " + opcode


class X86Printer(Printer):
    memory_prefixes = {
        8: "byte ptr",
        16: "word ptr",
        32: "dword ptr",
        64: "qword ptr",
        80: "tbyte ptr",
        128: "xmmword ptr",
        256: "ymmword ptr",
        512: "zmmword ptr",
        4608: "ptr",
    }
    prologue_template = [
        ".intel_syntax noprefix\n",
        ".test_case_enter:\n",
    ]
    epilogue_template = [
        ".section .data.main\n",
        ".test_case_exit:\n",
    ]

    def __init__(self, _: X86TargetDesc) -> None:
        super().__init__()

    def print(self, test_case: TestCase, outfile: str) -> None:
        with open(outfile, "w") as f:
            # print prologue
            for line in self.prologue_template:
                f.write(line)

            # print the test case
            for func in test_case.functions:
                self.print_function(func, f)

            # print epilogue
            for line in self.epilogue_template:
                f.write(line)

    def print_function(self, func: Function, file):
        file.write(f".section .data.{func.owner.name}\n")
        file.write(f"{func.name}:\n")
        for bb in func:
            self.print_basic_block(bb, file)

        self.print_basic_block(func.exit, file)

    def print_basic_block(self, bb: BasicBlock, file):
        file.write(f"{bb.name.lower()}:\n")
        for inst in bb:
            file.write(self.instruction_to_str(inst) + "\n")
        for inst in bb.terminators:
            file.write(self.instruction_to_str(inst) + "\n")

    def instruction_to_str(self, inst: Instruction):
        if inst.name == "macro":
            return self.macro_to_str(inst)

        operands = ", ".join([self.operand_to_str(op) for op in inst.operands])
        if inst.is_instrumentation:
            comment = "# instrumentation"
        elif inst.is_noremove:
            comment = "# noremove"
        else:
            comment = ""
        return f"{inst.name} {operands} {comment}"

    def operand_to_str(self, op: Operand) -> str:
        if isinstance(op, MemoryOperand) or isinstance(op, AgenOperand):
            prefix = self.memory_prefixes[op.width]
            return f"{prefix} [{op.value}]"

        return op.value

    def macro_to_str(self, inst: Instruction):
        macro_placeholder = "nop qword ptr [rax + 0xff]"
        if inst.operands[1].value.lower() == ".noarg":
            return f".macro{inst.operands[0].value}: {macro_placeholder}"
        else:
            return f".macro{inst.operands[0].value}{inst.operands[1].value}: {macro_placeholder}"


class X86RandomGenerator(X86Generator, RandomGenerator):

    def __init__(self, instruction_set: InstructionSet, seed: int):
        super().__init__(instruction_set, seed)
