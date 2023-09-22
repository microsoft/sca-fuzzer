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
from typing import List, Dict, Set, Optional, Tuple
from subprocess import run
from elftools.elf.elffile import ELFFile, SymbolTableSection  # type: ignore

from ..isa_loader import InstructionSet
from ..interfaces import TestCase, Operand, RegisterOperand, FlagsOperand, MemoryOperand, \
    ImmediateOperand, AgenOperand, OT, Instruction, BasicBlock, InstructionSpec, \
    PageTableModifier, MAIN_REGION_SIZE, FAULTY_REGION_SIZE, Function, ActorType, ElfSection, Symbol
from ..generator import ConfigurableGenerator, RandomGenerator, Pass, Printer, GeneratorException
from ..config import CONF
from .x86_target_desc import X86TargetDesc


class X86Generator(ConfigurableGenerator, abc.ABC):

    def __init__(self, instruction_set: InstructionSet, seed: int):
        super(X86Generator, self).__init__(instruction_set, seed)
        self.target_desc = X86TargetDesc()
        self.passes = [
            X86SandboxPass(self.target_desc),
            X86PatchUndefinedFlagsPass(self.instruction_set, self),
            X86PatchUndefinedResultPass(),
            X86NonCanonicalAddressPass(),
            X86PatchOpcodesPass(),
        ]
        self.printer = X86Printer(self.target_desc)

        # select PTE bits that could be set
        self.pte_bit_choices: List[Tuple[int, bool]] = []
        if 'assist-accessed' in CONF.permitted_faults:
            self.pte_bit_choices.append(self.target_desc.pte_bits["ACCESSED"])
        if 'assist-dirty' in CONF.permitted_faults:
            self.pte_bit_choices.append(self.target_desc.pte_bits["DIRTY"])
        if 'PF-present' in CONF.permitted_faults:
            self.pte_bit_choices.append(self.target_desc.pte_bits["PRESENT"])
        if 'PF-writable' in CONF.permitted_faults:
            self.pte_bit_choices.append(self.target_desc.pte_bits["RW"])
        if 'PF-smap' in CONF.permitted_faults:
            self.pte_bit_choices.append(self.target_desc.pte_bits["USER"])

    def get_elf_data(self, test_case: TestCase, obj_file: str) -> None:
        exit_addr: int = -1
        function_symbol_entries: Dict = {}
        instruction_addresses: Dict[str, List[int]] = {}
        section_headers: Dict = {}

        # parse ELF data
        with open(obj_file, "rb") as f:
            data = ELFFile(f)

            # we build objects in such a way that there should be no segments
            assert data.num_segments() == 0, f"{data.num_segments()}"

            # collect section info
            for id_, s in enumerate(data.iter_sections()):
                if ".data." not in s.name:
                    continue
                name = s.name
                section_headers[name] = s.header
                section_headers[name]['sid'] = id_

            # get addresses of functions and macros
            symtab: SymbolTableSection = data.get_section_by_name(".symtab")  # type: ignore
            for s in symtab.iter_symbols():
                name = s.name
                if ".function_" in name:
                    function_symbol_entries[name] = s.entry

                if ".test_case_exit" in name:
                    exit_addr = s.entry.st_value

        # parse objdump output
        dump = run(
            f"objdump --no-show-raw-insn -D -M intel -m i386:x86-64 {obj_file} "
            "| awk '/ [0-9a-f]+:/{print $1} /section/{print $0}'",
            shell=True,
            check=True,
            capture_output=True)

        section_name = ""
        for line in dump.stdout.decode().split("\n"):
            if not line:
                continue

            if "section" in line:
                try:
                    section_name = line.split()[-1][:-1]
                except ValueError:
                    section_name = ""
                if section_name == "":
                    self.LOG.error(f"Invalid actor label: {line.split()[-1]}")
                instruction_addresses[section_name] = []
                continue
            assert section_name != "", "Failed to parse objdump output (section_name)"

            instruction_addresses[section_name].append(int(line[:-1], 16))

        # order function symbols by section id and offset
        func_names_ordered: Dict[int, List] = {}
        for f, e in function_symbol_entries.items():
            sid = e.st_shndx
            if not func_names_ordered.get(sid):
                func_names_ordered[sid] = []
            func_names_ordered[sid].append(f)
        for sid in func_names_ordered.keys():
            func_names_ordered[sid].sort(key=lambda x: function_symbol_entries[x].st_value)

        # add collected data to the test case
        address_map: Dict[int, Dict[int, Instruction]] = {}
        for section_name, address_list in sorted(instruction_addresses.items()):
            sid = section_headers[section_name]['sid']
            actor = test_case.get_actor_by_name(section_name.split(".")[2])
            actor.elf_section = ElfSection(sid, section_headers[section_name]['sh_offset'],
                                           section_headers[section_name]['sh_size'])

            counter = 0
            address_map[actor.id_] = {}
            for func_name in func_names_ordered[sid]:
                func = test_case.get_function_by_name(func_name)
                assert func.owner == actor

                offset = function_symbol_entries[func.name].st_value
                assert offset == address_list[counter]

                # add the function into the symbol table
                # FIXME: replace 0 with symbol id
                test_case.symbol_table.append(Symbol(
                    aid=actor.id_,
                    id_=0,
                    offset=offset,
                ))

                for bb in list(func) + [func.exit]:
                    for inst in list(bb) + bb.terminators:
                        address = address_list[counter]

                        # connect instructions with their addresses
                        inst.section_id = sid
                        inst.section_offset = address
                        address_map[actor.id_][address] = inst

                        # add macros to the symbol table
                        if inst.name == "MACRO":
                            test_case.symbol_table.append(
                                Symbol(
                                    aid=actor.id_,
                                    id_=int(inst.operands[0].value),
                                    offset=address,
                                ))

                        counter += 1

        # the last instruction in .data.0_host is the test case exit, and it must map to a NOP
        address_map[0][exit_addr] = Instruction("NOP", False, "BASE-NOP", True)

        test_case.address_map = address_map

    def get_return_instruction(self) -> Instruction:
        return Instruction("RET", False, "", True)

    def get_unconditional_jump_instruction(self) -> Instruction:
        return Instruction("JMP", False, "UNCOND_BR", True)

    def create_pte(self, test_case: TestCase):
        """
        Pick a random PTE bit (among the permitted ones) and set/reset it
        """
        if not self.pte_bit_choices:  # no choices, so PTE should stay intact
            return

        pte_bit = random.choice(self.pte_bit_choices)
        if pte_bit[1]:
            mask_clear = 0xffffffffffffffff ^ (1 << pte_bit[0])
            mask_set = 0x0
        else:
            mask_clear = 0xffffffffffffffff
            mask_set = 0x0 | (1 << pte_bit[0])
        test_case.faulty_pte = PageTableModifier(mask_set, mask_clear)


class X86LFENCEPass(Pass):

    def run_on_test_case(self, test_case: TestCase) -> None:
        for func in test_case.functions:
            for bb in func:
                insertion_points = []
                for instr in bb:
                    # make a copy to avoid infinite insertions
                    insertion_points.append(instr)

                for instr in insertion_points:
                    bb.insert_after(instr, Instruction("LFENCE", True))


class X86NonCanonicalAddressPass(Pass):

    def run_on_test_case(self, test_case: TestCase) -> None:
        if 'GP-noncanonical' not in CONF.permitted_faults:
            return

        for func in test_case.functions:
            for bb in func:
                memory_instructions = []
                for instr in bb:
                    if instr.is_instrumentation:
                        continue
                    if instr.name in ["DIV", "IDIV"]:
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

                        masks_list = ["RAX", "RBX"]
                        mask_reg = masks_list[0]
                        # Do not overwrite offset register with mask
                        for operands in src_operands:
                            op_regs = re.split(r'\+|-|\*| ', operands.value)
                            for reg in op_regs:
                                if X86TargetDesc.reg_normalized[mask_reg] == \
                                   X86TargetDesc.reg_normalized[reg]:
                                    mask_reg = masks_list[1]

                        offset_list = ["RCX", "RDX"]
                        offset_reg = offset_list[0]
                        # Do not reuse destination register
                        for op in instr.get_all_operands():
                            if not isinstance(op, RegisterOperand):
                                continue
                            if X86TargetDesc.reg_normalized[offset_reg] == \
                               X86TargetDesc.reg_normalized[op.value]:
                                offset_reg = offset_list[1]

                        mask = hex((random.getrandbits(16) << 48))
                        lea = Instruction("LEA", True) \
                            .add_op(RegisterOperand(offset_reg, 64, False, True)) \
                            .add_op(MemoryOperand(registers, 64, True, False))
                        bb.insert_before(instr, lea)
                        mov = Instruction("MOV", True) \
                            .add_op(RegisterOperand(mask_reg, 64, True, True)) \
                            .add_op(ImmediateOperand(mask, 64))
                        bb.insert_before(instr, mov)
                        mask = Instruction("XOR", True) \
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


class X86SandboxPass(Pass):
    mask_3bits = "0b111"
    bit_test_names = ["BT", "BTC", "BTR", "BTS", "LOCK BT", "LOCK BTC", "LOCK BTR", "LOCK BTS"]

    def __init__(self, target_desc: X86TargetDesc):
        super().__init__()
        input_memory_size = MAIN_REGION_SIZE + FAULTY_REGION_SIZE
        mask_size = int(math.log(input_memory_size, 2)) - CONF.memory_access_zeroed_bits
        self.sandbox_address_mask = "0b" + "1" * mask_size + "0" * CONF.memory_access_zeroed_bits
        self.target_desc = target_desc

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
                    if inst.has_mem_operand(True):
                        memory_instructions.append(inst)
                    if inst.name in ["DIV", "REX DIV", "IDIV", "REX IDIV"]:
                        divisions.append(inst)
                    elif inst.name in self.bit_test_names:
                        bit_tests.append(inst)
                    elif "REP" in inst.name:
                        repeated_instructions.append(inst)
                    elif inst.category == "BASE-ROTATE" or inst.category == "BASE-SHIFT":
                        corrupted_cf.append(inst)
                    elif inst.name == "ENCLU":
                        enclu.append(inst)

                # sandbox them
                for inst in memory_instructions:
                    self.sandbox_memory_access(inst, bb)

                for inst in divisions:  # must be after memory accesses
                    self.sandbox_division(inst, bb)

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
        if "SSE" in instr.category:
            mask = mask[:-4] + "0" * 4

        if mem_operands and not implicit_mem_operands:
            assert len(mem_operands) == 1, \
                f"Instructions with multiple memory accesses are not yet supported: {instr.name}"
            mem_operand: Operand = mem_operands[0]
            address_reg = mem_operand.value
            imm_width = mem_operand.width if mem_operand.width <= 32 else 32
            apply_mask = Instruction("AND", True) \
                .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                .add_op(ImmediateOperand(mask, imm_width)) \
                .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
            parent.insert_before(instr, apply_mask)
            instr.get_mem_operands()[0].value = "R14 + " + address_reg
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
                apply_mask = Instruction("AND", True) \
                    .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                    .add_op(ImmediateOperand(mask, imm_width)) \
                    .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
                add_base = Instruction("ADD", True) \
                    .add_op(RegisterOperand(address_reg, mem_operand.width, True, True)) \
                    .add_op(RegisterOperand("R14", 64, True, False)) \
                    .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
                parent.insert_before(instr, apply_mask)
                parent.insert_before(instr, add_base)
            return

        raise GeneratorException("Attempt to sandbox an instruction without memory operands")

    def sandbox_division(self, inst: Instruction, parent: BasicBlock):
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
        # Copy div source operand as we may need to modify it
        divisor = deepcopy(inst.operands[0])
        size = divisor.width

        # This option prevents triggering of Zero Division Injection in the tests
        if size == 64 and CONF.x86_disable_div64:  # type: ignore
            parent.delete(inst)
            return

        # Prevent div by zero
        if 'DE-zero' not in CONF.permitted_faults:
            if "IDIV" not in inst.name or 'DE-overflow' in CONF.permitted_faults:
                # for unsigned division and signed divisions with overflow permitted,
                # it is sufficient to OR the divisor with 1 to prevent div by zero
                instrumentation = Instruction("OR", True) \
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
                instrumentation = Instruction("OR", True) \
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
                instrumentation = Instruction("AND", True) \
                    .add_op(divider_8_bit) \
                    .add_op(ImmediateOperand("0b11111000", 8)) \
                    .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
                parent.insert_before(inst, instrumentation)

        # Prevent div overflows
        if 'DE-overflow' in CONF.permitted_faults:
            return

        # Check for the cases that are impossible to instrument:
        # - division by D register
        # - division by a memory value with the RDX offset
        # - division where AX is both the dividend and the offset in memory
        if divisor.value in ["RDX", "EDX", "DX", "DH", "DL"] \
           or "RDX" in divisor.value \
           or ("RAX" in divisor.value and size == 8):
            parent.delete(inst)
            return

        # Special case: dividend in AX
        # instrumentation: ax = 1
        if size == 8:
            instrumentation = Instruction("MOV", True).\
                add_op(RegisterOperand("AX", 16, False, True)).\
                add_op(ImmediateOperand("1", 16))
            parent.insert_before(inst, instrumentation)
            return

        # Normal case
        d_register = {64: "RDX", 32: "EDX", 16: "DX"}[size]

        # signed div
        if "IDIV" in inst.name:
            # it's extremely hard to prevent overflows with large signed divisions
            # that's why we simplify the case by assigning zero to the upper bits of the dividend
            # instrumentation, thus making the dividend at most `4 << div_size - 1`
            # D = D & 3
            instrumentation = Instruction("AND", True) \
                .add_op(RegisterOperand(d_register, size, True, True)) \
                .add_op(ImmediateOperand("0b11", 8)) \
                .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
            parent.insert_before(inst, instrumentation)

        # unsigned div
        else:
            # instrumentation:
            # D = (D & divisor) >> 1  # ensure that D is always smaller than the divisor
            instrumentation = Instruction("AND", True) \
                .add_op(RegisterOperand(d_register, size, True, True)) \
                .add_op(divisor) \
                .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
            parent.insert_before(inst, instrumentation)
            divisor.dest = True

            instrumentation = Instruction("SHR", True) \
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
            apply_mask = Instruction("AND", True) \
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
        apply_mask = Instruction("AND", True) \
            .add_op(RegisterOperand("RCX", 64, True, True)) \
            .add_op(ImmediateOperand("0xff", 8)) \
            .add_op(FlagsOperand(["w", "w", "undef", "w", "w", "", "", "", "w"]), True)
        add_base = Instruction("ADD", True) \
            .add_op(RegisterOperand("RCX", 64, True, True)) \
            .add_op(ImmediateOperand("1", 1)) \
            .add_op(FlagsOperand(["w", "w", "w", "w", "w", "", "", "", "w"]), True)
        parent.insert_before(inst, apply_mask)
        parent.insert_before(inst, add_base)

    def sandbox_corrupted_cf(self, inst: Instruction, parent: BasicBlock):
        set_cf = Instruction("STC", True) \
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
        set_rax = Instruction("MOV", True) \
            .add_op(RegisterOperand("EAX", 32, True, True)) \
            .add_op(ImmediateOperand(random.choice(options), 1))
        parent.insert_before(inst, set_rax)

    @staticmethod
    def requires_sandbox(inst: InstructionSpec):
        if inst.has_mem_operand:
            return True
        if inst.name in ["DIV", "REX DIV"]:
            return True
        if inst.name in ["BT", "BTC", "BTR", "BTS", "LOCK BT", "LOCK BTC", "LOCK BTR", "LOCK BTS"]:
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
                    patches = self.find_flags_patch(list(flags_to_set), flags_to_set)
                    for patch in patches:
                        bb.insert_before(bb.get_first(), patch)
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
                    if inst.name in ["BSF", "BSR"]:
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
        apply_mask = Instruction("OR", True) \
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
        "UD2": [
            # UD2 instruction
            "0x0f, 0x0b",

            # invalid in 64-bit mode;
            # all the following opcodes are padded
            # with NOP to prevent misinterpretation by objdump
            "0x06, 0x90",  # 32-bit encoding of PUSH
            "0x07, 0x90",  # 32-bit encoding of POP
            "0x0E, 0x90",  # alternative 32-bit encoding of PUSH
            "0x16, 0x90",  # alternative 32-bit encoding of PUSH
            "0x17, 0x90",  # alternative 32-bit encoding of POP
            "0x1E, 0x90",  # alternative 32-bit encoding of PUSH
            "0x1F, 0x90",  # alternative 32-bit encoding of POP
            "0x27, 0x90",  # DAA
            "0x2F, 0x90",  # DAS
            "0x37, 0x90",  # AAA
            "0x3f, 0x90",  # AAS
            "0x60, 0x90",  # PUSHA
            "0x61, 0x90",  # POPA
            "0x62, 0x90",  # BOUND
            "0x82, 0x90",  # 32-bit aliases for logical instructions
            "0x9A, 0x90",  # 32-bit encoding of CALLF
            "0xC4, 0x90",  # LES
            "0xD4, 0x90",  # AAM
            "0xD5, 0x90",  # AAD
            "0xD6, 0x90",  # reserved
            "0xEA, 0x90",  # 32-bit encoding of JMPF
        ],
        "INT1": ["0xf1"]
    }

    def run_on_test_case(self, test_case: TestCase) -> None:
        for func in test_case.functions:
            for bb in func:
                # collect all UD instructions
                to_patch = []
                for inst in bb:
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
        128: "xmmword ptr",
        256: "ymmword ptr",
        512: "zmmword ptr"
    }
    prologue_template = [
        ".intel_syntax noprefix\n",
        ".test_case_enter:\n",
    ]
    epilogue_template = [
        ".section .data.0_host\n",
        ".test_case_exit:\n",
    ]

    def __init__(self, target_desc: X86TargetDesc) -> None:
        self.macro_labels = {v: k for k, v in target_desc.macro_ids.items()}
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
        owner_type = "host" if func.owner.type_ == ActorType.HOST else "guest"
        file.write(f".section .data.{func.owner.id_}_{owner_type}\n")
        file.write(f"{func.name}:\n")
        for bb in func:
            self.print_basic_block(bb, file)

        self.print_basic_block(func.exit, file)

    def print_basic_block(self, bb: BasicBlock, file):
        file.write(f"{bb.name}:\n")
        for inst in bb:
            file.write(self.instruction_to_str(inst) + "\n")
        for inst in bb.terminators:
            file.write(self.instruction_to_str(inst) + "\n")

    def instruction_to_str(self, inst: Instruction):
        if inst.category == "MACRO":
            return self.macro_to_str(inst)

        operands = ", ".join([self.operand_to_str(op) for op in inst.operands])
        comment = "# instrumentation" if inst.is_instrumentation else ""
        return f"{inst.name} {operands} {comment}"

    def operand_to_str(self, op: Operand) -> str:
        if isinstance(op, MemoryOperand) or isinstance(op, AgenOperand):
            prefix = self.memory_prefixes[op.width]
            return f"{prefix} [{op.value}]"

        return op.value

    def macro_to_str(self, inst: Instruction):
        label = self.macro_labels[int(inst.operands[0].value)]
        return f".macro.{label}: nop dword ptr [rax + rax*1 + 0x1]"


class X86RandomGenerator(X86Generator, RandomGenerator):

    def __init__(self, instruction_set: InstructionSet, seed: int):
        super().__init__(instruction_set, seed)
