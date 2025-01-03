"""
File: Selection of unit tests for the data container classes

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=missing-function-docstring  # no need in tests
# pylint: disable=missing-class-docstring  # no need in tests

import os
import random
import unittest
from unittest.mock import MagicMock

import tempfile
import numpy as np

from src.tc_components.actor import Actor, ActorMode, ActorPL
from src.tc_components.test_case_code import CodeSection, TestCaseProgram, BasicBlock, Function
from src.tc_components.test_case_binary import TestCaseBinary, SymbolTableEntry
from src.tc_components.test_case_data import InputData, _ACTOR_DATA_SIZE
from src.instruction_spec import InstructionSpec, OperandSpec, OT
from src.tc_components.instruction import Instruction, Operand, \
    copy_op_with_flow_modification, copy_op_with_value_modification, copy_inst_with_modification, \
    RegisterOp, MemoryOp, ImmediateOp, LabelOp, AgenOp, CondOp, \
    FlagsOp
from src.config import ActorConf


def _get_dummy_actor_dict() -> ActorConf:
    actor_dict: ActorConf = {
        'mode': 'host',
        'privilege_level': 'kernel',
        'name': 'test_actor',
        'data_properties': {
            'randomized': False,
            'executable': True
        },
        'data_ept_properties': {
            'randomized': False,
            'executable': True,
        },
        'observer': False,
        "instruction_blocklist": set(),
        "fault_blocklist": set(),
    }
    return actor_dict


class ActorTest(unittest.TestCase):

    def test_dict_constructor(self) -> None:
        # Mock actor_dict
        actor_dict = _get_dummy_actor_dict()

        # Create Actor from dict
        actor = Actor.from_dict(actor_dict, MagicMock())

        # Assertions
        self.assertEqual(actor.mode, ActorMode.HOST)
        self.assertEqual(actor.privilege_level, ActorPL.KERNEL)
        self.assertEqual(actor.name, 'test_actor')
        self.assertFalse(actor.observer)

        # Guest/User Actor
        actor_dict['mode'] = 'guest'
        actor_dict['privilege_level'] = 'user'
        actor = Actor.from_dict(actor_dict, MagicMock())
        self.assertEqual(actor.mode, ActorMode.GUEST)
        self.assertEqual(actor.privilege_level, ActorPL.USER)

        # Invalid privilege level
        actor_dict['privilege_level'] = 'invalid_pl'
        with self.assertRaises(ValueError):
            _ = Actor.from_dict(actor_dict, MagicMock())

        # Invalid mode
        actor_dict['mode'] = 'invalid_mode'
        with self.assertRaises(ValueError):
            _ = Actor.from_dict(actor_dict, MagicMock())

    def test_create_main(self) -> None:
        # Call the create_main method
        main_actor = Actor.create_main()

        # Assert the properties of the returned Actor object
        self.assertEqual(main_actor.mode, ActorMode.HOST)
        self.assertEqual(main_actor.privilege_level, ActorPL.KERNEL)
        self.assertEqual(main_actor.name, "main")

    def test_get_id(self) -> None:
        # Create an Actor instance
        actor_dict = _get_dummy_actor_dict()
        actor = Actor.from_dict(actor_dict, MagicMock())
        section = CodeSection(actor)

        # Call get_id without assigning an ElfSection and assert it raises an AssertionError
        with self.assertRaises(AssertionError):
            actor.get_id()

        # Create and assign an elf data
        section.assign_elf_data(offset=0, size=0, id_=42)

        # Call get_id and assert the returned ID
        self.assertEqual(actor.get_id(), 42)

    def test_is_main(self) -> None:
        actor_dict = _get_dummy_actor_dict()
        actor_dict['name'] = 'main'
        target_desc = MagicMock()

        main_actor = Actor.from_dict(actor_dict, target_desc)
        self.assertTrue(main_actor.is_main)

        actor_dict['name'] = 'non_main_actor'
        non_main_actor = Actor.from_dict(actor_dict, target_desc)
        self.assertFalse(non_main_actor.is_main)

    def test_pte_constructor(self) -> None:
        actor_dict = _get_dummy_actor_dict()
        actor_dict['data_properties'] = {'randomized': False, 'executable': True}
        actor_dict['data_ept_properties'] = {'randomized': False, 'executable': False}

        # Mock target_desc
        target_desc = MagicMock()
        target_desc.pte_bits = {'non_executable': (0, True)}
        target_desc.epte_bits = {'executable': (0, False)}

        # Create Actor from dict
        actor = Actor.from_dict(actor_dict, target_desc)

        self.assertEqual(actor.data_properties, 0)
        self.assertEqual(actor.data_ept_properties, 0)

        actor_dict['data_properties'] = {'randomized': True, 'executable': True}
        actor_dict['data_ept_properties'] = {'randomized': True, 'executable': True}
        random.seed(43)

        actor = Actor.from_dict(actor_dict, target_desc)
        self.assertEqual(actor.data_properties, 1)
        self.assertEqual(actor.data_ept_properties, 1)


class InstructionSpecTest(unittest.TestCase):

    def test_OT_str(self) -> None:
        self.assertEqual(str(OT.REG), "REG")
        self.assertEqual(str(OT.MEM), "MEM")
        self.assertEqual(str(OT.IMM), "IMM")
        self.assertEqual(str(OT.LABEL), "LABEL")
        self.assertEqual(str(OT.AGEN), "AGEN")
        self.assertEqual(str(OT.FLAGS), "FLAGS")
        self.assertEqual(str(OT.COND), "COND")

    def test_operand_str(self) -> None:
        # Create an OperandSpec object
        operand = OperandSpec(values=['rax', 'rbx'], type_=OT.REG, src=True, dest=False)

        # Assert the string representation of the OperandSpec object
        self.assertEqual(str(operand), "(rax, rbx)")

        # Check the string representation of an OperandSpec object with no values
        operand = OperandSpec(values=[], type_=OT.REG, src=True, dest=False)
        self.assertEqual(str(operand), "()")

    def test_instruction_spec_str(self) -> None:
        # Create an InstructionSpec object with operands
        operand = OperandSpec(values=['rax', 'rbx'], type_=OT.REG, src=True, dest=False)
        instruction = InstructionSpec(name='MOV', category='MOV')
        instruction.operands.append(operand)

        # Assert the string representation of the InstructionSpec object
        self.assertEqual(str(instruction), "MOV (rax, rbx) ")

    def test_instruction_spec_hash(self) -> None:
        # Create an InstructionSpec object
        operand = OperandSpec(values=['rax', 'rbx'], type_=OT.REG, src=True, dest=False)
        instruction = InstructionSpec(name='MOV', category='MOV')
        instruction.operands.append(operand)

        # Assert the hash of the InstructionSpec object
        self.assertEqual(hash(instruction), hash(str(instruction)))


class OperandTest(unittest.TestCase):

    def test_operand_from_spec(self) -> None:
        for type_ in [OT.REG, OT.MEM, OT.IMM, OT.LABEL, OT.AGEN, OT.FLAGS, OT.COND]:
            values = ["val"] if type_ != OT.FLAGS else ["", "", "", "", "", "", "", "", ""]
            val = "val" if type_ != OT.FLAGS else "flags"
            src = True if type_ != OT.FLAGS else False  # pylint: disable=simplifiable-if-expression

            # Create an OperandSpec object
            operand_spec = OperandSpec(values=values, type_=type_, src=src, dest=False)

            # Create an Operand object from the OperandSpec object
            operand = Operand.from_fixed_spec(operand_spec)

            # Assert the properties of the Operand object
            self.assertEqual(operand.value, val)
            self.assertEqual(operand.src, src)
            self.assertFalse(operand.dest)

    def test_flag_print(self) -> None:
        operand = FlagsOp(("", "", "", "", "", "", "", "", ""))
        self.assertEqual(str(operand), "FLAGS: CF|PF|AF|ZF|SF|TF|IF|DF|OF")

    def test_flag_accessors(self) -> None:
        # ("CF", "PF", "AF", "ZF", "SF", "TF", "IF", "DF", "OF")
        operand = FlagsOp(("w", "r", "r/w", "r/cw", "undef", "", "", "", ""))

        self.assertEqual(operand.get_flags_by_type("read"), ["PF", "AF", "ZF"])
        self.assertEqual(operand.get_flags_by_type("write"), ["CF", "AF", "ZF"])
        self.assertEqual(operand.get_flags_by_type("overwrite"), ["CF"])
        self.assertEqual(operand.get_flags_by_type("undef"), ["SF"])

    def test_operand_copy_methods(self) -> None:
        reg_op = RegisterOp("rax", 64, True, False)
        mem_op = MemoryOp("0x0", 64, True, False)
        imm_op = ImmediateOp("0x0", 64)
        label_op = LabelOp("label")
        agen_op = AgenOp("0x0", 64)
        cond_op = CondOp("cond")

        # Test copy_op_with_value_modification
        for op in [reg_op, mem_op, imm_op, label_op, agen_op, cond_op]:
            new_op = copy_op_with_value_modification(op, "new_val")  # type: ignore
            self.assertEqual(new_op.value, "new_val")
            self.assertEqual(new_op.src, op.src)
            self.assertEqual(new_op.dest, op.dest)

        # Test copy_op_with_flow_modification - src
        for op in [reg_op, mem_op]:
            new_op = copy_op_with_flow_modification(op, src=False)  # type: ignore
            self.assertEqual(new_op.value, op.value)
            self.assertEqual(new_op.width, op.width)  # type: ignore
            self.assertEqual(new_op.dest, op.dest)
            self.assertFalse(new_op.src)

        # Test copy_op_with_flow_modification - dest
        for op in [reg_op, mem_op]:
            new_op = copy_op_with_flow_modification(op, dest=True)  # type: ignore
            self.assertEqual(new_op.value, op.value)
            self.assertEqual(new_op.width, op.width)  # type: ignore
            self.assertEqual(new_op.src, op.src)
            self.assertTrue(new_op.dest)


class InstructionTest(unittest.TestCase):

    def test_instruction_from_spec(self) -> None:
        # Create an InstructionSpec object
        operand = OperandSpec(values=['rax', 'rbx'], type_=OT.REG, src=True, dest=False)
        instruction_spec = InstructionSpec(name='MOV', category='MOV')
        instruction_spec.operands.append(operand)

        # Create an Instruction object from the InstructionSpec object
        instruction = Instruction.from_spec(instruction_spec)

        # Assert the properties of the Instruction object
        self.assertEqual(instruction.name, 'MOV')
        self.assertEqual(instruction.category, 'MOV')
        self.assertFalse(instruction.is_control_flow)
        self.assertFalse(instruction.is_instrumentation)
        self.assertFalse(instruction.is_noremove)
        self.assertFalse(instruction.is_from_template)
        self.assertEqual(len(instruction.operands), 0)  # Operands are generated separately!
        self.assertEqual(len(instruction.implicit_operands), 0)

    def test_instruction_str(self) -> None:
        # Create an Instruction object
        operand = RegisterOp("rax", 64, True, False)
        instruction = Instruction("MOV", "MOV")
        instruction.operands.append(operand)

        # Assert the string representation of the Instruction object
        self.assertEqual(str(instruction), "MOV rax")

    def test_instr_add_op(self) -> None:
        instruction = Instruction("MOV", "MOV")
        operand = RegisterOp("rax", 64, True, False)
        implicit_operand = RegisterOp("rbx", 64, True, False)

        # Add explicit operand
        instruction = instruction.add_op(operand)
        self.assertEqual(len(instruction.operands), 1)
        self.assertEqual(instruction.operands[0], operand)

        # Add implicit operand
        instruction = instruction.add_op(implicit_operand, implicit=True)
        self.assertEqual(len(instruction.implicit_operands), 1)
        self.assertEqual(instruction.implicit_operands[0], implicit_operand)

    def test_instr_properties(self) -> None:
        # Case 1: Instruction with no memory operands
        instruction = Instruction("MOV", "MOV")
        op_reg = RegisterOp("rax", 64, True, False)
        instruction.operands.append(op_reg)

        self.assertFalse(instruction.has_mem_operand(include_implicit=True))
        self.assertFalse(instruction.has_write(include_implicit=True))
        self.assertFalse(instruction.has_read(include_implicit=True))

        # Case 2: Instruction with an explicit read
        instruction = Instruction("MOV", "MOV")
        op = MemoryOp("0x0", 64, True, False)
        instruction.operands.append(op)

        self.assertTrue(instruction.has_mem_operand(include_implicit=False))
        self.assertTrue(instruction.has_mem_operand(include_implicit=True))
        self.assertFalse(instruction.has_write(include_implicit=True))
        self.assertTrue(instruction.has_read(include_implicit=True))

        # Case 3: Instruction with an explicit write
        instruction = Instruction("MOV", "MOV")
        op = MemoryOp("0x0", 64, False, True)
        instruction.operands.append(op)

        self.assertTrue(instruction.has_mem_operand(include_implicit=False))
        self.assertTrue(instruction.has_mem_operand(include_implicit=True))
        self.assertTrue(instruction.has_write(include_implicit=True))
        self.assertFalse(instruction.has_read(include_implicit=True))

        # Case 4: Instruction with an implicit read
        instruction = Instruction("MOV", "MOV")
        op = MemoryOp("0x0", 64, True, False)
        instruction.implicit_operands.append(op)

        self.assertFalse(instruction.has_mem_operand(include_implicit=False))
        self.assertTrue(instruction.has_mem_operand(include_implicit=True))
        self.assertFalse(instruction.has_write(include_implicit=True))
        self.assertTrue(instruction.has_read(include_implicit=True))

        # Case 5: Instruction with an implicit write
        instruction = Instruction("MOV", "MOV")
        op = MemoryOp("0x0", 64, False, True)
        instruction.implicit_operands.append(op)

        self.assertFalse(instruction.has_mem_operand(include_implicit=False))
        self.assertTrue(instruction.has_mem_operand(include_implicit=True))
        self.assertTrue(instruction.has_write(include_implicit=True))
        self.assertFalse(instruction.has_read(include_implicit=True))

    def test_operand_accessors(self) -> None:
        reg_op = RegisterOp("rax", 64, True, False)
        mem_op = MemoryOp("0x0", 64, True, True)
        imm_op = ImmediateOp("0x0", 64)
        label_op = LabelOp("label")
        agen_op = AgenOp("0x0", 64)
        cond_op = CondOp("cond")
        flags_op = FlagsOp(("", "", "", "", "", "", "", "", ""))

        # Case 1: Explicit operands
        instruction = Instruction("MOV", "MOV")
        instruction.operands.extend([reg_op, mem_op, imm_op, label_op, agen_op, cond_op, flags_op])

        self.assertEqual(instruction.get_all_operands(),
                         [reg_op, mem_op, imm_op, label_op, agen_op, cond_op, flags_op])
        self.assertEqual(instruction.get_src_operands(),
                         [reg_op, mem_op, imm_op, label_op, agen_op, cond_op])
        self.assertEqual(instruction.get_dest_operands(), [mem_op])
        self.assertEqual(instruction.get_mem_operands(), [mem_op])
        self.assertEqual(instruction.get_flags_operand(), flags_op)
        self.assertEqual(instruction.get_reg_operands(), [reg_op])
        self.assertEqual(instruction.get_cond_operand(), cond_op)
        self.assertEqual(instruction.get_label_operand(), label_op)
        self.assertEqual(instruction.get_imm_operands(), [imm_op])

        # Case 2: Implicit operands
        instruction = Instruction("MOV", "MOV")
        instruction.implicit_operands.extend([reg_op, mem_op, imm_op, agen_op, flags_op])

        self.assertEqual(instruction.get_all_operands(),
                         [reg_op, mem_op, imm_op, agen_op, flags_op])
        self.assertEqual(instruction.get_src_operands(), [])
        self.assertEqual(
            instruction.get_src_operands(include_implicit=True), [reg_op, mem_op, imm_op, agen_op])
        self.assertEqual(instruction.get_dest_operands(), [])
        self.assertEqual(instruction.get_dest_operands(include_implicit=True), [mem_op])
        self.assertEqual(instruction.get_mem_operands(), [])
        self.assertEqual(instruction.get_mem_operands(include_implicit=True), [mem_op])
        self.assertEqual(instruction.get_flags_operand(), flags_op)
        self.assertEqual(instruction.get_reg_operands(), [])
        self.assertEqual(instruction.get_reg_operands(include_implicit=True), [reg_op])
        self.assertEqual(instruction.get_cond_operand(), None)
        self.assertEqual(instruction.get_label_operand(), None)
        self.assertEqual(instruction.get_imm_operands(), [])
        self.assertEqual(instruction.get_imm_operands(include_implicit=True), [imm_op])

        # Case 3: No operands
        instruction = Instruction("MOV", "MOV")

        self.assertEqual(instruction.get_all_operands(), [])
        self.assertEqual(instruction.get_src_operands(True), [])
        self.assertEqual(instruction.get_dest_operands(True), [])
        self.assertEqual(instruction.get_mem_operands(True), [])
        self.assertEqual(instruction.get_flags_operand(), None)
        self.assertEqual(instruction.get_reg_operands(True), [])

    def test_copy_with_modification(self) -> None:
        # pylint: disable=protected-access

        # Create an Instruction object
        org_instruction = Instruction(
            "MOV", "MOV", is_control_flow=False, is_instrumentation=False, is_noremove=False)
        org_instruction.is_from_template = True
        org_instruction._section_id = 1
        org_instruction._section_offset = 1
        org_instruction._line_num = 1
        org_instruction._size = 1

        # Add operands
        reg_op = RegisterOp("rax", 64, True, False)
        org_instruction.operands.append(reg_op)

        # Copy with no modification
        new_instruction = copy_inst_with_modification(org_instruction)
        self.assertEqual(new_instruction.name, "MOV")
        self.assertEqual(new_instruction.category, "MOV")
        self.assertFalse(new_instruction.is_control_flow)
        self.assertFalse(new_instruction.is_instrumentation)
        self.assertFalse(new_instruction.is_noremove)
        self.assertTrue(new_instruction.is_from_template)
        self.assertEqual(new_instruction._section_id, 1)
        self.assertEqual(new_instruction._section_offset, 1)
        self.assertEqual(new_instruction._line_num, 1)
        self.assertEqual(new_instruction._size, 1)
        self.assertEqual(new_instruction.operands, [reg_op])

        # Copy with modifications
        new_instruction = copy_inst_with_modification(
            org_instruction,
            name="NOP",
            category="NOP",
            is_control_flow=True,
            is_instrumentation=True,
            is_noremove=True)
        self.assertEqual(new_instruction.name, "NOP")
        self.assertEqual(new_instruction.category, "NOP")
        self.assertTrue(new_instruction.is_control_flow)
        self.assertTrue(new_instruction.is_instrumentation)
        self.assertTrue(new_instruction.is_noremove)
        self.assertTrue(new_instruction.is_from_template)
        self.assertEqual(new_instruction._section_id, 1)
        self.assertEqual(new_instruction._section_offset, 1)
        self.assertEqual(new_instruction._line_num, 1)
        self.assertEqual(new_instruction._size, 1)
        self.assertEqual(new_instruction.operands, [reg_op])

    def test_line_num_interface(self) -> None:
        # Check unassigned line number
        instruction = Instruction("MOV", "MOV")
        with self.assertRaises(AssertionError):
            instruction.line_num()

        # Check valid line number
        instruction._line_num = 10  # Assuming _line_num is a protected attribute
        self.assertEqual(instruction.line_num(), 10)


class TestCaseBinaryTest(unittest.TestCase):

    def test_get_macro_offset(self) -> None:
        # Create an instance of TestCaseBinary
        test_case_code = TestCaseProgram("")
        test_case_bin = TestCaseBinary("", test_case_code)

        # Handling of non-assigned macro table
        with self.assertRaises(AssertionError):
            test_case_bin.get_macro_offset(1)

        # Mock the _symbol_table with symbols containing the desired macro_type
        symbol1 = SymbolTableEntry(sid=0, offset=1, type_=1, arg=0)
        symbol2 = SymbolTableEntry(sid=0, offset=10, type_=2, arg=0)
        symbol_table = [symbol1, symbol2]
        test_case_bin.assign_elf_data(symbol_table, MagicMock())

        # Call get_macro_offset and assert the returned offset
        self.assertEqual(test_case_bin.get_macro_offset(1), 1)
        self.assertEqual(test_case_bin.get_macro_offset(2), 10)

        # Check non-existing macro type
        self.assertEqual(test_case_bin.get_macro_offset(3), -1)


class TestCaseCodeTest(unittest.TestCase):

    def test_basic_block_str(self) -> None:
        bb = BasicBlock("bb1", MagicMock())
        self.assertEqual(str(bb), "bb1")

    def test_basic_block_get_owner(self) -> None:
        # Normal case
        actor = Actor.create_main()
        section = CodeSection(actor)
        func = Function("func1", section)
        bb = BasicBlock("bb1", func)

        self.assertEqual(bb.get_owner(), actor)

        # No-parent BB
        bb = BasicBlock("bb1", None)
        with self.assertRaises(AssertionError):
            bb.get_owner()


class InputDataTest(unittest.TestCase):

    def test_data_sizes(self) -> None:
        # Test data_size_per_actor
        self.assertEqual(InputData.data_size_per_actor(), _ACTOR_DATA_SIZE)

        # Test n_data_entries_per_actor
        self.assertEqual(InputData.n_data_entries_per_actor(), _ACTOR_DATA_SIZE // 8)

    def test_hash(self) -> None:
        input_data = InputData(1)
        self.assertEqual(hash(input_data), hash(input_data.tobytes()))

    def test_str(self) -> None:
        input_data = InputData(1)
        input_data.seed = 42
        self.assertEqual(str(input_data), "42")
        self.assertEqual(repr(input_data), "42")

    def test_set_actor_data(self) -> None:
        # Create an instance of InputData
        input_data = InputData(1)

        # Attempt setting data with invalid shape
        data = np.zeros((1,), dtype=np.uint64)
        with self.assertRaises(AssertionError):
            input_data.set_actor_data(0, data)

        # Set the actor data with a valid shape
        size = input_data.itemsize // 8
        data = np.array([42 for _ in range(size)], dtype=np.uint64)
        input_data.set_actor_data(0, data)
        self.assertEqual(input_data[0]["main"][0], 42)

    def test_save(self) -> None:
        # Create an instance of InputData
        input_data = InputData(1)
        data = np.array([42 for _ in range(input_data.itemsize // 8)], dtype=np.uint64)
        input_data.set_actor_data(0, data)

        # Create a temporary binary file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name

        # Save the input data to the binary file
        input_data.save(path)

        # Check the contents of the binary file
        with open(path, 'rb') as f:
            contents = np.fromfile(f, dtype=np.uint64)
            self.assertEqual(contents[0], 42)

        # Remove the temporary binary file
        os.unlink(path)

    def test_load(self) -> None:
        input_data = InputData(1)

        # Create a temporary binary file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        data = np.array([42 for _ in range(input_data.itemsize // 8)], dtype=np.uint64)
        with open(path, 'wb') as f:
            f.write(data.tobytes())

        # Load the input data from the binary file
        input_data.load(path)
        self.assertEqual(input_data[0]["main"][0], 42)

        # Remove the temporary binary file
        os.unlink(path)

    def test_linear_view(self) -> None:
        input_data = InputData(1)
        data = np.array([42 for _ in range(input_data.itemsize // 8)], dtype=np.uint64)
        input_data.set_actor_data(0, data)

        # Get the linear view of the input for the actor
        linear_view = input_data.linear_view(0)

        # Assert the shape of the linear view
        self.assertEqual(linear_view.shape, (input_data.itemsize // 8,))

        # Assert the contents of the linear view
        self.assertEqual(linear_view[0], 42)
