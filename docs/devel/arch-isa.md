# Instruction Set Specification

|                  |                    |
| ---------------- | ------------------ |
| Module           | `rvzr/isa_spec.py` |
| Public interface | `InstructionSet`   |
| Inputs           | `base.json`        |
| Outputs          | `InstructionSet`   |

This module manages the instruction set available for fuzzing. It loads ISA definitions from a JSON file (`base.json`) and applies user-configured filters to create a pool of allowed instructions.

Each instruction is represented by an `InstructionSpec` containing instruction name and category, operand specifications, and instruction properties.

Processing pipeline:

1. Load ISA specification from JSON
2. Apply filters (allowlist, blocklist, categories, register restrictions)
3. Remove duplicates
4. Categorize instructions by type (control flow, memory access, etc.)


