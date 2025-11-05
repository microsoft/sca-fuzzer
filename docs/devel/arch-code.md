# Test Case Code Generation

|                  |                          |
| ---------------- | ------------------------ |
| Module           | `rvzr/code_generator.py` |
| Public interface | `CodeGenerator`          |
| Inputs           | `InstructionSet`         |
| Outputs          | `TestCaseProgram`        |

This module generates random assembly programs for testing. The generator creates programs designed to trigger speculative execution and expose microarchitectural leaks.

### Generation process

1. Create control flow graph — Generate a random Directed Acyclic Graph (DAG) of basic blocks. The DAG structure prevents infinite loops while allowing branches and mispredictions.

2. Add jump instructions — Insert conditional and unconditional jumps at block boundaries to connect the blocks according to the DAG.

3. Fill basic blocks — Populate blocks with random instructions from the tested instruction pool, respecting instruction frequencies and operand constraints.

4. Instrument — (Optionally) Prevent faults by masking memory addresses, avoiding division by zero, and ensuring all accesses stay within the sandbox.

5. Assemble — Convert to binary and extract metadata.

6. Transform into RCBF — Serialize the test case into Revizor's custom binary format ([RCBF](binary-formats.md)) for execution.

### Test case representation

```text
TestCaseProgram
  ├─ CodeSection (one per actor)
  │    └─ Function
  │         └─ BasicBlock
  │              └─ InstructionNode
  │                   └─ Instruction
  │                        └─ Operand
  └─ TestCaseBinary
       └─ SymbolTable
```

### Variants

Architecture-specific implementations of the code generator exist for x86 and ARM64, named `X86Generator` and `ARM64Generator` in `rvzr/arch/*/code_generator.py`
