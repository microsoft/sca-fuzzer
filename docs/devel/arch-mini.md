# Post-violation Analysis

|                  |                                 |
| ---------------- | ------------------------------- |
| Module           | `rvzr/postprocessing/`          |
| Public interface | `Minimizer`                     |
| Inputs           | Violation artifact (.asm, .bin) |
| Outputs          | Minimized test case and inputs  |

After confirming a violation, users can run post-processing to simplify the test case and identify the root cause. The postprocessing module applies minimization passes that reduce complexity while preserving the violation.

Class hierarchy:

```text
Minimizer
  └─ Orchestrates passes, manages files

BaseMinimizationPass
  ├─ Instruction passes (modify code)
  ├─ Data passes (modify inputs)
  └─ Analysis passes (add annotations)
```

Instruction passes (operate on test case code):

- `InstructionRemovalPass` — Remove instructions one at a time to find essential ones
- `NopReplacementPass` — Replace with NOPs (preserves alignment)
- `InstructionSimplificationPass` — Replace complex instructions with simpler ones
- `ConstantSimplificationPass` — Simplify immediate values
- `MaskSimplificationPass` — Simplify bitmasks
- `LabelRemovalPass` — Remove unused labels
- `FenceInsertionPass` — Insert fences to identify speculation boundaries

Data passes (operate on inputs):

- `DifferentialInputMinimizerPass` — Use delta debugging to find minimal byte differences
- `InputSequenceMinimizationPass` — Reduce number of inputs

Analysis passes (add annotations):

- `AddViolationCommentsPass` — Annotate assembly with memory addresses from execution
