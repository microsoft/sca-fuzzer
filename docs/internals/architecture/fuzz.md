# Orchestration Module

|                  |                                          |
| ---------------- | ---------------------------------------- |
| Module           | `rvzr/fuzzer.py`                         |
| Public interface | `Fuzzer`                                 |
| Inputs           | `Config`, `InstructionSet`, ASM Template |
| Outputs          | Violation artifact, logs                 |

The `Fuzzer` class is the main coordinator. It manages the core components (`CodeGenerator`, `DataGenerator`, `Model`, `Executor`, and `Analyser`) and orchestrates the fuzzing loop.

## Main workflow

```text
Fuzzer.start()
  └─> for each test case:
        ├─> CodeGenerator.create_test_case() → TestCaseProgram
        ├─> DataGenerator.generate() → List[InputData]
        └─> Fuzzer.fuzzing_round(program, inputs)
              ├─> Model.trace_test_case() → List[CTrace]
              ├─> Executor.trace_test_case() → List[HTrace]
              ├─> Analyser.filter_violations() → List[Violation]
              └─> if violation: multi-stage filtering pipeline
```


## Multi-stage filtering

When a potential violation is found, the Fuzzer runs it through several validation stages. Each stage modifies parameters and re-checks the violation to rule out false positives:

1. `fast` — Initial fast detection using minimal speculative nesting on the model side and small sample size on the executor side
2. `nesting` — Re-collect ctraces with the model using full speculative nesting. This rules out false positives caused by incomplete speculation modeling
3. `taint_mistake` — Re-collect ctraces for the boosted inputs to rule out boosting-based generation mistakes
4. `priming` — Perform a so-called "priming test" (swap the order of violating inputs) to rule out false positives caused by inconsistent microarchitectural state across executions
5. `noise` — Increase sample size on the executor side to increase statistical confidence and rule out noise-induced violations
6. `arch_mismatch` — Compare the architectural output (i.e., register/memory states) of the model and executor to rule out violations caused by functional mismatches (i.e., by bugs in the model or executor)

If a violation survives all stages, Revizor saves a reproduction package (called "violation artifact") containing the test case, inputs, configuration, and detailed report.

## Fuzzer variants

The `Fuzzer` class is abstract. There are several variants modifying the baseline logic:

- `X86Fuzzer` / `ARM64Fuzzer` — Architecture-specific implementations
- `ArchitecturalFuzzer` — Validates model correctness (i.e., performs stage 6 `arch_mismatch` for all test cases, even non-violating ones)
- `ArchDiffFuzzer` — Completely discards the model, and instead compares two hardware executions, one with a normal test case and one with a speculation fence added after every instruction. This variant is used to detect speculation-induced architectural bugs, like zenbleed.
