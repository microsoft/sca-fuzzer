# Contract Tracing

|                  |                                |
| ---------------- | ------------------------------ |
| Module           | `rvzr/model.py`                |
| Public interface | `Model`                        |
| Inputs           | `TestCaseProgram`, `InputData` |
| Outputs          | `CTrace`                       |

## Model

The Model executes test cases according to a leakage contract and produces contract traces (CTraces). These represent the information expected to leak during execution, including speculative execution.

Revizor supports two model backends:

- **Unicorn**: This backend is based on the [Unicorn CPU emulator](https://www.unicorn-engine.org/). It implements the contract by hooking into instruction execution and memory access events. Documentation is provided in [Unicorn Backend](../model-backends/model-unicorn.md).
- **DynamoRIO**: This backend uses [DynamoRIO](https://dynamorio.org/) for dynamic binary instrumentation. It instruments the test case to insert hooks for tracing and speculation simulation. Documentation is provided in [DynamoRIO Backend](../model-backends/model-dr.md).

Both implement the same interface defined by the abstract `Model` class.

## Contract Trace Representation

A `CTrace` is a sequence of typed observations representing leaked information:

```text
CTrace
  └─ List[CTraceEntry]
       ├─ mem    Memory address
       ├─ pc     Program counter
       ├─ val    Data value
       ├─ reg    Register value
       └─ ind    Indirect branch target
```

CTraces use `xxhash` for fast equality checking, enabling efficient grouping into equivalence classes.
