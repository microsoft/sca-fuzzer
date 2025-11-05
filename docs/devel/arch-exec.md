# Hardware Tracing

|                  |                                         |
| ---------------- | --------------------------------------- |
| Module           | `rvzr/executor.py`, `rvzr/executor_km/` |
| Public interface | `Executor`                              |
| Inputs           | `TestCaseProgram`, `InputData`          |
| Outputs          | `HTrace`                                |

## Executor

The Executor runs test cases on real hardware and collects hardware traces (HTraces) using side-channel measurements. It uses a two-layer architecture: Python code communicates with a kernel module that performs measurements in kernel space.

```text
Python (executor.py)
  ├─ X86IntelExecutor
  ├─ X86AMDExecutor
  └─ ARM64Executor
       │
       │ /sys/rvzr_executor/ interface
       ▼
Kernel Module (executor_km/)
```

## HTrace representation

The `HTrace` class (`rvzr/traces.py`) represents hardware traces collected during execution. The executor produces one `HTrace` object per program-input pair, meaning that for each `TestCaseProgram` execution with each `InputData` input, one `HTrace` is generated.

Each `HTrace` encapsulates multiple measurements results (samples): This is because the executor typically repeats the execution several times and each execution produces one measurement sample. Such repeated measurements allow us to apply statistical methods when comparing noisy hardware traces (see [Trace Analysis](arch-analysis.md) below).

The structure of an `HTrace` is as follows:

```text
HTrace
  └─ Array[RawHTraceSample]
       ├─ trace       Main measurement (cache bitmap, timestamp, or registers)
       └─ pfc0-pfc4   Performance counter values
```
