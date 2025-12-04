# Test Case Data Generation

|                  |                          |
| ---------------- | ------------------------ |
| Module           | `rvzr/data_generator.py` |
| Public interface | `DataGenerator`          |
| Inputs           | `Config`                 |
| Outputs          | `InputData`              |

`DataGenerator` generates input data that is used to initialize registers and memory before executing a test case, on both the model and the target hardware.


## Generation modes

Two input generation modes are supported:

### Standard generation

Interface: `DataGenerator.generate(...)`

This method creates fully random inputs using a PRNG. Can optionally reduce entropy (to increase trace collisions) or inject special values (zeros, boundary values) to trigger edge cases.

### Boosted generation

Interface: `DataGenerator.generate_boosted(...)`

Boosted generation solves the following challenge:
Two detect a violation via relational non-interference testing, we always need at least two inputs that produce identical contract traces (see [Trace Analysis](overview.md#6-trace-analysis)). Generating such contract-equivalent inputs through pure randomness is extremely inefficient because the entropy of contract traces is usually very high, and thus most random inputs produce unique traces.

Boosted generation addresses this by leveraging dynamic taint analysis on the model side. It works as follows: Start by producing a set of random inputs using standard generation. Then, we execute the test case with each input in the model and perform backwards taint analysis to identify which input bytes affect the contract trace (tainted) and which don't (untainted). This produces a set of `InputTaint` objects that map input bytes to their taint status. These taint maps a fed back into the `generate_boosted()` method, which creates new inputs such that the tainted bytes remain fixed while the untainted bytes are randomized.

```text
Original InputData → Model → InputTaint → N contract-equivalent inputs
```

Such "boosted" inputs are guaranteed to produce the same contract trace as the original input while still being mostly random.


## Data Representation

Each input is represented as an `InputData` object, which is a numpy structured array containing

- Memory contents
- General-purpose registers
- SIMD registers
- Flags and special registers

for each actor in the test case. This object can be serialized into Revizor's custom binary format ([RDBF](../../ref/binary-formats.md)) for consumption by the model and executor.
