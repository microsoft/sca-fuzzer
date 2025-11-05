# Code Structure

The Revizor codebase is organized into the following main directories:

```text
rvzr/                         Main source code directory containing core fuzzing logic
  ├── *.py                    Core modules that implement main fuzzing components
  ├── tc_components/          Test case representation objects (code and data)
  ├── model_unicorn/          Unicorn-based leakage model
  ├── model_dynamorio/        DynamoRIO-based leakage model
  ├── executor_km/            Kernel module that implements the hardware executor
  ├── postprocessing/         Minimization utilities for contract counterexamples
  └── arch/                   Architecture-specific implementations (x86/ and arm64/)
tests/                        Unit and integration tests
docs/                         Documentation files
```

The main entry point is `rvzr/cli.py`, which parses command-line arguments and initializes the `Fuzzer` object.

