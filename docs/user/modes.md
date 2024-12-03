# Modes of Operation

Revizor supports several modes of operation, each targeting a different use cases.
The selection of the mode is described in the [CLI documentation](cli.md).
Below is a brief description of each mode.


| Mode             | CLI Key       | Use Case                 | Description                                                                                                |
| ---------------- | ------------- | ------------------------ | ---------------------------------------------------------------------------------------------------------- |
| Fuzzing          | fuzz          | General Testing          | Test a CPU against a contract model. Test cases generated randomly                                         |
| Template Fuzzing | tfuzz         | Targeted Testing         | Test a CPU against a contract model. Test cases generated based on a template                              |
| Reproduce        | reproduce     | Reproducing a Violation  | Reproduce a violation found by fuzzing OR run a manually-written test case                                 |
| Minimization     | minimize      | Violation Simplification | Simplify a test case by applying a series of simplification passes to the test case program and its inputs |
| Trace Analysis   | analyse       | Stand-alone Analysis     | Analyze pre-recorded traces for violations                                                                 |
| Generation       | generate      | Stand-alone Generation   | Only generate test cases, without testing them                                                             |
| ISA Spec Install | download_spec | Tool Installation        | Call a script that downloads the instruction set specification                                             |


## Fuzzing and Template Fuzzing Modes

Two main modes of operation in revizor are fuzzing and template fuzzing.
These modes are used to test a CPU against a contract model.
In both modes, revizor generates test cases and executes them on the target CPU and the model, records the corresponding traces, and checks if the hardware traces contain the same (or less) information as the contract traces.

In the fuzzing mode, test cases are generated randomly, with the instruction set and size of test cases defined by the config file.
This mode is used for broad testing of the CPU.

In the template fuzzing mode, test cases are generated based on a template:
The generator takes an assembly template as an input, and produces a test case by expanding the `random_instructions` macro in the template.
This mode is used to narrow down the fuzzing space and focus on specific scenarios, such as testing microarchitectural patches or certain interactions between actors.

## Reproduce

In this mode, Revizor loads a test case from a set of files and runs a single round of the fuzzer with this test case.
The test case is usually a violation previously found in the (template) fuzzing mode, but it can also be written manually.

There are three main use cases for this mode:

1. **Analysis of the violation**: to understand the root cause of the violation, the user may manually modify the test case and re-run it in the reproduce mode to see if the violation is still present.
2. **Reproducibility check**: to check if a violation is reproducible on different CPUs, or on different configurations of the same CPU (e.g., after a microcode patch has been applied).
3. **Manual testing**: to test a manually-written test case.

## Minimization

In this mode, Revizor takes a test case that causes a violation and applies a series of simplification passes to the test case program and its inputs.
The goal is to reduce the test case to its minimal form to simplify the root cause analysis of the violation.
Revizor supports an extensive list of passes, described in the [minimization documentation](minimization.md).

## Stand-alone Interfaces

The `analyse` and `generate` modes are used to perform stand-alone access to modules of Revizor.
In the `analyse` mode, the user can analyze pre-recorded traces for violations.
In the `generate` mode, the user can generate test cases without testing them.

## ISA Spec Install

The `download_spec` mode isn't used for testing, but rather for tool installation.
It provides an interface to download, parse, and store the instruction specifications for the tested ISA in the JSON format.
