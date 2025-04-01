# Architecture Overview

This document provides an overview of Revizor's architecture and its key components.

## How Revizor works

Revizor detects contract violations via a method called Model-based Relational Testing (MRT).
This method relies on a [leakage model](../contracts.md) that encodes known microarchitectural vulnerabilities to predict the information leaked when executing some code, which
 allows it to distinguish between expected and unexpected  leaks. The approach generates random code that is executed both in the CPU-under-test and in the model. It then measures the microarchitectural state changes caused by the code and compares it to the leakage predicted by the model. If the observed leakage matches the model’s prediction, this indicates that the CPU is behaving as expected, and
 the test case is discarded. Otherwise, if the random code exposed unexpected information, this indicates a potential security vulnerability, and the generated code can be used as a starting point for further (manual) analysis of the new leak.

Revizor works by executing the following loop for a number of rounds, or until a model violation is detected, as summarized by the diagram:

![architecture](../assets/fuzzing-flow.png)

### 1. Initialization

The first step (executed only once) is to receive fuzzing configuration from the user.
The configuration specifies the target CPU, its ISA specification, the instruction pool to be tested, the side-channel to be tested, and other fuzzing parameters.

**Details**: All interactions with a user are handled by the `cli.py` module, which parses the command-line arguments. Based on the arguments it creates an `InstructionSet` object (defined in `isa_spec.py`) and a `Config` object (defined in `config.py`). It also initializes the `Fuzzer` object (defined in `fuzzer.py`), which will handle the fuzzing process from now on.

### 2. Code Generation

A testing round starts by generating a [test case program](tc-representation.md). The program is essentially a random sequence of assembly instructions with a semi-random control flow, generated from a predefined instruction pool. The code generator create such a program based on the ISA specification provided by the user.

The generator can be configured to constrain the shape of the program’s control-flow graph, control the pool of instructions, and configure the instruction frequencies. It also (optionally) instruments the program to prevent undesired faults, such as division by zero.

**Details**: `Fuzzer` invokes code generation by calling `CodeGenerator::create_test_case` (defined in `code_generator.py`).
This method uses the `InstructionSet` and `Config` objects as the basis for the generation process.
The created test case is returned as a `TestCaseProgram` object (defined in `tc_components/test_case_code.py`).

### 3. Data Generation

The next step is to generate a set of program inputs. Each input is a binary blob, used by the model and the executor to initialize the program’s memory and registers before it is executed. The data generator creates random (but seeded) values to populate the binary blob according to a predefined [format](binary-formats.md#revizor-data-binary-format-rdbf).

**Details**: Data generator is implemented by the `data_generator.py` module. The main interface to the generator is the `DataGenerator` class, with its `generate` method being the main entry point.
The generated data is returned as a list of `InputData` objects (defined in `tc_components/test_case_data.py`).

### 4. Model Execution

The model takes the generated program and executes it with each of the generated inputs.
The model records the data that we expect to be leaked on the given CPU, and to emulate the expected speculative behavior. For mode details on leakage models, see [Speculation Contracts](../contracts.md).

**Details**: The model is implemented by the `model.py` module.
The main interface to the model is the `Model` class, with its `load_test_case` and `trace_test_case` methods being the main entry points.
`load_test_case` takes a `TestCaseProgram` object and loads its binary into the model.
`trace_test_case` takes a list of `InputData` objects, loads their data into the model's memory one at a time and executes the loaded program with each.
The resulting contract traces are returned as a list of `CTrace` objects (defined in `traces.py`).

Note that Revizor supports multiple modelling backends, which are implemented as subclasses of the `Model` class. The current backends are based on [Unicorn](unicorn-model.md) and [DynamoRIO](dr-model.md).

### 5. Hardware Execution

The executor takes a program, executes it on the target CPU with each of the inputs, and collects hardware traces for each execution. The traces are typically (though not strictly necessarily) collected via a side-channel attack, such as Prime+Probe, in which case a trace is a set of cache lines evicted by the program. In addition to collecting traces, the executor also ensures a low-noise and reproducible execution environment, for example, by disabling interrupts and flushing caches before starting a measurement.

**Details**: The executor is implemented by the `executor.py` module.
The main interface to the executor is the `Executor` class, with its `load_test_case` and `trace_test_case` methods being the main entry points.
`load_test_case` takes a `TestCaseProgram` object and loads its binary into the executor.
`trace_test_case` takes a list of `InputData` objects, loads their data into the executor's memory one at a time and executes the loaded program with each.
The resulting hardware traces are returned as a list of `HTrace` objects (defined in `traces.py`).

The architecture of Revizor can potentially support many types of executors, but currently, we support only one. It is implemented as a kernel module (`x86/executor`), to which the `Executor` class acts as an adapter.

### 6. Trace Analysis

The trace analyzer uses the leakage predicted by the model to filter out instances of expected leaks from the set of collected hardware traces, thus leaving only the unexpected leaks. The analyzer performs the filtering by [checking the noninterference property w.r.t. the model](../contracts.md).

The key aspect of this approach is that MRT never directly compares the hardware traces to the model’s prediction; instead, it compares the exposed information. This allows a complex modern CPU to be tested against a simple model, and still effectively filter out expected leaks while detecting unexpected leaks.

**Details**: The analyzer is implemented by the `analyser.py` module.
The main interface to the analyzer is the `Analyser` class, with its `filter_violation` method being the main entry point.
It takes a list of `CTrace` and a list of `HTrace` objects, and returns a `Violation` object (defined in `traces.py`) if a contract violation is detected.

### 7. Post-violation Analysis

If a violation is detected, the fuzzer performs a sequence of [post-violation tests](post-violation.md) to filter out various types of false positives.
If the violation survives all these tests, it is reported to the user.
The user can then utilize the [postprocessing features of Revizor](../user/minimization.md) to identify the root cause of leakage.

**Details**: The post-violation analysis is implemented largely in the `Fuzzer::fuzzing_round` method.
The reporting of the violation is done by the `logs.py:FuzzLogger` class, which is accessed via the `report_violation` method.
The post-processing is implemented by various classes in the `postprocessing` module.

## Revizor Modules and Interfaces

**UNDER CONSTRUCTION**: If you are interested in this topic, please contact us by opening an issue on GitHub, and we will prioritize this document.
