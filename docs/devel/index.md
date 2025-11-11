# Developer Documentation

This section provides technical documentation for developers contributing to Revizor.

## Development Guidelines

- [General Guidelines](guidelines-general.md): Development environment setup, testing procedures, contribution workflow
- [Code Style](guidelines-code-style.md): Formatting conventions for Python and C code, naming conventions
- [Git Workflow](guidelines-git.md): Branch management, commit message format, merge procedures

## Architecture and Modules

- [Overview](arch-overview.md): High-level system architecture and component interaction
- [Code Structure](code-structure.md): Organization of the source code directory and key modules
- [Orchestration](arch-fuzz.md): Main fuzzing loop and coordination between components
- [ISA Specification](arch-isa.md): Instruction set architecture definitions and JSON-based specification format
- [Test Case Code Generation](arch-code.md): Program generation algorithm and relevant classes
- [Test Case Data Generation](arch-data.md): Data generation algorithm and relevant classes
- [Hardware Tracing](arch-exec.md): Execution of test cases on the target HW and hardware trace collection
- [Contract Tracing](arch-model.md): Leakage modeling and contract trace generation (high-level overview; implementation details in backend-specific pages)
- [Trace Analysis](arch-analysis.md): Comparison of contract and hardware traces to detect violations
- [Minimization](arch-mini.md): Post-detection reduction of test cases to minimal reproducing examples
- [Logging](arch-logging.md): Logging infrastructure and debugging facilities

## Contract Modeling Backends

Revizor supports two different backends for contract-based leakage modeling. They are documented in the following pages:

- [Unicorn Backend](model-unicorn.md): Backend based on the Unicorn CPU emulator
- [DynamoRIO Backend](model-dr.md): Backend based on the DynamoRIO dynamic binary instrumentation engine

## Advanced Topics

- [Register Allocation](registers.md): Executor reserves a subset of registers for its own use; this page documents their purpose
- [Test Case Sandbox](sandbox.md): Memory layout of the sandbox environment in which test cases are executed
- [Macros](macros.md): Implementation of macros in Executor and Models
- [Binary Formats](binary-formats.md): Serialized binary formats for test case programs and data
