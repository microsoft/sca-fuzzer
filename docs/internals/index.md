# Developer Documentation

This section provides technical documentation for developers contributing to Revizor.

## Development Guidelines

- [Guide to Contributing](contributing/overview.md): Overview of the contribution process and resources
- [General Guidelines](contributing/general.md): Development environment setup, testing procedures, contribution workflow
- [Code Style](contributing/code-style.md): Formatting conventions for Python and C code, naming conventions
- [Git Workflow](contributing/git.md): Branch management, commit message format, merge procedures

## Architecture and Modules

- [Code Structure](code-structure.md): Organization of the source code directory and key modules
- [Overview](architecture/overview.md): High-level system architecture and component interaction
    - [Orchestration](architecture/fuzz.md): Main fuzzing loop and coordination between components
    - [ISA Specification](architecture/isa.md): Instruction set architecture definitions and JSON-based specification format
    - [Test Case Code Generation](architecture/code.md): Program generation algorithm and relevant classes
    - [Test Case Data Generation](architecture/data.md): Data generation algorithm and relevant classes
    - [Hardware Tracing](architecture/exec.md): Execution of test cases on the target HW and hardware trace collection
    - [Contract Tracing](architecture/model.md): Leakage modeling and contract trace generation (high-level overview; implementation details in backend-specific pages)
    - [Trace Analysis](architecture/analysis.md): Comparison of contract and hardware traces to detect violations
    - [Minimization](architecture/mini.md): Post-detection reduction of test cases to minimal reproducing examples
    - [Logging](architecture/logging.md): Logging infrastructure and debugging facilities

## Contract Modeling Backends

Revizor supports two different backends for contract-based leakage modeling. They are documented in the following pages:

- [Unicorn Backend](model-backends/model-unicorn.md): Backend based on the Unicorn CPU emulator
- [DynamoRIO Backend](model-backends/model-dr.md): Backend based on the DynamoRIO dynamic binary instrumentation engine
