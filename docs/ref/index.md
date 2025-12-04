# Reference Documentation

Complete technical reference for all Revizor components, commands, configuration options, and formats.

## User-Facing Components

* [Command Line Interface](cli.md)
Complete reference for all `rvzr` command-line options and arguments. Covers common options and mode-specific parameters.
* [Execution Modes](modes.md)
Detailed specifications for all execution modes: fuzzing, template fuzzing, reproduce, minimize, analyse, generate, and download_spec.

* [Configuration Options](config.md)
Complete reference for all configuration file parameters organized by component: fuzzer, generator, executor, model, analyser, and actors.

* [Macros Reference](macros.md)
Complete reference for all template macros including measurement control, fault handling, code generation, and actor transitions.

* [Minimization Passes](minimization-passes.md)
Complete list of available minimization passes for reducing test case complexity while preserving violations.

## Architecture & Internals

Low-level technical references for Revizor's internal components.

* [Binary Formats](binary-formats.md)
Specifications for Revizor's binary file formats: RCBF (Revizor Contract Binary Format) and RDBF (Revizor DynamoRIO Binary Format).

* [Registers](registers.md)
Register specifications and conventions for x86-64 and ARM64 architectures.

* [Sandbox](sandbox.md)
Memory layout and sandboxing mechanisms used during test execution.
