# Execution Modes

Revizor supports several modes of operation, each targeting a different use cases.
The selection of the mode is described in the [CLI documentation](cli.md).
Below is a brief description of each mode.

## Overview

| Mode             | CLI Key       | Use Case                      | Description                                                                                                |
| ---------------- | ------------- | ----------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Fuzzing          | fuzz          | General Testing               | Test a CPU against a contract model. Test cases generated randomly                                         |
| Template Fuzzing | tfuzz         | Targeted Testing              | Test a CPU against a contract model. Test cases generated based on a template                              |
| Reproduce        | reproduce     | Reproducing a Violation       | Reproduce a violation found by fuzzing OR run a manually-written test case                                 |
| Minimization     | minimize      | Simplification of a Violation | Simplify a test case by applying a series of simplification passes to the test case program and its inputs |
| Trace Analysis   | analyse       | External Integration          | Analyze pre-recorded traces for violations                                                                 |
| Generation       | generate      | External Integration          | Only generate test cases, without testing them                                                             |
| ISA Spec Install | download_spec | Tool Installation             | Call a script that downloads the instruction set specification                                             |


## <a name="fuzz"></a> `fuzz`

=== "Syntax"
```bash
$ rvzr fuzz [OPTIONS]
```

:   Main fuzzing mode of Revizor.
In this mode, Revizor randomly generates test cases and executes them on the target CPU and the model, records the corresponding traces, and checks if the hardware traces contain the same (or less) information as the contract traces. That is, it implements [Model-Based Relational Testing](../intro/03_primer.md#model-based-relational-testing-and-revizor) approach.

:   **Use case:** Broad testing of CPU behavior against contract specifications.



## <a name="tfuzz"></a> `tfuzz`

=== "Syntax"
```bash
$ rvzr tfuzz [OPTIONS]
```

:   Similar to the fuzzing mode, but test cases are generated based on a template. For details on templates, see the [template fuzzing how-to guide](../howto/use-templates.md).

:   **Use case:** Targeted testing of specific scenarios, microarchitectural patches, or actor interactions.


## <a name="reproduce"></a> `reproduce`

=== "Syntax"
```bash
$ rvzr reproduce [OPTIONS]
```
:   In this mode, Revizor loads and executes a specific test case data and inputs from files. Performs single fuzzing round with the provided test case and inputs, and reports the results.

:   Test cases can be violations from previous fuzzing runs or manually-written test programs.

:   **Use cases:**

    - Checking reproducibility: Testing if a violation artifact can be consistently reproduced on other CPUs or configurations.
    - Verification of a violation: Confirming that a violation is genuine and not a false positive.
    - Manual testing: Executing a custom test case written by the user.
    - Root-causing: Checking the impact of manual modifications to a test case.



## <a name="minimize"></a> `minimize`

=== "Syntax"
```bash
$ rvzr minimize [OPTIONS]
```

:   In this mode, Revizor applies simplification passes to a violation test case, reducing program and input complexity while preserving the violation behavior.

:   **Use case:** Simplify violations for root cause analysis.



## <a name="analyse"></a> `analyse`

=== "Syntax"
```bash
$ rvzr analyse [OPTIONS]
```

:   In this mode, Revizor analyzes pre-recorded contract and hardware traces for violations without executing test cases.
Accepts trace files as input and applies the configured analyser to detect contract violations.

:   **Use case:** Integration with external tools that perform trace collection separately from Revizor.


## <a name="generate"></a> `generate`

=== "Syntax"
```bash
$ rvzr generate [OPTIONS]
```
:   Generates test cases without execution. Outputs test programs and inputs to them.

:   **Use case:** Integration with external tools that use Revizor's test case generation capabilities.



## <a name="download_spec"></a> `download_spec`

=== "Syntax"
```bash
$ rvzr download_spec [OPTIONS]
```
:   This mode is only used when Revizor is being set up. Downloads, parses, and stores instruction set specifications in JSON format.

:   **Use case:** Tool installation and ISA specification management.


## What's Next?

* [Command Line Interface](cli.md) - How to run Revizor in different modes
* [Minimization Passes](minimization-passes.md) - Available passes for the `minimize` mode
