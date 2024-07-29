# Command-Line Interface

Revizor is controlled via two interfaces: command line and configuration file.
Command line arguments specify the mode of operation and set high-level parameters (e.g., file paths, number of fuzzing rounds).
Configuration files specify details of the fuzzing campaign (e.g., the target contract, generation parameters, etc).

This document describes the command-line interface.
For information on configuration files, see the [configuration documentation](config.md).

## Modes

Revizor can run in one of multiple "modes":

* **Fuzzing mode** is revizor's main form of execution.
In this mode, revizor generates random test cases, tests them on the target CPU and the model,
and checks for contract violations.
* **Template fuzzing mode** is a variant of fuzzing mode that uses a template to generate test cases.
* **Reproduce mode** is a variant of fuzzing mode that attempts to reproduce a violation found in a previous run.
* **Minimize mode** accepts a test case and attempts to simplify it by applying a series of passes.

To select a mode on the command-line, begin your command with:

```shell
rvzr MODE # ... arguments go here

# Where MODE can be:
#   fuzz            for fuzzing mode
#   tfuzz           for template fuzzing mode
#   reproduce       for reproduce mode
#   minimize        for test case minimization mode
```

## Fuzzing Mode

The following command-line arguments are supported in `fuzz` mode:

```
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to the configuration file (YAML) that will be used during fuzzing.
  -I INCLUDE_DIR, --include-dir INCLUDE_DIR
                        Path to the directory containing configuration files that included by the main configuration file (received via --config).
  -s INSTRUCTION_SET, --instruction-set INSTRUCTION_SET
                        Path to the instruction set specification (JSON) file.
  -n NUM_TEST_CASES, --num-test-cases NUM_TEST_CASES
                        Number of test cases.
  -i NUM_INPUTS, --num-inputs NUM_INPUTS
                        Number of inputs per test case.
  -w WORKING_DIRECTORY, --working-directory WORKING_DIRECTORY
  -t TESTCASE, --testcase TESTCASE
                        Use an existing test case [DEPRECATED - see reproduce]
  --timeout TIMEOUT     Run fuzzing with a time limit [seconds]. No timeout when set to zero.
  --nonstop             Don't stop after detecting an unexpected result
  --save-violations SAVE_VIOLATIONS
                        If set, store all detected violations in working directory.
```

## Template Fuzzing Mode

The following command-line arguments are supported in `analyse` mode:

```
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to the configuration file (YAML) that will be used during fuzzing.
  -I INCLUDE_DIR, --include-dir INCLUDE_DIR
                        Path to the directory containing configuration files that included by the main configuration file (received
                        via --config).
  -s INSTRUCTION_SET, --instruction-set INSTRUCTION_SET
                        Path to the instruction set specification (JSON) file.
  -n NUM_TEST_CASES, --num-test-cases NUM_TEST_CASES
                        Number of test cases.
  -i NUM_INPUTS, --num-inputs NUM_INPUTS
                        Number of inputs per test case.
  -w WORKING_DIRECTORY, --working-directory WORKING_DIRECTORY
  -t TEMPLATE, --template TEMPLATE
                        The template to use for generating test cases
  --timeout TIMEOUT     Run fuzzing with a time limit [seconds]. No timeout when set to zero.
  --nonstop             Don't stop after detecting an unexpected result
  --enable-store-violations ENABLE_STORE_VIOLATIONS
                        If set, store all detected violations in working directory.
```

## Reproduce Mode

The following command-line arguments are supported in `reproduce` mode:

```
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to the configuration file (YAML) that will be used during fuzzing.
  -I INCLUDE_DIR, --include-dir INCLUDE_DIR
                        Path to the directory containing configuration files that included by the main configuration file (received
                        via --config).
  -s INSTRUCTION_SET, --instruction-set INSTRUCTION_SET
                        Path to the instruction set specification (JSON) file.
  -t TESTCASE, --testcase TESTCASE
                        Path to the test case
  -i [INPUTS ...], --inputs [INPUTS ...]
                        Path to the directory with inputs
  -n NUM_INPUTS, --num-inputs NUM_INPUTS
                        Number of inputs per test case. [IGNORED if --input-dir is set]
```

## Minimize Mode

Minimize mode is described in detail in the [minimization documentation](minimization.md).
