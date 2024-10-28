# Command-Line Interface

Revizor is controlled via two interfaces: command line and configuration file.
Command line arguments specify the mode of operation and set high-level parameters (e.g., file paths, number of fuzzing rounds).
Configuration files specify details of the fuzzing campaign (e.g., the target contract, generation parameters, etc).

This document describes the command-line interface.
For information on configuration files, see the [configuration documentation](config.md).

## Modes

The command line options depend on the selected mode of operation (see [modes page](modes.md) for their descriptions).
To select a mode on the command-line, begin your command with:

```shell
rvzr MODE # ... arguments go here

# Where MODE can be:
#   fuzz            fuzzing mode
#   tfuzz           template fuzzing mode
#   reproduce       reproduce mode
#   minimize        test case minimization mode
#   analyse         stand-alone trace analysis mode
#   generate        stand-alone generation mode
#   download_spec   call the script that downloads the instruction set specification
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
  --save-violations SAVE_VIOLATIONS
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

The following command-line arguments are supported in `minimize` mode.
See also the [minimization documentation](minimization.md) for a list of available minimization passes.

```
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to the configuration file (YAML) that will be used during fuzzing.
  -I INCLUDE_DIR, --include-dir INCLUDE_DIR
                        Path to the directory containing configuration files that included by the main configuration file (received
                        via --config).
  -s INSTRUCTION_SET, --instruction-set INSTRUCTION_SET
                        Path to the instruction set specification (JSON) file.
  --testcase TESTCASE, -t TESTCASE
                        Path to the test case program that needs to be minimized.
  -i NUM_INPUTS, --num-inputs NUM_INPUTS
                        Number of inputs to the program that will be used during minimization.
  --testcase-outfile TESTCASE_OUTFILE, -o TESTCASE_OUTFILE
                        Output path for the minimized test case program.
  --input-outdir INPUT_OUTDIR
                        Output directory for storing minimized inputs.
  --num-attempts NUM_ATTEMPTS
                        Number of attempts to minimize the test case.
  --enable-<pass>       Enable a specific pass during minimization.
```

## Stand-alone Trace Analysis Mode

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
  --ctraces CTRACES
  --htraces HTRACES
```

## Stand-alone Generation Mode

The following command-line arguments are supported in `generate` mode:

```
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        Path to the configuration file (YAML) that will be used during fuzzing.
  -I INCLUDE_DIR, --include-dir INCLUDE_DIR
                        Path to the directory containing configuration files that included by the main configuration file (received
                        via --config).
  -s INSTRUCTION_SET, --instruction-set INSTRUCTION_SET
                        Path to the instruction set specification (JSON) file.
  -r SEED, --seed SEED  Add seed to generate test case.
  -n NUM_TEST_CASES, --num-test-cases NUM_TEST_CASES
                        Number of test cases.
  -i NUM_INPUTS, --num-inputs NUM_INPUTS
                        Number of inputs per test case.
  -w WORKING_DIRECTORY, --working-directory WORKING_DIRECTORY
  --permit-overwrite    Permit overwriting existing files.
```

## Download Instruction Set Specification

The following command-line arguments are supported in `download_spec` mode:

```
  -h, --help            show this help message and exit
  -a ARCHITECTURE, --architecture ARCHITECTURE   The ISA to download the specification for (e.g., x86-64)
  --outfile OUTFILE, -o OUTFILE   The destination file to save the downloaded specification.
  --extensions [EXTENSIONS ...]   List of ISA extensions to include in the specification (e.g., SSE, VTX)
```
