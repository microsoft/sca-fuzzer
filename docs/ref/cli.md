# Command-Line Interface

This document provides a complete reference for all command-line options accepted by the `rvzr` command (or `./revizor.py` if running directly from the source tree).

!!! note "CLI vs Configuration Files"
    Revizor is controlled via two interfaces: command line arguments and a configuration file.
    Command line arguments specify the mode of operation and set high-level parameters (e.g., file paths, number of fuzzing rounds), while the configuration file specifies details of the fuzzing campaign (e.g., the target contract, generation parameters, etc). This document focuses on the former; for information on configuration files, see the [configuration documentation](config.md).


## General Syntax

The general syntax of the command line is:

```
rvzr MODE [OPTIONS]

# Where MODE can be:
#   fuzz            fuzzing mode
#   tfuzz           template fuzzing mode
#   reproduce       reproduce mode
#   minimize        test case minimization mode
#   analyse         stand-alone trace analysis mode
#   generate        stand-alone generation mode
#   download_spec   call the script that downloads the instruction set specification
```

The available options depend on the selected mode. See [Execution Modes](modes.md) for descriptions of each mode's purpose and behavior.

For example, a typical way to run Revizor is in fuzzing mode with a command like this:

```bash
rvzr fuzz -s base.json -n 100 -i 10  -c config.yaml -w ./violations
```

This command will run the fuzzer for 100 iterations (i.e., 100 test cases), with 10 inputs per test case.
The fuzzer will use the ISA spec stored in the `base.json` file, and will read the configuration from `config.yaml`. If the fuzzer finds a violation, it will be stored in the `./violations` directory.


## Fuzzing Mode

Command-line arguments supported in `fuzz` mode:

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

Command-line arguments supported in `tfuzz` mode:

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

Command-line arguments supported in `reproduce` mode:

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

Command-line arguments supported in `minimize` mode:

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

See also the [minimization documentation](minimization-passes.md) for a list of available minimization passes.

## Stand-alone Trace Analysis

Command-line arguments supported in `analyse` mode:

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

## Stand-alone Generation

Command-line arguments supported in `generate` mode:

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

### Download Instruction Set Specification

The following command-line arguments are supported in `download_spec` mode:

```
  -h, --help            show this help message and exit
  -a ARCHITECTURE, --architecture ARCHITECTURE   The ISA to download the specification for (e.g., x86-64)
  --outfile OUTFILE, -o OUTFILE   The destination file to save the downloaded specification.
  --extensions [EXTENSIONS ...]   List of ISA extensions to include in the specification (e.g., SSE, VTX)
```
