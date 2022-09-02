# Command-Line Interface

Revizor can run in one of multiple "modes":

* **Fuzzing mode** is revizor's main form of execution. It's what invokes all
  components of [revizor's architecture](architecture.md) to enable hardware
  fuzzing.
* **Analysis mode** invokes the analyser to compare existing contract traces and
  hardware traces.
* **Minimize mode** accepts a test case and attempts to minimize its size.
  It acts as a "watered-down" version of **fuzzing mode** that focuses solely on
  a single test case.

To select a mode on the command-line, begin your command with:

```shell
cli.py MODE # ... arguments go here

# Where MODE can be:
#   fuzz            for fuzzing mode
#   analyse         for analysis mode
#   minimize        for test case minimization mode
```

## Fuzzing Mode

The following command-line arguments are supported in `fuzz` mode:

* `-s` / `--instruction-set` - accepts a path to an XML file specifying the
  instruction set revizor should use.
* `-c` / `--config` - accepts a path to a YAML configuration file for revizor.
* `-n` / `--num-test-cases` - accepts an integer specifying the number of test
  cases to create and test during the fuzzing campaign.
* `-i` / `--num-inputs` - accepts an integer specifying the number of inputs to
  generate for each test case (which corresponds to the number of contract
  traces to collect).
* `-w` / `--working-directory` - accepts a path to a directory into which
  revizor will place its output files during the campaign.
* `-t` / `--testcase` - accepts a path to an existing test case for the fuzzer
  to run. (Revizor will *only* run this test case if this is specified.)
* `--timeout` - accepts an integer specifying the number of seconds to run the
  fuzzer. Once the timeout has been reached, fuzzing will cease.
* `--nonstop` - if enabled, this keeps the fuzzer running after it encounters a
  violation. (Otherwise, if it's not specified, revizor will stop after the
  first violation is found.)

## Analysis Mode

The following command-line arguments are supported in `analyse` mode:

* `--ctraces` - accepts a path to a file containing contract traces.
* `--htraces` - accepts a path to a file containing hardware traces.
* `-c` / `--config` - accepts a path to a YAML configuration file for revizor.

## Minimize Mode

The following command-line arguments are support in `minimize` mode:

* `-i` / `--infile` - accepts a path to the test case revizor will attempt to
  minimize.
* `-o` / `--outfile` - accepts a path specifying where the minimized version of
  the original test case will be written to.
* `-c` / `--config` - accepts a path to a YAML configuration file for revizor.
* `-n` / `--num-inputs` - accepts an integer specifying the number of inputs to
  try for the test case.
* `-f` / `--add-fences` - if enabled, revizor will add as many `LFENCE`
  instructions as possible to the test case's assembly code while still
  preserving the violation-inducing behavior.
* `-s` / `--instruction-set` - accepts a path to an XML file specifying the
  instruction set revizor should use.

