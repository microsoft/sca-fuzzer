# Quick Start Guide

## Testbed

Get yourself a machine for testing: Revizor can test x86-64 CPUs, Intel or AMD.
You will need a Linux installation running directly on the hardware (testing from within a VM is not supported).

## Installation

Follow the installation instructions on [this page](install.md).

## Config File

The fuzzing process is controlled by a configuration file in the YAML format, passed via `--config` option. At the very minimum, this file should contain the following fields:
* `contract_observation_clause` and `contract_execution_clause` describe the contract that the CPU-under-test is tested against. See [this page](https://microsoft.github.io/sca-fuzzer/config/) for a list of available contracts. If you don't know what a contract is, Sec. 3 of [this paper](https://arxiv.org/pdf/2105.06872.pdf) will give you a high-level introduction to contracts, and [this paper](https://www.microsoft.com/en-us/research/publication/hardware-software-contracts-for-secure-speculation/) will provide a deep dive into contracts.
* `instruction_categories` is a list of instruction types that will be tested. Effectively, Revizor uses this list to filter out instructions from `base.json` (the file you downloaded via `rvzr download_spec`).

For a full list of configuration options, see [docs](https://microsoft.github.io/sca-fuzzer/config/).

## Baseline Experiment

After a fresh installation, it is normally a good idea to do a quick test run to check that everything works ok.

For example, we can create a configuration file `config.yaml` with only simple arithmetic instructions. As this instruction set does not include any instructions that would trigger speculation on Intel or AMD CPUs (at least that we know of), the expected contract would be `CT-SEQ`:

```yaml
# config.yaml
instruction_categories:
  - BASE-BINARY  # arithmetic instructions
max_bb_per_function: 1  # no branches!
min_bb_per_function: 1

contract_observation_clause: loads+stores+pc  # aka CT
contract_execution_clause:
  - no_speculation  # aka SEQ
```

Start the fuzzer:
```bash
rvzr fuzz -s base.json -i 50 -n 100 -c config.yaml  -w .
```

This command should terminate with no violations.


## Detection of a Simple Contract Violation

Next, we could intentionally make a mistake in a contract to check that Revizor can detect it.
To this end, we can modify the config file from the previous example to include instructions that trigger speculation (e.g., conditional branches) but keep the contract the same:
```yaml
# config.yaml
instruction_categories:
  - BASE-BINARY  # arithmetic instructions
  - BASE-COND_BR
max_bb_per_function: 5  # up to 5 branches per test case
min_bb_per_function: 1

contract_observation_clause: loads+stores+pc  # aka CT
contract_execution_clause:
  - no_speculation  # aka SEQ
```

Start the fuzzer:
```bash
rvzr fuzz -s base.json -i 50 -n 1000 -c config.yaml -w .
```

As your CPU-under-test almost definitely implements branch prediction, Revizor should detect a violation within a few minutes, with a message similar to this:

```
================================ Violations detected ==========================
  Contract trace (hash):

    0111010000011100111000001010010011110101110011110100000111010110
  Hardware traces:
   Inputs [907599882]:
    .....^......^......^...........................................^
   Inputs [2282448906]:
    ...................^.....^...................................^.^

```

You can find the violating test case as well as the violation report in the directory named `./violation-*/`.
It will contain an assembly file `program.asm` that surfaced a violation, a sequence of inputs `input-*.bin` to this program, and some details about the violation in `report.txt`.

## Full-Scale Fuzzing Campaign

To start a full-scale test, write your own configuration file (see description [here](config.md) and an example config [here](https://github.com/microsoft/sca-fuzzer/tree/main/src/tests/big-fuzz.yaml)), and launch the fuzzer.

Below is a example launch command, which will start a 24-hour fuzzing session, with 100 input classes per test case, and which uses [big-fuzz.yaml](https://github.com/microsoft/sca-fuzzer/tree/main/src/tests/big-fuzz.yaml) configuration:
```shell
rvzr fuzz -s base.json -c src/tests/big-fuzz.yaml -i 100 -n 100000000 --timeout 86400 -w `pwd` --nonstop
```

When you find a violation, you will have to do some manual investigation to understand the source of it; [this guide](fuzzing-guide.md) is an example of how to do such an investigation.
