
## Installation

**Warning**:
Revizor runs randomly-generated code in kernel space.
This means that a misconfiguration (or a bug) can crash the system and potentially lead to data loss.
Make sure you're not running Revizor on a production machine, and that you have a backup of your data.

### 1. Requirements

* Architecture: Revizor supports Intel and AMD x86-64 CPUs.
We have experimental support for ARM CPUs (see `arm-port` branch) but it is at very early stages, so use it on your own peril.

* No virtualization: You will need a bare-metal OS installation.
Testing from inside a VM is not supported.

* OS: The target machine has to be running Linux v4.15 or later.

### 2. Python Package

The preferred installation method is using `pip` within a virtual environment.
The python version must be 3.9 or later.

```bash
sudo apt install python3.9 python3.9-venv
/usr/bin/python3.9 -m pip install virtualenv
/usr/bin/python3.9 -m virtualenv ~/venv-revizor
source ~/venv-revizor/bin/activate
pip install revizor-fuzzer
```

### 3. Executor

In addition to the Python package, you will need to build and install the executor, which is a kernel module.

```bash
# building a kernel module require kernel headers
sudo apt-get install linux-headers-$(uname -r) linux-headers-generic

# get the source code
git clone https://github.com/microsoft/sca-fuzzer.git

# build executor
cd sca-fuzzer/src/x86/executor
make uninstall  # the command will give an error message, but it's ok!
make clean
make
make install
```

### 4. Download ISA spec

```bash
rvzr download_spec -a x86-64 --extensions ALL_SUPPORTED --outfile base.json

# Alternatively, use the following command to include system instructions;
# however, mind that testing these instructions may crash the system if misconfigured!
# rvzr download_spec -a x86-64 --extensions ALL_AND_UNSAFE --outfile base.json
```

### 5. Test the Installation

To make sure that the installation was successful, run the following command:

```bash
./tests/quick-test.sh

# The expected output is:
Detection: OK
Filtering: OK
```

If you see any other output, check if the previous steps were executed correctly.
If you still have issues, please [open an issue](https://github.com/microsoft/sca-fuzzer/issues).


### 6. (Optional) System Configuration

External processes can interfere with Revizor's measurements.
To minimize this interference, we recommend the following system configuration:
* Disable Hyperthreading (BIOS option);
* Disable Turbo Boost (BIOS option);
* Boot the kernel on a single core (add `-maxcpus=1` to [Linux boot parameters]((https://wiki.ubuntu.com/Kernel/KernelBootParameters))).

If you skip these steps, Revizor may produce false positives, especially if you use a low (sample size)[./docs/config.md) for measurements.
However, a large sample size (> 300-400) usually mitigates this issue.

## Quick Start

The following is an example of a simple fuzzing session with Revizor that will detect Spectre V1-like violations.

Create a configuration file `config.yaml` with the following content:
```yaml
# config.yaml
instruction_categories:
  - BASE-BINARY  # arithmetic instructions
  - BASE-COND_BR  # conditional branches
max_bb_per_function: 5  # up to 5 branches per test case
min_bb_per_function: 1
max_successors_per_bb: 2  # enable basic blocks with conditional branches

contract_observation_clause: loads+stores+pc  # aka CT
contract_execution_clause:
  - no_speculation  # aka SEQ
```

Start the fuzzer:
```bash
rvzr fuzz -s base.json -i 50 -n 1000 -c config.yaml -w .
```

You will likely see a violation within a few minutes, as most modern CPUs implement branch prediction, which is a prerequisite for Spectre-like attacks, and so the contract `CT-SEQ` is likely to be violated.

```
================================ Violations detected ==========================
Contract trace:
 18422470923634754929 (hash)
Hardware traces:
  Input group 1: [7]
  Input group 2: [57]
  ^..........................................^.............^^..^^. [500    | 0     ]
  ^....^...................................................^^..^^. [0      | 500   ]

```

You can find the violating test case as well as the violation report in the directory named `./violation-*/`.
It will contain an assembly file `program.asm` that surfaced a violation, a sequence of inputs `input_*.bin` to this program, and some details about the violation in `report.txt`.

## Command Line Interface

The fuzzer is controlled via a single command line interface `rvzr` (or `revizor.py` if you're running directly from the source tree).

It accepts the following arguments:
* `-s, --instruction-set PATH` - path to the ISA description file
* `-c, --config PATH` - path to the fuzzing configuration file
* `-n , --num-test-cases N` - number of test cases to be tested
* `-i , --num-inputs N` - number of input classes per test case. The number of actual inputs = input classes * inputs_per_class, which is a configuration option
* `-t , --testcase PATH` - use an existing test case instead of generating random test cases
* `--timeout TIMEOUT` - run fuzzing with a time limit [seconds]
* `-w` - working directory where the detected violations will be stored

For example, this command
```bash
rvzr fuzz -s base.json -n 100 -i 10  -c config.yaml -w ./violations
```
will run the fuzzer for 100 iterations (i.e., 100 test cases), with 10 inputs per test case.
The fuzzer will use the ISA spec stored in the `base.json` file, and will read the configuration from `config.yaml`. If the fuzzer finds a violation, it will be stored in the `./violations` directory.

See [docs](https://microsoft.github.io/sca-fuzzer/cli/) for more details.


## How To Fuzz With Revizor

The fuzzing process is controlled by a configuration file in the YAML format, passed via `--config` option. At the very minimum, this file should contain the following fields:
* `contract_observation_clause` and `contract_execution_clause` describe the contract that the CPU-under-test is tested against. See [this page](https://microsoft.github.io/sca-fuzzer/config/) for a list of available contracts. If you don't know what a contract is, Sec. 3 of [this paper](https://arxiv.org/pdf/2105.06872.pdf) will give you a high-level introduction to contracts, and [this paper](https://www.microsoft.com/en-us/research/publication/hardware-software-contracts-for-secure-speculation/) will provide a deep dive into contracts.
* `instruction_categories` is a list of instruction types that will be tested. Effectively, Revizor uses this list to filter out instructions from `base.json` (the file you downloaded via `rvzr download_spec`).

For a full list of configuration options, see [docs](https://microsoft.github.io/sca-fuzzer/config/).

### Baseline Experiment

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

### Full-Scale Fuzzing Campaign

To start a full-scale test, write your own configuration file (see description [here](config.md) and an example config [here](https://github.com/microsoft/sca-fuzzer/tree/main/demo/big-fuzz.yaml)), and launch the fuzzer.

Below is a example launch command, which will start a 24-hour fuzzing session, with 100 input classes per test case, and which uses [big-fuzz.yaml](https://github.com/microsoft/sca-fuzzer/tree/main/demo/big-fuzz.yaml) configuration:
```shell
rvzr fuzz -s base.json -c demo/big-fuzz.yaml -i 100 -n 100000000 --timeout 86400 -w `pwd` --nonstop
```

If there is a violation, you can try to reproduce it with the following command:

```shell
rvzr reproduce -s base.json -c violation-<timestamp>/reproduce.yaml -t violation-<timestamp>/program.asm -i violation-<timestamp>/input_*.bin
```

If the violation is reproducible, it is useful to minimize it, so that it is easier to understand the root cause (note that minimization uses a different config file):

```shell
rvzr minimize -s base.json -c violation-<timestamp>/minimize.yaml -g violation-<timestamp>/program.asm -o violation-<timestamp>/minimized.asm -i 100 --num-attempts 10 --enable-simplification-pass
```

The result of minimization will be stored in `violation-<timestamp>/minimized.asm`.
If the result is still too complicated, try [other minimization passes](minimization.md).

The further analysis is manual; you can find an example in [this guide](fuzzing-guide.md).

## Need Help with Revizor?

If you find a bug in Revizor, don't hesitate to [open an issue](https://github.com/microsoft/sca-fuzzer/issues).

If something is confusing or you need help in using Revizor, we have a [discussion page](https://github.com/microsoft/sca-fuzzer/discussions).

## Documentation

For more details, see [the website](https://microsoft.github.io/sca-fuzzer/).
