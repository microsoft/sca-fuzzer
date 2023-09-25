# Revizor

![GitHub](https://img.shields.io/github/license/microsoft/sca-fuzzer)
![PyPI](https://img.shields.io/pypi/v/revizor-fuzzer)
![GitHub all releases](https://img.shields.io/github/downloads/microsoft/sca-fuzzer/total)
![GitHub contributors](https://img.shields.io/github/contributors/microsoft/sca-fuzzer)
<!-- ![PyPI - Downloads](https://img.shields.io/pypi/dm/revizor-fuzzer) -->

Revizor is a security-oriented fuzzer for detecting information leaks in CPUs, such as [Spectre and Meltdown](https://meltdownattack.com/).
It tests CPUs against [Leakage Contracts](https://arxiv.org/abs/2006.03841) and searches for unexpected leaks.

For more details, see our [Paper](https://dl.acm.org/doi/10.1145/3503222.3507729) (open access [here](https://arxiv.org/abs/2105.06872)), and the [follow-up paper](https://arxiv.org/pdf/2301.07642.pdf).

## Installation

**Warning**:
Keep in mind that the Revizor runs randomly-generated code in kernel space.
As you can imagine, things could go wrong.
Make sure you're not running Revizor on an important machine.

### 1. Check Requirements

* Architecture: Revizor supports Intel and AMD x86-64 CPUs.
We also have experimental support for ARM CPUs (see `arm-port` branch) but it is at very early stages, use it on your own peril.

* No virtualization: You will need a bare-metal OS installation.
Testing from inside a VM is not (yet) supported.

* OS: The target machine has to be running Linux v4.15 or later.

### 2. Install Revizor Python Package

If you use `pip`, you can install Revizor with:

```bash
pip install revizor-fuzzer
```

Alternatively, install Revizor from sources:
```bash
# run from the project root directory
make install
```

If the installation fails with `'revizor-fuzzer' requires a different Python:`, you'll have to install Python 3.9 and run Revizor from a virtual environment:
```bash
sudo apt install python3.9 python3.9-venv
/usr/bin/python3.9 -m pip install virtualenv
/usr/bin/python3.9 -m virtualenv ~/venv-revizor
source ~/venv-revizor/bin/activate
pip install revizor-fuzzer
```

### 3. Install Revizor Executor (kernel module)

Then build and install the kernel module:

```bash
# building a kernel module require kernel headers
sudo apt-get install linux-headers-$(uname -r)

# get the source code
git clone https://github.com/microsoft/sca-fuzzer.git

# build the executor
cd sca-fuzzer/src/x86/executor
make uninstall  # the command will give an error message, but it's ok!
make clean
make
make install
```

### 4. Download ISA spec

```bash
rvzr download_spec -a x86-64 --extensions ALL_SUPPORTED --outfile base.json
```

### 5. (Optional) System Configuration

For more stable results, disable hyperthreading (there's usually a BIOS option for it).
If you do not disable hyperthreading, you will see a warning every time you invoke Revizor; you can ignore it.

Optionally (and it *really* is optional), you can boot the kernel on a single core by adding `-maxcpus=1` to the boot parameters ([how to add a boot parameter](https://wiki.ubuntu.com/Kernel/KernelBootParameters)).


## Command Line Interface

The fuzzer is controlled via a single command line interface `rvzr` (or `revizor.py` if you're running directly from the source directory).

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


### Detection of a Simple Contract Violation

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

### Full-Scale Fuzzing Campaign

To start a full-scale test, write your own configuration file (see description [here](config.md) and an example config [here](https://github.com/microsoft/sca-fuzzer/tree/main/src/tests/big-fuzz.yaml)), and launch the fuzzer.

Below is a example launch command, which will start a 24-hour fuzzing session, with 100 input classes per test case, and which uses [big-fuzz.yaml](https://github.com/microsoft/sca-fuzzer/tree/main/src/tests/big-fuzz.yaml) configuration:
```shell
rvzr fuzz -s base.json -c src/tests/big-fuzz.yaml -i 100 -n 100000000 --timeout 86400 -w `pwd` --nonstop
```

When you find a violation, you will have to do some manual investigation to understand the source of it; [this guide](fuzzing-guide.md) is an example of how to do such an investigation.

## Need Help with Revizor?

If you find a bug in Revizor, don't hesitate to [open an issue](https://github.com/microsoft/sca-fuzzer/issues).

If something is confusing or you need help in using Revizor, we have a [discussion page](https://github.com/microsoft/sca-fuzzer/discussions).

## Documentation

For more details, see [the website](https://microsoft.github.io/sca-fuzzer/).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
