# Revizor

This is Revizor, a microarchitectural fuzzer.
It is a rather unconventional fuzzer as, instead of finding bugs in programs, Revizor searches for microarchitectural vulnerabilities in CPUs.

What is a microarchitectural vulnerability?
In the context of Revizor, it is a violation of out expectations about the CPU behavior, expressed as contract violations (see [Contracts](https://arxiv.org/abs/2006.03841)).
The most prominent examples would be [Spectre](https://spectreattack.com/) and [Meltdown](https://meltdownattack.com/).
Alternatively, a "bug" could also be in a form of a microarchitectural backdoor or an unknown optimization, although we are yet to encounter one of those.

See our [Technical Report](https://arxiv.org/abs/2105.06872) for details.

# Getting Started

**Note:** If you find missing or confusing explanations, or a bug in Revizor, don't hesitate to open an issue.

**Warning**: Revizor executes randomly generated code in kernel space.
As you can imagine, things could go wrong.
We did our best to avoid it and to make Revizor stable, but still, no software is perfect.
Make sure you're not running these experiments on an important machine.

## Requirements & Dependencies

1. Hardware Requirements

So far, Revizor supports only Intel CPU. It was tested on Intel Core i7-6700 and i7-9700, but it should work on any other Intel CPU just as well.

1. Software Requirements

* Linux v5.6+ (tested on Linux v5.6.6-300 and v5.6.13-100; there is a good chance it will work on other versions as well, but it's not guaranteed).
* Linux Kernel Headers
* Python 3.7+
* [Unicorn 1.0.2+](https://www.unicorn-engine.org/docs/)
* Python bindings to Unicorn:
```shell
pip3 install --user unicorn

# OR, if installed from sources
cd bindings/python
sudo make install
```
* Python packages `pyyaml`, `types-pyyaml`, `numpy`, `iced-x86`:
```shell
pip3 install --user pyyaml types-pyyaml numpy iced-x86
```

1. Software Requirements for Revizor Development

Tests: 
* [Bash Automated Testing System](https://bats-core.readthedocs.io/en/latest/index.html)
* [mypy](https://mypy.readthedocs.io/en/latest/getting_started.html#installing-and-running-mypy)
* `GNU datamash`

Documentation:
* [pdoc3](https://pypi.org/project/pdoc3/)

1. (Optional) System Configuration

For more stable results, disable hyperthreading (there's usually a BIOS option for it).
If you do not disable hyperthreading, you will see a warning every time you invoke Revizor; you can ignore it.

Optionally (and it *really* is optional), you can boot the kernel on a single core by adding `-maxcpus=1` to the boot parameters ([how to add a boot parameter](https://wiki.ubuntu.com/Kernel/KernelBootParameters)). 

In addition, you might want to stop any other actively-running software on the tested machine. We never encountered issues with it, but it might be useful.

## Installation

1. Get submodules:
```bash
# from the root directory of this project
git submodule update --init --recursive
```

2. Get the x86-64 ISA description:
```bash
cd src/x86/isa_loader
./get_spec.py --extensions BASE SSE SSE2 CLFLUSHOPT CLFSH
```

3. Install the executor:
```bash
cd revizor/src/executor/x86 
sudo rmmod x86-executor  # the command will give an error message, but it's ok!
make clean
make
sudo insmod x86-executor.ko
```

## Running Tests

```bash
cd src/tests
./runtests.sh
```

If a few (up to 3) "Detection" tests fail, it's fine, you might just have a slightly different microarchitecture. But if other tests fail - something is broken.

## Basic Usability Test

1. Fuzz in a violation-free configuration:
```bash
./cli.py fuzz -s x86/isa_spec/base.json -i 50 -n 100 -c tests/test-nondetection.yaml
```

No violations should be detected.

2. Fuzz in a configuration with a known contract violation (Spectre V1):
```bash
./cli.py fuzz -s x86/isa_spec/base.json -i 20 -n 1000 -c tests/test-detection.yaml
```

A violation should be detected within a few minutes, with a message similar to this:

```
================================ Violations detected ==========================
  Contract trace (hash):

    0111010000011100111000001010010011110101110011110100000111010110
  Hardware traces:
   Inputs [907599882]:
    _____^______^______^___________________________________________^
   Inputs [2282448906]:
    ___________________^_____^___________________________________^_^

```

Congratulations, you just found your first Spectre! You can find the violating test case in `generated.asm`.

# Fuzzing Example

To start a real fuzzing campaign, write your own configuration file (see description [here](docs/config.md) and an example config [here](src/tests/big-fuzz.yaml)), and launch the fuzzer.

Below is a example launch command, which will start a 24-hour fuzzing session, with 50 input classes per test case:

```shell
./cli.py fuzz -s x86/isa_spec/base.json -c tests/big-fuzz.yaml -i 50 -n 100000000 --timeout 86400 -w `pwd` --nonstop
```

# Command line interface

The fuzzer is controlled via a single command line interface `cli.py` (located in `src/cli.py`). It accepts the following arguments:

* `-s, --instruction-set PATH` - path to the ISA description file
* `-c, --config PATH` - path to the fuzzing configuration file
* `-n , --num-test-cases N` - number of test cases to be tested
* `-i , --num-inputs N` - number of input classes per test case. The number of actual inputs = input classes * inputs_per_class, which is a configuration option
* `-t , --testcase PATH` - use an existing test case instead of generating random test cases
* `--timeout TIMEOUT` - run fuzzing with a time limit [seconds]
* `--nonstop` - don't stop after detecting a contract violation
* `-w` - working directory where the detected violations will be stored

# Documentation

For more details, see [docs/_main.md](docs/_main.md).

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.