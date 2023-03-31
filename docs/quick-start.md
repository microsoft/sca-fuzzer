# Quick Start Guide

## 1. Testbed

Get yourself a machine for testing: Revizor can test x86-64 CPUs, Intel or AMD.
You will need a Linux installation running directly on the hardware (testing from within a VM is not supported).

## 2. Installation

Follow the installation instructions on [this page](install.md).

## 3. Baseline Testing

Try running Revizor in a simple, violation-free configuration:

```bash
./cli.py fuzz -s x86/isa_spec/base.json -i 50 -n 100 -c tests/test-nondetection.yaml
```

This command should terminate with no output.

## 4. Simile Detection

Try starting detecting a contract violation with Revizor:


```bash
./cli.py fuzz -s x86/isa_spec/base.json -i 20 -n 1000 -c tests/test-detection.yaml -w .
```

This command will test the CPU against a contract that completely forbids speculation.
As your CPU under test almost definitely implements at least some form of speculation, Revizor should detect a violation within a few minutes, with a message similar to this:

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

## 5. Start Real Fuzzing

Write your own configuration file (see description [here](config.md) and an example config [here](https://github.com/microsoft/sca-fuzzer/tree/main/src/tests/big-fuzz.yaml)), and launch the fuzzer.

Below is a example launch command, which will start a 24-hour fuzzing session, with 100 input classes per test case:

```shell
./cli.py fuzz -s x86/isa_spec/base.json -c tests/big-fuzz.yaml -i 100 -n 100000000 --timeout 86400 -w `pwd` --nonstop
```

When you find a violation, you will have to do some manual investigation to understand the source of it;
[this guide](fuzzing-guide.md) is an example of how to do such an investigation.
