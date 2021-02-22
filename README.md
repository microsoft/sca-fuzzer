# SCA-Fuzzer

This is SCA-Fuzzer, a different kind of fuzzer.
Instead of finding bugs in programs, SCA-Fuzzer searches for microarchitectural bugs in CPUs.

What is a bug in a CPU?
In the context of SCA-Fuzzer, a bug is a violation of out expectations about how the CPU should behave.
The most prominent examples would be [Spectre](https://spectreattack.com/) and [Meltdown](https://meltdownattack.com/).
It could also be a microarchitectural backdoor or an unknown optimization, although we are yet to encounter one of those.

See our ~~[Technical Report]~~ (under construction) for details.


**Origin**: This is an independently developed and improved fork of [SCA-Fuzzer from Microsoft](https://github.com/microsoft/sca-fuzzer).

# Getting Started

Below are quick-and-dirty instructions on how to use SCA-Fuzzer.
More detailed instructions will be added some time later.

**Warning**: SCA-Fuzzer executes randomly generated code in kernel space.
As you can imagine, things can go wrong.
Usually they don't, but sometimes they do.
So, make sure you're not running these experiments on an important machine.

0. Requirements:
   * Linux v5.6+ (tested on Linux v5.6.6-300 and v5.6.13-100; there is a good chance it will work on other versions as well, but it's not guaranteed).
   * Linux Kernel Headers
   * Python 3.7+
   * [Unicorn 1.0.2+](https://www.unicorn-engine.org/docs/)
   * [PyYAML](https://pyyaml.org/wiki/PyYAMLDocumentation)
   * For tests: [Bash Automated Testing System](https://bats-core.readthedocs.io/en/latest/index.html)
    
1. Get dependencies:

```bash
git submodule init
git submodule update
cp src/executor/x86/base.xml instruction_sets/x86
```

2. Install the x86 executor:

```bash
cd src/executor/x86 
sudo rmmod x86-executor
make clean
make
sudo insmod x86-executor.ko
```

3. Test it:

```bash
cd src/
./tests/run.bats
```

If some of the "Detection" tests fail, it's fine, you might just have a slightly different microarchitecture. But if other tests fail - something is broken.

4. Fuzz it:

This one should not detect any violations and should take a few minutes to run:

```bash
cd src/
./cli.py fuzz -s instruction_sets/x86/base.xml -i 1000 -n 10 -v -c ../evaluation/1_fuzzing_main/bm-bpas.yaml
```

5. Find your first Spectre!

This one should not detect a violations within several minutes.
The detected violation is most likely an instance of Spectre V1.

```bash
cd src/
./cli.py fuzz -s instruction_sets/x86/base.xml -i 100 -n 1000 -v -c ../evaluation/fast-spectre-v1.yaml
```

You can find the test case that triggered this violation in `src/generated.asm`.



# Interfaces and Architecture

![architecture](Arch.png)

**THE TEXT BELOW IS UNDER CONSTRUCTION. PROCEED WITH CAUTION**


## Instruction Set Spec
This XML file: https://www.uops.info/xml.html originating from Intel XED (https://intelxed.github.io/)

Received from: `--instruction-set` (or `-s`) CLI argument.
Passed down to: `Generator.__init__`


## Generator Initializer
None so far.

In future, may include test case templates, grammar, etc.

## Test Case
An assembly file. Currently, in Intel syntax.

Received from: `self.generator.create_test_case()` + `self.generator.materialize(filename)`
Passed down to: `model.load_test_case` and `executor.load_test_case`


## Inputs
Currently, each input is a single 32-bit integer, used later as a PRNG seed inside the test case to initialize memory and registers.
Inputs are generated in batches; that is, Input Generator returns `List[int]`.

Received from: `input_gen.generate(...)`
Passed down to: `model.trace_test_case(inputs)` and `executor.trace_test_case(inputs)`.
