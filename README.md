# SCA-Fuzzer

This is SCA-Fuzzer, a different kind of fuzzer.
Instead of finding bugs in programs, SCA-Fuzzer searches for microarchitectural bugs in CPUs.

What is a bug in a CPU?
In the context of SCA-Fuzzer, a bug is a violation of out expectations about how the CPU should behave.
The most prominent examples would be [Spectre](https://spectreattack.com/) and [Meltdown](https://meltdownattack.com/).
It could also be a microarchitectural backdoor or an unknown optimization, although we yet to encounter one of those.

See our ~~[Technical Report]~~ (under construction) for details.


**Origin**: This is an independently developed and much improved fork of [SCA-Fuzzer from Microsoft][https://github.com/microsoft/sca-fuzzer].

# Getting Started

**UNDER CONSTRUCTION**

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
