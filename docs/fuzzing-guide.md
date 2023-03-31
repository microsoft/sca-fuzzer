# Guide on running a testing campaign and analyzing a violation

In this guide, we will walk through the process of testing a CPU for unexpected speculative leaks with Revizor.
We will also show how to analyze a contract violation discovered by this campaign.

This example is based on a real testing campaign that led to a discovery of Zero Division Injection, described in [Hide&Seek with Spectres](https://arxiv.org/abs/2301.07642).

## Preparation

We perform a fuzzing campaign in which we test arithmetic operations on an x86-64 CPUs.
As the source of side channel information (i.e., the source of hardware traces), we chose L1D cache.
In other words, this campaign will test the information that arithmetic operations can expose through an L1D cache.

For the sake of this example, let's assume that we do not know of any speculative vulnerabilities that could be triggered by these instructions.
Accordingly, our expected contract is going to be `ct-seq`, a contract that describes cache leakage for non-speculating instructions.

We encode this setup in the following configuration file:
```yaml
instruction_set: x86-64 # target instruction set

# define a pool of tested instructions
instruction_categories:
  - BASE-BINARY  # BINARY is a keyword for arithmetic operations

# by default, Revizor will not generate 64-bit divisions
# we disable this behavior
x86_disable_div64: false

# since we are relying on a cache side channel to collect hardware traces,
# we expect to observe the addresses of loads and stores in the traces,
# as well as the changes in the PC
contract_observation_clause: loads+stores+pc

# we expect to see not speculation in this fuzzing campaign
contract_execution_clause:
  - no_speculation

# use Prime+Probe to collect hardware traces
executor_mode: P+P

# enable some optimization features to make fuzzing faster
enable_speculation_filter: true
enable_observation_filter: true

# by default Revizor adds conditional branches to all test cases
# since we are not interested in branches in this experiment,
# disable them
min_bb_per_function: 1
max_bb_per_function: 1
```

We save the configuration into a file (`config.yaml`) and start a fuzzing campaign.

## Fuzzing Campaign

We start Revizor with the following command:

```shell
./cli.py fuzz -s x86/isa_spec/base.json -c config.yaml -n 100000 -i 100 -w ./results
```

Here
* `-s x86/isa_spec/base.json` - tells Revizor where to find a description of the tested instructions
* `-c config.yaml` - points Revizor to the configuration file described above
* `-n 100000` - number of randomly-generated programs to be tested. Note that 100k programs will be tested only if none of them surfaces a contract violation; otherwise, Revizor will stop as soon as it detects a violation
* `-i 100` - number of inputs per test case
* `-w ./results` - directory where the detected violations will be stored.

After about an hour of fuzzing, Revizor finds a violation, saves the corresponding program into `./results/violation<timestamp>.asm`, and terminates.

The violation on its own is already a sign that something unexpected is going on:
Since we were testing against a contract that does not permit speculation (`no_speculation` in `config.yaml`), this violation indicates that Revizor found a program that speculatively leaks information.
This is a new finding because there has been previously no reports of speculative leaks caused by arithmetic instructions.

## Analyzing The Violation

The next step is to find out what caused this violation.
The program that surfaced a violation looks like this:

```assembly
.intel_syntax noprefix
MFENCE # instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:
JMP .bb_main.0
.bb_main.0:
AND RAX, 0b1111111111111 # instrumentation
LOCK SBB word ptr [R14 + RAX], DX
SUB RAX, -63
NEG BX
INC DL
AND RAX, 0b1111111111111 # instrumentation
LOCK ADC dword ptr [R14 + RAX], -12
AND RBX, 0b1111111111111 # instrumentation
SUB CL, byte ptr [R14 + RBX]
AND RDI, 0b1111111111111 # instrumentation
CMP word ptr [R14 + RDI], -24
CMP RAX, 382711631
AND RBX, 0b1111111111111 # instrumentation
LOCK DEC byte ptr [R14 + RBX]
IMUL CL
SBB AL, -106
CMP RAX, 383545172
AND RBX, 0b1111111111111 # instrumentation
SBB DL, byte ptr [R14 + RBX]
AND RBX, 0b1111111111111 # instrumentation
ADD word ptr [R14 + RBX], -102
AND RBX, 0b1111111111111 # instrumentation
LOCK INC dword ptr [R14 + RBX]
AND RSI, 0b1111111111111 # instrumentation
ADD EDX, dword ptr [R14 + RSI]
SUB AL, 66
OR RBX, 1 # instrumentation
AND RDX, RBX # instrumentation
SHR RDX, 1 # instrumentation
DIV RBX
IMUL ESI, EBX
AND RDX, 0b1111111111111 # instrumentation
MUL dword ptr [R14 + RDX]
AND RAX, 0b1111111111111 # instrumentation
LOCK SBB byte ptr [R14 + RAX], CL
ADC DIL, 32
SBB BL, DL
OR RSI, 1 # instrumentation
AND RDX, RSI # instrumentation
SHR RDX, 1 # instrumentation
DIV RSI
.bb_main.exit:
.test_case_exit:
MFENCE # instrumentation
```
(Note: if you're following along this guide, your detected violation is going to contain a completely different assembly. But don't worry about it, the analysis process is going to be the same.)

This is a randomly-generated sequence of assembly instructions, so if we try to find out the source of the unexpected leakage in it, we will have to put a very considerable effort.
Fortunately, we don't have to do it, as there are several techniques that can significantly simplify the analysis.

### 1. Remove irrelevant instructions from the program

```shell
./cli.py minimize -s x86/isa_spec/base.json -c config.yaml -i /results/violation<timestamp>.asm -o min.asm -n 100
```

It simplifies the program and stores the result into `min.asm`. The result is:

```assembly
.intel_syntax noprefix
MFENCE # instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:
.bb_main.0:
AND RAX, 0b1111111111111 # instrumentation
LOCK SBB word ptr [R14 + RAX], DX
INC DL
AND RBX, 0b1111111111111 # instrumentation
LOCK DEC byte ptr [R14 + RBX]
AND RBX, 0b1111111111111 # instrumentation
SBB DL, byte ptr [R14 + RBX]
OR RBX, 1 # instrumentation
AND RDX, RBX # instrumentation
SHR RDX, 1 # instrumentation
DIV RBX
AND RDX, 0b1111111111111 # instrumentation
MUL dword ptr [R14 + RDX]
AND RAX, 0b1111111111111 # instrumentation
LOCK SBB byte ptr [R14 + RAX], CL
.bb_main.exit:
.test_case_exit:
MFENCE # instrumentation
```

We can further simplify the test case manually, by removing the unused labels (e.g., `bb_main.0`).
Note that `.test_case_enter:` and `.test_case_exit:` have to remain because Revizor's automation scripts use it to define the start and the end of the test case.

As a result, we get a minimal version of the program:

```assembly
.intel_syntax noprefix
MFENCE # instrumentation
.test_case_enter:
AND RAX, 0b1111111111111 # instrumentation
LOCK SBB word ptr [R14 + RAX], DX
INC DL
AND RBX, 0b1111111111111 # instrumentation
LOCK DEC byte ptr [R14 + RBX]
AND RBX, 0b1111111111111 # instrumentation
SBB DL, byte ptr [R14 + RBX]
OR RBX, 1 # instrumentation
AND RDX, RBX # instrumentation
SHR RDX, 1 # instrumentation
DIV RBX
AND RDX, 0b1111111111111 # instrumentation
MUL dword ptr [R14 + RDX]
AND RAX, 0b1111111111111 # instrumentation
LOCK SBB byte ptr [R14 + RAX], CL
.test_case_exit:
MFENCE # instrumentation
```

To make sure that we didn't make a mistake while modifying the program, we can verify the result by reproducing the violation:

```shell
./cli.py fuzz -s x86/isa_spec/base.json -c config.yaml -t min.asm -i 100
```

### 2. Add speculation fences to narrow down the part of the program that causes leakage

```shell
./cli.py minimize -s x86/isa_spec/base.json -c config.yaml -i min.asm -o min.asm -n 100 --add-fences
```

This command iteratively attempts to add an `LFENCE` before every instruction in the program while checking if the violation persists. The result is:

```assembly
.intel_syntax noprefix
MFENCE # instrumentation
.test_case_enter:
LFENCE
AND RAX, 0b1111111111111 # instrumentation
LFENCE
LOCK SBB word ptr [R14 + RAX], DX
AND RBX, 0b1111111111111 # instrumentation
LOCK DEC byte ptr [R14 + RBX]
AND RBX, 0b1111111111111 # instrumentation
SBB DL, byte ptr [R14 + RBX]
OR RBX, 1 # instrumentation
AND RDX, RBX # instrumentation
SHR RDX, 1 # instrumentation
DIV RBX
AND RDX, 0b1111111111111 # instrumentation
MUL dword ptr [R14 + RDX]
AND RAX, 0b1111111111111 # instrumentation
LOCK SBB byte ptr [R14 + RAX], CL
.test_case_exit:
MFENCE # instrumentation
```

Only two fences were inserted, after `.test_case_enter:` and after `AND RAX, 0b1111111111111`.
It means that all the remaining instructions are somehow involved in the speculative leak (although we cannot yet tell how exactly).


### 3. Use the statistics reported by Revizor to find the specific instruction that triggers speculation

At this point, we start making manual changes to the program.
We go through the program, try removing instructions one at a time, execute the modified program on Revizor, and check the statistic from the speculation filter.

For example, let's say we start from the bottom.
We first try to remove the last line (`LOCK SBB byte ptr [R14 + RAX], CL`), and execute the program on Revizor:
```shell
./cli.py fuzz -s x86/isa_spec/base.json -c config.yaml -t min.asm -i 100

INFO: [fuzzer] Starting at 17:16:52
0     ( 0%)| Stats:
================================ Statistics ===================================
Test Cases: 1
Inputs per test case: 200.0
Flaky violations: 0
Required priming: 0
Violations: 0
Effectiveness:
  Effectiveness: 1.0
  Total Cls: 20.0
  Effective Cls: 20.0
Filters:
  Speculation Filter: 1
  Observation Filter: 1
```

Even though Revizor did not report a violation, the line `Speculation Filter: 1` tells us that Revizor detected some speculation. Accordingly, we deduce that the instruction we removed (`LOCK SBB`) is *not* the source of speculation.

We continue the process with one instruction at a time, and we see the same result with the next three instructions (`AND`, `MUL`, and `AND`).
However, when we try removing `DIV` from the program, we Revizor produces the following output:

```shell
================================ Statistics ===================================
Test Cases: 1
Inputs per test case: 200.0
Flaky violations: 0
Required priming: 0
Violations: 0
Effectiveness:
  Effectiveness: 0.0
  Total Cls: 0.0
  Effective Cls: 0.0
Filters:
  Speculation Filter: 0
  Observation Filter: 0
```

The line `Speculation Filter: 0` tells us that Revizor did not detect any speculation while executing the version of the program without `DIV`. It means that this division was the source of speculative leakage.

### 4. TO BE CONTINUED...
