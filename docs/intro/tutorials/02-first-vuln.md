# Tutorial 2: Detecting Your First Vulnerability

This tutorial is the first step into actual vulnerability detection. You'll learn how to set up a fuzzing campaign that tests conditional branches. And, most likely, it will end with a detection of Spectre V1.

### Testing Workflow

Before we begin with actual testing, let's take a step back and consider how a typical testing workflow looks like.

The process of using Revizor normally constitutes of the following steps:

1. **Design the campaign** by selecting which instructions to test and choosing an appropriate contract that defines what behavior we consider a violation.
2. **Create a configuration file** that captures these decisions.
3. **Run the fuzzer** to generate and execute random test cases.
4. **Validate the violation** to ensure it's genuine and not a false positive.
5. **Minimize the test case** to remove unnecessary complexity, making it easier to understand.
6. **Analyze the minimized program** to identify the root cause of the vulnerability.

In the following, we will go step-by-step through this workflow.

### Plan the campaign

Let's imagine we have a new CPU and want to determine if conditional branches produce any information leakage on it. These instructions are infamous for causing Spectre V1, therefore it is always useful to start with them when testing a new CPU.

The first step is planning our fuzzing campaign strategically.

For effective testing, we'll focus on a minimal instruction subset rather than the entire ISA. Spectre V1 requires only two capabilities: conditional branches (to trigger misprediction) and memory accesses (to leak information through side channels). By limiting our instruction set to just arithmetic operations and conditional branches, we accomplish two goals. First, the fuzzer will find violations faster because there are fewer instruction combinations to explore. Second, when we do find a violation, it will be much easier to analyze because the test case will be simpler.

!!! warning
    Note that this focused approach is *not* representative of a real fuzzing campaign. This tutorial is intentionally simplified to help with understanding. In a real campaign, you'll need to find balance between having a broad scope (increases changes of finding unknown vulnerabilities) and having focus on specific CPU features (simplifies root-cause analysis). For more guidance on campaign design, see [How to Design a Fuzzing Campaign](../../howto/design-campaign.md).

We'll pair this minimal instruction set with the strictest possible contract—one that forbids any speculation whatsoever. This means Revizor will flag any speculative behavior as a violation. While this contract is more restrictive than what modern CPUs actually guarantee, it's perfect for our purposes. Since we're only testing conditional branches and simple arithmetic, any speculation we detect will almost certainly be Spectre V1.

With this campaign plan, we are trying to answer a specific question: "Does this CPU leak information through conditional branches?"

### Create the configuration file

Now that we've planned our campaign, let's translate it into a configuration file. Create a YAML file with the following content:

```yaml
# tested instructions
instruction_categories:
  - BASE-BINARY
  - BASE-COND_BR

# contract
contract_observation_clause: loads+stores+pc
contract_execution_clause:
  - no_speculation

# enable perf. optimizations
enable_speculation_filter: true
enable_observation_filter: true
enable_fast_path_model: true
```

The `instruction_categories` section implements our decision to use a minimal instruction set. We're including `BASE-BINARY` for arithmetic operations like addition and comparison, and `BASE-COND_BR` for conditional branches like `jz` and `jne`. These two categories give the fuzzer everything it needs to express Spectre V1 patterns.

The contract configuration consists of two clauses. The `contract_observation_clause` tells Revizor what microarchitectural side effects to track. We're using `loads+stores+pc`, which observes memory access addresses and the program counter—exactly what an attacker would monitor through cache timing attacks. The `contract_execution_clause` defines what execution behavior is allowed. By setting it to `no_speculation`, we're telling Revizor that any speculative execution is a violation.

The performance optimization flags at the bottom significantly speed up fuzzing without affecting correctness. The `enable_speculation_filter` skips test cases that don't trigger speculation at all. The `enable_observation_filter` skips test cases that leave no observable traces. The `enable_fast_path_model` allows Revizor to reuse contract traces across similar inputs, reducing the model execution overhead.

For a complete reference of all configuration options, see the [Configuration Reference](../../ref/config.md).

### Run the fuzzer

Now we're ready to start fuzzing. Run Revizor with the following command:

```
./revizor.py fuzz -s base.json -c config.yaml -n 1000 -i 10 -w .
```

This command tells Revizor to run 1000 test cases (`-n 1000`), with 10 inputs per test case (`-i 10`), using the ISA specification from `base.json` (`-s`) and our configuration file (`-c`). The `-w .` flag tells Revizor to save any violations it finds to the current directory.

As the fuzzer runs, you'll see a continuously updating progress line:

```
50    ( 5%)| Stats: Cls:10/10,In:20,R:7,SF:38,OF:6,Fst:6,CN:0,CT:0,P1:0,CS:0,P2:0,V:0
```

### View the detected violation

After a minute or so, you should see a violation.
It will be reported in a format similar to this:

```
================================ Violations detected ==========================
Violation Details:

-----------------------------------------------------------------------------------
                             HTrace                              | ID:4   | ID:14 |
-----------------------------------------------------------------------------------
^......^...^........^.................^...........^............. | 626    | 0     |
^......^...^........^........................................... | 1      | 18    |
^^.....^...^........^....^...................................... | 0      | 609   |

```

Excellent! We've successfully detected a contract violation. Let's understand what this violation report is telling us.


The report shows us the violation details in a table format. The header row displays the input IDs that triggered the violation—in this case, inputs 4 and 14:

`| ID:4   | ID:14 |`

These are two inputs from our test case that the contract predicted would behave identically, but the hardware traces show they behaved differently.

The three rows below show the different hardware traces that were observed:

```
^......^...^........^.................^...........^.............
^......^...^........^...........................................
^^.....^...^........^....^......................................
```

Each row represents a distinct cache access pattern, visualized as a bitmap where `^` marks an accessed cache line and `.` marks an untouched cache line. We're using Prime+Probe cache side channel measurements (default), so each position in the bitmap corresponds to one of the 64 cache sets in the L1D cache. (A cache set is a group of cache lines that compete for the same position in the cache—when the CPU accesses memory at a particular address, the data goes into a specific cache set determined by the address bits.)

For example, the first trace reads like this:

```
Cache Set 0 accessed
|          Cache Set 11 accessed
|          |                          Cache set 38 accessed
|          |                          |
^......^...^........^.................^...........^.............
       |            |                             |
       |            |                             Cache Set 50 accessed
       |            Cache Set 20 accessed
       Cache Set 7 accessed
```

Finally, the numbers in the columns tell us how often each trace appeared for each input:

```
... | 626    | 0     |
... | 1      | 18    |
... | 0      | 609   |
```

Looking at the first hardware trace we see it appeared 626 times for input 4 but never for input 14. The third trace shows the opposite pattern—0 times for input 4 but 609 times for input 14. This clear separation in the distributions confirms this is a genuine violation, not random noise.

What we're seeing is a data-dependent cache access pattern. The test case accessed different cache lines depending on the input data, creating an observable side channel. We don't know yet what caused this channel, but we can already tell that it's likely to be caused by speculation; non-speculative cache accesses are permitted by our reference contract, so they wouldn't be reported as violations.

For more details on interpreting violation reports, see [How to Interpret Violation Results](../../howto/interpret-results.md).

### Violation Artifact

The artifact for this violation is stored in a directory named `violation-<timestamp>`:

```bash
$ ls -l violation-251203-103338
input_0000.bin  input_0004.bin  input_0008.bin  input_0012.bin  input_0016.bin  minimize.yaml    reproduce.yaml
input_0001.bin  input_0005.bin  input_0009.bin  input_0013.bin  input_0017.bin  org-config.yaml
input_0002.bin  input_0006.bin  input_0010.bin  input_0014.bin  input_0018.bin  program.asm
input_0003.bin  input_0007.bin  input_0011.bin  input_0015.bin  input_0019.bin  report.txt
```

The `program.asm` file holds the test case program that triggered the violation. The `input_*.bin` files contain the input sequence that exposed the leak. The `report.txt` file provides additional details including hardware and contract traces. The configuration files include `org-config.yaml` (the original configuration), `reproduce.yaml` (for reproducing the violation), and `minimize.yaml` (for test case minimization).

### Validate the violation

Let's verify this violation is genuine and reproducible. First, we'll move the violation artifacts to a simpler path:

```bash
mv violation-251203-103338 ./violation
```

Now we'll reproduce the violation using the saved artifacts:

```bash
./revizor.py reproduce -s base.json -c ./violation/reproduce.yaml -t ./violation/program.asm -i ./violation/input*.bin
```

If the violation is genuine, we should see Revizor report it again:

```
================================ Violations detected ==========================
Violation Details:

-----------------------------------------------------------------------------------
                             HTrace                              | ID:4   | ID:14 |
-----------------------------------------------------------------------------------
^......^...^........^.................^...........^............. | 626    | 0     |
^......^...^........^........................................... | 1      | 20    |
^^.....^...^........^....^...................................... | 0      | 607   |
```

Perfect! The hardware traces are roughly the same as before, confirming this is a stable, reproducible violation.

!!! tip "Dealing with False Positives"
    In most cases, violations are genuine. However, if you're on a high-noise system, you might occasionally see non-reproducible violations. If this happens, adjust the noise tolerance by increasing `analyser_stat_threshold` or `executor_sample_sizes` in your configuration file (see the [Configuration Reference](../../ref/config.md) for details), then rerun the fuzzer. Also, consider trying to mitigate the noise, for example by disabling hyperthreading or by turning prefetchers off.


### Minimize the test case

Now that we've confirmed the violation is real, let's simplify it for easier analysis. The minimizer will systematically remove unnecessary instructions while keeping the violation reproducible.

Use the following command. We won't go into it's details now as they are irrelevant to this tutorial. If you're curious, check our [How to Minimize](../../howto/minimize.md) guide.

```bash
./revizor.py minimize -s base.json \
    -c ./violation/minimize.yaml -t ./violation/program.asm \
    -o ./violation/min.asm -i 10 --num-attempts 3 \
    --enable-instruction-pass 1 \
    --enable-simplification-pass 1 \
    --enable-nop-pass 1 \
    --enable-constant-pass 1 \
    --enable-mask-pass 1 \
    --enable-label-pass 1
```

We'll see the minimization progress as it works through multiple passes:

```
[PASS 1] Reproducing the violation
  > Violation reproduced. Proceeding with minimization
  > Violating input IDs: [4, 14]
[INFO] Minimization attempt 1/3
[PASS 2] Instruction Removal Pass

........---...--
[PASS 3] Instruction Simplification Pass

--..-
[PASS 4] NOP Replacement Pass

(and so on...)
```

This process typically takes 5-10 minutes. Each `.` indicates a failed removal attempt (the violation disappeared), while each `-` shows a successful simplification (the violation persisted with fewer instructions). After it finishes, we'll find the minimized program in `./violation/min.asm`.

``` asm
.intel_syntax noprefix
.section .data.main
.function_0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
add al, -118 # instrumentation
and rdi, 0b1111111111100 # instrumentation
adc al, byte ptr [r14 + rdi]
mov rax, -1332388169
imul eax, eax, -75
and rcx, 0b1111111111000 # instrumentation
add dword ptr [r14 + rcx], eax
and rax, 0b1111111111000 # instrumentation
imul qword ptr [r14 + rax]
and rcx, 0b1111111000000 # instrumentation
lock inc qword ptr [r14 + rcx]
and rdi, 0b1111111111000 # instrumentation
add byte ptr [r14 + rdi], al
sub dl, al
jp .bb_0.1
jmp .exit_0
.bb_0.1:
and rbx, 0b1111111111000 # instrumentation
cmp dword ptr [r14 + rbx], eax
and rdi, 0b1111111111000 # instrumentation
cmp qword ptr [r14 + rdi], rbx
and rbx, 0b1111111000000 # instrumentation
lock sub word ptr [r14 + rbx], dx
and rbx, 0b1111111111000 # instrumentation
dec word ptr [r14 + rbx]
and rsi, 0b1111111111000 # instrumentation
neg qword ptr [r14 + rsi]
and rbx, 0b1111111111000 # instrumentation
adc ax, word ptr [r14 + rbx]
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
.section .data.main
.test_case_exit:nop
```

Let's verify the minimized program still triggers the violation:

``` bash
$ ./revizor.py reproduce -s base.json -c ./violation/reproduce.yaml -t ./violation/min.asm -i ./violation/input*.bin

INFO: [prog_gen] Setting program_generator_seed to random value: 112509

INFO: [fuzzer] Starting at 11:04:52
> Entering slow path...> Priming  1             > Increasing sample size... to 50> Increasing sample size... to 100> Increasing sample size... to 500> Priming  1

================================ Violations detected ==========================
Violation Details:

-----------------------------------------------------------------------------------
                             HTrace                              | ID:5   | ID:15 |
-----------------------------------------------------------------------------------
^^................^..^.......................................... | 404    | 15    |
^^.........^....^.^..^.......................................... | 223    | 0     |
^^................^..^.......^....................^............. | 0      | 612   |
```

Excellent! The violation still reproduces with the minimized program. We've successfully reduced the test case while preserving the vulnerability.

The program is still fairly complex, though. Let's run input minimization to identify exactly which values are being leaked.

### Analyze the leak through input minimization

```bash
$ revizor ./revizor.py minimize -s base.json -c ./violation/minimize.yaml -t ./violation/min.asm -o ./violation/min.asm -i 25  --input-outdir ./violation/min-inputs \
    --enable-input-diff-pass 1 \
    --enable-input-seq-pass 1 \
    --enable-instruction-pass false
```

Among other information, the minimizer prints the leaked values:

```
  > Minimizing the difference between inputs 2 and 3

Address    +0x0     +0x40    +0x80    +0xc0    +0x100   +0x140   +0x180   +0x1c0
0x00000000 ........ ....=... ........ ........ ........ ........ ........ ........
0x00000200 ........ ........ ........ ........ ........ ........ ........ ........
0x00000400 ........ ........ ........ ........ ........ ........ ........ ........
0x00000600 ........ ........ ........ ........ ........ ........ ........ ........
0x00000800 ........ ........ ........ ........ ........ ........ ........ ........
0x00000a00 ........ ........ ........ ........ ........ ........ ........ ........
0x00000c00 ........ ........ ........ ........ ........ ........ ........ ........
0x00000e00 ........ ........ ........ ........ ........ ........ ........ ........
0x00001000 ........ ........ ........ ........ ........ ........ ........ ........
0x00001200 ........ ........ ........ ........ ........ ........ ........ ........
0x00001400 ........ ........ ........ ........ ........ ........ ........ ........
0x00001600 ........ ........ ........ ........ ........ ........ ........ ........
0x00001800 ........ ........ ........ ........ ........ ........ ........ ........
0x00001a00 ........ ........ ........ ........ ........ ........ ........ ........
0x00001c00 ........ ........ ........ ........ ........ ........ ........ ........
0x00001e00 ........ ........ ........ ........ ........ ........ ........ ........
0x00002000 ....^...
0x00002040 ........ ........ ........ ........
  > Result: Leaked 1 bytes
  > Addresses: ['0x2020']
```

There are two bits of information that we learn from here:

- Most of the input has been successfully zeroed-out (`.`). This means it is likely irrelevant to the leak.
- The only non-zero byte is at address `0x2020` (marked with `^`). This is likely the leaked byte.

To understand how this address maps to the test case, we need to look at the layout of the input: [here](../../ref/artifact-file-formats.md). We can see that the leak is within the GPR region of actor 0 (the only actor in this test case). Specifically, 0x2020 - 0x2000 = 0x20, is the offset used to initialize RSI (GPRs are ordered as: `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `flags`, `rsp`).

Now we just need to find how the test case uses RSI (possibly speculatively), and we will have a good idea of the root-cause of the leak.

Let's inspect the minimized program in `./violation/min.asm`:

``` asm linenums="1"
.intel_syntax noprefix
.section .data.main
.function_0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
add al, -118
and rdi, 0b1111111111100
adc al, byte ptr [r14 + rdi]
# mem access: [5] 0x1578 cl 21:56 | [15] 0x1578 cl 21:56
mov rax, -1332388169
imul eax, eax, -75
and rcx, 0b1111111111000
add dword ptr [r14 + rcx], eax
# mem access: [5] 0x2498-0x2498 cl 18:24 | [15] 0x2498-0x2498 cl 18:24
and rax, 0b1111111111000
imul qword ptr [r14 + rax]
# mem access: [5] 0x1060 cl 1:32 | [15] 0x1060 cl 1:32
and rcx, 0b1111111000000
lock inc qword ptr [r14 + rcx]
# mem access: [5] 0x2480-0x2480 cl 18:0 | [15] 0x2480-0x2480 cl 18:0
and rdi, 0b1111111111000
add byte ptr [r14 + rdi], al
# mem access: [5] 0x1578-0x1578 cl 21:56 | [15] 0x1578-0x1578 cl 21:56
sub dl, al
jp .bb_0.1
jmp .exit_0
.bb_0.1:
and rbx, 0b1111111111000
cmp dword ptr [r14 + rbx], eax
and rdi, 0b1111111111000
cmp qword ptr [r14 + rdi], rbx
and rbx, 0b1111111000000
lock sub word ptr [r14 + rbx], dx
and rbx, 0b1111111111000
dec word ptr [r14 + rbx]
and rsi, 0b1111111111000
neg qword ptr [r14 + rsi] # <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< HERE: RSI is used here
and rbx, 0b1111111111000
adc ax, word ptr [r14 + rbx]
.exit_0:
.macro.measurement_end: nop qword ptr [rax + 0xff]
.section .data.main
.test_case_exit:nop
```

We can see that RSI is used in the instruction at line 36:

``` asm
neg qword ptr [r14 + rsi]
```

That already gives most of the information we need. We can see a clear Spectre V1 pattern here:

1. There is a conditional branch at line 24 (`jp .bb_0.1`)
2. And a load of a previously-unused value on a mispredicted path (line 36)

To verify that, let's inspect the actual value of RSI in the violating inputs (inputs 2 and 3 according to the minimizer output above). We can use `hexdump` for that:

``` bash
$ hexdump -C ./violation/min-inputs/min_input_0002.bin | grep 2020
00002020  93 22 00 00 93 22 00 00  00 00 00 00 00 00 00 00  |."..."..........|
$ hexdump -C ./violation/min-inputs/min_input_0003.bin | grep 2020
00002020  40 00 00 00 40 00 00 00  00 00 00 00 00 00 00 00  |@...@...........|
```

So the value of RSI were:

- Input 2: `rsi=0x0000229300002293`
- Input 3: `rsi=0x0000004000000040`

These values were masked by the instruction at line 35:

``` asm
and rsi, 0b1111111111000 # instrumentation
```

Which means that the values of RSI used in memory accesses at line 36 were:

- Input 2: `0x0000229300002293 & 0b1111111111000 = 0x290`
- Input 3: `0x0000004000000040 & 0b1111111111000 = 0x040`

All memory accesses within the test case are relative to `r14`, which is page-aligned and points to the base of the sandbox memory.

Therefore, we can calculate the ID of the cache lines accessed by the instruction at line 36 as follows:

- Input 2: cache line ID = `0x290 // 0x40 = 0xa = 10`
- Input 3: cache line ID = `0x040 // 0x40 = 0x1 = 1`

So, if our hypothesis is correct, we should see that in the hardware trace of the violation, cache lines 10 and 1 were accessed when executing inputs 2 and 3. Let's verify it by running rvzr in the reproduce mode:

```
$ ./revizor.py reproduce -s base.json -c ./violation/reproduce.yaml -t ./violation/min.asm -i ./violation/min-inputs/min_input_*.bin

-----------------------------------------------------------------------------------
                             HTrace                              | ID:2   | ID:3  |
-----------------------------------------------------------------------------------
^^........^..................................................... | 626    | 0     |
^^.............................................................. | 1      | 627   |

```

The first hardware trace (dominant for input 2) is:

```
^^........^.....................................................
||        |
||        Cache set 10 accessed
|Cache set 1
Cache set 0 accessed
```

The second hardware trace (dominant for input 3) is:

```
^^..............................................................
||
| Cache set 1 accessed
Cache set 0 accessed
```

Indeed, we see that our hypothesis is correct! The instruction at line 36 accessed different cache lines depending on the value of RSI, which was influenced by speculative execution after the conditional branch at line 24.

This tells us that the root-cause of the leak was misprediction of a conditional branch that led to speculative leak of a value (RSI) through a data access.

### Summary

Congratulations! We've successfully detected and analyzed a Spectre V1 vulnerability from start to finish.

!!! success "What We've Learned"
    In this section, we've walked through the complete workflow for detecting speculative execution vulnerabilities:

    - **Strategic planning**: Choosing a minimal instruction set and appropriate contract focused our search
    - **Violation detection**: Revizor found the vulnerability automatically in under two minutes
    - **Validation**: Reproduction confirmed the violation was genuine and stable
    - **Minimization**: We reduced a complex test case to its essential components
    - **Root-cause analysis**: By examining register values and cache access patterns, we identified the exact mechanism of the leak

    This same workflow applies to discovering and analyzing any speculative execution vulnerability.

### What's Next?

Proceed to [Tutorial 3](./03-faults.md) to see how the same principles can be applied to detect more complex vulnerabilities based on CPU exceptions and faults.
