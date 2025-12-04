# Tutorial 2: Detecting Your First Vulnerability (Part 3)

This tutorial picks up where [part 2](part2.md) left off. We will minimize and root-cause the violation.

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

Proceed to [Tutorial 3](../tutorial3-faults/part1.md) to see how the same principles can be applied to detect more complex vulnerabilities based on CPU exceptions and faults.
