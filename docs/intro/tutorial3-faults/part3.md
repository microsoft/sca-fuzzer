# Tutorial 3: Testing faults with Revizor (Part 3)

This tutorial picks up where [part 2](part2.md) left off. We will minimize and root-cause the violation.

### Minimize the test case

Now we minimize the test case to make it easier to analyze:

```
./revizor.py minimize -s base.json -c ./violation/minimize.yaml -t ./violation/program.asm  -o ./violation/min.asm -i 10 --num-attempts 3 \
    --enable-instruction-pass 1 \
    --enable-simplification-pass 1 \
    --enable-nop-pass 1 \
    --enable-constant-pass 1 \
    --enable-mask-pass 1 \
    --enable-label-pass 1
```

After the minimization completes, verify that the minimized program still reproduces the violation:

```
./revizor.py reproduce -s base.json -c ./violation/reproduce.yaml -t ./violation/min.asm -i ./violation/input*.bin

INFO: [prog_gen] Setting program_generator_seed to random value: 578824

INFO: [fuzzer] Starting at 12:14:08
> Entering slow path...> Priming  6             > Increasing sample size... to 50> Increasing sample size... to 100> Increasing sample size... to 500> Priming  6

================================ Violations detected ==========================
Violation Details:

-----------------------------------------------------------------------------------
                             HTrace                              | ID:11  | ID:31 |
-----------------------------------------------------------------------------------
^^.^.......^...^........^.........................^...^........^ | 627    | 0     |
^^.^.......^...^........^.........................^............^ | 0      | 627   |
```

### Identify the leaked value

Next, we minimize the inputs to identify which specific values are being leaked:

```
./revizor.py minimize -s base.json -c ./violation/minimize.yaml -t ./violation/min.asm -o ./violation/min.asm -i 10 --input-outdir ./violation/min-inputs \
    --enable-input-diff-pass 1 \
    --enable-input-seq-pass 1 \
    --enable-comment-pass 1 \
    --enable-instruction-pass false

(skipping output for brevity)
  > Minimizing the difference between inputs 0 and 1

Address    +0x0     +0x40    +0x80    +0xc0    +0x100   +0x140   +0x180   +0x1c0
0x00000000 ........ ........ ........ ........ ........ ........ ........ ........
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
0x00002000 ..=.=^..
0x00002040 ........ ........ ........ ........
  > Result: Leaked 1 bytes
  > Addresses: ['0x2028']
  > Saving new inputs in '/home/t-oleksenkoo/revizor/violation/min-inputs'
  > Violating input IDs: [5, 15]
```

Key takeaways:

- The leaked value originates from address `0x2028` in the input, which corresponds to offset `0x28` in the GPR initialization region of the sandbox memory, used to initialize the `RDI` register.
- Two other values in the input were not zeroed out, which indicates they are somehow relevant to triggering the violation. Namely, those are offsets `0x10` and `0x20`, which correspond to `RCX` and `RSI`.

### Perform root-cause analysis

With the minimized program and inputs, we can now investigate the root cause. The minimized program is as follows:

``` asm linenums="1"
.intel_syntax noprefix
.section .data.main
.function_0:
.macro.measurement_start: nop qword ptr [rax + 0xff]
and rsi, 0b1111111111000 # instrumentation
add rdi, qword ptr [r14 + rsi]
add cl, dl
and rcx, 0b1111111111000 # instrumentation
add qword ptr [r14 + rcx], rbx
and rbx, 0b1111111111000 # instrumentation
add dword ptr [r14 + rbx], ecx
and rax, 0b1111111111000 # instrumentation
cmp dword ptr [r14 + rax], ecx
and rdi, 0b1111111111000 # instrumentation
or byte ptr [r14 + rdi], 1 # instrumentation  # <<<<<<<<<<<<<<< HERE: RDI is used here
mov ax, 1 # instrumentation
div byte ptr [r14 + rdi]                      # <<<<<<<<<<<<<<< HERE: RDI is used here
and rsi, 0b1111111111000 # instrumentation
sub byte ptr [r14 + rsi], bl
and rcx, 0b1111111111000 # instrumentation
sub al, byte ptr [r14 + rcx]
and rcx, 0b1111111111000 # instrumentation
mul qword ptr [r14 + rcx]
and rax, 0b1111111000000 # instrumentation
lock sub word ptr [r14 + rax], -128
.macro.measurement_end: nop qword ptr [rax + 0xff]
.section .data.main
.test_case_exit:nop
```

RDI is used in two places:

1. Line 15: `or byte ptr [r14 + rdi], 1` (a write)
2. Line 17: `div byte ptr [r14 + rdi]` (a read)

This is a clear data-dependent pattern, which explains why RDI is being leaked. But normally, these patterns should not be reported as violations of CT-DEH (our selected contract), since the contract permits cache-based leakage. So if the violation was reported, it means these instructions were not executed in the model. Let's investigate why.

We will inspect how the model executes this program. To this end, we will add a debug flag to the config file:

```yaml
logging_modes:
    - dbg_model
```

Then, we will reproduce the violation again, now with a verbose log of test case execution on the model:

```
./revizor.py reproduce -s base.json -c ./violation/reproduce.yaml -t ./violation/min.asm -i ./violation/min-inputs/min_input_0000.bin

                     ##### Input 0 #####
0x0 : macro .measurement_start, .noarg
  rax=0x0000000000000000 rbx=0x0000000000000000 rcx=0x0000d04a0000d04a rdx=0x0000000000000000
  rsi=0x0000d0510000d051 rdi=0x000056b8000056b8 flags=0b000000000010
  xmm0=0x00000000000000000000000000000000 xmm1=0x00000000000000000000000000000000
  xmm2=0x00000000000000000000000000000000 xmm3=0x00000000000000000000000000000000
  xmm4=0x00000000000000000000000000000000 xmm5=0x00000000000000000000000000000000
  xmm6=0x00000000000000000000000000000000 xmm7=0x00000000000000000000000000000000

0x8 : and rsi, 0b1111111111000
  rax=0x0000000000000000 rbx=0x0000000000000000 rcx=0x0000d04a0000d04a rdx=0x0000000000000000
  rsi=0x0000d0510000d051 rdi=0x000056b8000056b8 flags=0b000000000010
  xmm0=0x00000000000000000000000000000000 xmm1=0x00000000000000000000000000000000
  xmm2=0x00000000000000000000000000000000 xmm3=0x00000000000000000000000000000000
  xmm4=0x00000000000000000000000000000000 xmm5=0x00000000000000000000000000000000
  xmm6=0x00000000000000000000000000000000 xmm7=0x00000000000000000000000000000000

0xf : add rdi, [r14 +rsi]
  rax=0x0000000000000000 rbx=0x0000000000000000 rcx=0x0000d04a0000d04a rdx=0x0000000000000000
  rsi=0x0000000000001050 rdi=0x000056b8000056b8 flags=0b000000000110
  xmm0=0x00000000000000000000000000000000 xmm1=0x00000000000000000000000000000000
  xmm2=0x00000000000000000000000000000000 xmm3=0x00000000000000000000000000000000
  xmm4=0x00000000000000000000000000000000 xmm5=0x00000000000000000000000000000000
  xmm6=0x00000000000000000000000000000000 xmm7=0x00000000000000000000000000000000

    > load from +0x2050 value 0x0
EXCEPTION #13: Read from non-readable memory (UC_ERR_READ_PROT)
0x13: [transient, nesting = 1] add cl, dl
  rax=0x0000000000000000 rbx=0x0000000000000000 rcx=0x0000d04a0000d04a rdx=0x0000000000000000
  rsi=0x0000000000001050 rdi=0x000056b8000056b8 flags=0b000000000110
  xmm0=0x00000000000000000000000000000000 xmm1=0x00000000000000000000000000000000
  xmm2=0x00000000000000000000000000000000 xmm3=0x00000000000000000000000000000000
  xmm4=0x00000000000000000000000000000000 xmm5=0x00000000000000000000000000000000
  xmm6=0x00000000000000000000000000000000 xmm7=0x00000000000000000000000000000000

0x15: [transient, nesting = 1] and rcx, 0b1111111111000
  rax=0x0000000000000000 rbx=0x0000000000000000 rcx=0x0000d04a0000d04a rdx=0x0000000000000000
  rsi=0x0000000000001050 rdi=0x000056b8000056b8 flags=0b000000000010
  xmm0=0x00000000000000000000000000000000 xmm1=0x00000000000000000000000000000000
  xmm2=0x00000000000000000000000000000000 xmm3=0x00000000000000000000000000000000
  xmm4=0x00000000000000000000000000000000 xmm5=0x00000000000000000000000000000000
  xmm6=0x00000000000000000000000000000000 xmm7=0x00000000000000000000000000000000

0x1c: [transient, nesting = 1] add [r14 +rcx], rbx
  rax=0x0000000000000000 rbx=0x0000000000000000 rcx=0x0000000000001048 rdx=0x0000000000000000
  rsi=0x0000000000001050 rdi=0x000056b8000056b8 flags=0b000000000110
  xmm0=0x00000000000000000000000000000000 xmm1=0x00000000000000000000000000000000
  xmm2=0x00000000000000000000000000000000 xmm3=0x00000000000000000000000000000000
  xmm4=0x00000000000000000000000000000000 xmm5=0x00000000000000000000000000000000
  xmm6=0x00000000000000000000000000000000 xmm7=0x00000000000000000000000000000000

    > load from +0x2048 value 0x0
EXCEPTION #13: Read from non-readable memory (UC_ERR_READ_PROT)
ROLLBACK to 0x7f
```

This log shows in detail which instructions from the test case were executed by the model, whether they were transient or non-transient, and the register/memory state before each instruction.

We can see that, early in the execution of the test case, a page fault occurs when trying to read from memory at address `0x2050`. This is because of the configuration we're using, where the second page of the sandbox memory (the faulty page) is set as non-readable.

Accordingly, since we're using `delayed-exception-handling` execution clause, the model will not execute any instructions that are data-dependent on this faulting load. This includes the two instructions that use RDI (lines 15 and 17), since RDI was computed based on the value loaded from address `0x2050`.

From this, we can conclude that the CPU implements some sort of speculation on page faults: The RDI-dependent instructions were not supposed to be executed, but we see leakage of RDI in cache traces nonetheless.

To understand what specific value is returned speculatively, we can manually modify the test case, and replace the instructions after the faulting load with a gadget that will specifically leak RDI:

``` asm linenums="1"
.intel_syntax noprefix
.section .data.main

.macro.measurement_start: nop qword ptr [rax + 0xff]
and rsi, 0b1111111111000 # instrumentation
mov rdi, qword ptr [r14 + rsi]

and rdi, 0b111111111111  # mask the value of RDI
mov rdi, qword ptr [r14 + rdi]
.macro.measurement_end: nop qword ptr [rax + 0xff]

.test_case_exit:
```

Will will also enable another debug mode to see the hardware traces even when no violation is detected:

```yaml
logging_modes:
    # - dbg_model
    - dbg_dump_htraces
```

Then, we can run the modified test case:

```
$ ./revizor.py reproduce -s base.json -c ./violation/reproduce.yaml \
    -t ./violation/min.asm -i ./violation/min-inputs/min_input_0000.bin

================================ Collected Traces =============================
- Input 0:
  HTr:
    ^^.^.......^............^.........................^............^ [10]

  Feedback: (816, 685, 64, 0, 0)
```

We see that multiple cache lines were accesses, so it is hard to pinpoint the exact one that belongs to the speculative leak. (We likely have all these evictions due to the page walk triggered by the page fault.)

We can identify the specific cache line by further modifying the test case to add an hard offset to the speculative memory access, e.g., changing:

``` asm
mov rdi, qword ptr [r14 + rdi + 0x100]
```

Then, we can run it again and see how the hardware trace changes:

```
./revizor.py reproduce -s base.json -c ./violation/reproduce.yaml -t ./violation/min.asm -i ./violation/min-inputs/min_input_0000.bin

================================ Collected Traces =============================
- Input 0:
  HTr:
    ^^.^^......^............^.........................^............^ [10]

  Feedback: (816, 685, 71, 0, 0)
```

Let's compare it side-by-side with the previous trace:

```
Before: ^^.^.......^............^.........................^............^
After:  ^^.^^......^............^.........................^............^
            |
            + Added cache set access due to +0x100 offset
              (cache set ID 4)
```

This shows that the speculative access used cache set ID 4. From this, we can do a simple calculation to deduce the value of RDI that was used for the memory access:

```
Cache ID = 4
Cache Line Size = 0x40
Hardcoded Offset = 0x100
Speculative Address = (Cache ID * Cache Line Size) = rdi + Hardcoded Offset // ignore r14
=>
rdi_masked = (Cache ID * Cache Line Size) - Hardcoded Offset = (4 * 0x40) - 0x100 = 0x0
```

Now we know that the masked value of RDI used in the speculative access was `0x0`. The remaining part is to figure out what was the original value of RDI before masking. For that, we can shift the pre-mask value of RDI by 12 bits (since the mask is `0b111111111111` = 0xfff = 12 bits) and repeat the procedure. We'll do 6 times to reveal the whole value.

The resulting traces are as follows:

```
no shift: ^^.^.......^............^.........................^............^
12 bits:  ^^.^.......^............^.........................^............^
24 bits:  ^^.^.......^............^.........................^............^
36 bits:  ^^.^.......^............^.........................^............^
48 bits:  ^^.^.......^............^.........................^............^
60 bits:  ^^.^.......^............^.........................^............^
```

We can see that in all cases, the cache set accessed is 0, which means that the masked value of RDI was always 0, regardless of how much we shifted it.

This tells us that the faulting load returned 0 speculatively, which reveals to us the root cause of the violation. This is an instance of a previously-discovered vulnerability called LVI-Null, which we have successfully and independently rediscovered using Revizor!

!!! success "What We've Learned"
    In this section, we applied the same systematic workflow to a different vulnerability class:

    - **Flexible configuration**: By changing just a few configuration options (removing branches, adding page faults, adjusting the contract), we refocused our search entirely
    - **Contract selection matters**: The `delayed-exception-handling` contract helped filter out trivial violations while exposing genuine leaks
    - **Deep analysis techniques**: We manually modified test cases and used offset manipulation to precisely identify what value the CPU returned speculatively

    The same workflow—plan, configure, fuzz, validate, minimize, analyze—works across all speculative execution vulnerability classes.

### What's Next?

Proceed to [Tutorial 4](../tutorial4-isolation/part1.md) to see how we can go even further and start testing high-level isolation properties.
