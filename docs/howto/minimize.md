# How to Minimize Test Cases

This guide discussed a process of test case minimization, which aims to reduce complexity of violation artifacts by simplifying test programs and input sequences while preserving the violation. This is typically a post-processing step performed after a fuzzing campaign has detected a violation, with the goal of producing a minimal test case suitable for human analysis and root-cause investigation.

The minimization is done by using Revizor's `minimize` mode, which post-processes a violation through a series of transformation passes that simplify both the test program and input sequence.

!!! note "Related Documentation"
    For a complete list of available passes and their detailed descriptions, see the [Minimization Passes reference](../ref/minimization-passes.md).

!!! info "Prerequisites"
    Before starting, ensure you have:

    - Revizor installed and functional on the target system
    - A violation directory (`violation-<timestamp>`) produced during fuzzing
    - The configuration file (`config.yaml`) used in the original fuzzing campaign
    - Access to the same hardware where the violation was detected

## Basic Usage

Run the minimizer with the following syntax:

```bash
rvzr minimize -s <spec_file> -c <config_file> -t <program_file> -o <output_file> \
    -i <num_inputs> --input-outdir <input_outdir> --num-attempts <num_attempts> \
    [pass_options]
```

Parameters:

- `-s`: Path to ISA specification (e.g., `base.json`)
- `-c`: Path to configuration file (typically `minimize.yaml` from violation directory)
- `-t`: Path to test program (typically `program.asm` from violation directory)
- `-o`: Output path for minimized program
- `-i`: Number of inputs in the sequence (must match the original fuzzing campaign)
- `--input-outdir`: Directory to store minimized input files
- `--num-attempts`: Number of minimization iterations to perform
- `[pass_options]`: Enable specific minimization passes (see [Minimization Passes](../ref/minimization-passes.md))

Example command (assuming a violation directory named `violation-0000-0000`):

```bash
rvzr minimize -s base.json -c violation-0000-0000/minimize.yaml -t violation-0000-0000/program.asm \
    -i 25 --input-outdir ./min-inputs --num-attempts 10 --enable-instruction-pass 1 \
    -o min.asm
```

This command generates an input sequence of 25 inputs based on the seed in `violation-0000-0000/minimize.yaml`, applies the instruction removal pass 10 times to simplify `program.asm`, and writes the minimized program to `min.asm`. The simplified input sequence is stored in `./min-inputs`.

## Interpreting the Output

Each minimization pass prints progress indicators to the console as it executes. Understanding this output helps verify that minimization is progressing correctly.

### Program Pass Output

Program passes display one character per instruction to indicate success or failure:

- `.` indicates the pass succeeded on this instruction (e.g., instruction was successfully removed)
- `-` indicates the pass failed on this instruction (e.g., removing this instruction breaks the violation)

Example output when running `--enable-instruction-pass`:

```
[Pass 2] Instruction Removal Pass

.............-.....--.-------..----
```

Interpret this output by reading from right to left, since the pass iterates from the end of the program to the beginning. In this example, the pass successfully removed the last 13 instructions, failed on the 14th instruction from the end, succeeded on the 15th, and so on.

### Input Pass Output

The `input-diff` pass uses a memory-map visualization to show minimization progress. Each character represents one byte in the input sequence:

- `.` indicates zeroing the byte succeeded
- `+` indicates copying the byte from the first input to the second succeeded
- `=` indicates the byte was already identical in both inputs
- `^` indicates the pass could not minimize this byte (it remains different between inputs)

Example output from `--enable-input-diff-pass`:

```
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
0x00002000 ====^=..
0x00002040 ........ ........ ........ ........
  > Result: Leaked 1 bytes
  > Addresses: ['0x2020']
```

This output shows that the pass successfully minimized most input differences. The byte at address `0x2020` (marked with `^`) remains different between the two inputs and likely contributes to the violation. Bytes at addresses `0x2000-0x2018` and `0x2028` (marked with `=`) were already identical.

### Comment Pass Output

Enable `--enable-comment-pass` to annotate the minimized program with analysis information. The pass inserts comments indicating which memory accesses contributed to the violation, making it easier to identify the root cause.

Comment format:

```
# mem access: [input1_id] [load_addr]-[store_addr]
  CL [cache_set_id]:[cache_line_offset] | [input2_id] [load_addr]-[store_addr]
  CL [cache_set_id]:[cache_line_offset]
```

Each comment shows the memory addresses accessed by an instruction when executed with the two inputs that triggered the violation. The comment includes both virtual addresses and their corresponding L1D cache set IDs and line offsets.

Example comment:

```asm
# mem access: [1] 0x800-0x800 CL 32:0 | [11] 0x710-0x710 CL 28:10
```

This indicates that when executed with input 1, the instruction accessed address `0x800` (cache set 32, offset 0), and when executed with input 11, it accessed address `0x710` (cache set 28, offset 10). These different cache set accesses likely contributed to the violation.

## Complete Workflow Example

This example demonstrates a typical minimization workflow. Assume a fuzzing campaign detected a violation:

```bash
rvzr fuzz -s base.json -c config.yaml -n 1000 -i 25 -w .
```

The fuzzer created a violation directory (e.g., `violation-000000-000000`) containing the test case artifacts.

### Step 1: Minimize the Program

Apply all program passes to simplify the test case while preserving the violation:

```bash
rvzr minimize -s base.json -c ./violation-000000-000000/minimize.yaml \
    -t ./violation-000000-000000/program.asm \
    -o min.asm -i 25 --num-attempts 3 \
    --enable-instruction-pass 1 \
    --enable-simplification-pass 1 \
    --enable-nop-pass 1 \
    --enable-constant-pass 1 \
    --enable-mask-pass 1 \
    --enable-label-pass 1
```

### Step 2: Verify Program Minimization

Confirm the minimized program still triggers the violation:

```bash
rvzr fuzz -s base.json -c ./violation-000000-000000/minimize.yaml -t min.asm -i 25
```

If the violation is no longer detected, reduce `--num-attempts` or disable some passes, then retry step 1.

### Step 3: Minimize Inputs and Add Annotations

Apply input passes and analysis passes to further simplify the test case and add helpful comments:

```bash
rvzr minimize -s base.json -c ./violation-000000-000000/minimize.yaml \
    -t min.asm -o commented.asm -i 25 \
    --input-outdir ./inputs \
    --enable-input-diff-pass 1 \
    --enable-input-seq-pass 1 \
    --enable-comment-pass 1
```

### Step 4: Verify Complete Minimization

Reproduce the violation with the minimized program and inputs:

```bash
rvzr reproduce -s base.json -c ./violation-000000-000000/reproduce.yaml \
    -t commented.asm -i ./inputs/min_input*.bin
```

If successful, the minimized test case in `commented.asm` and `./inputs/` is ready for detailed analysis. The annotated comments will help identify the root cause of the violation.

!!! tip "Troubleshooting Failed Minimization"
    If minimization breaks the violation, try these adjustments:

    - Reduce `--num-attempts` to perform fewer iterations
    - Disable aggressive passes like `--enable-simplification-pass`
    - Minimize the program before minimizing inputs
    - Check that `data_generator_seed` matches the original fuzzing campaign


## What's Next?

Once a violation is minimized, the next step is typically to analyze it manually to understand the root cause. The [How to Root-Cause a Violation](root-cause-a-violation.md) guide is dedicated to this topic.

## See Also

- [Minimization Passes](../ref/minimization-passes.md) - Complete list of available passes and their options
- [CLI Reference](../ref/cli.md) - Full command-line interface documentation
- [Execution Modes](../ref/modes.md) - Overview of all Revizor execution modes
- [Configuration Options](../ref/config.md) - Configuration file reference including `data_generator_seed`
- [How to Design a Fuzzing Campaign](design-campaign.md) - Set up effective fuzzing campaigns
- [How to Interpret Results](interpret-results.md) - Understand fuzzing outputs and violation reports
- [Trace Analysis and Violation Detection](../topics/trace-analysis.md) - Understanding how violations are detected
