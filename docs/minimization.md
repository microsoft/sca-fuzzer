# Minimization of Violation Artifacts

`minimize` mode of Revizor performs post-processing of the violation artifacts produced as a result of testing a CPU in the `fuzz` mode.
This mode takes a violating program and its sequence of inputs, and it performs a series of transformation passes to simplify the program and the inputs while preserving the violation.
The goal is to produce a minimal artifact that would be easier to understand and analyze by a human.

## Usage

To run the minimization mode, you need a program that violates the contract (e.g., `program.asm`), a configuration file that was used to detect the violation (e.g., `config.yaml`), a specification of the instruction set (e.g., `base.json`).
The config file must set the input generation seed (`input_gen_seed`) to the value that matches the seed used in the `fuzz` mode to generate the violating inputs.

The syntax of the command is as follows:

```bash
rvzr minimize -s <spec_file> -c <config_file> -t <program_file> -o <output_file> -i <num_inputs> --input-outdir <input_outdir> --num-attempts <num_attempts> <pass_list>
```

A typical example of the command is:

```bash
rvzr minimize -s base.json -c config.yaml -i 25 -t program.asm -o min.asm --input-outdir ./inputs --num-attempts 10 --enable-instruction-pass 1
```

This example command will take the program `program.asm`, generate an input sequence of length 25 based on the seed in `config.yaml`, and then apply a series of transformation passes (see the list of supported passes below) to simplify the program and the inputs. The passes will be applied 10 times. The resulting simplified program will be written to `min.asm`, and the simplified input sequence will be written to the directory `<dir>`.

## Supported Passes

`minimize` mode supports three types of passes: program passes modify the program, input passes modify the input sequence, and analysis passes provide additional information about the violation, usually by adding comments to the program.

### Program Passes

```
--enable-instruction-pass
```

Enables the instruction minimization pass that iteratively removes instructions from the program while preserving the violation.

```
--enable-simplification-pass
```

Enables the instruction simplification pass that replaces complex instructions with simpler ones while preserving the violation.

```
--enable-nop-pass
```

Enables the NOP replacement pass that iteratively replaces instructions with NOPs of the same size while preserving the violation.

```
--enable-constant-pass
```

Enables the constant simplification pass that replaces immediate arguments of instructions with 0s while preserving the violation.

```
--enable-mask-pass
```

Enables the mask simplification pass that reduces the size of the instrumentation masks while preserving the violation.

```
--enable-label-pass
```

Enables the label removal pass that removes unused labels from the assembly file.

```
--enable-fence-pass
```

Enables the fence insertion pass that adds LFENCEs after instructions while preserving the violation.

### Input Passes

```
--enable-input-seq-pass
```

Enables the input sequence minimization pass that removes inputs from the original generated sequence while preserving the violation.

```
--enable-input-diff-pass
```

Enables the violating input difference minimization pass that operates on the pair of (contract-equivalent) inputs that triggered the violation and attempts to minimize the difference between the two inputs.
It does so by iterating over all bytes in the inputs, and (1) attempting to replace each byte with zero, and if it fails, (2) copying the byte from the first input to the second input.

### Analysis Passes

```
--enable-source-analysis
```

Enables the speculation source identification pass that analyzes the program to identify suspected sources of speculation, and adds the corresponding comments to the assembly file.
Note that the analysis is not guaranteed to be correct, and it may produce false results.

```
--enable-comment-pass
```

Enables the violation comment pass that adds comments to the assembly file with details about the violation.
Namely, it adds comments to every memory access in the following format:

`# mem access: [input1_id] [load_addr]-[store_addr] CL [cache_set_id]:[cache_line_offset] | [input2_id] [load_addr]-[store_addr] CL [cache_set_id]:[cache_line_offset]`

The comment indicates the addresses (`load_addr` and `store_addr`) of the given memory operation when executed with the two inputs that triggered the violation (`input1_id` and `input2_id`).
For convenience, it also provides the L1D cache set ID and line offset that correspond to the addresses of the memory operation.

For example, this comment

`# mem access: [1] 0x800-0x800 CL 32:0 | [11] 0x710-0x710 CL 28:10`

indicates that the memory operation preceded by this comment was executed with two inputs, `1` and `11`, and the memory operation accessed the addresses `0x800` and `0x710` in the two inputs, respectively.
The address `0x800` corresponded to cache set `32` and line offset `0`, while the address `0x710` corresponded to cache set `28` and line offset `10`.

## Interpreting the Output

When a pass executes, it prints out the progress into the console.

### Output of Program Passes

Most of the passes print out one character per instruction, with `.` indicating that the pass succeeded, and `-` indicating that the pass failed on the given instruction.
For example, if `--enable-instruction-pass` is enabled, the output may look like this:

```
[Pass 2] Instruction Removal Pass

.............-.....--.-------..----
```
This means that the pass successfully removed the last 13 instructions, failed to remove the 14th instruction, succeeded on the 15th instruction, and so on. Note that the pass iterates from bottom to top, hence the output is printed in reverse order.

### Output of Input Passes

The `input-diff` pass has a slightly different output format.
It prints out a compact representation of the input difference, with each character representing a byte in the input sequence:
* `.` indicates that zeroing the byte succeeded
* `+` indicates that copying the byte succeeded
* `=` indicates that the byte was already the same in both inputs
* `^` indicates that the pass failed to minimize the byte, and it remained different in the two inputs

For example, the output of the `input-diff` pass may look like this:

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

This output indicates that the pass successfully minimized the input difference for all bytes except for the byte at address `0x2020`, which remained different in the two inputs, and the bytes at addresses `0x2000-0x2018` and `0x2028` were already the same in both inputs.


## Usage Example

The following example demonstrates a typical workflow of using the `minimize` mode to simplify a violating program and its input sequence.

0. Let's assume that a violation artifact was produces as a result of a fuzzing campaign like this:

```bash
rvzr fuzz -s base.json -c config.yaml -n 1000 -i 25 -w .
```

1. The first step is to minimize the violating program by enabling all program passes:

```bash
rvzr minimize -s base.json -c ./violation-000000-000000/minimize.yaml \
     -t ./violation/violation-000000-000000/program.asm \
     -o min.asm -i 25 --num-attempts 3 \
     --enable-instruction-pass 1 \
     --enable-simplification-pass 1 \
     --enable-nop-pass 1 \
     --enable-constant-pass 1 \
     --enable-mask-pass 1 \
     --enable-label-pass 1
```

2. Verify the violation is preserved by reproducing it with the minimized program and the original input sequence:

```bash
rvzr fuzz -s base.json -c minimize.yaml -t min.asm -i 25
```

If the violation is detected, move to the next step.
Otherwise, re-run the first command with a lower number of `--num-attempts` or try to disable some of the passes.

3. The next step is to minimize the inputs by enabling all input passes, and to add analysis comments:

```bash
rvzr minimize -s base.json -c ./violation/violation-240712-132351/minimize.yaml \
    -t min.asm \
    -o commented.asm -i 25  \
    --input-outdir ./inputs \
    --enable-input-diff-pass 1 \
    --enable-input-seq-pass 1 \
    --enable-source-analysis 1 \
    --enable-comment-pass 1
```

4. The final step is to try to reproduce the violation with the minimized program and inputs to verify that the violation is preserved:

```bash
rvzr reproduce -s base.json -c ./violation/violation-240712-132351/reproduce.yaml \
    -t commented.asm -i ./inputs/min_input*.bin
```

If the violation is detected, the minimized program and inputs can be used for further analysis.
