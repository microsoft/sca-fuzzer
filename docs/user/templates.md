# Template-Based Mode in Revizor

Template-based mode (`tfuzz`) enables targeted testing of specific CPU scenarios by using predefined assembly templates that get expanded with random instructions. This mode narrows down the fuzzing space to focus on particular interaction patterns while maintaining randomization within those patterns.

## Overview

Template-based mode generates test cases from assembly templates containing macros that get dynamically expanded during generation. Templates define the structure and flow of test cases while allowing specific sections to be populated with random instructions based on configuration.

## Command Line Usage

Template-based mode is invoked using the `rvzr tfuzz` command. The invocation is almost identical to the normal `rvzr fuzz` mode, but it takes an additional `-t` or `--template` parameter to specify the assembly template file.

Invocation example:

```bash
rvzr tfuzz -t template.asm -c config.yaml -s base.json -n 10 -i 100
```

where `template.asm` is the template file.


## Template Structure

Templates are assembly files that combine:

- Regular assembly instructions
- Macros (special pseudo-instructions as described in [Macros](macros.md))

Example template:

```asm
.intel_syntax noprefix
.section .data.main

.macro.random_instructions.10.0:  ; Replaced with 10 random instructions
div rax, rbx                      ; rax and rbx may be set by random instructions
jmp .test_case_exit               ; Jump to exit point if no exception occurs

.fault_handler:
    .macro.random_instructions.10.1:  ; Generate 10 random instructions executed when a fault occurs

.test_case_exit:
```

Revizor will take this template and replace the `.macro.random_instructions.N` with N random instructions from the instruction pool defined in the configuration file. A new test case will be generated this way in each fuzzing round, allowing for a wide variety of test cases while still adhering to the structure defined in the template. For example, if `-n 10` is specified, the generator will produce 10 test cases based on the template, each with different random instruction sequences.
