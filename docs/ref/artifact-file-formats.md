# Artifact File Formats

This document describes the structure of violations artifact files stored by Revizor when it detects a contract violation.

## Program Artifact Format

The program artifact is stored as an assembly file named `program.asm` in the violation directory (e.g., `violation-<timestamp>/program.asm`).

The file uses Intel syntax and is structured around actors, with each actor's code placed in a separate section.

The program artifact is structured as follows:

```asm
.intel_syntax noprefix         # Required: Use Intel syntax
.test_case_enter:              # Required: marks the beginning of the test case

.section .data.main            # Start of "main" actor section
...                            # Instructions for main actor,
                               # including possible control transfers to other actors

.test_case_exit:               # Required: marks the end of the test case;
                               # Must be within the "main" actor section

.section .data.actor2          # Start of "actor2" actor section
...                            # Instructions for actor2
```


## Input Data Artifact Format

The inputs to the program are stored as binary files in the violation directory, named according to their order in the input sequence (e.g., `violation-<timestamp>/input_004.bin`).

The format mimics the layout of the [sandbox memory](sandbox.md), with the only exception that some of the sections are removed as they are irrelevant for input data (e.g., the MACRO STACK and the padding areas).

The layout of the input data files is as follows:

| Offset | Actor ID | Section Name | Size, B |
| ------ | -------- | ------------ | ------- |
| 0x0    | ACTOR 0  | MAIN AREA    | 0x1000  |
| 0x1000 |          | FAULTY AREA  | 0x1000  |
| 0x2000 |          | GPR AREA     | 0x40    |
| 0x2040 |          | SIMD AREA    | 0x100   |
| 0x2140 |          | (unused)     | 0xec0   |
| 0x0    | ACTOR 1  | MAIN AREA    | 0x1000  |
| 0x1000 |          | FAULTY AREA  | 0x1000  |
| 0x2000 |          | GPR AREA     | 0x40    |
| 0x2040 |          | SIMD AREA    | 0x100   |
| 0x2140 |          | (unused)     | 0xec0   |
| ...    | ...      | ...          | ...     |



