# Tutorial 1: Your First Fuzz (Part 1)

This is the first part of the tutorial on the basic usage of Revizor.

### Overview

In this first tutorial, we'll start with a baseline experiment to verify your Revizor installation and familiarize yourself with the basic workflow. This tutorial walks you through a simple fuzzing campaign that should find no violations.

The goal of this first campaign is verification, not vulnerability detection. We'll deliberately choose an instruction set that should not trigger speculation on Intel or AMD CPUs—specifically, simple arithmetic operations without any branches or memory speculation sources. Since there are no conditional branches to mispredict and no page faults to speculate around, we expect the CPU to execute sequentially without any speculative side effects.

This baseline is useful for two reasons. First, it confirms your installation is working correctly. If the fuzzer crashes or behaves unexpectedly, you'll know there's a setup issue rather than discovering problems later during more complex campaigns. Second, it establishes what "no violations" looks like, so you can recognize the difference when you do find a vulnerability in the next tutorial.

### Create your first configuration file

Revizor's behavior is controlled by a YAML configuration file that specifies which instructions to test and what contract to check against. Create a file named `config.yaml` with the following content:

```yaml
# tested instructions
instruction_categories:
  - BASE-BINARY

# prevent branch generation
max_bb_per_function: 1
min_bb_per_function: 1

# contract
contract_observation_clause: loads+stores+pc
contract_execution_clause:
  - no_speculation
```

Let's understand each section. The `instruction_categories` field tells Revizor which instructions to include in generated test cases. We're using `BASE-BINARY`, which includes only arithmetic and logical operations like `add`, `sub`, `and`, `xor`, and `mov`. These operations are data-processing instructions that don't involve control flow or special memory access patterns.

The `max_bb_per_function` and `min_bb_per_function` settings both set to 1 ensure that Revizor generates programs with exactly one basic block—meaning no branches at all. This simplifies our test cases to pure arithmetic sequences, eliminating any possibility of branch misprediction.

The contract configuration section is set to use the simplest contract, CT-SEQ. This contract assumes nothing about the target CPU except the presence of CPU caches, making it a zero-knowledge baseline for detecting unknown vulnerabilities. With CT-SEQ, Revizor reports any information leaks beyond the most trivial non-speculative cache accesses.

For a complete reference of all configuration options, see the [Configuration Reference](../../ref/config.md).

### What's Next

In [Part 2](part2.md), we'll use this configuration to run your first fuzzing campaign.
