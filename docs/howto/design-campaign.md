# How to Design a Fuzzing Campaign

This guide shows you how to design and configure a fuzzing campaign for detecting speculative execution vulnerabilities. A campaign consists of three components: a configuration file (YAML), command-line arguments, and optionally a template file (ASM).

!!! note "Prerequisites"
    - Revizor installed and the executor kernel module loaded
    - Basic understanding of [contracts](../topics/contracts.md) and what you want to test

## Select Instruction Set

Choose which instruction subset to test. Smaller subsets are more effective because violations are found faster and root-cause analysis is simpler. For comprehensive ISA coverage, split testing into multiple targeted campaigns rather than running a single large campaign.

Specify instruction categories in your configuration file using `instruction_categories`:

```yaml
instruction_categories:
  - BASE-BINARY      # arithmetic instructions
  - BASE-STRINGOP    # string operations
  - BASE-LOGIC       # logical operations
```

Verify which instructions are included by enabling debug logging:

```yaml
logging_modes: ['info', 'stat', 'dbg_generator']
```

For fine-grained control over the instruction set, see the [Configuration Reference](../ref/config.md#instruction_categories).

## Configure Exception Testing

Enable exception testing using the `generator_faults_allowlist` option:

```yaml
generator_faults_allowlist:
  - div-by-zero              # division by zero exceptions
```

Ensure the corresponding instructions are included in your instruction set. For example, `div-by-zero` requires division instructions in the tested pool.

For testing Meltdown or Foreshadow-like vulnerabilities, configure memory access permissions through actor-specific `data_properties` and `data_ept_properties`:

```yaml
actors:
  - main:
      data_properties:
        present: false     # trigger page faults
        writable: false    # trigger write protection faults
```

See the [Sandbox Reference](../ref/sandbox.md) for details on memory permissions and the [Configuration Reference](../ref/config.md#generator_faults_allowlist) for all exception handling options.

## Configure Actors for Multi-Domain Testing

For cross-domain leakage testing, define [actors](../glossary.md#actor) to represent different security domains:

```yaml
actors:
  - main:
      mode: host
      privilege_level: kernel
  - guest:
      mode: guest
      privilege_level: kernel
      observer: true
```

Create corresponding template files to specify transition sequences between actors. See [Actors](../topics/actors.md) for detailed instructions.

## Select Contract

Choose a [contract](../glossary.md#speculation-contract) that defines what execution behavior constitutes a violation. Contract selection depends on whether you are testing cross-domain leakage and which known vulnerabilities you want to filter out.

For detailed guidance on selecting the appropriate contract for your testing scenario, see [How to Choose a Contract](choose-contract.md).

Example configuration:

```yaml
contract_observation_clause: ct
contract_execution_clause:
  - seq
```

See the [Configuration Reference](../ref/config.md#contract_observation_clause) for all available contract options.

## Configure Noise Threshold

Adjust noise tolerance based on your system characteristics. Higher thresholds and larger sample sizes reduce false positives but may miss subtle leaks and decrease performance. Lower thresholds increase sensitivity but may produce false positives on noisy systems.

For high-noise systems:

```yaml
analyser_stat_threshold: 0.5      # conservative threshold
executor_sample_sizes: [50, 100, 500, 1000]
```

For low-noise systems:

```yaml
analyser_stat_threshold: 0.1      # sensitive threshold
executor_sample_sizes: [10, 50, 100]
```

Start with low-noise settings and increase thresholds if you encounter non-reproducible violations. See the [Trace Analysis Guide](../topics/trace-analysis.md#statistical-trace-comparison) for more information on noise handling.

## Enable Reproducibility

Set deterministic seeds to make the campaign reproducible:

```yaml
program_generator_seed: 12345     # deterministic program generation
data_generator_seed: 67890        # deterministic input generation
```

Reproducible campaigns are essential for debugging and comparing results across different runs.

## Configure Test Case Shape

Control the structure of generated test cases:

```yaml
program_size: 64                  # instructions per program
avg_mem_accesses: 32              # average memory accesses
min_bb_per_function: 1            # minimum basic blocks per function
max_bb_per_function: 2            # maximum basic blocks per function
min_successors_per_bb: 1          # minimum successors per basic block
max_successors_per_bb: 1          # maximum successors per basic block
```

Larger programs may find more complex interactions but require longer analysis time. Start with smaller programs and increase size if needed.

## Use Templates for Targeted Testing

Use templates when targeting specific microarchitectural scenarios. Templates define fixed assembly structures with random instruction insertion, allowing you to focus on specific patterns while maintaining variability.

Example template:

```asm
.section .data.main
.function_main_0:
    # Fixed initialization
    mov rax, 0

    # Random instruction sequence
    .macro.random_instructions.32.0:

    # Fixed measurement
    .macro.measurement_start:
    mov rbx, [r14]
    .macro.measurement_end:

.test_case_exit:
```

See [How to Use Templates](use-templates.md) for detailed template syntax and the [Macro Reference](../ref/macros.md) for available macros.

## Complete Example

This campaign tests whether division-by-zero exceptions cause unexpected information leakage on the target CPU. It focuses on simple arithmetic instructions to isolate exception handling behavior and answers the question: "Does division by zero on this CPU leak information through microarchitectural side channels?"

The configuration assumes a CPU with relatively low non-determinism, using moderate sample sizes and a conservative statistical threshold. The campaign uses the DEH (Delay Exception Handling) contract to filter out trivial cases of out-of-order handling of the exception. Test cases are kept small (32 instructions, no branches) to simplify analysis and accelerate violation detection. Each campaign iteration generates 100 different inputs per test case to explore various data-dependent behaviors around division operations.

```yaml
# Instruction selection
instruction_categories:
  - BASE-BINARY

# Exception handling
generator_faults_allowlist:
  - div-by-zero

# Contract
contract_observation_clause: ct
contract_execution_clause:
  - deh

# Noise handling
analyser_stat_threshold: 0.2
executor_sample_sizes: [10, 50, 100, 500]

# Reproducibility
program_generator_seed: 12345
data_generator_seed: 67890

# Test case shape: 32 instructions with no branches
program_size: 32
avg_mem_accesses: 16
min_bb_per_function: 1
max_bb_per_function: 1

# Single actor
actors:
  - main:
      mode: host
      privilege_level: kernel
      data_properties:  # no page faults
        present: true
        writable: true

# Debugging
logging_modes: ['info', 'stat', 'dbg_generator']
```

Launch the campaign:

```bash
rvzr fuzz -s base.json -c config.yaml -n 100000 -i 100 -w ./violations --timeout 3600
```


## What's Next?

- How-to: [Choose a Contract](choose-contract.md) - Select the appropriate contract for your testing scenario
- How-to: [Use Templates](use-templates.md) - Create targeted test cases
- How-to: [Interpret Results](interpret-results.md) - Understand fuzzing output
- Topic: [Actors](../topics/actors.md) - Configure multi-domain testing
- Topic: [Contracts](../topics/contracts.md) - Understanding leakage contracts
- Topic: [Test Case Generation](../topics/test-case-generation.md) - How test cases are generated
- Reference: [Configuration Options](../ref/config.md) - Complete configuration reference
- Reference: [CLI Reference](../ref/cli.md) - Command-line interface reference
