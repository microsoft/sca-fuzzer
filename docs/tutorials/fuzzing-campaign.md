# Tutorial: Designing a Revizor Fuzzing Campaign

A Revizor fuzzing experiment is determined by three components: the configuration file (YAML), command-line arguments, and optionally a template file (ASM). This tutorial outlines the systematic approach to designing a fuzzing campaign.

## 1. Instruction Set

The first consideration is determining which instruction subset to test. Testing smaller instruction subsets is generally more effective because violations are found faster and root-cause analysis is simplified. For comprehensive ISA coverage, split into multiple targeted campaigns rather than a single large campaign. Each campaign should focus on a specific subset.

Control instruction categories using the `instruction_categories` configuration option:

```yaml
instruction_categories:
  - BASE-BINARY      # arithmetic instructions
  - BASE-STRINGOP    # string operations
  - BASE-LOGIC       # logical operations
```

To verify included instructions, add `dbg_generator` to the `logging_modes` configuration:

```yaml
logging_modes: ['info', 'stat', 'dbg_generator']
```

More configuration options are available for more fine-grained control over the instruction set. See [config.md](../user/config.md) for details.

## 2. Exceptions

Decide if the campaign should cover exceptions. If so, use `generator_faults_allowlist` config option.

```yaml
generator_faults_allowlist:
  - div-by-zero              # division by zero exceptions
```

Also ensure corresponding instructions are included in the tested pool. For example, `div-by-zero` will have no effect if division instructions are not in the pool.

If you want to test for Meltdown or Foreshadow-like vulnerabilities, you'll need to enable faults.
These are controlled through separate actor-specific options, `data_properties` and `data_ept_properties` fields, which control permissions on the FAULTY area of the given actor (see [Sandbox](../devel/sandbox.md) for details).

```yaml
actors:
  - main:
      data_properties:
        present: false     # trigger page faults
        writable: false    # trigger write protection faults
```

More config options are available for exception handling. See [config.md](../user/config.md) for details.

## 3. Actors and Security Domains

For cross-domain leakage testing, configure the `actors` field and create corresponding templates (see [actors.md](../user/actors.md) for details):

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

Actor configurations define security domains and their interaction patterns. Use templates to specify transition sequences between actors.

## 4. Contract Selection

Contract selection is critical and depends on two primary factors: whether you're testing cross-actor leakage and whether you need to filter known leaks. Revizor contracts consist of observation and execution clauses.

**Contract Selection Decision Tree:**

* For cross-actor leakage testing, use the `noninterference` contract:
```yaml
contract_observation_clause: ct
contract_execution_clause:
  - noninterference
```

The `noninterference` contract ensures that observer actors cannot learn information about victim actors through microarchitectural channels. This is appropriate for testing isolation between security domains such as kernel/user, host/guest, or different VMs.

Note you have to also set the `observer` flag in the actor configuration to flag the observer (i.e., attacker) actor. If not set, the `noninterference` contract will not work as expected.

Example actor configuration for a cross-domain scenario:
```yaml
actors:
  - main:
      mode: host
      privilege_level: kernel
  - observer:
      mode: guest
      privilege_level: kernel
      observer: true
```

* For filtering known instances of leakage while detection unknown leaks, use the corresponding execution clause. E.g., to filter out Spectre V1, use the `cond` contract:
```yaml
contract_observation_clause: ct
contract_execution_clause:
  - cond
```

The `cond` contract permits conditional branch misprediction, effectively filtering out Spectre V1 violations while detecting other speculative leaks.

For complete list of supported execution clauses, see [config.md](../user/config.md). If the type of speculation you're interested in is not listed, you can try to write a custom speculator for Revizor. Feel free to reach out to the Revizor team for assistance on the [discussion page](https://github.com/microsoft/sca-fuzzer/discussions).

* Otherwise, if you want to detect all speculative leaks without filtering, use the `seq` contract:
```yaml
contract_observation_clause: ct
contract_execution_clause:
  - seq
```

The `seq` contract reports all detected speculative leaks, providing the most comprehensive coverage but potentially including known or acceptable leaks.

## 5. Noise Threshold

Configure noise tolerance based on system characteristics:

**High-noise systems**:
```yaml
analyser_stat_threshold: 0.5      # conservative threshold
executor_sample_sizes: [50, 100, 500, 1000]
```

**Low-noise systems**:
```yaml
analyser_stat_threshold: 0.1      # sensitive threshold
executor_sample_sizes: [10, 50, 100]
```

Higher thresholds and sample sizes reduces false positives but may miss subtle leaks and also reduce performance. Lower thresholds increase sensitivity but may cause false positives on a noisy system.

If unsure about the noise level, start with low-noise settings and adjust if you detect non-reproducible violations.

## 6. Reproducibility Configuration

To make the fuzzing campaign reproducible, set deterministic seeds for program and data generation:

```yaml
program_generator_seed: 12345     # deterministic program generation
data_generator_seed: 67890        # deterministic input generation
```

## 7. Test Case Shape Configuration

Control the structure of generated test cases:

```yaml
program_size: 64                  # instructions per program
avg_mem_accesses: 32              # average memory accesses
min_bb_per_function: 1            # minimum basic blocks per function
max_bb_per_function: 2            # maximum basic blocks per function
min_successors_per_bb: 1          # minimum successors per basic block
max_successors_per_bb: 1          # maximum successors per basic block
```

Larger programs may find more complex interactions but require longer analysis time.

## 8. Template-Based Fuzzing

If you're interested in a very specific microarchitectural scenario, you can use templates to define fixed assembly structures with random instruction insertion. This allows you to focus on specific patterns while still introducing variability.

Example template structure:

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

See [templates.md](../user/templates.md) for more details on template syntax and usage.

## 9. Example Configuration

Complete configuration for testing arithmetic instructions with exception handling:

```yaml
# Instruction selection
instruction_categories:
  - BASE-BINARY

# Exception handling
generator_faults_allowlist:
  - div-by-zero

# Contract
contract_observation_clause: loads+stores+pc
contract_execution_clause:
  - seq

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

## 10. Launch Command

Execute the fuzzing campaign:

```bash
rvzr fuzz -s base.json -c config.yaml -n 100000 -i 100 -w ./violations --timeout 3600
```

Parameters:

- `-s`: ISA specification file
- `-c`: Configuration file
- `-n`: Number of test cases
- `-i`: Inputs per test case
- `-w`: Working directory for violations
- `--timeout`: Time limit in seconds

## Key Principles

1. **Start focused**: Test instruction subsets rather than entire ISA
2. **Incremental complexity**: Begin with simple scenarios, add complexity gradually
3. **Noise-aware configuration**: Adjust thresholds based on system characteristics
4. **Systematic coverage**: Use multiple targeted campaigns rather than single broad campaign
5. **Reproducible setup**: Use deterministic seeds for consistent results

For additional configuration options, consult [config.md](../user/config.md). For multi-actor scenarios, see [actors.md](../user/actors.md). For template syntax, refer to [templates.md](../user/templates.md).
