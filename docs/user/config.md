# Configuration File

Below is a list of the available configuration options for Revizor, which are passed down to Revizor via a config file.
For an example of how to write the config file, see [rvzr/tests/big-fuzz.yaml](https://github.com/microsoft/sca-fuzzer/tree/main/rvzr/tests/big-fuzz.yaml).

## Fuzzing Configuration

```yaml
Name: fuzzer
Default: 'basic'
Options: 'basic' | 'architectural' | 'archdiff'
```

This option selects the fuzzing mode. The available options are:

* `basic` - normal model-based fuzzing. A violation in this mode indicates that the CPU
exposes more information than predicted by the contract. This option should be used in most
testing campaigns.
* `architectural` - self-fuzzing for architectural mismatches between the model and the executor.
This option should be used for testing the fuzzer itself, i.e., a violation in this
mode indicates a bug in the fuzzer rather then a bug in the CPU. This is useful when running
the fuzzer with a previously-untested instruction set, or when a new contract is implemented.
* `archdiff` - fuzzing for architectural invariants. This is a special mode targeted for
for semi-microarchitectural violations, similar to ZenBleed. This mode is experimental and
should be used with caution.

```yaml
Name: enable_priming
Default: True
```

This option enables or disables priming. This options should be set to True in most cases,
as priming is crucial for eliminating false positives.

Priming solves the following problem: Revizor collects hardware traces for inputs in a sequence,
and the microarchitectural state is not reset between the inputs. This means that the microarchitectural
state for the input at, for example, position 100 is different from the state for the input at position 200.
Accordingly, the hardware traces for these inputs may differ because the measurements are taken in different
microarchitectural contexts.

To address this issue, we uses priming, which swaps the inputs in the sequence and re-runs the tests.
For example, if the original sequence is (i1 . . . i99,i100,i101 . . . i199,i200), the priming
sequence will be (i1 . . . i99,i200,i101 . . . i199,i100). If the violation persists in this
sequence, it is a true positive. If the violation disappears, it is a false positive, and it
will be discarded.

```yaml
Name: enable_speculation_filter
Default: False
```

If enabled, Revizor will discard test cases that do not trigger speculation.

This option is useful for improving the throughput of the fuzzer,
but it can discard potential violations if the leakage is not caused by speculation.

```yaml
Name: enable_observation_filter
Default: False
```

If enabled, Revizor will discard test cases that do not leave speculative traces.
The filtering is performed by adding an `LFENCE` after
each instruction in the test case, and comparing the resulting hardware traces with the original.
If the traces are identical, the test case is discarded.

This option is useful for improving the throughput of the fuzzer,
but it can discard potential violations if the leakage is not caused by speculation.

```yaml
Name: enable_fast_path_model
Default: True
```

If enabled, the same contract trace will be used for all inputs in the same taint-based input class.

```yaml
Name: color
Default: False
```

If enabled, the output will be colored.
This option is helps a lot with readability, but may produce corrupted output when redirected to a file.

```yaml
Name: logging_modes
Default: ['info', 'stat']
Options: 'info' | 'stat' | 'dbg_timestamp' | 'dbg_violation' | 'dbg_dump_htraces' | 'dbg_dump_ctraces' | 'dbg_dump_traces_unlimited' | 'dbg_executor_raw' | 'dbg_model' | 'dbg_coverage' | 'dbg_generator' | 'dbg_priming' | 'dbg_isa_filter'
```

This option controls the output:

* `info` - general information about the progress of fuzzing;
* `stat` - statistics the end of the fuzzing campaign;
* `dbg_timestamp` - every 1000 test cases print the timestamp during the fuzzing process;
* `dbg_violation` - upon detecting a violation, print detailed information about it;
* `dbg_dump_htraces` - print the first 100 hardware traces for every test case;
* `dbg_dump_ctraces` - print the first 100 contract traces for every test case;
* `dbg_dump_traces_unlimited` - print ALL traces (use carefully, produces LOTS of text);
* `dbg_executor_raw` - prints hardware traces for every stage of the fuzzing process;
  this differs from `dbg_dump_htraces` in that it prints the traces collected by
  speculation/observation filters as well as at every iteration of multi-sample collection;
* `dbg_model` - print a detailed info about EVERY instruction executed on the model (use carefully, produces LOTS of text);
* `dbg_coverage` - stores instruction coverage information;
* `dbg_generator` - prints a list of instructions used to generate test cases;
* `dbg_priming` - prints information about the priming process; only useful for debugging the priming mechanism itself.
* `dbg_isa_filter` - when rvzr loads information about the instruction set (normally, from `base.json`), it filters out some of the instructions, either because of the config options provided by the user, or because some instructions are known to cause issues in the model or executor. This debug option prints the list of instructions that were filtered out, along with the reason for filtering them out.

```yaml
Name: multiline_output
Default: False
```

If enabled, each output message will be printed on a separate line.
Otherwise, the fuzzing progress will be continuously overwriting the same line (works only in the terminal).


## Program Generator Configuration

```yaml
Name: instruction_set
Default: (architecture-dependent)
Options: 'x86-64' | 'arm64'
```

The instruction set under test. Currently, only x86-64 is supported.

```yaml
Name: instruction_categories
Default: (architecture-dependent; see rvzr/arch/<isa>/config.py for details)
Options: (depends on model backend; see <isa>_config.py for details)
```

Select a list of instruction categories to be used when generating programs.
This list effectively filters out instructions from the ISA descriptor file (e.g., `base.json`)
passed via the command line (`-s`).

```yaml
Name: instruction_blocklist
Default: (architecture-dependent; see rvzr/arch/<isa>/config.py for details)
Options: (any instruction names)
```

A list of instructions that will NOT be used for generating programs.
This list filters out instructions from `instruction_categories`, but not from `instruction_allowlist`.

The resulting instruction pool is:
     (instructions from instruction_categories - instruction_blocklist) + instruction_allowlist

The instructions that are blocked by default are known to cause issues in the model or executor,
and hence should generally be avoided when fuzzing.

```yaml
Name: instruction_blocklist_append
Default: []
Options: (any instruction names)
```

A list of instructions that will be appended to the default instruction blocklist.
This option is identical to `instruction_blocklist`, but the list is added to the previous
blocklist instead of replacing it.
This is useful when you want to block some instructions in addition to the default blocklist.

```yaml
Name: instruction_allowlist
Default: []
Options: (any instruction names)
```

A list of instructions to use for generating programs.
This list has priority over `instruction_categories` and over `instruction_blocklist`,
thus adding instructions on top of the categories.

The resulting instruction pool is:
     (instructions from instruction_categories - instruction_blocklist) + instruction_allowlist

```yaml
Name: program_generator_seed
Default: 0
```

Seed of the program generator. If set to zero, a random seed will be used for each run.


```yaml
Name: program_size
Default: 24
```

Number of instructions per program. The actual size might be larger because of the instrumentation.


```yaml
Name: avg_mem_accesses
Default: 12
```

Average number of memory accesses in generated programs.
The actual number will be random, but the average over all programs will be close to this value.

```yaml
Name: min_bb_per_function
Default: 1
```

Minimal number of basic blocks per function in generated programs.

```yaml
Name: max_bb_per_function
Default: 2
```

Maximal number of basic blocks per function in generated programs.

```yaml
Name: min_successors_per_bb
Default: 1
```

Minimal number of successors for each basic block in generated programs.

Note 1: this config option is a *hint*; it could be ignored if the instruction set does not
have the necessary instructions to satisfy it, or if a certain number of successor is required
for correctness

Note 2: If min_successors_per_bb > max_successors_per_bb, the value is
overwritten with max_successors_per_bb

```yaml
Name: max_successors_per_bb
Default: 1
```

Maximal number of successors for each basic block in generated programs.

Note: this config option is a *hint*; it could be ignored if the instruction set does not
have the necessary instructions to satisfy it, or if a certain number of successor is required
for correctness

```yaml
Name: register_allowlist
Default: []
Options: (any register names)
```

A list of registers that CAN be used for generating programs.

This list has higher priority than `register_blocklist`.
The resulting list is: (all registers - `register_blocklist`) + `register_allowlist`.

```yaml
Name: register_blocklist
Default: (all but RAX, RBX, RCX, RDX, RDI, RSI, XMM0-XMM7)
Options: (any register names)
```

A list of registers that will NOT be used for generating programs.

This list has lower priority than `register_allowlist`.
The resulting list is: (all registers - `register_blocklist`) + `register_allowlist`.

The default blocked registers are used by the executor internally, and thus should be avoided.

```yaml
Name: generator_faults_allowlist
Default: []
Options: 'div-by-zero' | 'div-overflow' | 'opcode-undefined' | 'bounds-range-exceeded' | 'breakpoint' | 'debug-register' | 'non-canonical-access' | 'user-to-kernel-access'
```

By default, the generator will produce programs that never trigger exceptions.
This option modifies this behavior by permitting the generator to produce 'unsafe' instruction sequences
that could potentially trigger an exception. The model and executor will also be configured to handle
these exceptions gracefully.

The available options are:

* `div-by-zero` - generate divisions with unmasked divisor, which can cause a division by zero exception.
* `div-overflow` - generate divisions with unmasked dividend, which can cause an overflow exception.
* `opcode-undefined` - generate undefined opcodes, which can cause an undefined opcode exception.
* `bounds-range-exceeded` - apply MPX instructions for random bounds checks.
  This is possible only if MPX is included in the tested instruction set.
* `breakpoint` - generate breakpoints, which can cause INT3 exceptions.
* `debug-register` - generate instructions that cause INT1 exceptions.
* `non-canonical-access` - randomly select a memory access in a generated program and instrument it to access a non-canonical address.
* `user-to-kernel-access` - randomly select memory access instructions in user-privilege actors and instrument them to access the kernel actor's (actor 0) memory. This creates cross-privilege-level memory access patterns useful for detecting CPU vulnerabilities like Meltdown. Requires at least one actor with `privilege_level: user`. The instrumentation modifies both the memory operands and the sandboxing masks to ensure accesses target the kernel's FAULTY data area.

## Actor Configuration

All actors are defined in the `actors` list, with the following syntax:

```yaml
actors:
  - <actor1_name>
    - <actor_option>: <value>
    - <actor_option>:
       - <sub_option1>: <value1>
       - <sub_option2>: <value2>
    ...
  - <actor2_name>
      ...
  ...
```

The following options are available for each actor:

```yaml
Actor Option: mode
Default: 'host'
Options: 'host' | 'guest'
```

The execution mode of the actor. The available options are:

* `host` - the actor runs in the normal, non-virtualized mode.
* `guest` - the actor runs in a VM (one VM per actor).

```yaml
Actor Option: privilege_level
Default: 'kernel'
Options: 'user' | 'kernel'
```

The privilege level of the actor. The available options are:

* `user` - the actor runs in user mode (CPL=3).
* `kernel` - the actor runs in kernel mode (CPL=0).

```yaml
Actor Option: data_properties
Default: (see below)
Options: 'present' | 'writable' | 'user' | 'accessed'
         | 'dirty' | 'executable' | 'reserved_bit' | 'randomized'
```

The properties of the data memory used by the actor.
These properties are applied only to the second page (FAULTY_AREA) of the actor's data region.

The available options are:

* `present` [default: True] - the value of the Present bit in the page table entry.
* `writable` [default: True] - the value of the Writable bit in the page table entry.
* `user` [default: False] - the value of the User/Supervisor bit in the page table entry.
* `accessed` [default: True] - the value of the Accessed bit in the page table entry.
* `dirty` [default: True] - the value of the Dirty bit in the page table entry.
* `executable` [default: False] - the value of the Executable bit in the page table entry.
* `reserved_bit` [default: False] - the value of the Reserved bit in the page table entry.
* `randomized` [default: False] - if true, the values of the above properties will be randomized for each test case.

Note that the above properties are set in the host page tables for actors with `mode: host`,
and in the guest page tables for actors with `mode: guest`.

```yaml
Actor Option: data_ept_properties
Default: (see below)
Options: 'present' | 'writable' | 'executable' | 'accessed' | 'dirty' | 'user'
        | 'reserved_bit' | 'randomized'
```

The properties of the EPT entry used by the actor (on Intel) or the NPT entry (on AMD).
The properties are applied only to the second page (FAULTY_AREA) of the actor's data region.

This property has no effect on actors with `mode: host`.

The available options are:

* `present` [default: True] - the value of the Present bit in the EPT/NPT entry.
* `writable` [default: True] - the value of the Writable bit in the EPT/NPT entry.
* `executable` [default: False] - the value of the Executable bit in the EPT/NPT entry.
* `accessed` [default: True] - the value of the Accessed bit in the EPT/NPT entry.
* `dirty` [default: True] - the value of the Dirty bit in the EPT/NPT entry.
* `user` [default: False] - the value of the User/Supervisor bit in the EPT/NPT entry.
* `reserved_bit` [default: False] - the value of the Reserved bit in the EPT/NPT entry.
* `randomized` [default: False] - if true, the values of the above properties will be randomized for each test case.

```yaml
Actor Option: observer
Default: False
```

If enabled, the actor will be an observer actor, hence modelling an attacker.
This option is only used if the contract is `noninterference`, and it is ignored otherwise.

```yaml
Actor Option: instruction_blocklist
Default: []
Options: (any instruction names)
```

Actor-specific instruction blocklist. This list has priority over the global `instruction_blocklist`.

```yaml
Actor Option: fault_blocklist
Default: []
Options: (any fault names from generator_faults_allowlist)
```

Actor-specific fault blocklist. This list has priority over the global `generator_faults_allowlist` and prevents specific actors from having certain fault-inducing instrumentation applied to their code.

For example, when using `user-to-kernel-access`, you typically want to add it to the kernel actor's `fault_blocklist` to prevent the kernel from accessing its own memory (which would not be a cross-privilege access).

## Input Generator Configuration

```yaml
Name: data_generator
Default: 'random'
Options: 'random'
```

The input generator type. Currently, only random input generation is supported.

```yaml
Name: data_generator_seed
Default: 10
```

Seed of the input generator. If set to zero, a random seed will be used for each run.

```yaml
Name: data_generator_entropy_bits
Default: 16
```

Entropy of the random values created by the input generator. The maximum value is 31.

```yaml
Name: input_gen_probability_of_special_value
Default: 0.05
```

If non-zero, the input generator will generate not only random values for the input data, but also, with a given probability,
special values, such as zero or the maximum integer value (MAX INT). This is used to test fast paths in the microarchitecture.

```yaml
Name: inputs_per_class
Default: 2
```

Number of inputs generated for each input class by the Contract-Driven Input Generator.
For the explanation of the input classes and the generation algorithm, see (this paper)[https://arxiv.org/pdf/2301.07642], Section 4.D. Contract-driven Input Generator.

## Contract Configuration

```yaml
Name: contract_execution_clause
Default: ['seq']
Options: 'seq' | 'no_speculation' | 'seq-assist' | 'cond' | 'conditional_br_misprediction' | 'bpas' | 'nullinj-fault' | 'nullinj-assist' | 'delayed-exception-handling' | 'div-zero' | 'div-overflow' | 'meltdown' | 'fault-skip' | 'noncanonical' | 'vspec-ops-div' | 'vspec-ops-memory-faults' | 'vspec-ops-memory-assists' | 'vspec-ops-gp' | 'vspec-all-div' | 'vspec-all-memory-faults' | 'vspec-all-memory-assists'
```

The execution clause of the contract.

* `seq` - sequential execution.
* `no_speculation` - sequential execution. Synonym for `seq`.
* `seq-assist` - sequential execution with possible microcode assists.
* `cond` - permitted misprediction of conditional branches.
* `conditional_br_misprediction` - permitted misprediction of conditional branches. Synonym for `cond`.
* `bpas` - permitted speculative store bypass
* `nullinj-fault` - page faults are permitted to speculatively return zero.
* `nullinj-assist` - microcode assists are permitted to speculatively return zero.
* `delayed-exception-handling` - upon an exception or a fault, data-independent instructions that follow the exception are allowed to execute speculatively.
* `meltdown` - permission-based page faults are permitted to speculatively return the value in the memory.
* `fault-skip` - upon a fault, the faulting instruction is speculatively skipped.
* `noncanonical` - permitted speculative non-canonical memory accesses.
* `vspec*` - experimental contracts for value speculation. See (this paper)[https://www.usenix.org/system/files/usenixsecurity23-hofmann.pdf] for details.
* `div-zero` - experimental contract; do not use.
* `div-overflow` - experimental contract; do not use.

```yaml
Name: contract_observation_clause
Default: 'ct'
Options: 'none' | 'l1d' | 'memory' | 'pc' | 'ct' | 'loads+stores+pc' | 'ct-nonspecstore' | 'ctr' | 'arch' | 'tct' | 'tcto' | 'ct-ni'
```

The observation clause of the contract. In most cases, the default value should be used.

For single-actor experiments, the following options are available:

* `none` - the model observes nothing. Useful for testing the fuzzer.
* `l1d` - the model observes the addresses of data accesses, adjusted to imitate the L1D cache trace.
  Has very few real applications, and should be generally avoided.
* `memory` - the model observes the addresses of data accesses.
* `ct` (constant time tracer) - the model observes the addresses of data accesses and the control flow.
* `loads+stores+pc` - the model observes the addresses of data accesses and the control flow. Synonym for `ct`.
* `ct-nonspecstore` - the model observes the addresses of data accesses and the control flow, but does not observe the addresses of stores during speculation.
* `ctr` - the model observes the addresses of data accesses and the control flow, as well as the values of the general-purpose registers.
* `arch` - the model observes the addresses of data accesses and the control flow, as well as the values loaded from memory.
  This clause imitates the security guarantees provided by secure speculation mechanisms like STT.
* `tct` (truncated constant time tracer) - the model observes address of the memory access and of the program counter at cache line granularity.
* `tcto` (truncated constant time tracer with overflows) - the model address of the memory access and of the program counter at cache line granularity + observe cache line overflows.

In multi-actor context, only one option is available:

* `ct-ni` - when executing actors with `observer: false`, the model observes the same data as as with `ct`. When executing actors with `observer: true`, the model observes complete memory of the actor as well as their register values.

```yaml
Name: model_backend
Default: 'unicorn'
Options: 'dummy' | 'unicorn' | 'dynamorio'
```

The backend used to implement the contract model. The available options are:
* `unicorn` - use the Unicorn emulator. This is the default option and it is recommended for most cases.
* `dynamorio` - use the DynamoRIO dynamic binary instrumentation framework. This option is newly added and experimental. Avoid using it unless you are doing development work on Revizor.
* `dummy` - use a dummy model. This model always returns the same (empty) contract trace, and as such will not produce meaningful results. This option is useful, however, when root-causing violations, because it allows to collect hardware traces without running the model, hence allowing to trace instructions that are not supported by any of the backends.

```yaml
Name: model_min_nesting
Default: 1
```

Minimum number of nested mispredictions in the model.
This value is used to generate the contract traces on the fast path of the fuzzer.

```yaml
Name: model_max_nesting
Default: 30
```

Maximum number of nested mispredictions in the model.
This value is used to generate the contract traces on the slow path of the fuzzer,
i.e., when a potential violation is detected and the fuzzer tries to check if it is a true positive.

```yaml
Name: model_max_spec_window
Default: 250
```

Size of the speculation window in the model.

## Executor Configuration

```yaml
Name: executor
Default: (auto-detected)
Options: 'x86-64-intel' | 'x86-64-amd' | 'arm64'
```

The executor type. The default value is auto-detected based on the `cpuinfo`.
Should be changed only if the auto-detection fails.

```yaml
Name: executor_mode
Default: 'P+P'
Options: 'P+P' | 'F+R' | 'E+R' | 'PP+P' | 'TSC'
```

Hardware trace collection mode. The available options are:

* `P+P` - prime and probe.
* `F+R` - flush and reload.
* `E+R` - evict and reload.
* `PP+P` - partial prime and probe (i.e., leave a subset of cache lines unprimed).
* `TSC` - use RDTSCP instruction to measure the time of the execution.

```yaml
Name: executor_warmups
Default: 5
```

Number of warmup rounds executed before starting to collect hardware traces.

```yaml
Name: executor_sample_sizes
Default: [10, 50, 100, 500]
```

A list of sample sizes to be used during the measurements.
The executor will first collect the hardware traces with the first sample size in the list,
and if a violation is detected, it will try to reproduce it with all the following sample sizes.

```yaml
Name: executor_filtering_repetitions
Default: 10
```

The sample size to be used by the speculation and observation filters.

```yaml
Name: executor_taskset
Default: 0
```

The ID of the CPU core on which the executor is running test cases.

```yaml
Name: enable_pre_run_flush
Default: True
```

If enabled, the executor will do its best to flush the microarchitectural state before running test cases.

```yaml
Name: x86_executor_enable_ssbp_patch
Default: True
```

Enable a microcode patch against Speculative Store Bypass, if available.

```yaml
Name: x86_executor_enable_prefetcher
Default: False
```

Enable all prefetchers, if the software controls are available.

```yaml
Name: x86_disable_div64
Default: True
```

Do not generate 64-bit division instructions.
Useful for avoiding certain types of speculation that are specific to 64-bit division.

```yaml
Name: x86_enable_hpa_gpa_collisions
Default: False
```

When a test case contains at least one guest actor, allocate its memory in the guest physical address space to match the corresponding host physical addresses of the main actor.
Useful for testing Foreshadow-like leaks.

```yaml
Name: x86_generator_align_locks
Default: True
```

When generating memory accesses with locks, apply instrumentation to align the locks to 8 bytes.
Useful for avoiding faults on unaligned accesses.


## Analyser Configuration

```yaml
Name: analyser
Default: 'chi2'
Options: 'chi2' | 'mwu' | 'sets' | 'bitmaps'
```

The type of the analyser that is used to compare the hardware traces and contract traces.

The available options are:

* `sets` - combine the hardware traces for each input into a set. A violation is reported if two inputs in the same contract-equivalence class have different sets of hardware traces.
* `bitmaps` - combine the hardware traces for each input into a bitmap. A violation is reported if two inputs in the same contract-equivalence class have different bitmaps of hardware traces.
* `chi2` - use the chi-squared homogeneity test to compare the hardware traces of inputs in the same contract-equivalence class. This test effectively checks if the hardware traces from two different inputs come from the same distribution. A violation is reported if the test fails.
* `mwu` - [experimental; both false positives and negatives are possible]
  use the Mann-Whitney U test to compare the hardware traces of inputs in the same contract-equivalence class. This test effectively checks if the hardware traces from two different inputs come from the same distribution. A violation is reported if the test fails.

```yaml
Name: analyser_subsets_is_violation
Default: False
```

This option is relevant only for the `sets` and `bitmaps` analysers.

If enabled, the analyser will not label hardware traces as mismatching if they form a subset relation.

```yaml
Name: analyser_outliers_threshold
Default: 0.1
```

This option is relevant only for the `sets` and `bitmaps` analysers.

The analyser will ignore the hardware traces that appear in less than this percentage of the repetitions.

```yaml
Name: analyser_stat_threshold
Default: 0.5
```

This option is relevant only for the `chi2` and `mwu` analysers.

The threshold for the statistical tests. If a pair of hardware traces has the (normalized) statistics below the threshold,
then the traces are considered equivalent.

For the chi2 test, the threshold is applied to the `statistics / (len(htrace1) + len(htrace2))`.

For the mwu test, the threshold is applied to the p-value.


## Miscellaneous Configuration

```yaml
Name: coverage_type
Default: 'none'
Options: 'none' | 'model_instructions'
```

The type of coverage tracking. The available options are:

* `none` - disable coverage tracking.
* `model_instructions` - track how many times the model executed each instruction.

```yaml
Name: minimizer_retries
Default: 1
```

Number of minimization retries. When the minimizer performs a check to reduce a test case, each check is attempted this number of times and it succeeds if at least one check is successful.
