# Configuration File

Below is a list of the available configuration options for Revizor, which are passed down to Revizor via a config file.
For an example of how to write the config file, see [src/tests/big-fuzz.yaml](https://github.com/microsoft/sca-fuzzer/tree/main/src/tests/big-fuzz.yaml).

Some of the options are omitted from the list as they should not be used in a normal fuzzing campaign.
For a complete list, see `src/config.py`.

## Contract

* `contract_execution_clause` : List[str]: Execution clause.
  Available options: "seq", "cond", "bpas", "null-injection".
* `contract_observation_clause` [str]: Observation clause.
  Available options: "l1d", "memory", "ct", "pc", "ct-nonspecstore", "ctr", "arch".

## General Configuration

* `enable_priming` [bool]: priming.
* `logging_modes` List[str]: Verbosity of the output.
  Available options:
  `info` - general information about the progress of fuzzing;
  `stat` - statistics the end of the fuzzing campaign;
  `dbg_timestamp` - periodically print the timestamp during the fuzzing process;
  `dbg_violation` - detailed information about the fuzzing progress and about the detected vulnerabilities;
  `dbg_dump_htraces` - print ALL hardware traces (use carefully, produces lots of text);
  `dbg_dump_ctraces` - print ALL contract traces (use carefully, produces lots of text);
  `dbg_model` - print a detailed trace of ALL executions on the model (use carefully, produces lots of text);
  `dbg_coverage` - periodically report detailed information about the changes in coverage.
* `multiline_output` [bool]: Print each output message on a separate line.
  Preferred when piping the log into a file.

# Model Configuration

* `model` [str]: Model type.
  Only one option is currently supported - "unicorn" (default).
* `model_max_nesting` [int]: Maximum number of simulated mispredictions.
* `model_max_spec_window` [int]: Size of the speculation window.

# Generator Configuration

* `instruction_set`  [str]: Tested ISA.
  Only one option is currently supported - "x86-64" (default).
* `generator` [str]: Test case generator type.
  Only one option is currently supported - "random" (default).
* `program_generator_seed` [int]: Test case generation seed.
  Will use a random seed if set to zero.
* `min_bb_per_function` [int]: Minimum number of basic blocks per test case.
* `max_bb_per_function` [int]: Maximum number of basic blocks per test case.
* `program_size` [int]: Number of instructions per test case.
  The actual size might be larger because of the instrumentation.
* `avg_mem_accesses` [int]: Average number of memory accesses per test case.
* `instruction_allowlist` [list(str)]: List of instructions to use for generating programs; combined with instruction_categories; has priority over instruction_blocklist.
  Used to select instructions from the instruction set file passed via command line (`--instruction-set`).
* `instruction_categories` [list(str)]: List of instruction categories to be used when generating programs.
  Used to filter out instructions from the instruction set file passed via command line (`--instruction-set`).
* `instruction_blocklist` [list(str)]: List of instructions to be excluded by the generator.
  Filters out instructions from instruction_categories, but not from instruction_allowlist.
* `generator_faults_allowlist` [list(str)]: by default, generator will produce programs that never trigger exceptions. This option modifies this behavior by permitting the generator to produce 'unsafe' instruction sequences that could potentially trigger an exception. Model and executor will also be configured to handle these exceptions gracefully

# Input Generator Configuration

* `input_generator` [str]: Input generator type.
  Only one option is currently supported - "random" (default)
* `input_gen_seed` [int]: Input generation seed.
  Will use a random seed if set to zero.
* `input_gen_entropy_bits` [int]: Entropy of the random values created by the input generator.
* `inputs_per_class` [int]: Number of inputs per input class.

# Executor Configuration

* `executor` [str]: Executor type.
  Only one option is currently supported - "default".
* `executor_mode` [str]: Hardware trace collection mode.
  Available options: 'P+P' - prime and probe; 'F+R' - flush and reload; 'E+R' - evict and reload.
* `executor_warmups` [int]: Number of warmup rounds executed before starting to collect hardware traces.
* `executor_repetitions` [int]: Number of repetitions while collecting hardware traces.
* `executor_taskset` [int]: CPU number on which the executor is running test cases.
* `enable_pre_run_flush` [bool]: If enabled, the executor will do its best to flush the microarchitectural state before running test cases.
  Enabled by default.

# Analyser Configuration

* `analyser` [str]: Analyser type.
  Only one option is currently supported - "equivalence-classes" (default).
* `analyser_permit_subsets` [bool]: If enabled, the analyser will not label hardware traces as mismatching if they form a subset relation.
  Enabled by default.

# Coverage Configuration

* `coverage_type` [str]: Coverage type.
  Available options:
  'none' - disable coverage tracking (default);
  'model_instructions' - how many times the model executed each instruction.


# x86-specific configuration

* `x86_executor_enable_ssbp_patch` [bool]: Enable a patch against Speculative Store Bypass.
  Enabled by default.
* `x86_executor_enable_prefetcher` [bool]: Enable all pretechers.
  Disabled by default.
