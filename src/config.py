"""
File: Fuzzing Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List, Dict
from .x86 import x86_config


class ConfigException(SystemExit):
    pass


class ConfCls:
    config_path: str = ""
    # ==============================================================================================
    # Fuzzer
    fuzzer: str = "basic"
    """ fuzzer: type of the fuzzing algorithm """
    ignore_flaky_violations: bool = True
    """ ignore_flaky_violations: if True, don't report non-reproducible violations """
    enable_priming: bool = True
    """ enable_priming: whether to check violations with priming """
    enable_speculation_filter: bool = False
    """ enable_speculation_filter: if True, discard test cases that don't trigger speculation"""
    enable_observation_filter: bool = False
    """ enable_observation_filter: if True,discard test cases that don't leave speculative traces"""

    # ==============================================================================================
    # Execution Environment
    permitted_faults: List[str] = []
    """ permitted_faults: a list of faults that are permitted to happen during testing """

    # ==============================================================================================
    # Program Generator
    generator: str = "random"
    """ generator: type of the program generator """
    instruction_set: str = "x86-64"
    """ instruction_set: ISA under test """
    instruction_categories: List[str] = []
    """ instruction_categories: list of instruction categories to use for generating programs """
    instruction_blocklist: List[str] = []
    """ instruction_blocklist: list of instruction that will NOT be used for generating programs """
    program_generator_seed: int = 0
    """ program_generator_seed: seed of the program generator """
    program_size: int = 24
    """ program_size: size of generated programs """
    avg_mem_accesses: int = 12
    """ avg_mem_accesses: average number of memory accesses in generated programs """
    min_bb_per_function: int = 2
    """ min_bb_per_function: minimal number of basic blocks per function in generated programs """
    max_bb_per_function: int = 2
    """ max_bb_per_function: maximum number of basic blocks per function in generated programs """
    min_successors_per_bb: int = 1
    """ min_bb_per_function: min. number of successors for each basic block in generated programs
    Note 1: this config option is a *hint*; it could be ignored if the instruction set does not
    have the necessary instructions to satisfy it, or if a certain number of successor is required
    for correctness
    Note 2: If min_successors_per_bb > max_successors_per_bb, the value is
    overwritten with max_successors_per_bb """
    max_successors_per_bb: int = 2
    """ min_bb_per_function: min. number of successors for each basic block in generated programs
    Note: this config option is a *hint*; it could be ignored if the instruction set does not
    have the necessary instructions to satisfy it, or if a certain number of successor is required
    for correctness """
    register_blocklist: List[str] = []
    """ register_blocklist: list of registers that will NOT be used for generating programs """
    avoid_data_dependencies: bool = False
    """ [DEPRECATED] avoid_data_dependencies: """
    generate_memory_accesses_in_pairs: bool = False
    """ [DEPRECATED] generate_memory_accesses_in_pairs: """
    feedback_driven_generator: bool = False
    """ [DEPRECATED] feedback_driven_generator: """

    # ==============================================================================================
    # Input Generator
    input_generator: str = 'random'
    """ input_generator: type of the input generator """
    input_gen_seed: int = 10
    """ input_gen_seed: input generation seed; will use a random seed if set to zero """
    input_gen_entropy_bits: int = 16
    """ input_gen_entropy_bits: entropy of the random values created by the input generator """
    memory_access_zeroed_bits: int = 0
    """ [DEPRECATED] memory_access_zeroed_bits: """
    inputs_per_class: int = 2
    """ inputs_per_class: number of inputs per input class """
    input_main_region_size: int = 4096
    """ input_main_region_size: """
    input_faulty_region_size: int = 4096
    """ input_faulty_region_size: """
    input_register_region_size: int = 64
    """ input_register_region_size: """

    # ==============================================================================================
    # Contract Model
    model: str = 'x86-unicorn'
    """ model: """
    contract_execution_clause: List[str] = ["seq"]
    """ contract_execution_clause: """
    contract_observation_clause: str = 'ct'
    """ contract_observation_clause: """
    model_max_nesting: int = 5
    """ model_max_nesting: """
    model_max_spec_window: int = 250
    """ model_max_spec_window: """

    # ==============================================================================================
    # Executor
    executor: str = 'default'
    """ executor: executor type """
    executor_mode: str = 'P+P'
    """ executor_mode: hardware trace collection mode """
    executor_warmups: int = 50
    """ executor_warmups: number of warmup rounds executed before starting to collect
    hardware traces """
    executor_repetitions: int = 10
    """ executor_repetitions: number of repetitions while collecting hardware traces """
    executor_max_outliers: int = 1
    """ executor_max_outliers: """
    executor_taskset: int = 0
    """ executor_taskset: id of the CPU core on which the executor is running test cases """
    enable_pre_run_flush: bool = True
    """ enable_pre_run_flush: ff enabled, the executor will do its best to flush
    the microarchitectural state before running test cases """

    # ==============================================================================================
    # Analyser
    analyser: str = 'equivalence-classes'
    """ analyser: analyser type """
    analyser_permit_subsets: bool = True
    """ analyser_permit_subsets: if enabled, the analyser will not label hardware traces
    as mismatching if they form a subset relation """

    # ==============================================================================================
    # Coverage
    coverage_type: str = 'none'
    """ coverage_type: coverage type """

    # ==============================================================================================
    # Minimizer
    minimizer: str = 'violation'
    """ minimizer: type of the test case minimizer """

    # ==============================================================================================
    # Output
    multiline_output: bool = False
    """ multiline_output: """
    logging_modes: List[str] = ["info", "stat"]
    """ logging_modes: """
    color: bool = False

    # ==============================================================================================
    # Internal
    _borg_shared_state: Dict = {}
    _no_generation: bool = False
    _option_values: Dict[str, List] = {}  # set by ISA-specific config.py
    _default_instruction_blocklist: List[str] = []

    # Implementation of Borg pattern
    def __init__(self) -> None:
        self.setattr_internal("__dict__", self._borg_shared_state)

    def __setattr__(self, name, value):
        # print(f"CONF: setting {name} to {value}")

        # Sanity checks
        if name[0] == "_":
            raise ConfigException(
                f"ERROR: Attempting to set an internal configuration variable {name}.")
        if getattr(self, name, None) is None:
            raise ConfigException(f"ERROR: Unknown configuration variable {name}.\n"
                                  f"It's likely a typo in the configuration file.")
        if type(self.__getattribute__(name)) != type(value):
            raise ConfigException(f"ERROR: Wrong type of the configuration variable {name}.\n"
                                  f"It's likely a typo in the configuration file.")
        if name == "executor_max_outliers" and value > 20:
            print(f"WARNING: Configuration: Are you sure you want to"
                  f" ignore {self.executor_max_outliers} outliers?")
        if name == "coverage_type" and value > "none":
            super().__setattr__("feedback_driven_generator", "False")

        # value checks
        if self._option_values.get(name, '') != '':
            invalid = False
            if isinstance(value, List):
                for v in value:
                    if v not in self._option_values[name]:
                        invalid = True
                        break
            else:
                invalid = value not in self._option_values[name]
            if invalid:
                raise ConfigException(
                    f"ERROR: Unknown value '{value}' of config variable '{name}'\n"
                    f"Possible options: {self._option_values[name]}")
        if (self.input_main_region_size % 4096 != 0) or \
                (self.input_faulty_region_size % 4096 != 0):
            raise ConfigException("ERROR: Inputs must be page-aligned")
        if self.input_gen_entropy_bits + self.memory_access_zeroed_bits > 32:
            raise ConfigException(
                "ERROR: The sum of input_gen_entropy_bits and memory_access_zeroed_bits"
                " must be less or equal to 32 bits")

        # special handling
        if name == "instruction_set":
            super().__setattr__("instruction_set", value)
            self.update_arch()
            return

        if name == "instruction_blocklist":
            self._default_instruction_blocklist.extend(value)
            return

        super().__setattr__(name, value)

    def update_arch(self):
        # arch-specific config
        if self.instruction_set == "x86-64":
            config = x86_config
            prefix = "x86_"
        else:
            raise ConfigException(f"ERROR: Unknown architecture {self.instruction_set}")
        options = [i for i in dir(config) if i.startswith(prefix)]

        for option in options:
            values = getattr(config, option)
            trimmed_name = option.removeprefix(prefix)
            if trimmed_name == "option_values":
                self.setattr_internal("_option_values", values)
                continue

            if hasattr(self, trimmed_name):
                setattr(self, trimmed_name, values)
            else:
                super().__setattr__(option, values)

    def setattr_internal(self, name, val):
        """ Bypass value checks and set an internal config variable. Use with caution! """
        super().__setattr__(name, val)


CONF = ConfCls()
CONF.update_arch()
