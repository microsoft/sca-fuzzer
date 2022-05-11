"""
File: Fuzzing Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import x86.x86_config as x86_config
from typing import List, Dict


class ConfigException(SystemExit):
    pass


class ConfCls:
    config_path: str = ""
    # ==============================================================================================
    # Fuzzer
    no_priming = False
    min_primer_size: int = 1  # deprecated? # better leave at 1; otherwise may fail to build primer
    max_primer_size: int = 1000  # deprecated?
    # ==============================================================================================
    # Generator
    instruction_set = "x86-64"
    generator = "random"
    test_case_generator_seed: int = 0
    min_bb_per_function = 2
    max_bb_per_function = 2
    test_case_size = 24
    avg_mem_accesses = 12
    randomized_mem_alignment: bool = True
    avoid_data_dependencies: bool = False
    generate_memory_accesses_in_pairs: bool = False
    memory_access_zeroed_bits: int = 6
    extended_instruction_blocklist: List[str] = []
    gpr_blocklist: List[str] = []
    supported_categories: List[str] = []
    instruction_blocklist: List[str] = []
    # ==============================================================================================
    # Input Generator
    input_generator: str = 'random'
    input_gen_seed: int = 10  # zero is a reserved value, do not use it
    input_gen_entropy_bits: int = 3
    input_main_region_size: int = 4096
    input_assist_region_size: int = 4096
    input_register_region_size: int = 64
    inputs_per_class: int = 2
    # ==============================================================================================
    # Model
    model: str = 'x86-unicorn'
    contract_execution_clause: List[str] = ["seq"]  # options: "seq", "cond", "bpas"
    contract_observation_clause: str = 'ct'
    model_max_nesting: int = 5
    model_max_spec_window: int = 250
    # ==============================================================================================
    # Executor
    executor: str = 'x86-intel'
    executor_mode: str = 'P+P'
    executor_warmups: int = 50
    executor_repetitions: int = 20
    executor_max_outliers: int = 2
    executor_taskset: int = 0
    enable_ssbp_patch: bool = True
    enable_pre_run_flush: bool = True
    enable_assist_page: bool = False
    # ==============================================================================================
    # Analyser
    analyser: str = 'equivalence-classes'
    analyser_permit_subsets: bool = True
    # ==============================================================================================
    # Coverage
    coverage_type: str = 'none'
    feedback_driven_generator: bool = False  # temporary unused
    # ==============================================================================================
    # Output
    multiline_output: bool = False
    logging_modes: List[str] = ["info", "stat"]
    # ==============================================================================================
    # Internal
    _instance = None
    _no_generation: bool = False
    _option_values: Dict[str, List] = {
        'generator': ["random"],
        'input_generator': ["random"],
        'executor_mode': ['P+P', 'F+R', 'E+R'],
        'contract_observation_clause': [
            'l1d', 'memory', 'ct', 'pc', 'ct-nonspecstore', 'ctr', 'arch'
        ],
        'coverage_type': ['dependent-pairs', 'none'],
    }

    # Implementation of singleton
    def __new__(cls, *args, **kwargs):
        if not isinstance(cls._instance, cls):
            cls._instance = object.__new__(cls, *args, **kwargs)
        return cls._instance

    def __setattr__(self, name, value):
        # print(f"CONF: setting {name} to {value}")
        # sanity checks
        if name[0] == "_":
            raise ConfigException(f"Attempting to set an internal configuration variable {name}.")
        if getattr(self, name, None) is None:
            raise ConfigException(f"Unknown configuration variable {name}.\n"
                                  f"It's likely a typo in the configuration file.")
        if type(self.__getattribute__(name)) != type(value):
            raise ConfigException(f"Wrong type of the configuration variable {name}.\n"
                                  f"It's likely a typo in the configuration file.")
        if name == "executor_max_outliers" and value > 20:
            print(f"WARNING: Configuration: Are you sure you want to"
                  f" ignore {self.executor_max_outliers} outliers?")
        if name == "coverage_type" and value > "none":
            super().__setattr__("feedback_driven_generator", "False")

        # value checks
        if self._option_values.get(name, '') != '' and value not in self._option_values[name]:
            raise ConfigException(f"Unknown value '{value}' of configuration variable '{name}'")
        if (self.input_main_region_size % 4096 != 0) or \
                (self.input_assist_region_size % 4096 != 0):
            raise ConfigException("Inputs must be page-aligned")

        # special handling
        if name == "instruction_set":
            super().__setattr__("instruction_set", value)
            self.update_arch()
            return

        if name == "extended_instruction_blocklist":
            self.instruction_blocklist.extend(value)
            return

        super().__setattr__(name, value)

    def update_arch(self):
        # arch-specific config
        if self.instruction_set == "x86-64":
            config = x86_config
            prefix = "x86_"
        else:
            raise ConfigException(f"Unknown architecture {self.instruction_set}")
        options = [i for i in dir(config) if i.startswith(prefix)]

        for option in options:
            values = getattr(config, option)
            trimmed_name = option.removeprefix(prefix)
            if hasattr(self, trimmed_name):
                setattr(self, trimmed_name, values)
            else:
                setattr(self, option, values)


CONF = ConfCls()
CONF.instruction_set = "x86-64"
