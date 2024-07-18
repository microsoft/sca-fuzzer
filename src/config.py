"""
File: Fuzzing Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import yaml
from copy import deepcopy
from typing import List, Dict
from collections import OrderedDict
from .x86 import x86_config


class ConfigException(SystemExit):
    pass


class Conf:
    config_path: str = ""
    # ==============================================================================================
    # Fuzzer
    fuzzer: str = "basic"
    """ fuzzer: type of the fuzzing algorithm """
    enable_priming: bool = True
    """ enable_priming: whether to check violations with priming """
    enable_speculation_filter: bool = False
    """ enable_speculation_filter: if True, discard test cases that don't trigger speculation"""
    enable_observation_filter: bool = False
    """ enable_observation_filter: if True,discard test cases that don't leave speculative traces"""
    enable_fast_path_model: bool = True
    """ enable_fast_path_boosting: if enabled, the same contract trace will be used
    for all inputs in the same taint-based input class """

    # ==============================================================================================
    # Program Generator
    generator: str = "random"
    """ generator: type of the program generator """
    instruction_set: str = "x86-64"
    """ instruction_set: ISA under test """
    instruction_categories: List[str] = []
    """ instruction_categories: list of instruction categories to use for generating programs """
    instruction_allowlist: List[str] = []
    """ instruction_allowlist: list of instructions to use for generating programs;
    combined with instruction_categories; has priority over instruction_blocklist.
    The resulting list is:
     (instructions from instruction_categories - instruction_blocklist) + instruction_allowlist """
    instruction_blocklist: List[str] = []
    """ instruction_blocklist: list of instruction that will NOT be used for generating programs;
    filters out instructions from instruction_categories, but not from instruction_allowlist.
    The resulting list is:
     (instructions from instruction_categories - instruction_blocklist) + instruction_allowlist """
    program_generator_seed: int = 0
    """ program_generator_seed: seed of the program generator """
    program_size: int = 24
    """ program_size: size of generated programs """
    avg_mem_accesses: int = 12
    """ avg_mem_accesses: average number of memory accesses in generated programs """
    min_bb_per_function: int = 1
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
    max_successors_per_bb: int = 1
    """ min_bb_per_function: min. number of successors for each basic block in generated programs
    Note: this config option is a *hint*; it could be ignored if the instruction set does not
    have the necessary instructions to satisfy it, or if a certain number of successor is required
    for correctness """
    register_allowlist: List[str] = []
    """ register_allowlist: list of registers that CAN be used for generating programs;
     has higher priority than register_blocklist.
     The resulting list is: (all registers - register_blocklist) + register_allowlist """
    register_blocklist: List[str] = []
    """ register_blocklist: list of registers that will NOT be used for generating programs;
     has lower priority than register_allowlist.
     The resulting list is: (all registers - register_blocklist) + register_allowlist """
    generator_faults_allowlist: List[str] = []
    """ generator_faults_allowlist: by default, generator will produce programs that never
    trigger exceptions. This option modifies this behavior by permitting the generator to produce
    'unsafe' instruction sequences that could potentially trigger an exception. Model and executor
     will also be configured to handle these exceptions gracefully """

    avoid_data_dependencies: bool = False
    """ [DEPRECATED] avoid_data_dependencies: """
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

    # ==============================================================================================
    # Contract Model
    model: str = 'x86-unicorn'
    """ model: """
    contract_execution_clause: List[str] = ["seq"]
    """ contract_execution_clause: """
    contract_observation_clause: str = 'ct'
    """ contract_observation_clause: """
    model_min_nesting: int = 1
    """ model_max_nesting: """
    model_max_nesting: int = 30
    """ model_max_nesting: """
    model_max_spec_window: int = 250
    """ model_max_spec_window: """

    # ==============================================================================================
    # Executor
    executor: str = x86_config.try_get_cpu_vendor()
    """ executor: executor type """
    executor_mode: str = 'P+P'
    """ executor_mode: hardware trace collection mode """
    executor_warmups: int = 5
    """ executor_warmups: number of warmup rounds executed before starting to collect
    hardware traces """
    executor_sample_sizes: List[int] = [10]
    """ executor_sample_sizes: a list of sample sizes to be used during the measurements;
    the executor will first collect the hardware traces with the first sample size in the list,
    and if a violation is detected, it will try to reproduce it with all the following
    sample sizes """
    executor_filtering_repetitions: int = 10
    """ executor_filtering_repetitions: number of repetitions while filtering test cases """
    executor_taskset: int = 0
    """ executor_taskset: id of the CPU core on which the executor is running test cases """
    enable_pre_run_flush: bool = True
    """ enable_pre_run_flush: if enabled, the executor will do its best to flush
    the microarchitectural state before running test cases """

    # ==============================================================================================
    # Analyser
    analyser: str = 'chi2'
    """ analyser: type of the analyser """
    analyser_subsets_is_violation: bool = False
    """ analyser_subsets_is_violation: [only for analyser='sets' or analyser='bitmaps']
    if False, the analyser will not label hardware traces as mismatching if they form
    a subset relation """
    analyser_outliers_threshold: float = 0.1
    """ analyser_outliers_threshold: [only for analyser='sets' or analyser='bitmaps']
    analyser will ignore the htraces that appear in less then this percentage of the repetitions.
    I.e., a htrace passes the filter if it is observed at least
        (analyser_outliers_threshold * len(htrace)) times """
    analyser_stat_threshold: float = 0.5
    """ analyser_stat_threshold: [only for analyser='chi2' and analyser='mwu']
    Threshold for the statistical tests. If a pair of hardware traces has the (normalized)
    statistics below the threshold, then the traces are considered equivalent.

    Note: The threshold default value (0.5) is conservative and avoids false positives
    at cost of false negatives. For more precise results, set the threshold to a lower value.

    For the chi2 test, the threshold is the statistics / (len(htrace1) + len(htrace2))
    For the mwu test, the threshold is the p-value """

    # ==============================================================================================
    # Coverage
    coverage_type: str = 'none'
    """ coverage_type: coverage type """

    # ==============================================================================================
    # Minimizer
    minimizer: str = 'violation'
    """ minimizer: type of the test case minimizer """
    minimizer_retries: int = 1
    """ minimizer_retries: number of attempts to reproduce the violation when minimizing """

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
    _option_values: Dict[str, List]  # set by ISA-specific config.py
    _default_instruction_blocklist: List[str] = []
    _handled_faults: List[str]  # set by ISA-specific config.py
    _generator_fault_to_fault_name: Dict[str, str]  # set by ISA-specific config.py
    _actors: OrderedDict[str, Dict]
    _actor_default: Dict

    def __init__(self) -> None:
        # implementation of Borg pattern
        setattr(self, '__dict__', self._borg_shared_state)
        if not getattr(self, '_actors', None):
            self._actors = OrderedDict()

    def load(self, config_path: str) -> None:
        self.config_path = config_path
        with open(config_path, "r") as f:
            config_update: Dict = yaml.safe_load(f)

        # make sure to set the architecture-dependent defaults first
        if 'instruction_set' in config_update:
            self.instruction_set = config_update['instruction_set']
            self.set_to_arch_defaults()

        # set the rest of the options
        for var, value in config_update.items():
            # print(f"CONF: setting {name} to {value}")
            if var == "instruction_set":
                super().__setattr__("instruction_set", value)
                self.set_to_arch_defaults()
                continue
            if var == "instruction_blocklist":
                self._default_instruction_blocklist.extend(value)
                continue
            if var == "generator_faults_allowlist":
                self.update_handled_faults_with_generator_faults(value)
                self.safe_set(var, value)
                continue
            if var == "actors":
                self.set_actor_properties(value)
                continue

            self.safe_set(var, value)

    def safe_set(self, name: str, value) -> None:
        assert name not in ["instruction_set", "instruction_blocklist"]

        # sanity checks
        if name[0] == "_":
            raise ConfigException(
                f"ERROR: Attempting to set an internal configuration variable {name}.")
        if getattr(self, name, None) is None:
            raise ConfigException(f"ERROR: Unknown configuration variable {name}.\n"
                                  f"It's likely a typo in the configuration file.")
        if type(self.__getattribute__(name)) != type(value):
            raise ConfigException(f"ERROR: Wrong type of the configuration variable {name}.\n"
                                  f"It's likely a typo in the configuration file.")
        if self.input_gen_entropy_bits + self.memory_access_zeroed_bits > 32:
            raise ConfigException(
                "ERROR: The sum of input_gen_entropy_bits and memory_access_zeroed_bits"
                " must be less or equal to 32 bits")

        self._check_options(name, value)
        setattr(self, name, value)

    def _check_options(self, name: str, value) -> None:
        if name not in self._option_values:
            return
        options = self._option_values[name]

        invalid_value = None
        if isinstance(value, str):
            invalid_value = value if value not in options else None
        elif isinstance(value, List):
            for v in value:
                if v in options:
                    continue
                if isinstance(v, Dict):
                    for k in v:
                        if k not in options:
                            break
                    else:
                        continue
                invalid_value = v
                break
        else:
            raise ConfigException(f"ERROR: Unexpected type of config variable {name}")

        if invalid_value:
            raise ConfigException(
                f"ERROR: Unknown value '{invalid_value}' of config variable '{name}'\n"
                f"Possible options: {options}")
        return

    def set_to_arch_defaults(self):
        """ Set config options according to the architecture-specific defaults """

        if self.instruction_set == "x86-64":
            config = x86_config
        else:
            raise ConfigException(f"ERROR: Unknown architecture {self.instruction_set}")

        config_defaults = {}
        for c in dir(config):
            if c.startswith("__"):
                continue
            values = getattr(config, c)
            if type(values) not in [bool, int, float, str, dict, list]:
                continue
            config_defaults[c] = values

        if "_option_values" not in config_defaults:
            raise ConfigException("ERROR: ISA-specific config.py must define _option_values")

        for name, value in config_defaults.items():
            if name == "instruction_blocklist":
                self._default_instruction_blocklist.extend(value)
                continue
            if name == "generator_faults_allowlist":
                self.update_handled_faults_with_generator_faults(value)
                continue
            if name == "_actor_default":
                self._actor_default = deepcopy(value)
                self._actors = OrderedDict()
                self._actors['main'] = deepcopy(value)
                continue

            setattr(self, name, value)

    def update_handled_faults_with_generator_faults(self, new: List[str]):
        for gen_fault in new:
            if not gen_fault:
                continue
            if gen_fault not in self._generator_fault_to_fault_name:
                raise ConfigException(f"ERROR: Unknown generator fault {gen_fault}")
            fault = self._generator_fault_to_fault_name[gen_fault]
            if fault not in self._handled_faults:
                self._handled_faults.append(fault)

    def set_actor_properties(self, new):
        for actor_dict in new:
            name = next(iter(actor_dict))
            self._check_options("actor", actor_dict[name])
            update = {k: v for tmp_dict in actor_dict[name] for k, v in tmp_dict.items()}

            if name == "main":
                if update.get('mode', 'host') != 'host':
                    raise ConfigException("ERROR: The main actor must be in 'host' mode")
                if update.get('privilege_level', 'kernel') != 'kernel':
                    raise ConfigException(
                        "ERROR: The main actor must have 'kernel' privilege_level")

            if name in self._actors:
                entry = self._actors[name]
            else:
                entry = deepcopy(self._actor_default)

            for k, v in update.items():
                if k == "mode" and v not in self._option_values["actor_mode"]:
                    raise ConfigException(f"ERROR: Unsupported actor mode {v}")
                if k == "privilege_level" and v not in self._option_values["actor_privilege_level"]:
                    raise ConfigException(f"ERROR: Unsupported actor privilege_level {v}")

                if k == "data_properties":
                    for property_ in v:
                        for p_key, p_value in property_.items():
                            if p_key not in self._option_values["actor_data_properties"]:
                                raise ConfigException(
                                    f"ERROR: Unsupported actor data_properties value {p_key}")
                            entry[k][p_key] = p_value
                    continue
                if k == "data_ept_properties":
                    if update.get('mode', 'host') != 'guest':
                        raise ConfigException(
                            "ERROR: data_ept_properties can only be used in guest mode")
                    for property_ in v:
                        for p_key, p_value in property_.items():
                            if p_key not in self._option_values["actor_data_ept_properties"]:
                                raise ConfigException(
                                    f"ERROR: Unsupported actor data_ept_properties value {p_key}")
                            entry[k][p_key] = p_value
                    continue
                if k == "instruction_blocklist" or k == "fault_blocklist":
                    if v:
                        entry[k].update(v)
                    continue

                entry[k] = v
            self._actors[name] = entry


CONF = Conf()
CONF.set_to_arch_defaults()
