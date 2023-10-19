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

def try_get_cpu_vendor():
    try:
        import cpuinfo
        if 'AuthenticAMD' in cpuinfo.get_cpu_info()['vendor_id_raw']:
            return 'x86-64-amd'
        if 'GenuineIntel' in cpuinfo.get_cpu_info()['vendor_id_raw']:
            return 'x86-64-intel'
    except:
        pass
    return 'default'

class ConfigException(SystemExit):
    pass


class Conf:
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
    enable_fast_path_model: bool = True
    """ enable_fast_path_boosting: if enabled, the same contract trace will be used
    for all inputs in the same taint-based input class """
    enable_fast_path_executor: bool = True
    """ enable_fast_path_executor: if True, the executor will first collect hardware traces
    with (almost) no noise filtering, and will re-collect traces with noise filtering if
    a violation is detected
    """

    # ==============================================================================================
    # Execution Environment
    faulty_page_properties: List[str] = []
    """ faulty_page_properties: a list of page properties (e.g., present, writable) applied to
    the faulty page of the sandbox data area """

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
    generator_faults_allowlist: List[str] = []
    """ generator_faults_allowlist: by default, generator will produce programs that never
    trigger exceptions. This option modifies this behavior by permitting the generator to produce
    'unsafe' instruction sequences that could potentially trigger an exception. Model and executor
     will also be configured to handle these exceptions gracefully """

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
    executor: str = try_get_cpu_vendor()
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
    _option_values: Dict[str, List]  # set by ISA-specific config.py
    _default_instruction_blocklist: List[str] = []
    _faulty_page_properties_dict: Dict[str, bool] = {}
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
            if var == "faulty_page_properties":
                for v in value:
                    self.set_faulty_page_properties(v)
                continue
            if var == "actor":
                self.set_actor_properties(value)
                continue

            self.safe_set(var, value)

    def safe_set(self, name: str, value) -> None:
        assert name not in ["instruction_set", "instruction_blocklist", "faulty_page_properties"]

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
            if name == "faulty_page_properties":
                self.set_faulty_page_properties(value)
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
            if gen_fault not in self._generator_fault_to_fault_name:
                raise ConfigException(f"ERROR: Unknown generator fault {gen_fault}")
            fault = self._generator_fault_to_fault_name[gen_fault]
            if fault not in self._handled_faults:
                self._handled_faults.append(fault)

    def set_faulty_page_properties(self, new: Dict):
        for k, v in new.items():
            self._faulty_page_properties_dict[k] = v

    def set_actor_properties(self, new):
        self._check_options("actor", new)
        update = {k: v for tmp_dict in new for k, v in tmp_dict.items()}

        name = update['name']
        if name == "main":
            if update.get('mode', 'host') != 'host':
                raise ConfigException("ERROR: The main actor must be in host mode")

        if name in self._actors:
            entry = self._actors[name]
        else:
            entry = deepcopy(self._actor_default)

        for k, v in update.items():
            if k == "mode" and v not in self._option_values["actor_mode"]:
                raise ConfigException(f"ERROR: Unsupported actor mode {v}")
            entry[k] = v
        self._actors[name] = entry


CONF = Conf()
CONF.set_to_arch_defaults()
