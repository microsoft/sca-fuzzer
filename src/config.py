"""
File: Fuzzing Configuration Options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List


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
    supported_categories = [
        # Base x86
        "BINARY",
        "BITBYTE",
        "CMOV",
        "COND_BR",
        "CONVERT",
        "DATAXFER",
        "FLAGOP",
        "LOGICAL",
        "MISC",
        "NOP",
        "POP",
        "PUSH",
        "SEMAPHORE",
        "SETCC",
        "STRINGOP",
        "ROTATE",
        "SHIFT",

        # "UNCOND_BR",   # Not supported: Complex control flow
        # "CALL",        # Not supported: Complex control flow
        # "RET",         # Not supported: Complex control flow

        # "SEGOP",       # Not supported: System instructions
        # "INTERRUPT",   # Not supported: System instructions
        # "IO",          # Not supported: System instructions
        # "IOSTRINGOP",  # Not supported: System instructions
        # "SYSCALL",     # Not supported: System instructions
        # "SYSRET",      # Not supported: System instructions
        # "SYSTEM",      # Not supported: System instructions

        # Extensions
        # "BMI1",
    ]
    instruction_blocklist = [
        # Hard to fix:
        # - STI - enables interrupts, thus corrupting the measurements; CLI - just in case
        "STI", "CLI",
        # - CMPXCHG8B - Unicorn doesn't execute the mem. access hook
        #   bug: https://github.com/unicorn-engine/unicorn/issues/990
        "CMPXCHG8B", "LOCK CMPXCHG8B",
        # - Undefined instructions are, well, undefined
        "UD", "UD2",
        # - Incorrect emulation
        "CPUID",
        # - Requires support of segment registers
        "XLAT", "XLATB",
        # - Requires special instrumentation to avoid #DE faults
        "IDIV", "REX IDIV",
        # - Requires complex instrumentation
        "ENTERW", "ENTER", "LEAVEW", "LEAVE",

        # Stringops - under construction
        "CMPSB", "CMPSD", "CMPSW",
        "MOVSB", "MOVSD", "MOVSW",

        "REPE LODSB", "REPE LODSD", "REPE LODSW",
        "REPE SCASB", "REPE SCASD", "REPE SCASW",
        "REPE STOSB", "REPE STOSD", "REPE STOSW",
        "REPE CMPSB", "REPE CMPSD", "REPE CMPSW",
        "REPE MOVSB", "REPE MOVSD", "REPE MOVSW",

        "REPNE LODSB", "REPNE LODSD", "REPNE LODSW",
        "REPNE SCASB", "REPNE SCASD", "REPNE SCASW",
        "REPNE STOSB", "REPNE STOSD", "REPNE STOSW",
        "REPNE CMPSB", "REPNE CMPSD", "REPNE CMPSW",
        "REPNE MOVSB", "REPNE MOVSD", "REPNE MOVSW",
        # - not supported
        "LFENCE", "MFENCE", "SFENCE", "CLFLUSH"
    ]  # yapf: disable
    extended_instruction_blocklist: List[str] = []
    # x86 executor internally uses R15, R14, RSP, RBP and, thus, they are excluded
    # segment registers are also excluded as we don't support their handling so far
    # same for CR* and DR*
    gpr_blocklist = [
        # free - rax, rbx, rcx, rdx, rdi, rsi
        'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'RSP', 'RBP',
        'R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D', 'ESP', 'EBP',
        'R8W', 'R9W', 'R10W', 'R11W', 'R12W', 'R13W', 'R14W', 'R15W', 'SP', 'BP',
        'R8B', 'R9B', 'R10B', 'R11B', 'R12B', 'R13B', 'R14B', 'R15B', 'SPL', 'BPL',
        'ES', 'CS', 'SS', 'DS', 'FS', 'GS',
        'CR0', 'CR2', 'CR3', 'CR4', 'CR8',
        'DR0', 'DR1', 'DR2', 'DR3', 'DR4', 'DR5', 'DR6', 'DR7'
    ]  # yapf: disable
    _no_generation: bool = False
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
    executor_repetitions: int = 40
    executor_max_outliers: int = 3
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

    def set(self, name, value):
        options = {
            'instruction_set': ["x86-64"],
            'generator': ["random"],
            'input_generator': ["random"],
            'model': ['x86-unicorn'],
            'executor': ['x86-intel'],
            'executor_mode': ['P+P', 'F+R', 'E+R'],
            'contract_observation_clause': [
                'l1d', 'memory', 'ct', 'pc', 'ct-nonspecstore', 'ctr', 'arch'
            ],
            'coverage_type': ['dependent-pairs', 'none'],
        }

        if name[0] == "_":
            ConfigException(f"Attempting to set an internal configuration variable {name}.")
        if getattr(self, name, None) is None:
            ConfigException(f"Unknown configuration variable {name}.\n"
                            f"It's likely a typo in the configuration file.")
        if type(self.__getattribute__(name)) != type(value):
            ConfigException(f"Wrong type of the configuration variable {name}.\n"
                            f"It's likely a typo in the configuration file.")

        # value checks
        if options.get(name, '') != '' and value not in options[name]:
            ConfigException(f"Unknown value '{value}' of configuration variable '{name}'")
        if (self.input_main_region_size % 4096 != 0) or \
                (self.input_assist_region_size % 4096 != 0):
            ConfigException("Inputs must be page-aligned")

        # special handling
        if name == "extended_instruction_blocklist":
            self.instruction_blocklist.extend(value)

        self.__setattr__(name, value)

    def sanity_check(self):
        if self.executor_max_outliers > 20:
            print(f"WARNING: Configuration: Are you sure you want to"
                  f" ignore {self.executor_max_outliers} outliers?")
        if self.coverage_type == "none":
            self.feedback_driven_generator = False


CONF = ConfCls()


class ConfigException(SystemExit):
    pass
