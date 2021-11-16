"""
File: Fuzzing Configuration Options

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List


class ConfCls:
    # ==============================================================================================
    # Fuzzer
    priming_retries: int = 6
    no_priming = False
    min_primer_size: int = 10
    max_primer_size: int = 1000
    # ==============================================================================================
    # Generator
    instruction_set = "x86-64"
    generator = "random"
    min_bb_per_function = 1
    max_bb_per_function = 5
    max_bb_successors = 0  # zero -> automatically set based on the available instructions
    test_case_size = 32
    avg_mem_accesses = 12
    single_function_test_case = True
    avoid_data_dependencies: bool = True
    generate_memory_accesses_in_pairs: bool = True
    memory_access_zeroed_bits: int = 6
    supported_categories = [
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
        # "ROTATE",     # TBD: under construction
        # "SHIFT",      # TBD: under construction
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

        # "REPE LODSB", "REPE LODSD", "REPE LODSW",
        # "REPE SCASB", "REPE SCASD", "REPE SCASW",
        # "REPE STOSB", "REPE STOSD", "REPE STOSW",
        "REPE CMPSB", "REPE CMPSD", "REPE CMPSW",
        "REPE MOVSB", "REPE MOVSD", "REPE MOVSW",

        # "REPNE LODSB", "REPNE LODSD", "REPNE LODSW",
        # "REPNE SCASB", "REPNE SCASD", "REPNE SCASW",
        # "REPNE STOSB", "REPNE STOSD", "REPNE STOSW"
        "REPNE CMPSB", "REPNE CMPSD", "REPNE CMPSW",
        "REPNE MOVSB", "REPNE MOVSD", "REPNE MOVSW",
    ]
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
    ]
    # ==============================================================================================
    # Input Generator
    input_generator: str = 'random'
    input_generator_seed: int = 10  # zero is a reserved value, do not use it
    prng_entropy_bits: int = 3
    randomized_mem_alignment: bool = True
    input_main_region_size: int = 4096 // 8
    input_assist_region_size: int = (4096 - 64) // 8
    input_register_region_size: int = 64 // 8
    inputs_per_class: int = 3
    # ==============================================================================================
    # Model
    model: str = 'x86-unicorn'
    contract_execution_mode: List[str] = ["seq"]  # options: "seq", "cond", "bpas"
    contract_observation_mode: str = 'ct'
    max_nesting = 5
    max_speculation_window: int = 250
    dependency_tracking: bool = False
    # ==============================================================================================
    # Executor
    executor: str = 'x86-intel'
    measurement_cpu: int = 0
    warmups: int = 3
    num_measurements: int = 40
    max_outliers = 3
    attack_variant: str = 'P+P'
    enable_ssbp_patch: bool = True
    enable_pre_run_flush: bool = True
    enable_mds: bool = False
    # ==============================================================================================
    # Analyser
    analyser: str = 'equivalence-classes'
    max_subsets = 100
    ignore_first_cache_line = False
    dominant_traces = True
    compare_only_same_size = True
    ignore_single_entry_classes = True
    # ==============================================================================================
    # Coverage
    coverage_type: str = 'none'
    feedback_driven_generator: bool = True
    adaptive_input_number: bool = True
    combination_length_min: int = 1
    # ==============================================================================================
    # Output
    verbose: int = 0
    multiline_output: bool = False

    def __init__(self):
        if not self.dependency_tracking:
            self.inputs_per_class = 1

    def set(self, name, value):
        options = {
            'attack_variant': ['P+P', 'F+R', 'E+R'],
            'model': ['x86-unicorn'],
            'contract_observation_mode':
                ['l1d', 'memory', 'ct', 'pc', 'ct-nonspecstore', 'ctr', 'arch'],
            'coverage_type': ['dependencies', 'none'],
        }

        if getattr(self, name, None) is None:
            print(f"Error: Unknown configuration variable {name}.\n"
                  f"It's likely a typo in the configuration file.")
            exit(1)
        if type(self.__getattribute__(name)) != type(value):
            print(f"Error: Wrong type of the configuration variable {name}.\n"
                  f"It's likely a typo in the configuration file.")
            exit(1)

        # value checks
        # TODO: would be great to have more of these
        if options.get(name, '') != '' and value not in options[name]:
            print(f"Error: Unknown value '{value}' of configuration variable '{name}'")
            exit(1)

        self.__setattr__(name, value)


CONF = ConfCls()
