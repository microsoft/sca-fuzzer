"""
File: Fuzzing Configuration Options

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List


class ConfCls:
    self_test_mode: bool = False
    # ==============================================================================================
    # Fuzzer
    priming_retries: int = 6
    no_priming = False
    min_primer_size: int = 10
    max_primer_size: int = 1000
    # ==============================================================================================
    # Generator
    min_bb_per_function = 2
    max_bb_per_function = 5
    max_bb_successors = 0  # zero -> automatically set based on the available instructions
    test_case_size = 64
    avg_mem_accesses = 32
    single_function_test_case = True
    avoid_data_dependencies: bool = True
    generate_memory_accesses_in_pairs: bool = True
    memory_access_zeroed_bits: int = 6
    delay_on_rax: bool = True
    supported_categories = ["NOP"]
    instruction_blocklist = [
        # STI - enables interrupts, thus corrupting the measurements; CTI - just in case
        "STI", "CLI",
        # Muls - mismatch in Unicorn
        "{load} IMUL", "{store} IMUL", "IMUL", "MUL", "REX MUL", "REX IMUL",
        # Bit count - mismatch in Unicorn; undefined flags
        "BSF", "BSR", "TZCNT", "LZCNT",
        # BT - also mismatch
        "BT", "BTC", "BTR", "BTS", "LOCK BT", "LOCK BTC", "LOCK BTR", "LOCK BTS",
        # IDIV - preventing overflows for signed division is tricky
        # I haven't figured it yet
        "IDIV", "REX IDIV",
        # Categories: "SHIFT", "ROTATE", -> again, flags
        # Bug in Unicorn? UP: I think I fixed it, but will keep it blocked just in case, for now
        "XOR",

        # Fixable:
        # CX-based conditional jumps and loops -> decoding not yet supported
        "JRCXZ", "JECXZ", "JCXZ", "LOOP", "LOOPE", "LOOPNE",
    ]
    # x86 executor internally uses R15, R14, RSP, RBP and, thus, they are excluded
    # segment registers are also excluded as we don't support their handling so far
    # same for CR* and DR*
    gpr_blocklist = [
        # free - rax, rbx, rcx, rdx, r8, r9, r10
        'R11', 'R12', 'R13', 'R14', 'R15', 'RSP', 'RBP', 'RDI', 'RSI',
        'R11D', 'R12D', 'R13D', 'R14D', 'R15D', 'ESP', 'EBP', 'EDI', 'ESI',
        'R11W', 'R12W', 'R13W', 'R14W', 'R15W', 'SP', 'BP', 'DI', 'SI',
        'R11B', 'R12B', 'R13B', 'R14B', 'R15B', 'SPL', 'BPL', 'DL', 'SL',
        'ES', 'CS', 'SS', 'DS', 'FS', 'GS',
        'CR0', 'CR2', 'CR3', 'CR4', 'CR8',
        'DR0', 'DR1', 'DR2', 'DR3', 'DR4', 'DR5', 'DR6', 'DR7'
    ]
    # ==============================================================================================
    # Input Generator
    prng_seed: int = 10  # zero is a reserved value, do not use it
    prng_entropy_bits: int = 32
    randomized_mem_alignment: bool = True
    # ==============================================================================================
    # Model
    model: str = 'x86-unicorn'
    contract_execution_mode: List[str] = ["seq"]  # options: "seq", "cond", "bpas"
    contract_observation_mode: str = 'ct'
    max_nesting = 5
    max_speculation_window: int = 250
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
    coverage_type: str = 'dependencies'
    feedback_driven_generator: bool = False
    combination_length_min: int = 1
    # ==============================================================================================
    # Output
    verbose: int = 0
    multiline_output: bool = False

    def set(self, name, value):
        options = {
            'attack_variant': ['P+P', 'F+R', 'E+R'],
            'model': ['x86-serializing', 'x86-unicorn'],
            'contract_observation_mode': ['l1d', 'memory', 'ct', 'pc', 'ct-nonspecstore', 'arch'],
        }

        if self.__getattribute__(name) is None:
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
