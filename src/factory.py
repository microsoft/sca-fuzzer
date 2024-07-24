"""
File: Configuration factory

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from typing import Tuple, Dict, Type, List, Callable

from . import input_generator, analyser, postprocessor, interfaces, model
from .x86 import x86_model, x86_executor, x86_fuzzer, x86_generator, x86_asm_parser, get_spec
from .config import CONF, ConfigException

GENERATORS: Dict[str, Type[interfaces.Generator]] = {
    "x86-64-random": x86_generator.X86RandomGenerator
}

INPUT_GENERATORS: Dict[str, Type[interfaces.InputGenerator]] = {
    'random': input_generator.NumpyRandomInputGenerator,
}

TRACERS: Dict[str, Type[model.UnicornTracer]] = {
    "none": model.NoneTracer,
    "l1d": model.L1DTracer,
    "pc": model.PCTracer,
    "memory": model.MemoryTracer,
    "ct": model.CTTracer,
    "loads+stores+pc": model.CTTracer,
    "ct-nonspecstore": model.CTNonSpecStoreTracer,
    "ctr": model.CTRTracer,
    "arch": model.ArchTracer,
    "tct": model.TruncatedCTTracer,
    "tcto": model.TruncatedCTWithOverflowsTracer,
}

X86_EXECUTION_CLAUSES: Dict[str, Type[x86_model.UnicornModel]] = {
    "seq": x86_model.X86UnicornSeq,
    "no_speculation": x86_model.X86UnicornSeq,
    "seq-assist": x86_model.X86SequentialAssist,
    "cond": x86_model.X86UnicornCond,
    "conditional_br_misprediction": x86_model.X86UnicornCond,
    "bpas": x86_model.X86UnicornBpas,
    "nullinj-fault": x86_model.X86UnicornNull,
    "nullinj-assist": x86_model.X86UnicornNullAssist,
    "delayed-exception-handling": x86_model.X86UnicornDEH,
    "div-zero": x86_model.X86UnicornDivZero,
    "div-overflow": x86_model.X86UnicornDivOverflow,
    "meltdown": x86_model.X86Meltdown,
    "fault-skip": x86_model.X86FaultSkip,
    "noncanonical": x86_model.X86NonCanonicalAddress,
    "vspec-ops-div": x86_model.x86UnicornVspecOpsDIV,
    "vspec-ops-memory-faults": x86_model.x86UnicornVspecOpsMemoryFaults,
    "vspec-ops-memory-assists": x86_model.x86UnicornVspecOpsMemoryAssists,
    "vspec-ops-gp": x86_model.x86UnicornVspecOpsGP,
    "vspec-all-div": x86_model.x86UnicornVspecAllDIV,
    "vspec-all-memory-faults": x86_model.X86UnicornVspecAllMemoryFaults,
    "vspec-all-memory-assists": x86_model.X86UnicornVspecAllMemoryAssists,
    "noninterference": x86_model.ActorNonInterferenceModel,
    "cond-bpas": x86_model.X86UnicornCondBpas,
    "cond-nullinj-fault": x86_model.X86NullInjCond,
}

EXECUTORS = {
    'x86-64-intel': x86_executor.X86IntelExecutor,
    'x86-64-amd': x86_executor.X86AMDExecutor,
}

ANALYSERS: Dict[str, Type[interfaces.Analyser]] = {
    'bitmaps': analyser.MergedBitmapAnalyser,
    'sets': analyser.SetAnalyser,
    'mwu': analyser.MWUAnalyser,
    'chi2': analyser.ChiSquaredAnalyser,
}

MINIMIZERS: Dict[str, Type[interfaces.Minimizer]] = {
    'violation': postprocessor.MainMinimizer,
}

SPEC_DOWNLOADERS: Dict[str, Type] = {
    'x86-64': get_spec.Downloader,
}

ASM_PARSERS: Dict[str, Type] = {
    'x86-64': x86_asm_parser.X86AsmParser,
}


def _get_from_config(options: Dict, key: str, conf_option_name: str, *args):
    GenCls = options.get(key, None)
    if GenCls:
        return GenCls(*args)

    raise ConfigException(
        f"ERROR: unknown value `{key}` of `{conf_option_name}` configuration option.\n"
        "  Available options are:\n  - " + "\n  - ".join(options.keys()))


def get_fuzzer(instruction_set, working_directory, testcase, inputs):
    if CONF.fuzzer == "architectural":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86ArchitecturalFuzzer(instruction_set, working_directory, testcase,
                                                     inputs)
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")
    elif CONF.fuzzer == "archdiff":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86ArchDiffFuzzer(instruction_set, working_directory, testcase,
                                                inputs)
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")
    elif CONF.fuzzer == "basic":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86Fuzzer(instruction_set, working_directory, testcase, inputs)
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")
    raise ConfigException("ERROR: unknown value of `fuzzer` configuration option")


def get_program_generator(instruction_set: interfaces.InstructionSetAbstract,
                          seed: int) -> interfaces.Generator:
    return _get_from_config(GENERATORS, CONF.instruction_set + "-" + CONF.generator,
                            "instruction_set", instruction_set, seed)


def get_asm_parser(generator: interfaces.Generator) -> interfaces.AsmParser:
    return _get_from_config(ASM_PARSERS, CONF.instruction_set, "instruction_set", generator)


def get_input_generator(seed: int) -> interfaces.InputGenerator:
    return _get_from_config(INPUT_GENERATORS, CONF.input_generator, "input_generator", seed)


def get_model(bases: Tuple[int, int], enable_mismatch_check_mode: bool = False) -> interfaces.Model:
    # observational clause of the contract
    tracer = _get_from_config(TRACERS, CONF.contract_observation_clause,
                              "contract_observation_clause")

    # execution clause of the contract
    if "cond" in CONF.contract_execution_clause and "bpas" in CONF.contract_execution_clause:
        clause_name = "cond-bpas"
    elif "conditional_br_misprediction" in CONF.contract_execution_clause and \
            "nullinj-fault" in CONF.contract_execution_clause:
        clause_name = "cond-nullinj-fault"
    elif len(CONF.contract_execution_clause) == 1:
        clause_name = CONF.contract_execution_clause[0]
    else:
        raise ConfigException(
            "ERROR: unknown value of `contract_execution_clause` configuration option")

    return _get_from_config(X86_EXECUTION_CLAUSES, clause_name, "contract_execution_clause",
                            bases[0], bases[1], tracer, enable_mismatch_check_mode)


def get_executor(enable_mismatch_check_mode: bool = False) -> interfaces.Executor:
    return _get_from_config(EXECUTORS, CONF.executor, "executor", enable_mismatch_check_mode)


def get_analyser() -> interfaces.Analyser:
    return _get_from_config(ANALYSERS, CONF.analyser, "analyser")


def get_minimizer(fuzzer: interfaces.Fuzzer,
                  instruction_set: interfaces.InstructionSetAbstract) -> interfaces.Minimizer:
    return _get_from_config(MINIMIZERS, "violation", "minimizer", fuzzer, instruction_set)


def get_downloader(arch: str, extensions: List[str], out_file: str) -> Callable:
    return _get_from_config(SPEC_DOWNLOADERS, arch, "architecture", extensions, out_file)
