"""
File: Configuration factory

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from typing import Tuple, Dict, Type, List, Callable

from . import input_generator, analyser, coverage, postprocessor, interfaces, model
from .x86 import x86_model, x86_executor, x86_fuzzer, x86_generator, get_spec
from .config import CONF, ConfigException

GENERATORS: Dict[str, Type[interfaces.Generator]] = {
    "x86-64-random": x86_generator.X86RandomGenerator
}

INPUT_GENERATORS: Dict[str, Type[interfaces.InputGenerator]] = {
    'random': input_generator.NumpyRandomInputGenerator,
    'legacy-random': input_generator.LegacyRandomInputGenerator,
}

TRACERS: Dict[str, Type[model.UnicornTracer]] = {
    "l1d": model.L1DTracer,
    "pc": model.PCTracer,
    "memory": model.MemoryTracer,
    "ct": model.CTTracer,
    "loads+stores+pc": model.CTTracer,
    "ct-nonspecstore": model.CTNonSpecStoreTracer,
    "ctr": model.CTRTracer,
    "arch": model.ArchTracer,
    "gpr": model.GPRTracer,
}

X86_SIMPLE_EXECUTION_CLAUSES: Dict[str, Type[x86_model.X86UnicornModel]] = {
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
}

EXECUTORS = {
    'x86-64': x86_executor.X86IntelExecutor,
}

ANALYSERS: Dict[str, Type[interfaces.Analyser]] = {
    'equivalence-classes': analyser.EquivalenceAnalyser,
}

COVERAGE: Dict[str, Type[interfaces.Coverage]] = {
    'dependent-pairs': coverage.DependentPairCoverage,
    'none': coverage.NoCoverage
}

MINIMIZERS: Dict[str, Type[interfaces.Minimizer]] = {
    'violation': postprocessor.MinimizerViolation,
}

SPEC_DOWNLOADERS: Dict[str, Type] = {
    'x86-64': get_spec.Downloader,
}


def _get_from_config(options: Dict, key: str, conf_option_name: str, *args):
    GenCls = options.get(key, None)
    if GenCls:
        return GenCls(*args)

    raise ConfigException(
        f"ERROR: unknown value {key} of `{conf_option_name}` configuration option")


def get_fuzzer(instruction_set, working_directory, testcase, inputs):
    if CONF.fuzzer == "architectural":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86ArchitecturalFuzzer(instruction_set, working_directory, testcase,
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


def get_input_generator(seed: int) -> interfaces.InputGenerator:
    return _get_from_config(INPUT_GENERATORS, CONF.input_generator, "input_generator", seed)


def get_model(bases: Tuple[int, int]) -> interfaces.Model:
    model_instance: model.UnicornModel

    if CONF.instruction_set == 'x86-64':
        if "cond" in CONF.contract_execution_clause and "bpas" in CONF.contract_execution_clause:
            model_instance = x86_model.X86UnicornCondBpas(bases[0], bases[1])
        elif len(CONF.contract_execution_clause) == 1:
            model_instance = _get_from_config(X86_SIMPLE_EXECUTION_CLAUSES,
                                              CONF.contract_execution_clause[0],
                                              "contract_execution_clause", bases[0], bases[1])
        else:
            raise ConfigException(
                "ERROR: unknown value of `contract_execution_clause` configuration option")

        model_instance.taint_tracker_cls = x86_model.X86TaintTracker

    else:
        raise ConfigException("ERROR: unknown value of `model` configuration option")

    # observational part of the contract
    model_instance.tracer = _get_from_config(TRACERS, CONF.contract_observation_clause,
                                             "contract_observation_clause")

    return model_instance


def get_executor() -> interfaces.Executor:
    if CONF.executor != 'default':
        raise ConfigException("ERROR: unknown value of `executor` configuration option")
    return _get_from_config(EXECUTORS, CONF.instruction_set, "instruction_set")


def get_analyser() -> interfaces.Analyser:
    return _get_from_config(ANALYSERS, CONF.analyser, "analyser")


def get_coverage(instruction_set: interfaces.InstructionSetAbstract, executor_: interfaces.Executor,
                 model: interfaces.Model, analyser: interfaces.Analyser) -> interfaces.Coverage:
    return _get_from_config(COVERAGE, CONF.coverage_type, "coverage_type", instruction_set,
                            executor_, model, analyser)


def get_minimizer(instruction_set: interfaces.InstructionSetAbstract) -> interfaces.Minimizer:
    return _get_from_config(MINIMIZERS, CONF.minimizer, "minimizer", instruction_set)


def get_downloader(arch: str, extensions: List[str], out_file: str) -> Callable:
    return _get_from_config(SPEC_DOWNLOADERS, arch, "architecture", extensions, out_file)
