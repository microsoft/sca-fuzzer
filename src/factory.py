from typing import Tuple, Dict, Type

import x86.x86_generator as x86_generator

import model
import x86.x86_model as x86_model

import x86.x86_executor as x86_executor

import x86.x86_fuzzer as x86_fuzzer
import input_generator
import analyser
import coverage
import postprocessor

import interfaces
from config import CONF, ConfigException


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
    "ct-nonspecstore": model.CTNonSpecStoreTracer,
    "ctr": model.CTRTracer,
    "arch": model.ArchTracer,
    "gpr": model.GPRTracer,
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


def _get_from_config(options: Dict, key: str, conf_option_name: str, *args):
    GenCls = options.get(key, None)
    if GenCls:
        return GenCls(*args)

    raise ConfigException(f"unknown value {key} for `{conf_option_name}` configuration option")


def get_fuzzer(instruction_set, working_directory, testcase):
    if CONF.instruction_set == "x86-64":
        return x86_fuzzer.X86Fuzzer(instruction_set, working_directory, testcase)
    raise ConfigException("unknown value of `instruction_set` configuration option")


def get_generator(instruction_set: interfaces.InstructionSetAbstract) -> interfaces.Generator:
    return _get_from_config(GENERATORS, CONF.instruction_set + "-" + CONF.generator,
                            "instruction_set", instruction_set)


def get_input_generator() -> interfaces.InputGenerator:
    return _get_from_config(INPUT_GENERATORS, CONF.input_generator, "input_generator")


def get_model(bases: Tuple[int, int]) -> interfaces.Model:
    model_instance: model.UnicornModel

    if CONF.instruction_set == 'x86-64':
        if "cond" in CONF.contract_execution_clause and "bpas" in CONF.contract_execution_clause:
            model_instance = x86_model.X86UnicornCondBpas(bases[0], bases[1])
        elif "cond" in CONF.contract_execution_clause:
            model_instance = x86_model.X86UnicornCond(bases[0], bases[1])
        elif "bpas" in CONF.contract_execution_clause:
            model_instance = x86_model.X86UnicornBpas(bases[0], bases[1])
        elif "null-injection" in CONF.contract_execution_clause:
            model_instance = x86_model.X86UnicornNull(bases[0], bases[1])
        elif "seq" in CONF.contract_execution_clause:
            model_instance = x86_model.X86UnicornSeq(bases[0], bases[1])
        else:
            raise ConfigException(
                "unknown value of `contract_execution_clause` configuration option")

        model_instance.taint_tracker_cls = x86_model.X86TaintTracker

    else:
        raise ConfigException("unknown value of `model` configuration option")

    # observational part of the contract
    model_instance.tracer = _get_from_config(TRACERS, CONF.contract_observation_clause,
                                             "contract_observation_clause")

    return model_instance


def get_executor() -> interfaces.Executor:
    if CONF.executor != 'default':
        raise ConfigException("unknown value of `executor` configuration option")
    return _get_from_config(EXECUTORS, CONF.instruction_set, "instruction_set")


def get_analyser() -> interfaces.Analyser:
    return _get_from_config(ANALYSERS, CONF.analyser, "analyser")


def get_coverage(instruction_set: interfaces.InstructionSetAbstract, executor_: interfaces.Executor,
                 model: interfaces.Model, analyser: interfaces.Analyser) -> interfaces.Coverage:
    return _get_from_config(COVERAGE, CONF.coverage_type, "coverage_type", instruction_set,
                            executor_, model, analyser)


def get_minimizer(instruction_set: interfaces.InstructionSetAbstract) -> interfaces.Minimizer:
    return _get_from_config(MINIMIZERS, CONF.minimizer, "minimizer", instruction_set)
