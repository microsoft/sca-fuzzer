"""
File: Configuration factory; constructs objects based on the configuration options.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import Dict, Type, List, TYPE_CHECKING, Any, Optional

from . import input_generator, analyser, executor, fuzzer, model
from .model_unicorn import tracer, speculator_abc, speculators_basic, \
    speculators_fault, interpreter, model as uc_model
from .postprocessing.minimizer import Minimizer

from .x86 import x86_executor, x86_fuzzer, x86_generator, x86_asm_parser, \
    x86_elf_parser, x86_target_desc, get_spec
from .config import CONF, ConfigException

if TYPE_CHECKING:
    from .isa_spec import InstructionSet
    from .target_desc import TargetDesc
    from .generator import CodeGenerator
    from .asm_parser import AsmParser
    from .elf_parser import ELFParser
    from .sandbox import BaseAddrTuple


class FactoryException(SystemExit):
    """ Exception raised by the factory functions """

    def __init__(self, options: Dict[str, Type[Any]], key: str, conf_option_name: str) -> None:
        super().__init__(
            f"ERROR: unknown value `{key}` of `{conf_option_name}` configuration option.\n"
            "  Available options are:\n  - " + "\n  - ".join(options.keys()))


# ==================================================================================================
# Common enumerations
# ==================================================================================================
_TARGET_DESC: Dict[str, Type[TargetDesc]] = {
    "x86-64": x86_target_desc.X86TargetDesc,
}


# ==================================================================================================
# Fuzzer Construction
# ==================================================================================================
def get_fuzzer(instruction_set_path: str, working_directory: str, existing_test_case: str,
               input_paths: Optional[List[str]]) -> fuzzer.Fuzzer:
    """ Construct a fuzzer based on the configuration options in the CONF object. """

    if CONF.fuzzer == "architectural":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86ArchitecturalFuzzer(instruction_set_path, working_directory,
                                                     existing_test_case, input_paths)
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")
    if CONF.fuzzer == "archdiff":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86ArchDiffFuzzer(instruction_set_path, working_directory,
                                                existing_test_case, input_paths)
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")
    if CONF.fuzzer == "basic":
        if CONF.instruction_set == "x86-64":
            return x86_fuzzer.X86Fuzzer(instruction_set_path, working_directory, existing_test_case,
                                        input_paths)
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")
    raise ConfigException("ERROR: unknown value of `fuzzer` configuration option")


# ==================================================================================================
# Executor Construction
# ==================================================================================================
_EXECUTORS = {
    'x86-64-intel': x86_executor.X86IntelExecutor,
    'x86-64-amd': x86_executor.X86AMDExecutor,
}


def get_executor(enable_mismatch_check_mode: bool = False) -> executor.Executor:
    """ Construct an executor based on the configuration options in the CONF object. """
    key: str = CONF.executor
    if key not in _EXECUTORS:
        raise FactoryException(_EXECUTORS, key, "executor")
    return _EXECUTORS[key](enable_mismatch_check_mode)


# ==================================================================================================
# Model Construction
# ==================================================================================================
_TRACERS: Dict[str, Type[tracer.UnicornTracer]] = {
    "none": tracer.NoneTracer,
    "l1d": tracer.L1DTracer,
    "pc": tracer.PCTracer,
    "memory": tracer.MemoryTracer,
    "ct": tracer.CTTracer,
    "loads+stores+pc": tracer.CTTracer,
    "ct-nonspecstore": tracer.CTNonSpecStoreTracer,
    "arch": tracer.ArchTracer,
    "tct": tracer.TruncatedCTTracer,
    "tcto": tracer.TruncatedCTWithOverflowsTracer,
    "ct-ni": tracer.ActorNITracer,
}

_SPECULATORS: Dict[str, Type[speculator_abc.UnicornSpeculator]] = {
    "seq": speculators_basic.SeqSpeculator,
    "no_speculation": speculators_basic.SeqSpeculator,
    "cond": speculators_basic.X86CondSpeculator,
    "conditional_br_misprediction": speculators_basic.X86CondSpeculator,
    "bpas": speculators_basic.StoreBpasSpeculator,
    "cond-bpas": speculators_basic.X86CondBpasSpeculator,
    "seq-assist": speculators_fault.SequentialAssistSpeculator,
    "nullinj-fault": speculators_fault.X86UnicornNull,
    "nullinj-assist": speculators_fault.X86UnicornNullAssist,
    "delayed-exception-handling": speculators_fault.X86UnicornDEH,
    "meltdown": speculators_fault.X86Meltdown,
    "noncanonical": speculators_fault.X86NonCanonicalAddress,

    # "vspec-ops-div": x86_unicorn_model.x86UnicornVspecOpsDIV,
    # "vspec-ops-memory-faults": x86_unicorn_model.x86UnicornVspecOpsMemoryFaults,
    # "vspec-ops-memory-assists": x86_unicorn_model.x86UnicornVspecOpsMemoryAssists,
    # "vspec-ops-gp": x86_unicorn_model.x86UnicornVspecOpsGP,
    # "vspec-all-div": x86_unicorn_model.x86UnicornVspecAllDIV,
    # "vspec-all-memory-faults": x86_unicorn_model.X86UnicornVspecAllMemoryFaults,
    # "vspec-all-memory-assists": x86_unicorn_model.X86UnicornVspecAllMemoryAssists,
}


def _get_exec_clause_name() -> str:
    """ Determine the name of the execution clause based on the configuration options """
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
    return clause_name


def get_model(bases: BaseAddrTuple, enable_mismatch_check_mode: bool = False) -> model.Model:
    """ Construct a model based on the configuration options in the CONF object. """

    if CONF.instruction_set != "x86-64":
        raise ConfigException("ERROR: unknown value of `instruction_set` configuration option")

    target_desc = _TARGET_DESC[CONF.instruction_set]()
    tracer_cls = _TRACERS[CONF.contract_observation_clause]
    speculator_cls = _SPECULATORS[_get_exec_clause_name()]
    interpreter_cls = interpreter.X86ExtraInterpreter
    model_ = uc_model.X86UnicornModel(bases, target_desc, speculator_cls, tracer_cls,
                                      interpreter_cls, enable_mismatch_check_mode)
    return model_


# ==================================================================================================
# Program Generator Construction and Related Classes
# ==================================================================================================
_GENERATORS: Dict[str, Type[CodeGenerator]] = {
    "x86-64": x86_generator.X86Generator,
}

_ASM_PARSERS: Dict[str, Type[AsmParser]] = {
    'x86-64': x86_asm_parser.X86AsmParser,
}

_ELF_PARSERS: Dict[str, Type[ELFParser]] = {
    'x86-64': x86_elf_parser.X86ELFParser,
}


def get_program_generator(seed: int, instruction_set: InstructionSet) -> CodeGenerator:
    """
    Produce a ProgramGenerator object based on the configuration options in the CONF object.
    """
    key: str = CONF.instruction_set
    target_desc = _TARGET_DESC[key]()
    elf_parser = _ELF_PARSERS[key](target_desc)
    asm_parser = _ASM_PARSERS[key](instruction_set, target_desc)
    generator = _GENERATORS[key](seed, instruction_set, target_desc, asm_parser, elf_parser)
    return generator


def get_asm_parser(instruction_set: InstructionSet) -> AsmParser:
    """ Produce an AsmParser object based on the configuration options in the CONF object. """
    key: str = CONF.instruction_set
    target_desc = _TARGET_DESC[key]()
    asm_parser = _ASM_PARSERS[key](instruction_set, target_desc)
    return asm_parser


def get_elf_parser() -> ELFParser:
    """ Produce an ELFParser object based on the configuration options in the CONF object. """
    key: str = CONF.instruction_set
    target_desc = _TARGET_DESC[key]()
    elf_parser = _ELF_PARSERS[key](target_desc)
    return elf_parser


# ==================================================================================================
# Input Generator Construction
# ==================================================================================================
_INPUT_GENERATORS: Dict[str, Type[input_generator.InputGenerator]] = {
    'random': input_generator.InputGenerator,
}


def get_input_generator(seed: int) -> input_generator.InputGenerator:
    """ Produce an InputGenerator object based on the configuration options in the CONF object. """
    key: str = CONF.input_generator
    if key not in _INPUT_GENERATORS:
        raise FactoryException(_INPUT_GENERATORS, key, "input_generator")
    return _INPUT_GENERATORS[key](seed)


# ==================================================================================================
# Analyser Construction
# ==================================================================================================
_ANALYZERS: Dict[str, Type[analyser.Analyser]] = {
    'bitmaps': analyser.MergedBitmapAnalyser,
    'sets': analyser.SetAnalyser,
    'mwu': analyser.MWUAnalyser,
    'chi2': analyser.ChiSquaredAnalyser,
}


def get_analyser() -> analyser.Analyser:
    """ Construct an analyser based on the configuration options in the CONF object. """
    key: str = CONF.analyser
    if key not in _ANALYZERS:
        raise FactoryException(_ANALYZERS, key, "analyser")
    return _ANALYZERS[key]()


# ==================================================================================================
# Minimizer Construction
# ==================================================================================================
_MINIMIZERS: Dict[str, Type[Minimizer]] = {
    'violation': Minimizer,
}


def get_minimizer(fuzzer_: fuzzer.Fuzzer, instruction_set: InstructionSet) -> Minimizer:
    """ Construct a minimizer based on the configuration options in the CONF object. """
    key: str = "violation"  # expansion point for future; currently hardcoded
    if key not in _MINIMIZERS:
        raise FactoryException(_MINIMIZERS, key, "minimizer")
    return _MINIMIZERS[key](fuzzer_, instruction_set)


# ==================================================================================================
# Spec Downloader Construction
# ==================================================================================================
_SPEC_DOWNLOADERS: Dict[str, Type[get_spec.Downloader]] = {
    'x86-64': get_spec.Downloader,
}


def get_downloader(arch: str, extensions: List[str], out_file: str) -> get_spec.Downloader:
    """ Construct a class that downloads an ISA spec for the given architecture. """
    key: str = arch
    if key not in _SPEC_DOWNLOADERS:
        raise FactoryException(_SPEC_DOWNLOADERS, key, "downloader")
    return _SPEC_DOWNLOADERS[key](extensions, out_file)
