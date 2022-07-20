from typing import Tuple, Dict, Type

import x86.x86_generator as x86_generator

import model
import x86.x86_model as x86_model

from interfaces import Model, Generator, InstructionSetAbstract
from config import CONF, ConfigException

REGISTERED_GENERATORS: Dict[str, Type[Generator]] = {
    "x86-64-random": x86_generator.X86RandomGenerator
}


def get_generator(instruction_set: InstructionSetAbstract) -> Generator:
    key = CONF.instruction_set + "-" + CONF.generator
    GenCls = REGISTERED_GENERATORS.get(key, None)
    if GenCls:
        return GenCls(instruction_set)

    raise ConfigException(f"unknown value {key} for `instruction_set` configuration option")


def get_model(bases: Tuple[int, int]) -> Model:
    model_instance: model.UnicornModel
    if CONF.model == 'x86-unicorn':
        # functional part of the contract
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
    if CONF.contract_observation_clause == "l1d":
        model_instance.tracer = model.L1DTracer()
    elif CONF.contract_observation_clause == 'pc':
        model_instance.tracer = model.PCTracer()
    elif CONF.contract_observation_clause == 'memory':
        model_instance.tracer = model.MemoryTracer()
    elif CONF.contract_observation_clause == 'ct':
        model_instance.tracer = model.CTTracer()
    elif CONF.contract_observation_clause == 'ct-nonspecstore':
        model_instance.tracer = model.CTNonSpecStoreTracer()
    elif CONF.contract_observation_clause == 'ctr':
        model_instance.tracer = model.CTRTracer()
    elif CONF.contract_observation_clause == 'arch':
        model_instance.tracer = model.ArchTracer()
    else:
        raise ConfigException("unknown value of `contract_observation_clause` configuration option")

    return model_instance
