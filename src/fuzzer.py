"""
File: Fuzzing Orchestration

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List
import copy

from . import factory
from .interfaces import CTrace, HTrace, Input, InputTaint, EquivalenceClass, TestCase, Generator, \
    InputGenerator, Model, Executor, Analyser, Coverage, InputID, Measurement
from .isa_loader import InstructionSet
from .config import CONF
from .util import Logger, STAT, TWOS_COMPLEMENT_MASK_64, bit_count, pretty_trace


class Fuzzer:
    instruction_set: InstructionSet
    existing_test_case: str
    input_paths: List[str]

    generator: Generator
    input_gen: InputGenerator
    executor: Executor
    model: Model
    analyser: Analyser
    coverage: Coverage

    LOG: Logger  # name capitalized to make logging easily distinguishable from the main logic

    def __init__(self,
                 instruction_set_spec: str,
                 work_dir: str,
                 existing_test_case: str = "",
                 inputs: List[str] = []):
        self._adjust_config(existing_test_case)
        self.existing_test_case = existing_test_case
        self.input_paths = inputs

        self.instruction_set = InstructionSet(instruction_set_spec, CONF.instruction_categories)
        self.work_dir = work_dir
        self.LOG = Logger()

    def _adjust_config(self, existing_test_case):
        if existing_test_case:
            CONF.setattr_internal("_no_generation", True)
            CONF.setattr_internal("_default_instruction_blocklist", [])
            CONF.register_blocklist = []
        # more adjustments could be implemented by subclasses!

    def initialize_modules(self):
        """ create all main modules """
        self.generator = factory.get_program_generator(self.instruction_set,
                                                       CONF.program_generator_seed)
        self.input_gen = factory.get_input_generator(CONF.input_gen_seed)
        self.executor = factory.get_executor()
        self.model = factory.get_model(self.executor.read_base_addresses())
        self.analyser = factory.get_analyser()
        self.coverage = factory.get_coverage(self.instruction_set, self.executor, self.model,
                                             self.analyser)

    def start(self,
              num_test_cases: int,
              num_inputs: int,
              timeout: int,
              nonstop: bool = False) -> bool:
        start_time = datetime.today()
        self.LOG.fuzzer_start(num_test_cases, start_time)

        # create all main modules
        self.initialize_modules()

        for i in range(num_test_cases):
            self.LOG.fuzzer_start_round(i)
            self.LOG.dbg_report_coverage(i, self.coverage.get_brief())

            # terminate the fuzzer if the timeout has expired
            if timeout:
                now = datetime.today()
                if (now - start_time).total_seconds() > timeout:
                    self.LOG.fuzzer_timeout()
                    break

            # Generate a test case
            test_case: TestCase
            if self.existing_test_case:
                test_case = self.generator.load(self.existing_test_case)
            else:
                test_case = self.generator.create_test_case('generated.asm')
            STAT.test_cases += 1

            # Generate the execution environment
            self.generator.create_pte(test_case)

            # Prepare inputs
            inputs: List[Input]
            if self.input_paths:
                inputs = self.input_gen.load(self.input_paths)
            else:
                inputs = self.input_gen.generate(num_inputs)
            STAT.num_inputs += len(inputs) * CONF.inputs_per_class

            # Check if the test case is useful
            if self.filter(test_case, inputs):
                continue

            # Fuzz the test case
            violation = self.fuzzing_round(test_case, inputs)

            if violation:
                self.LOG.fuzzer_report_violations(violation, self.model)
                self.store_test_case(test_case, violation)
                STAT.violations += 1
                if not nonstop:
                    break

        self.LOG.fuzzer_finish()
        return STAT.violations > 0

    def filter(self, test_case, inputs):
        return False  # implemented by architecture-specific subclasses

    def fuzzing_round(self, test_case: TestCase, inputs: List[Input]) -> Optional[EquivalenceClass]:
        self.model.load_test_case(test_case)
        self.executor.load_test_case(test_case)
        self.coverage.load_test_case(test_case)

        # 1. Test for contract violations with nesting=1
        ctraces: List[CTrace]
        htraces: List[HTrace]

        # at this point we need to increase the effectiveness of inputs
        # so that we can detect contract violations (note that it wasn't necessary
        # up to this point because we weren't testing against a contract)
        boosted_inputs: List[Input] = self.boost_inputs(inputs, 1)

        # check for violations
        ctraces = self.model.trace_test_case(boosted_inputs, 1)
        htraces = self.executor.trace_test_case(boosted_inputs, CONF.executor_repetitions)
        self.LOG.trc_fuzzer_dump_traces(self.model, boosted_inputs, htraces, ctraces,
                                        self.executor.get_last_feedback())
        violations = self.analyser.filter_violations(boosted_inputs, ctraces, htraces, True)
        if not violations:  # nothing detected? -> we are done here, move to next test case
            return None

        # 2. Repeat with with max nesting
        if 'seq' not in CONF.contract_execution_clause:
            self.LOG.fuzzer_nesting_increased()
            boosted_inputs = self.boost_inputs(inputs, CONF.model_max_nesting)
            ctraces = self.model.trace_test_case(boosted_inputs, CONF.model_max_nesting)
            htraces = self.executor.trace_test_case(boosted_inputs, CONF.executor_repetitions)
            violations = self.analyser.filter_violations(boosted_inputs, ctraces, htraces, True)
            if not violations:
                return None

        # 3. Check if the violation is reproducible
        if self.check_if_reproducible(violations, boosted_inputs, htraces):
            STAT.flaky_violations += 1
            if CONF.ignore_flaky_violations:
                return None

        # 4. Check if the violation survives priming
        if not CONF.enable_priming:
            return violations[-1]
        STAT.required_priming += 1

        violation_stack = list(violations)  # make a copy
        while violation_stack:
            self.LOG.fuzzer_priming(len(violation_stack))
            violation: EquivalenceClass = violation_stack.pop()
            if self.priming(violation, boosted_inputs):
                break
        else:
            # All violations were cleared by priming.
            return None

        # Violation survived priming. Report it
        return violation

    def boost_inputs(self, inputs: List[Input], nesting: int) -> List[Input]:
        if CONF.inputs_per_class == 1:
            return inputs

        taints: List[InputTaint]
        taints = self.model.get_taints(inputs, nesting)

        # ensure that we have many inputs in each input classes
        boosted_inputs: List[Input] = list(inputs)  # make a copy
        for _ in range(CONF.inputs_per_class - 1):
            boosted_inputs += self.input_gen.extend_equivalence_classes(inputs, taints)
        return boosted_inputs

    def store_test_case(self, test_case: TestCase, violation: EquivalenceClass):
        if not self.work_dir:
            return
        Path(self.work_dir).mkdir(exist_ok=True)

        # store test case
        timestamp = datetime.today().strftime('%y%m%d-%H%M%S')
        test_case.save(f"{self.work_dir}/violation-{timestamp}.asm")

        # store config file
        shutil.copy2(CONF.config_path, f"{self.work_dir}/config-{timestamp}.yaml")

        # store the violation report
        with open(f"{self.work_dir}/report-{timestamp}.txt", "w") as f:
            f.write("# Violation Report\n\n")
            f.write(f"Detected: {datetime.today().strftime('%d.%m.%y at %H:%M:%S')}\n\n")
            f.write("## Counterexample Inputs\n")
            for m in violation.measurements:
                f.write(f"\nInput #{m.input_id}\n")
                f.write(f"* Contract trace hash: {m.ctrace}\n")
                f.write(f"* Hardware trace: {pretty_trace(m.htrace)}\n")

    # ==============================================================================================
    # Single-stage interfaces
    def generate_test_batch(self, program_generator_seed: int, num_test_cases: int, num_inputs: int,
                            permit_overwrite: bool):
        self.LOG.fuzzer_start(0, datetime.today())

        # prepare for generation
        STAT.test_cases = num_test_cases
        CONF.program_generator_seed = program_generator_seed
        program_gen = factory.get_program_generator(self.instruction_set,
                                                    CONF.program_generator_seed)
        input_gen = factory.get_input_generator(CONF.input_gen_seed)

        # generate test cases
        Path(self.work_dir).mkdir(exist_ok=True)
        for i in range(0, num_test_cases):
            test_case_dir = self.work_dir + "/tc" + str(i)
            try:
                Path(test_case_dir).mkdir(exist_ok=permit_overwrite)
            except FileExistsError:
                self.LOG.error(f"Directory '{test_case_dir}' already exists\n"
                               "       Use --permit-overwrite to overwrite the test case")

            program_gen.create_test_case(test_case_dir + "/" + "program.asm", True)
            inputs = input_gen.generate(num_inputs)
            for j, input_ in enumerate(inputs):
                input_.save(f"{test_case_dir}/input{j}.bin")

        self.LOG.fuzzer_finish()

    @staticmethod
    def analyse_traces_from_files(ctrace_file: str, htrace_file: str):
        logger = Logger()
        logger.dbg_violation = False  # make sure we don't try to call the model
        logger.fuzzer_start(0, datetime.today())
        STAT.test_cases = 1

        # read traces
        ctraces: List[CTrace] = []
        htraces: List[HTrace] = []

        with open(ctrace_file, 'r') as f:
            for line in f:
                ctraces.append(int(line))
        with open(htrace_file, 'r') as f:
            for line in f:
                htraces.append(int(line))

        assert len(ctraces) == len(htraces), \
            "The number of hardware traces does not match the number of contract traces"

        dummy_inputs = factory.get_input_generator(0).generate(len(ctraces))

        # check for violations
        analyser = factory.get_analyser()
        violations = analyser.filter_violations(dummy_inputs, ctraces, htraces, True)

        # print results
        if violations:
            logger.fuzzer_report_violations(violations[0], None)

        logger.fuzzer_finish()

    # ==============================================================================================
    # Priming and reproducibility
    def check_if_reproducible(self, violations: List[EquivalenceClass], inputs: List[Input],
                              org_htraces: List[HTrace]) -> bool:
        # re-collect htraces
        htraces: List[HTrace] = self.executor.trace_test_case(inputs, CONF.executor_repetitions)

        # check if all htraces that had a violation match
        violating_input_ids = []
        for violation in violations:
            for measurement in violation.measurements:
                violating_input_ids.append(measurement.input_id)

        for i in violating_input_ids:
            if htraces[i] != org_htraces[i]:
                return True
        return False

    def priming(self, org_violation: EquivalenceClass, all_inputs: List[Input]) -> bool:
        """
        Try priming the inputs that caused the violations

        return: True if the violation survived priming
        """
        violation = copy.copy(org_violation)
        ordered_htraces = sorted(
            violation.htrace_map.keys(), key=lambda x: bit_count(x), reverse=False)

        for current_htrace in ordered_htraces:
            current_input_id = violation.htrace_map[current_htrace][-1].input_id

            # list of inputs that produced a different HTrace
            input_ids_to_test: List[InputID] = [
                m.input_id for m in violation.measurements if m.htrace != current_htrace
            ]

            # insert the tested inputs into their places
            for input_id in input_ids_to_test:
                primer = list(all_inputs)
                primer[current_input_id] = all_inputs[input_id]

                # try priming
                htraces: List[HTrace] = self.executor.trace_test_case(primer,
                                                                      CONF.executor_repetitions)
                primed_htrace = htraces[current_input_id]
                if primed_htrace == current_htrace:
                    continue

                # if the primed measurement triggered more speculation, it's ok
                if (primed_htrace ^ TWOS_COMPLEMENT_MASK_64) & current_htrace == 0:
                    continue

                return True

        return False


class ArchitecturalFuzzer(Fuzzer):
    """
    A stripped-down version of the fuzzer that compares the architectural results
    of the model execution vs execution on the CPU
    """

    def __init__(self,
                 instruction_set_spec: str,
                 work_dir: str,
                 existing_test_case: str = "",
                 inputs: List[str] = []):
        CONF.setattr_internal('executor_mode', "GPR")
        CONF.contract_observation_clause = 'gpr'
        super().__init__(instruction_set_spec, work_dir, existing_test_case, inputs)
        self.LOG.warning("fuzzer", "Running in architectural mode. "
                         "Contract violations can't be detected!")

    def fuzzing_round(self, test_case: TestCase, inputs: List[Input]) -> Optional[EquivalenceClass]:
        self.model.load_test_case(test_case)
        self.executor.load_test_case(test_case)
        self.coverage.load_test_case(test_case)

        # collect architectural hardware traces
        htraces: List[List[int]] = [[t] for t in self.executor.trace_test_case(inputs, 1)]
        for i, trace in enumerate(self.executor.get_last_feedback()):
            htraces[i].extend(trace)

        # collect architectural model traces
        ctraces: List[List[int]] = []
        for input_ in inputs:
            self.model.trace_test_case([input_], CONF.model_max_nesting)
            ctraces.append(self.model.tracer.get_contract_trace_full())

        # check for violations - since we simply check the equality of traces, we don't need
        # to invoke the analyser
        for i, input_ in enumerate(inputs):
            if ctraces[i] != htraces[i]:
                print(f"Input #{i}")
                print(f"Model: {ctraces[i]}")
                print(f"CPU:   {htraces[i]}")

                eq_cls = EquivalenceClass()
                eq_cls.ctrace = ctraces[i][0]
                eq_cls.measurements = [Measurement(i, inputs[i], ctraces[i][0], htraces[i][0])]
                eq_cls.build_htrace_map()
                return eq_cls

        return None
