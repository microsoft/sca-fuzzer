"""
File: Fuzzing Orchestration

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Callable
import copy

from . import factory
from .interfaces import Fuzzer, CTrace, HTrace, Input, EquivalenceClass, TestCase, \
    Generator, InputGenerator, Model, Executor, Analyser, InputID, Measurement, InputTaint
from .isa_loader import InstructionSet
from .config import CONF
from .util import Logger, STAT, pretty_htrace


class FuzzerGeneric(Fuzzer):
    instruction_set: InstructionSet
    existing_test_case: str
    input_paths: List[str]
    generation_function: Callable[[str], TestCase]

    generator: Generator
    input_gen: InputGenerator
    executor: Executor
    model: Model
    analyser: Analyser

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

    def _adjust_config(self, _: str):
        pass
        # more adjustments could be implemented by subclasses!

    def initialize_modules(self):
        """ create all main modules """
        self.generator = factory.get_program_generator(self.instruction_set,
                                                       CONF.program_generator_seed)
        self.input_gen = factory.get_input_generator(CONF.input_gen_seed)
        self.executor = factory.get_executor()
        self.model = factory.get_model(self.executor.read_base_addresses())
        self.analyser = factory.get_analyser()
        self.asm_parser = factory.get_asm_parser(self.generator)

    def start_random(self,
                     num_test_cases: int,
                     num_inputs: int,
                     timeout: int,
                     nonstop: bool = False) -> bool:
        self.initialize_modules()
        self.generation_function = self.generator.create_test_case
        return self._start(num_test_cases, num_inputs, timeout, nonstop)

    def start_from_template(self,
                            num_test_cases: int,
                            num_inputs: int,
                            timeout: int,
                            nonstop: bool = False) -> bool:
        self.initialize_modules()
        self.generation_function = self.generator.create_test_case_from_template
        return self._start(num_test_cases, num_inputs, timeout, nonstop)

    def start_from_asm(self,
                       num_test_cases: int,
                       num_inputs: int,
                       timeout: int,
                       nonstop: bool = False) -> bool:
        self.initialize_modules()
        self.generation_function = self.asm_parser.parse_file
        return self._start(num_test_cases, num_inputs, timeout, nonstop)

    def _start(self,
               num_test_cases: int,
               num_inputs: int,
               timeout: int,
               nonstop: bool = False) -> bool:
        start_time = datetime.today()
        self.LOG.fuzzer_start(num_test_cases, start_time)

        for i in range(num_test_cases):
            self.LOG.fuzzer_start_round(i)

            # terminate the fuzzer if the timeout has expired
            if timeout:
                now = datetime.today()
                if (now - start_time).total_seconds() > timeout:
                    self.LOG.fuzzer_timeout()
                    break

            # Generate a test case
            test_case: TestCase = self.generation_function(self.existing_test_case)
            self.input_gen.n_actors = len(test_case.actors)
            STAT.test_cases += 1

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
                self.store_test_case(test_case, inputs, violation)
                STAT.violations += 1
                if not nonstop:
                    break

        self.LOG.fuzzer_finish()
        self.LOG.dbg_report_coverage(self.model)
        return STAT.violations > 0

    def filter(self, test_case, inputs):
        return False  # implemented by architecture-specific subclasses

    def fuzzing_round(self, test_case: TestCase, inputs: List[Input]) -> Optional[EquivalenceClass]:
        """ Run a single fuzzing round: collect contract and hardware traces for the given test
        case and inputs, and check for contract violations.

        The function implements a multi-stage approach to testing, with the first measurement being
        fast but with a chance of false positives, and the later stages filtering out various
        types of potential false positives. The exact number of stages depends on
        the configuration.
        """
        # Common variables
        ctraces: List[CTrace] = []
        htraces: List[HTrace] = []
        boosted_inputs: List[Input] = []
        feedback: List = []
        violations: List[EquivalenceClass] = []

        # Define the starting parameters for the current configuration
        n_reps: int = CONF.executor_repetitions
        threshold: float = CONF.executor_outliers_threshold
        fast_boosting: bool = CONF.enable_fast_path_model

        min_nesting: int = CONF.model_min_nesting
        max_nesting: int = CONF.model_max_nesting
        if "seq" in CONF.contract_execution_clause or \
           "seq-assist" in CONF.contract_execution_clause or \
           "sandbox" in CONF.contract_execution_clause or \
           "no_speculation" in CONF.contract_execution_clause:
            min_nesting = 1
            max_nesting = 1
        nesting: int = min_nesting

        # 0. Load the test case into the model and executor
        self.model.load_test_case(test_case)
        self.executor.load_test_case(test_case)

        # 1. Fast path: Collect traces with minimal nesting and repetitions
        violations, ctraces, boosted_inputs = self._collect_traces(
            inputs, n_reps, threshold, nesting, record_stats=True, fast_boosting=fast_boosting)
        if not violations:
            STAT.no_fast_violation += 1
            return None

        # 2. Slow path: Go through potential sources of false violations in the fast path,
        #    and check them one at a time, starting with the most likely ones
        self.LOG.fuzzer_slow_path()

        # 2.2 FP might appear because the model did not go deep enough into nested speculation.
        #     To remove such FPs, we re-run the model tracing with max nesting. As taints depend on
        #     contract traces, we also have to re-boost the inputs, and re-collect hardware traces
        #     for the new inputs
        if nesting < max_nesting:
            violations, ctraces, boosted_inputs = self._collect_traces(
                inputs, n_reps, threshold, max_nesting, fast_boosting=fast_boosting)
            nesting = max_nesting
            if not violations:
                STAT.fp_nesting += 1
                return None

        # 2.3 FP might appear because of imperfect tainting (e.g., due to a bug in taint tracker).
        #     To remove such FPs, we collect contract traces for all boosted inputs, and check if
        #     the violation is still present
        if fast_boosting:
            violations, ctraces, boosted_inputs = self._collect_traces(
                inputs, n_reps, threshold, nesting, fast_boosting=False)
            fast_boosting = False
            if not violations:
                STAT.fp_taint_mistakes += 1
                return None

        # 2.4 FP might appear because of probabilistic nature of the hardware measurements.
        #     To remove such FPs, we collect more hardware traces and check if the violation is
        #     present
        violations, _, __ = self._collect_traces(
            boosted_inputs,
            n_reps,
            threshold,
            nesting,
            reuse_ctraces=ctraces,
            ensure_convergence=True)
        if not violations:
            STAT.fp_noise += 1
            return None

        # 3. Check if the violation survives priming
        if CONF.enable_priming:
            violation_stack = list(violations)  # make a copy
            while violation_stack:
                self.LOG.fuzzer_priming(len(violation_stack))
                violation: EquivalenceClass = violation_stack.pop()
                if self.priming(violation, boosted_inputs):
                    violations = [violation]
                    break
            else:
                # All violations were cleared by priming.
                STAT.fp_priming += 1
                return None

        # Violation survived all checks. Report it
        feedback = self.executor.get_last_feedback()
        self.LOG.trc_fuzzer_dump_traces(self.model, boosted_inputs, htraces, ctraces, feedback,
                                        CONF.model_max_nesting)
        return violations[0]

    def _collect_traces(self,
                        inputs: List[Input],
                        n_reps: int,
                        threshold: float,
                        model_nesting: int,
                        reuse_ctraces: List[CTrace] = [],
                        record_stats: bool = False,
                        fast_boosting: bool = True,
                        ensure_convergence: bool = False):
        ctraces: List[CTrace]
        taints: List[InputTaint]
        boosted_inputs: List[Input]

        if reuse_ctraces:
            assert len(reuse_ctraces) == len(inputs)
            ctraces = reuse_ctraces
            boosted_inputs = inputs
        else:
            # if contract traces are not already provided, collect them and boost inputs

            # collect taints and contract traces for initial inputs
            ctraces, taints = self.model.trace_test_case_with_taints(inputs, model_nesting)

            # ensure that we have many inputs in each input classes
            self.input_gen.reset_boosting_state()
            boosted_inputs = list(inputs)  # make a copy
            for _ in range(CONF.inputs_per_class - 1):
                boosted_inputs += self.input_gen.extend_equivalence_classes(inputs, taints)

            if fast_boosting:
                # records same ctrace for all members of the same input class
                ctraces = ctraces * CONF.inputs_per_class
            else:
                # compute ctraces separately for every boosted input
                ctraces = self.model.trace_test_case(boosted_inputs, model_nesting)
            assert len(ctraces) == len(boosted_inputs)

        # collect hardware traces
        htraces = self.executor.trace_test_case(
            boosted_inputs, n_reps, threshold, ensure_convergence=ensure_convergence)

        # check for violations
        violations = self.analyser.filter_violations(
            boosted_inputs, ctraces, htraces, stats=record_stats)
        if not violations:
            # if violation is detected, print debug traces (if requested)
            feedback = self.executor.get_last_feedback()
            self.LOG.trc_fuzzer_dump_traces(self.model, boosted_inputs, htraces, ctraces, feedback,
                                            CONF.model_max_nesting)

        # label all non-violating inputs as ignored by executor, so that we don't trigger
        # a chain reaction of false positives when the measurement results are non-deterministic
        violating_input_ids = [
            m.input_id for i in range(len(violations)) for m in violations[i].measurements
        ]
        ignored_input_ids = [i for i in range(len(boosted_inputs)) if i not in violating_input_ids]
        self.executor.ignore_inputs(ignored_input_ids)

        return violations, ctraces, boosted_inputs

    def store_test_case(self, test_case: TestCase, inputs: List[Input],
                        violation: EquivalenceClass):
        if not self.work_dir:
            return
        timestamp = datetime.today().strftime('%y%m%d-%H%M%S')
        violation_dir = f"{self.work_dir}/violation-{timestamp}"
        Path(self.work_dir).mkdir(exist_ok=True)
        Path(violation_dir).mkdir()

        # store violation and the config file
        test_case.save(f"{violation_dir}/program.asm")
        for i, input_ in enumerate(inputs):
            input_.save(f"{violation_dir}/input_{i}.bin")
        shutil.copy2(CONF.config_path, f"{violation_dir}/config.yaml")

        # we're about to store in a file - disable colors
        color_on = CONF.color
        CONF.color = False

        # store the violation report
        with open(f"{violation_dir}/report.txt", "w") as f:
            f.write("# Violation Report\n\n")
            f.write(f"* Test Case ID: {STAT.test_cases - 1}\n")
            f.write(f"* Detected: {datetime.today().strftime('%d.%m.%y at %H:%M:%S')}\n\n")
            f.write("* Time to detection:"
                    f" {(datetime.today() - self.LOG.start_time).total_seconds()}\n")
            f.write("* Statistics:\n")
            f.write(str(STAT) + "\n")

            f.write("\n## Generation Properties\n")
            f.write(f"* Program seed: {test_case.seed}\n")
            f.write(f"* Input seed: {inputs[0].seed}\n")
            f.write("* Faulty page properties:\n")
            for actor_id in test_case.actors:
                actor = test_case.actors[actor_id]
                f.write(f"  * Actor {actor_id}: {actor.data_properties}\n")

            f.write("\n## Counterexample Inputs\n")
            for m in violation.measurements:
                f.write(f"\nInput #{m.input_id}\n")
                f.write(f"* Hardware trace: {pretty_htrace(m.htrace)}\n")
                f.write(f"* Contract trace (hash): {m.ctrace}\n")
                ctrace_full = self.model.dbg_get_trace_detailed(m.input_, CONF.model_max_nesting)
                f.write(f"* Contract trace (detailed): {ctrace_full}\n")

        # re-enable colors if enabled previously
        CONF.color = color_on

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
                htraces.append(HTrace(frozenset({int(line)}), hash(int(line))))

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
    def priming(self, org_violation: EquivalenceClass, all_inputs: List[Input]) -> bool:
        """
        Try priming the inputs that caused the violations

        return: True if the violation survived priming
        """
        violation = copy.copy(org_violation)
        ordered_htraces = sorted(violation.htrace_map.keys(), key=lambda x: len(x), reverse=False)
        n_reps = CONF.executor_repetitions

        for current_htrace in ordered_htraces:
            current_input_id = violation.htrace_map[current_htrace][-1].input_id

            # list of inputs that produced a different HTrace
            input_ids_to_test: List[InputID] = [
                m.input_id for m in violation.measurements if m.htrace != current_htrace
            ]
            input_id_to_htrace = {m.input_id: m.htrace for m in violation.measurements}

            # iterate over all inputs in the violation and insert swap them with current_input_id
            for input_id in input_ids_to_test:
                self.LOG.dbg_priming_progress(input_id, current_input_id)

                # determine the list of traces that we are trying to reproduce
                traces_to_reproduce = set(current_htrace.raw)
                traces_to_reproduce -= set(input_id_to_htrace[input_id].raw)
                if 0 in traces_to_reproduce:
                    traces_to_reproduce.remove(0)
                if len(traces_to_reproduce) == 0:
                    continue

                # insert the tested input into its new place
                primer = list(all_inputs)
                primer[current_input_id] = all_inputs[input_id]

                # try the new input sequence multiple times, until (1) we observe all traces
                # that we try to reproduce or (2) we run out of attempts
                survived = False
                attempts = 30  # FIXME: make this configurable
                for _ in range(attempts):
                    htraces: List[HTrace] = self.executor.trace_test_case(
                        primer, n_reps, 1.0, ensure_convergence=False)
                    target_htrace = htraces[current_input_id]
                    self.LOG.dbg_priming_observations(traces_to_reproduce, target_htrace.raw)

                    # fast exit in case of a tracing error
                    if target_htrace.raw == {0}:
                        return False

                    # remove the reproduced traces
                    for trace in target_htrace.raw:
                        if trace in traces_to_reproduce:
                            traces_to_reproduce.remove(trace)

                    # if we reproduced all traces, we can stop
                    if not traces_to_reproduce:
                        survived = True
                        break

                if survived:
                    continue
                else:
                    # if not all traces were reproduced, it's a genuine violation
                    # and we can stop
                    return True

        # all traces were reproduced, so it's a false positive
        return False


class ArchitecturalFuzzer(FuzzerGeneric):
    """
    A stripped-down version of the fuzzer that compares the architectural results
    of the model execution vs execution on the CPU
    """

    def __init__(self,
                 instruction_set_spec: str,
                 work_dir: str,
                 existing_test_case: str = "",
                 inputs: List[str] = []):
        CONF.contract_observation_clause = 'gpr'
        super().__init__(instruction_set_spec, work_dir, existing_test_case, inputs)
        self.LOG.warning("fuzzer", "Running in architectural mode. "
                         "Contract violations can't be detected!")

    def fuzzing_round(self, test_case: TestCase, inputs: List[Input]) -> Optional[EquivalenceClass]:
        self.model.load_test_case(test_case)
        self.executor.load_test_case(test_case)

        # collect architectural hardware traces
        htrace_objs = self.executor.trace_test_case(inputs, 1, 1.0)
        if not htrace_objs:  # tracing error
            return None
        htraces: List[List[int]] = []
        for htrace_obj in htrace_objs:
            htrace = list(htrace_obj.raw)[0]
            htraces.append([htrace])
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
                print(f"\nInput #{i}")
                print(f"Model: {[hex(v) for v in ctraces[i]]}")
                print(f"CPU:   {[hex(v) for v in htraces[i]]}")

                eq_cls = EquivalenceClass()
                eq_cls.ctrace = ctraces[i][0]
                eq_cls.measurements = [Measurement(i, inputs[i], ctraces[i][0], htrace_objs[i])]
                eq_cls.build_htrace_map()
                return eq_cls
            elif "dbg_dump_htraces" in CONF.logging_modes:
                print(f"Input #{i}")
                print(f"Model: {[hex(v) for v in ctraces[i]]}")
                print(f"CPU:   {[hex(v) for v in htraces[i]]}")

        return None
