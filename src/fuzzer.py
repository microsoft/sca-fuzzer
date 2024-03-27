"""
File: Fuzzing Orchestration

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Callable, Tuple
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

        self.reference_htraces: List[HTrace] = []

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

    def fuzzing_round(self,
                      test_case: TestCase,
                      inputs: List[Input],
                      ignore_list: List[int] = []) -> Optional[EquivalenceClass]:
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
        n_reps: int = CONF.executor_sample_sizes[0]
        fast_boosting: bool = CONF.enable_fast_path_model

        min_nesting: int = CONF.model_min_nesting
        max_nesting: int = CONF.model_max_nesting
        if not self.model.is_speculative_contract:
            min_nesting = 1
            max_nesting = 1
        nesting: int = min_nesting

        # 0. Load the test case into the model and executor
        self.model.load_test_case(test_case)
        self.executor.load_test_case(test_case)
        if ignore_list:
            self.executor.set_ignore_list(ignore_list)

        # 1. Fast path: Collect traces with minimal nesting and repetitions
        violations, ctraces, boosted_inputs, htraces = self._collect_traces(
            inputs,
            n_reps,
            nesting,
            record_stats=True,
            fast_boosting=fast_boosting,
            update_ignore_list=True)
        if not violations:
            STAT.fast_path += 1
            return None
        self.reference_htraces = htraces

        # 2. Slow path: Go through potential sources of false violations in the fast path,
        #    and check them one at a time, starting with the most likely ones
        self.LOG.fuzzer_slow_path()

        # 2.1 FP might appear because the model did not go deep enough into nested speculation.
        #     To remove such FPs, we re-run the model tracing with max nesting. As taints depend on
        #     contract traces, we also have to re-boost the inputs, and re-collect hardware traces
        #     for the new inputs
        if nesting < max_nesting:
            nesting = max_nesting
            violations, ctraces, boosted_inputs, _ = self._collect_traces(
                inputs, n_reps, max_nesting, fast_boosting=fast_boosting)
            if not violations:
                STAT.fp_nesting += 1
                return None

        # 2.2 FP might appear because of imperfect tainting (e.g., due to a bug in taint tracker).
        #     To remove such FPs, we collect contract traces for all boosted inputs, and check if
        #     the violation is still present
        if fast_boosting:
            full_ctraces = self.model.trace_test_case(boosted_inputs, nesting)
            if full_ctraces != ctraces:
                violations, ctraces, boosted_inputs, _ = self._collect_traces(
                    inputs, n_reps, nesting, fast_boosting=False)
                fast_boosting = False
                if not violations:
                    STAT.fp_taint_mistakes += 1
                    return None

        # 2.3 FP might appear because of interference between inputs. To remove such FPs, we
        #     use the priming test where we swap inputs that caused the violation with each other
        if CONF.enable_priming:
            violations = self._priming(violations, boosted_inputs)
            if not violations:
                STAT.fp_early_priming += 1
                feedback = self.executor.get_last_feedback()
                self.LOG.trc_fuzzer_dump_traces(self.model, boosted_inputs, htraces,
                                                self.reference_htraces, ctraces, feedback,
                                                CONF.model_max_nesting)
                return None

        # 2.4 FP might appear because we experienced noise. Retry the fast path N times,
        #     proceed only if the violation is persistent. Sleep for a short period of time
        #     between retries to tolerate noise bursts
        had_violation = True
        for n_reps in CONF.executor_sample_sizes[1:]:
            self.LOG.fuzzer_sample_size_increase(n_reps)
            n_reps -= len(htraces[0].raw)  # subtract the number of repetitions already done

            violations, _, __, htraces = self._collect_traces(
                boosted_inputs, n_reps, nesting, reuse_ctraces=ctraces, add_htraces=htraces)
            if not violations:
                had_violation = False
                break

            # 2.4.2 Priming might have failed because the sample size was too small, causing
            #     non-deterministic results. Retry the priming test with the largest sample size
            if CONF.enable_priming:
                violations = self._priming(violations, boosted_inputs)
                if not violations:
                    STAT.fp_priming += 1
                    feedback = self.executor.get_last_feedback()
                    self.LOG.trc_fuzzer_dump_traces(self.model, boosted_inputs, htraces,
                                                    self.reference_htraces, ctraces, feedback,
                                                    CONF.model_max_nesting)
                    return None

        if not had_violation:
            STAT.fp_large_sample += 1
            return None

        # Violation survived all checks. Report it
        feedback = self.executor.get_last_feedback()
        self.LOG.trc_fuzzer_dump_traces(self.model, boosted_inputs, htraces, self.reference_htraces,
                                        ctraces, feedback, CONF.model_max_nesting)
        return violations[0]

    def _collect_traces(self,
                        inputs: List[Input],
                        n_reps: int,
                        model_nesting: int,
                        reuse_ctraces: List[CTrace] = [],
                        record_stats: bool = False,
                        fast_boosting: bool = True,
                        update_ignore_list: bool = False,
                        add_htraces: List[HTrace] = []):
        ctraces: List[CTrace]
        boosted_inputs: List[Input]

        if reuse_ctraces:
            assert len(reuse_ctraces) == len(inputs)
            ctraces = reuse_ctraces
            boosted_inputs = inputs
        else:
            # if contract traces are not already provided, collect them and boost inputs
            boosted_inputs, ctraces = self._boost_inputs(inputs, model_nesting)

            if fast_boosting:
                # records same ctrace for all members of the same input class
                ctraces = ctraces * CONF.inputs_per_class
            else:
                # compute ctraces separately for every boosted input
                ctraces = self.model.trace_test_case(boosted_inputs, model_nesting)
            assert len(ctraces) == len(boosted_inputs)

        # collect hardware traces
        htraces = self.executor.trace_test_case(boosted_inputs, n_reps)
        if add_htraces:
            for i, h in enumerate(htraces):
                h.raw.extend(add_htraces[i].raw)
                h.hash_ = hash(tuple(h.raw))

        # check for violations
        violations = self.analyser.filter_violations(
            boosted_inputs, ctraces, htraces, stats=record_stats)
        if not violations:
            # if violation is detected, print debug traces (if requested)
            feedback = self.executor.get_last_feedback()
            self.LOG.trc_fuzzer_dump_traces(self.model, boosted_inputs, htraces,
                                            self.reference_htraces, ctraces, feedback,
                                            CONF.model_max_nesting)

        if update_ignore_list:
            # label all non-violating inputs as ignored by executor, so that we don't trigger
            # a chain reaction of false positives when the measurement results are non-deterministic
            violating_ids = [m.input_id for v in violations for m in v.measurements]
            ignored_input_ids = [i for i in range(len(boosted_inputs)) if i not in violating_ids]
            self.executor.extend_ignore_list(ignored_input_ids)

        return violations, ctraces, boosted_inputs, htraces

    def _boost_inputs(self, inputs: List[Input], nesting) -> Tuple[List[Input], List[CTrace]]:
        ctraces: List[CTrace]
        taints: List[InputTaint]

        # collect taints and contract traces for initial inputs
        ctraces, taints = self.model.trace_test_case_with_taints(inputs, nesting)

        # ensure that we have many inputs in each input classes
        self.input_gen.reset_boosting_state()
        boosted_inputs = list(inputs)  # make a copy
        for _ in range(CONF.inputs_per_class - 1):
            boosted_inputs += self.input_gen.extend_equivalence_classes(inputs, taints)
        return boosted_inputs, ctraces

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
            target_desc = self.generator.target_desc
            for actor_id in test_case.actors:
                f.write(f"  - Actor {actor_id}:\n")

                actor = test_case.actors[actor_id]
                pte_fields = []
                for field in target_desc.pte_bits:
                    offset, default = target_desc.pte_bits[field]
                    value = bool(actor.data_properties & (1 << offset))
                    if value != default:
                        pte_fields.append(f"{field}={value}")
                f.write(f"    * PTE: {'; '.join(pte_fields)}\n")

                if actor.mode != "guest":
                    continue
                epte_fields = []
                for field in target_desc.epte_bits:
                    offset, default = target_desc.epte_bits[field]
                    value = bool(actor.data_ept_properties & (1 << offset))
                    if value != default:
                        epte_fields.append(f"{field}={value}")
                f.write(f"    * EPTE: {'; '.join(epte_fields)}\n")

            f.write("\n## Counterexample Inputs\n")
            for m in violation.measurements:
                f.write(f"\nInput #{m.input_id}\n")
                f.write(f"* Hardware trace:\n {pretty_htrace(m.htrace)}\n")
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
                htraces.append(HTrace([int(line)]))

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

    def tune(self, num_test_cases: int, num_inputs: int, n_samples: int) -> None:
        self.LOG.fuzzer_start(0, datetime.today())
        self.LOG.warning("fuzzer", "Tuning is not implemented yet!")
        self.LOG.fuzzer_finish()

    # ==============================================================================================
    # Priming and reproducibility
    def _priming(self, violations: List[EquivalenceClass],
                 inputs: List[Input]) -> List[EquivalenceClass]:
        violation_stack = list(violations)  # make a copy
        while violation_stack:
            self.LOG.fuzzer_priming(len(violation_stack))
            violation: EquivalenceClass = violation_stack.pop()
            if self._prime_one(violation, inputs):
                return [violation]
        return []

    def _prime_one(self, org_violation: EquivalenceClass, all_inputs: List[Input]) -> bool:
        """
        Try priming the inputs that caused the violations

        return: True if the violation survived priming
        """
        violation = copy.copy(org_violation)
        measurements_to_test = [hg[0] for hg in violation.htrace_groups]
        null_htrace = HTrace([0])
        n_reps = len(violation.measurements[0].htrace.raw)

        for current_measurement in measurements_to_test:
            current_input_id = current_measurement.input_id
            htrace_to_reproduce = current_measurement.htrace
            other_measurements = [m for m in measurements_to_test if m != current_measurement]

            # list of inputs that produced a different HTrace
            input_ids_to_test: List[InputID] = [m.input_id for m in other_measurements]

            # iterate over all inputs in the violation and insert swap them with current_input_id
            for input_id in input_ids_to_test:
                self.LOG.dbg_priming_progress(input_id, current_input_id)

                # insert the tested input into its new place
                primer = list(all_inputs)
                primer[current_input_id] = all_inputs[input_id]

                # try the new input sequence and check if the traces observed for the new input
                # are equivalent to the original ones
                htraces: List[HTrace] = self.executor.trace_test_case(primer, n_reps)
                new_htrace = htraces[current_input_id]

                # fast exit in case of a tracing error
                if not new_htrace.raw or new_htrace == null_htrace:
                    self.LOG.warning("fuzzer", "Tracing error during priming. "
                                     "Skipping this test case")
                    return False

                if self.analyser.htraces_are_equivalent(new_htrace, htrace_to_reproduce):
                    continue

                self.LOG.dbg_priming_fail(input_id, current_input_id, htrace_to_reproduce,
                                          new_htrace)

                # could not reproduce; it's a genuine violation
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

    def fuzzing_round(self,
                      test_case: TestCase,
                      inputs: List[Input],
                      _: List[int] = []) -> Optional[EquivalenceClass]:
        self.model.load_test_case(test_case)
        self.executor.load_test_case(test_case)

        # collect architectural hardware traces
        htrace_objs = self.executor.trace_test_case(inputs, 1)
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

                eq_cls = EquivalenceClass(ctraces[i][0], inputs)
                eq_cls.measurements = [Measurement(i, inputs[i], ctraces[i][0], htrace_objs[i])]
                self.analyser.build_htrace_groups(eq_cls)
                return eq_cls
            elif "dbg_dump_htraces" in CONF.logging_modes:
                print(f"Input #{i}")
                print(f"Model: {[hex(v) for v in ctraces[i]]}")
                print(f"CPU:   {[hex(v) for v in htraces[i]]}")

        return None
