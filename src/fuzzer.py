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
from .interfaces import Fuzzer, CTrace, HTrace, Input, Violation, TestCase, \
    Generator, InputGenerator, Model, Executor, Analyser, InputID, InputTaint, \
    HardwareTracingError
from .isa_loader import InstructionSet
from .config import CONF
from .util import Logger, STAT, pretty_htrace


class TracingArguments:
    """
    A container for the arguments of the _collect_traces function. This container is used to
    simplify the function signature and make it easier to maintain consistent arguments
    between various stages of a fuzzing round.
    """

    def __init__(self, inputs, n_reps, model_nesting, ctraces, record_stats, fast_boosting,
                 update_ignore_list, reuse_ctraces, added_htraces):
        self.inputs = inputs
        self.n_reps = n_reps
        self.model_nesting = model_nesting
        self.ctraces = ctraces
        self.record_stats = record_stats
        self.fast_boosting = fast_boosting
        self.update_ignore_list = update_ignore_list
        self.reuse_ctraces = reuse_ctraces
        self.added_htraces = added_htraces


class FuzzerGeneric(Fuzzer):
    """
    A generic fuzzer that can be used for any architecture. It provides a basic implementation
    of the fuzzer interface that can be used as a starting point for architecture-specific
    fuzzers.

    The fuzzer provides a multi-stage approach to testing, with the first measurement
    being fast but with a chance of false positives, and the later stages filtering out various
    types of potential false positives. The exact number of stages depends on the configuration.
    """
    instruction_set: InstructionSet
    existing_test_case: str
    input_paths: List[str]
    generation_function: Callable[[str], TestCase]

    generator: Generator
    input_gen: InputGenerator
    executor: Executor
    model: Model
    analyser: Analyser

    arch_executor: Executor
    arch_model: Model

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
        isa = self.instruction_set
        prog_seed = CONF.program_generator_seed
        data_seed = CONF.input_gen_seed

        self.generator = factory.get_program_generator(isa, prog_seed)
        self.input_gen = factory.get_input_generator(data_seed)
        self.executor = factory.get_executor()
        self.model = factory.get_model(self.executor.read_base_addresses())
        self.analyser = factory.get_analyser()
        self.asm_parser = factory.get_asm_parser(self.generator)

        self.arch_executor = factory.get_executor(True)
        self.arch_model = factory.get_model(self.arch_executor.read_base_addresses(), True)

    def start_random(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
                     save_violations: bool) -> bool:
        self.initialize_modules()
        self.generation_function = self.generator.create_test_case
        return self._start(num_test_cases, num_inputs, timeout, nonstop, save_violations)

    def start_from_template(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
                            save_violations: bool) -> bool:
        self.initialize_modules()
        self.generation_function = self.generator.create_test_case_from_template
        return self._start(num_test_cases, num_inputs, timeout, nonstop, save_violations)

    def start_from_asm(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
                       save_violations: bool) -> bool:
        self.initialize_modules()
        self.generation_function = self.asm_parser.parse_file
        return self._start(num_test_cases, num_inputs, timeout, nonstop, save_violations)

    def _start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool,
               save_violations: bool) -> bool:
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
                if save_violations:
                    self._store_violation_artifact(test_case, violation, self.work_dir)
                STAT.violations += 1
                if not nonstop:
                    break

        self.LOG.fuzzer_finish()
        self.LOG.dbg_report_coverage(self.model)
        return STAT.violations > 0

    def filter(self, test_case, inputs) -> bool:
        return False  # implemented by architecture-specific subclasses

    def fuzzing_round(self,
                      test_case: TestCase,
                      inputs: List[Input],
                      ignore_list: List[int] = []) -> Optional[Violation]:
        """
        Run a single fuzzing round: collect contract and hardware traces for the given test
        case and inputs, and check for contract violations.

        The function implements a multi-stage approach to testing, with the first measurement being
        fast but with a chance of false positives, and the later stages filtering out various
        types of potential false positives. The exact number of stages depends on
        the configuration.

        :param test_case: the test case to be executed
        :param inputs: the inputs to be tested
        :param ignore_list: a list of input IDs to be ignored by the executor
        :return: the first detected violation or None if no violations were found
        """
        # Common variables
        htraces: List[HTrace] = []
        violations: List[Violation] = []

        # Define the starting parameters for the current configuration
        n_reps: int = CONF.executor_sample_sizes[0]
        start_nesting: int = CONF.model_min_nesting if self.model.is_speculative_contract else 1
        end_nesting: int = CONF.model_max_nesting if self.model.is_speculative_contract else 1
        assert start_nesting <= end_nesting

        # Create the tracing arguments
        args = TracingArguments(
            inputs=inputs,
            n_reps=n_reps,
            model_nesting=start_nesting,
            ctraces=[],
            record_stats=True,
            fast_boosting=CONF.enable_fast_path_model,
            update_ignore_list=True,
            reuse_ctraces=False,
            added_htraces=[])

        # 0. Load the test case into the model and executor
        self.model.load_test_case(test_case)
        self.executor.load_test_case(test_case)
        if ignore_list:
            self.executor.set_ignore_list(ignore_list)

        # 1. Fast path: Collect traces with minimal nesting and repetitions
        args.inputs, args.ctraces = self._boost_inputs(inputs, start_nesting)
        violations, args.ctraces, htraces = self._collect_traces(args)
        if not violations:
            STAT.fast_path += 1
            return None
        self.reference_htraces = htraces  # we use the fast path traces as a reference
        args.record_stats = False  # we record stats only in the fast path

        # 2. Slow path: Go through potential sources of false violations in the fast path,
        #    and check them one at a time, starting with the most likely ones
        self.LOG.fuzzer_slow_path()

        # 2.1 FP might appear because the model did not go deep enough into nested speculation.
        #     To remove such FPs, we re-run the model tracing with max nesting. As taints depend on
        #     contract traces, we also have to re-boost the inputs, and re-collect hardware traces
        #     for the new inputs
        if start_nesting != end_nesting:
            args.model_nesting = end_nesting
            args.inputs, args.ctraces = self._boost_inputs(inputs, end_nesting)
            violations, args.ctraces, htraces = self._collect_traces(args)
            if not violations:
                STAT.fp_nesting += 1
                return None

        # 2.2 FP might appear because of imperfect tainting (e.g., due to a bug in taint tracker).
        #     To remove such FPs, we collect contract traces for all boosted inputs, and check if
        #     the violation is still present
        if CONF.enable_fast_path_model:
            args.fast_boosting = False

            full_ctraces = self.model.trace_test_case(args.inputs, end_nesting)
            if full_ctraces != args.ctraces:
                # notify the user about the mismatch
                self.LOG.warning("fuzzer", "Fast path contract traces do not match the full traces")
                if self.work_dir and not CONF._no_generation:
                    self.LOG.warning("fuzzer", f"Storing the bug into {self.work_dir}/bugs/")
                    self._store_violation_artifact(test_case, violations[0],
                                                   f"{self.work_dir}/bugs/")

                # re-run the experiment with the full contract traces
                violations, args.ctraces, _ = self._collect_traces(args)
                if not violations:
                    STAT.fp_taint_mistakes += 1
                    return None

        # At this point, we can be confident in contract traces, so we can start reusing them
        args.reuse_ctraces = True

        # 2.3 FP might appear because of interference between inputs. To remove such FPs, we
        #     use the priming test where we swap inputs that caused the violation with each other
        if CONF.enable_priming:
            violations = self._priming(violations, args.inputs)
            if not violations:
                STAT.fp_early_priming += 1
                self.LOG.trc_fuzzer_dump_traces(self.model, args.inputs, htraces,
                                                self.reference_htraces, args.ctraces, end_nesting)
                return None

        # 2.4 FP might appear because we experienced noise. Retry the experiment with a larger
        #     sample size to reduce the impact of noise
        for n_reps in CONF.executor_sample_sizes[1:]:
            self.LOG.fuzzer_sample_size_increase(n_reps)
            args.n_reps = n_reps
            args.n_reps -= len(htraces[0].raw)  # subtract the number of repetitions already done
            args.added_htraces = htraces

            violations, _, htraces = self._collect_traces(args)
            if not violations:
                STAT.fp_large_sample += 1
                return None

            # 2.4.2 Priming might have failed because the sample size was too small, causing
            #     non-deterministic results. Retry the priming test with the largest sample size
            if CONF.enable_priming:
                violations = self._priming(violations, args.inputs)
                if not violations:
                    STAT.fp_priming += 1
                    self.LOG.trc_fuzzer_dump_traces(self.model, args.inputs, htraces,
                                                    self.reference_htraces, args.ctraces,
                                                    end_nesting)
                    return None

        # 2.5 FP might appear because of a mismatch between the model and the executor.
        # Such cases are rare, hence we check for them last.
        # To remove such FPs, we check if the violation is caused by an architectural mismatch
        if self.is_architectural_mismatch(test_case, violations[0]):
            if self.work_dir and not CONF._no_generation:
                self.LOG.warning("fuzzer", f"Storing the bug into {self.work_dir}/bugs/")
                self._store_violation_artifact(test_case, violations[0], f"{self.work_dir}/bugs/")
            return None

        # Violation survived all checks. Report it
        self.LOG.trc_fuzzer_dump_traces(self.model, args.inputs, htraces, self.reference_htraces,
                                        args.ctraces, end_nesting)
        return violations[0]

    def _collect_traces(
            self, args: TracingArguments) -> Tuple[List[Violation], List[CTrace], List[HTrace]]:
        """
        Collect contract and hardware traces for the given inputs and check for violations.

        Depending on the flags, the function can reuse contract traces, merge new hardware traces
        with the existing ones, and update the ignore list of the executor.

        :param args: Container for the arguments of the function:
           - args.inputs: the inputs to be tested
           - args.n_reps: the number of repetitions to be used for hardware tracing
           - args.model_nesting: the nesting level to be used for contract tracing
           - args.reuse_ctraces: the contract traces to be reused for the given inputs
           - args.record_stats: whether to record statistics about the traces
           - args.fast_boosting: whether to assume that boosted inputs will have
               the same contract trace as the original inputs
           - args.update_ignore_list: whether to update the ignore list of the executor
           - args.added_htraces: additional hardware traces to be added to the existing ones
        :return: a tuple of violations, contract traces, and hardware traces
        """
        # Collect contract traces
        if args.reuse_ctraces:
            ctraces = args.ctraces
        elif args.fast_boosting:
            # records same ctrace for all members of the same input class
            ctraces = args.ctraces * CONF.inputs_per_class
        else:
            # compute ctraces separately for every boosted input
            ctraces = self.model.trace_test_case(args.inputs, args.model_nesting)
        assert len(ctraces) == len(args.inputs)

        # Collect hardware traces
        try:
            htraces = self.executor.trace_test_case(args.inputs, args.n_reps)
        except HardwareTracingError:
            return [], [], []
        assert len(htraces) == len(args.inputs)

        # Merge hardware traces if provided
        if args.added_htraces:
            for i, h in enumerate(htraces):
                htraces[i] = HTrace(h.raw + args.added_htraces[i].raw)

        # Check for violations
        violations = self.analyser.filter_violations(
            args.inputs, ctraces, htraces, stats=args.record_stats)
        if not violations:
            # if violation is detected, print debug traces (if requested)
            self.LOG.trc_fuzzer_dump_traces(self.model, args.inputs, htraces,
                                            self.reference_htraces, ctraces, CONF.model_max_nesting)

        if args.update_ignore_list:
            # label all non-violating inputs as ignored by executor, so that we don't trigger
            # a chain reaction of false positives when the measurement results are non-deterministic
            violating_ids = [m.input_id for v in violations for m in v.measurements]
            ignored_input_ids = [i for i in range(len(args.inputs)) if i not in violating_ids]
            self.executor.extend_ignore_list(ignored_input_ids)

        return violations, ctraces, htraces

    def _boost_inputs(self, inputs: List[Input], nesting) -> Tuple[List[Input], List[CTrace]]:
        """
        Boost the given inputs by generating additional inputs in the same equivalence classes,
        and also collect the contract traces for the ORIGINAL (i.e., non-boosted) inputs. Note
        that the contract traces for the boosted inputs are not collected here (for efficiency
        reasons), but are collected in the _collect_traces function.

        This function performs two tasks at once because contract tracing and input boosting
        rely on the same emulation function, so it is more efficient to do them together.

        :param inputs: the inputs to be boosted
        :param nesting: the speculation nesting level to be used by the model
        :return: a tuple of boosted inputs and contract traces for the original inputs
        :raises AssertionError: if the number of contract traces does not match the number
                of original inputs
        """
        ctraces: List[CTrace]
        taints: List[InputTaint]

        # collect taints and contract traces for initial inputs
        ctraces, taints = self.model.trace_test_case_with_taints(inputs, nesting)

        # ensure that we have many inputs in each input classes
        self.input_gen.reset_boosting_state()
        boosted_inputs = list(inputs)  # make a copy
        for _ in range(CONF.inputs_per_class - 1):
            boosted_inputs += self.input_gen.extend_equivalence_classes(inputs, taints)

        assert len(inputs) == len(ctraces)
        return boosted_inputs, ctraces

    def _store_violation_artifact(self, test_case: TestCase, violation: Violation, path: str):
        """
        Store a violation artifact into the given directory.

        A violation artifact consists of:
        - the test case that caused the violation (program.asm)
        - the inputs that caused the violation (input_*.bin)
        - the original configuration file (org-config.yaml)
        - the configuration file for reproducing violation from artifact (reproduce.yaml)
        - the configuration file for minimization (minimize.yaml)

        :param test_case: the test case that caused the violation
        :param violation: the violation to be stored
        :param path: the path to the directory where the artifact should be stored;
                    if empty, the artifact is stored in the current directory
        """
        # if the path is empty, store the artifact in the current directory
        if not path:
            path = "."

        # create a subdirectory for the violation artifact
        timestamp = datetime.today().strftime('%y%m%d-%H%M%S')
        violation_dir = f"{path}/violation-{timestamp}"
        Path(path).mkdir(exist_ok=True)
        Path(violation_dir).mkdir()

        # store violation
        test_case.save(f"{violation_dir}/program.asm")
        for i, input_ in enumerate(violation.input_sequence):
            input_.save(f"{violation_dir}/input_{i:04}.bin")

        # store the original configuration file
        if CONF._config_path:
            shutil.copy2(CONF._config_path, f"{violation_dir}/org-config.yaml")
        else:
            with open(f"{violation_dir}/org-config.yaml", "w") as f:
                f.write("# Original violation used a default config, hence this file is empty\n")

        # create patched configs for reproducing and minimizing the violation
        shutil.copy2(f"{violation_dir}/org-config.yaml", f"{violation_dir}/reproduce.yaml")
        with open(f"{violation_dir}/reproduce.yaml", "a") as f:
            f.write("\n# Overwrite some of the configuration options to reproduce the violation\n")
            f.write(f"input_gen_seed: {violation.input_sequence[0].seed}\n")
            f.write("inputs_per_class: 1\n")
        shutil.copy2(f"{violation_dir}/org-config.yaml", f"{violation_dir}/minimize.yaml")
        with open(f"{violation_dir}/minimize.yaml", "a") as f:
            f.write("\n# Overwrite some of the configuration options to reproduce the violation\n")
            f.write(f"input_gen_seed: {violation.input_sequence[0].seed}\n")

        # we're about to store stats into a file - disable colors
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
            f.write(f"* Input seed: {violation.input_sequence[0].seed}\n")
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
                ctraces.append(CTrace([int(line)]))
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

    # ==============================================================================================
    # Checking for false positives
    def _priming(self, violations: List[Violation], inputs: List[Input]) -> List[Violation]:
        violation_stack = list(violations)  # make a copy
        while violation_stack:
            self.LOG.fuzzer_priming(len(violation_stack))
            violation: Violation = violation_stack.pop()
            if self._prime_one(violation, inputs):
                return [violation]
        return []

    def _prime_one(self, org_violation: Violation, all_inputs: List[Input]) -> bool:
        """
        Try priming the inputs that caused the violations

        return: True if the violation survived priming
        """
        violation = copy.copy(org_violation)
        measurements_to_test = [hg[0] for hg in violation.htrace_groups]
        null_htrace = HTrace.get_null()
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

    def is_architectural_mismatch(self, test_case: TestCase, violation: Violation) -> bool:
        """
        Check if the violation is caused by an architectural mismatch between the model
        and the executor. For example, this may happen if the model incorrectly emulates the
        execution of an instruction due to a bug in the emulator.

        :return: True if the violation is caused by an architectural mismatch; False otherwise
        """
        inputs = violation.input_sequence
        hardware_regs: List[List[int]] = []
        model_regs: List[List[int]] = []

        self.arch_model.load_test_case(test_case)
        self.arch_executor.load_test_case(test_case)

        # Collect architectural hardware traces
        try:
            htraces = self.arch_executor.trace_test_case(inputs, 1)
        except HardwareTracingError:
            return False  # skip test case in case of a tracing error
        for htrace_obj in htraces:
            hardware_regs.append(
                [htrace_obj.raw[0]]  # rax
                + list(htrace_obj.perf_counters[0]),  # rbx ... rdi
            )

        # Collect architectural model traces
        ctraces = self.arch_model.trace_test_case(inputs, CONF.model_max_nesting)
        for ctrace in ctraces:
            model_regs.append(ctrace.raw)

        # Debug outputs
        self.LOG.dbg_fuzzer_dump_architectural_traces(hardware_regs, model_regs)

        # Check for violations
        # Note: since we simply check the equality of traces, we don't need to invoke the analyser
        for i in range(len(inputs)):
            if model_regs[i] != hardware_regs[i]:
                self.LOG.fuzzer_report_architectural_violation(i, hardware_regs[i], model_regs[i])
                return True

        return False


class ArchitecturalFuzzer(FuzzerGeneric):
    """
    A simplified fuzzer that checks for architectural mismatches between the model and the
    executor. This fuzzer is useful for detecting bugs in Revizor, but it cannot detect
    contract violations.

    The fuzzer piggy-backs on the is_architectural_mismatch function of FuzzerGeneric
    to check for mismatches.
    """

    def __init__(self,
                 instruction_set_spec: str,
                 work_dir: str,
                 existing_test_case: str = "",
                 inputs: List[str] = []):
        super().__init__(instruction_set_spec, work_dir, existing_test_case, inputs)
        self.LOG.warning("fuzzer", "Running in architectural mode. "
                         "Contract violations can't be detected!")

    def fuzzing_round(self,
                      test_case: TestCase,
                      inputs: List[Input],
                      _: List[int] = []) -> Optional[Violation]:
        """
        Run a single fuzzing round: collect contract and hardware traces for the given test
        case and inputs, and check for architectural mismatches.
        """
        # Create a pseudo-violation to reuse the existing is_architectural_mismatch function
        null_ctrace = CTrace.get_null()
        violation = Violation.from_measurements(null_ctrace, [], [], inputs)

        # Check for architectural mismatches
        if self.is_architectural_mismatch(test_case, violation):
            return violation

        return None
