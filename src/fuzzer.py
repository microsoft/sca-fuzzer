"""
File: Fuzzing Orchestration

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import shutil
import os
import yaml
from pathlib import Path
from datetime import datetime
from typing import Optional, List
from copy import copy

import factory
from interfaces import CTrace, HTrace, Input, InputTaint, EquivalenceClass, TestCase, Generator, \
    InputGenerator, Model, Executor, Analyser, Coverage, InputID
from isa_loader import InstructionSet

from config import CONF
from service import STAT, LOGGER, TWOS_COMPLEMENT_MASK_64, bit_count


class Fuzzer:
    instruction_set: InstructionSet
    existing_test_case: str

    generator: Generator
    input_gen: InputGenerator
    executor: Executor
    model: Model
    analyser: Analyser
    coverage: Coverage

    def __init__(self, instruction_set_spec: str, work_dir: str, existing_test_case: str = ""):
        self.existing_test_case = existing_test_case
        if existing_test_case:
            CONF.setattr_internal("_no_generation", True)
            CONF.setattr_internal("_default_instruction_blocklist", [])
            CONF.register_blocklist = []

        self.instruction_set = InstructionSet(instruction_set_spec, CONF.instruction_categories)
        self.work_dir = work_dir

    def initialize_modules(self):
        """ create all main modules """
        self.generator = factory.get_program_generator(self.instruction_set,
                                                       CONF.program_generator_seed)
        self.input_gen: InputGenerator = factory.get_input_generator(CONF.input_gen_seed)

        self.executor: Executor = factory.get_executor()
        self.model: Model = factory.get_model(self.executor.read_base_addresses())
        self.analyser: Analyser = factory.get_analyser()
        self.coverage: Coverage = factory.get_coverage(self.instruction_set, self.executor,
                                                       self.model, self.analyser)

    def start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool = False):
        start_time = datetime.today()
        LOGGER.fuzzer_start(num_test_cases, start_time)

        # create all main modules
        self.initialize_modules()

        for i in range(num_test_cases):
            LOGGER.fuzzer_start_round(i)
            LOGGER.dbg_report_coverage(i, self.coverage.get_brief())

            # Generate a test case
            if not self.existing_test_case:
                test_case = self.generator.create_test_case('generated.asm')
            else:
                test_case = self.generator.parse_existing_test_case(self.existing_test_case)
            STAT.test_cases += 1

            # Prepare inputs
            inputs: List[Input] = self.input_gen.generate(num_inputs)
            STAT.num_inputs += len(inputs) * CONF.inputs_per_class

            # Check if the test case is useful
            if self.filter(test_case, inputs):
                continue

            # Fuzz the test case
            violation = self.fuzzing_round(test_case, inputs)

            if violation:
                LOGGER.fuzzer_report_violations(violation, self.model)
                self.store_test_case(test_case, False)
                STAT.violations += 1
                if not nonstop:
                    break

            # stop fuzzing after a timeout
            if timeout:
                now = datetime.today()
                if (now - start_time).total_seconds() > timeout:
                    LOGGER.fuzzer_timeout()
                    break

        LOGGER.fuzzer_finish()

    def filter(self, test_case, inputs):
        return False  # implemented by architecture-specific subclasses

    def fuzzing_round(self, test_case: TestCase, inputs: List[Input]) -> Optional[EquivalenceClass]:
        self.model.load_test_case(test_case)
        self.executor.load_test_case(test_case)
        self.coverage.load_test_case(test_case)

        # 1. Test for contract violations with nesting=1
        # Test against the most basic contract - seq with no nesting - to check
        # if the traces contain *any* speculative information
        ctraces: List[CTrace]
        htraces: List[HTrace]

        # at this point we need to increase the effectiveness of inputs
        # so that we can detect contract violations (note that it wasn't necessary
        # up to this point because we weren't testing against a contract)
        boosted_inputs: List[Input] = self.boost_inputs(inputs, 1)

        # check for violations
        ctraces = self.model.trace_test_case(boosted_inputs, 1)
        htraces = self.executor.trace_test_case(boosted_inputs, CONF.executor_repetitions)
        LOGGER.trc_fuzzer_dump_traces(self.model, boosted_inputs, htraces, ctraces,
                                      self.executor.get_last_feedback())
        violations = self.analyser.filter_violations(boosted_inputs, ctraces, htraces, True)
        if not violations:  # nothing detected? -> we are done here, move to next test case
            return None

        # 4. Repeat with with max nesting
        # Test against the target contract to check if the speculative information
        # is already exposed in the contract. If it isn't - we found a violation
        if 'seq' not in CONF.contract_execution_clause:
            LOGGER.fuzzer_nesting_increased()
            boosted_inputs = self.boost_inputs(inputs, CONF.model_max_nesting)
            ctraces = self.model.trace_test_case(boosted_inputs, CONF.model_max_nesting)
            htraces = self.executor.trace_test_case(boosted_inputs, CONF.executor_repetitions)
            violations = self.analyser.filter_violations(boosted_inputs, ctraces, htraces, True)
            if not violations:
                return None

        # 5. Check if the violation survives priming
        if not CONF.enable_priming:
            return violations[-1]
        STAT.required_priming += 1

        violation_stack = list(violations)  # make a copy
        while violation_stack:
            LOGGER.fuzzer_priming(len(violation_stack))
            violation: EquivalenceClass = violation_stack.pop()
            if self.priming(violation, boosted_inputs):
                break
        else:
            # All violations were cleared by priming.
            # Check whether it was actually successful priming
            # or the measurement are just flaky
            if self.check_if_reproducible(violations, boosted_inputs, htraces):
                STAT.flaky_violations += 1
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

    def store_test_case(self, test_case: TestCase, require_retires: bool):
        if not self.work_dir:
            return

        type_ = "retry" if require_retires else "violation"
        timestamp = datetime.today().strftime('%H%M%S-%d-%m-%y')
        name = type_ + timestamp + ".asm"
        Path(self.work_dir).mkdir(exist_ok=True)
        test_case.save(self.work_dir + "/" + name)

        if not Path(self.work_dir + "/config.yaml").exists:
            shutil.copy2(CONF.config_path, self.work_dir + "/config.yaml")

    # ==============================================================================================
    # Single-stage interfaces
    def generate_test_batch(self,
                            num_test_cases: int,
                            num_inputs: int,
                            input_format=None,
                            permit_overwrite=False):
        """
        A function invoked as a standalone way to generate fuzzer test cases and
        inputs without running the entire fuzzer. This accepts a seed, a number
        of test cases, and a number of inputs, and generates accordingly.

        * To generate only assembly test cases, set 'num_inputs' to 0.
        * To generate only inputs, set 'num_test_cases' to 0.

        The test cases and inputs are saved to individual files in the
        user-specified working directory (or the user's current directory, if no
        directory is specified).

        Optionally, this accepts an 'input_format' string that corresponds to
        one of the supported modes in the Input class' 'save()' method. If left
        as None, a default will be used.

        This also accepts 'permit_overwrite', which allows for an existing set
        of generated files to be overwritten in the same directory. By default
        this is false.
        """
        LOGGER.fuzzer_start(0, datetime.today())

        # prepare for generation
        STAT.test_cases = num_test_cases

        # log the given parameters
        log_msg = "Generating batch of %d program(s) and %d input(s). " \
                  "(program seed: %d) (input seed: %d)" % \
                  (num_test_cases, num_inputs, CONF.program_generator_seed, CONF.input_gen_seed)
        if input_format:
            log_msg += " (input file format: %s)" % input_format
        LOGGER.inform("fuzzer", log_msg)

        # if no working directory was supplied, use the current directory
        out_dir = self.work_dir
        if not out_dir or out_dir == "":
            out_dir = os.getcwd()
        Path(out_dir).mkdir(exist_ok=True, mode=0o755)

        # create the two generators
        self.generator = factory.get_program_generator(self.instruction_set,
                                                       CONF.program_generator_seed)
        self.input_gen = factory.get_input_generator(CONF.input_gen_seed)

        # invoke the test-case generator to create assembly files
        for i in range(num_test_cases):
            # attempt to create a directory for the test case
            test_case_dir = out_dir + "/tc" + str(i)
            try:
                Path(test_case_dir).mkdir(exist_ok=permit_overwrite, mode=0o755)
            except FileExistsError:
                LOGGER.error(f"Directory '{test_case_dir}' already exists\n"
                             "Use --permit-overwrite to overwrite the test case")

            # generate the program
            asm_path = os.path.join(test_case_dir, "program.asm")
            self.generator.create_test_case(asm_path, True)
            LOGGER.inform("fuzzer", "Created assembly test case at %s" % asm_path)

            # write the current configurations out to the test case's directory
            config_out_path = os.path.join(test_case_dir, "config.yml")
            config_fields = CONF.all()
            # TODO - use the new seed management (PR #21) to update the seed
            # in this loop iteration such that the correct seed is written
            # into the config file for this particular program
            # config_fields["program_generator_seed"] = self.generator._state
            with open(config_out_path, "w") as fp:
                yaml.dump(config_fields, fp)

        # if NO programs were specified but some inputs were specified, we'll
        # still generate the inputs and place them in 'tc0/', but there won't
        # be an assembly program in 'tc0/'
        input_loop = 0 if num_inputs == 0 else max(1, num_test_cases)
        for t in range(input_loop):
            # invoke the input generator to generate a number of inputs
            inputs: List[Input] = self.input_gen.generate(num_inputs)

            # select a directory to save these inputs to, then write them out
            save_dir = os.path.join(out_dir, f"tc{t}")
            Path(save_dir).mkdir(exist_ok=True, mode=0o755)
            for i, inp in enumerate(inputs):
                inp_path = os.path.join(save_dir, f"input_{i}.data")
                inp_path = inp.save(inp_path, mode=input_format)
                LOGGER.inform(
                    "fuzzer", "Created input with data_size=%d, "
                    "register_start=%d at %s" % (inp.data_size, inp.register_start, inp_path))

            # if we didn't save a copy of the config file in the previous loop,
            # do so now
            if num_test_cases == 0:
                config_out_path = os.path.join(save_dir, "config.yml")
                CONF.save(config_out_path)

        LOGGER.fuzzer_finish()

    @staticmethod
    def analyse_traces_from_files(ctrace_file: str, htrace_file: str):
        LOGGER.dbg_violation = False  # make sure we don't try to call the model
        LOGGER.fuzzer_start(0, datetime.today())
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
            LOGGER.fuzzer_report_violations(violations[0], None)

        LOGGER.fuzzer_finish()

    # ==============================================================================================
    # Priming and reproducibility
    def check_if_reproducible(self, violations: List[EquivalenceClass], inputs: List[Input],
                              org_htraces: List[HTrace]) -> bool:
        violating_input_ids = []
        for violation in violations:
            for measurement in violation.measurements:
                violating_input_ids.append(measurement.input_id)

        # re-collect htraces
        htraces: List[HTrace] = self.executor.trace_test_case(inputs, CONF.executor_repetitions)

        # check if all htraces that had a violation match
        for i in violating_input_ids:
            if htraces[i] != org_htraces[i]:
                return True
        return False

    def priming(self, org_violation: EquivalenceClass, all_inputs: List[Input]) -> bool:
        """
        Try priming the inputs that caused the violations

        return: True if the violation survived priming
        """
        violation = copy(org_violation)
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
