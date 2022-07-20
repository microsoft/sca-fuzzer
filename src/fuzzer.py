"""
File: Fuzzing Orchestration

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Tuple
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
            CONF.gpr_blocklist = []
            CONF.instruction_blocklist = []

        self.instruction_set = InstructionSet(instruction_set_spec, CONF.supported_categories)
        self.work_dir = work_dir

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

            # Prepare inputs
            inputs: List[Input] = self.input_gen.generate(CONF.input_gen_seed, num_inputs)

            # Fuzz the test case
            violation = self.fuzzing_round(test_case, inputs)
            STAT.test_cases += 1

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

    def fuzzing_round(self, test_case: TestCase, inputs: List[Input]) -> Optional[EquivalenceClass]:
        self.model.load_test_case(test_case)
        self.executor.load_test_case(test_case)
        self.coverage.load_test_case(test_case)

        # by default, we test without nested misprediction,
        # but retry with nesting upon a violation
        violations: List[EquivalenceClass] = []
        boosted_inputs: List[Input] = []
        for nesting in [1, CONF.model_max_nesting]:
            boosted_inputs = self.boost_inputs(inputs, nesting)
            STAT.num_inputs += len(boosted_inputs)

            # get traces
            ctraces: List[CTrace] = self.model.trace_test_case(boosted_inputs, nesting)
            htraces: List[HTrace] = self.executor.trace_test_case(boosted_inputs)
            LOGGER.trc_fuzzer_dump_traces(htraces, ctraces)

            # Check for violations
            violations = self.analyser.filter_violations(boosted_inputs, ctraces, htraces, True)

            # nothing detected? -> we are done here, move to next test case
            if not violations:
                return None

            # sequential contract? -> no point in trying higher nesting
            if 'seq' in CONF.contract_execution_clause:
                break

            # otherwise, try higher nesting
            if nesting == 1:
                LOGGER.fuzzer_nesting_increased()

        if CONF.no_priming:
            return violations[-1]

        # Try priming the inputs that disagree with the other ones within the same eq. class
        STAT.required_priming += 1
        while violations:
            LOGGER.fuzzer_priming(len(violations))
            violation: EquivalenceClass = violations.pop()
            if self.survives_priming(violation, boosted_inputs):
                break
        else:
            # all violations were cleaned. all good
            return None

        # Violation survived priming. Report it
        return violation

    def initialize_modules(self):
        """ create all main modules """
        self.generator = factory.get_generator(self.instruction_set)
        self.input_gen: InputGenerator = factory.get_input_generator()
        self.executor: Executor = factory.get_executor()
        self.model: Model = factory.get_model(self.executor.read_base_addresses())
        self.analyser: Analyser = factory.get_analyser()
        self.coverage: Coverage = factory.get_coverage(self.instruction_set, self.executor,
                                                       self.model, self.analyser)

    def boost_inputs(self, inputs: List[Input], nesting: int) -> List[Input]:
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
        shutil.copy2(test_case.asm_path, self.work_dir + "/" + name)

        if not Path(self.work_dir + "/config.yaml").exists:
            shutil.copy2(CONF.config_path, self.work_dir + "/config.yaml")

    # ==============================================================================================
    # Priming algorithm
    def survives_priming(self, org_violation: EquivalenceClass, all_inputs: List[Input]) -> bool:
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
                if not self.primer_is_effective(primer, [current_input_id], current_htrace):
                    return True

        return False

    def primer_is_effective(self, inputs: List[Input], positions: List[InputID],
                            expected_htrace: HTrace) -> bool:
        htraces: List[HTrace] = self.executor.trace_test_case(inputs, CONF.executor_repetitions)
        for i, htrace in enumerate(htraces):
            if i not in positions:
                continue
            if htrace == expected_htrace:
                continue

            # if the primed measurement triggered more speculation, it's ok
            if (htrace ^ TWOS_COMPLEMENT_MASK_64) & expected_htrace == 0:
                continue

            return False
        return True

    # ==============================================================================================
    # Batched priming algoritm - deprecated???
    def survives_priming_batched(self, org_violation: EquivalenceClass,
                                 all_inputs: List[Input]) -> bool:
        violation = copy(org_violation)
        ordered_htraces = sorted(
            violation.htrace_map.keys(), key=lambda x: bit_count(x), reverse=False)

        for current_htrace in ordered_htraces:
            current_input_id = violation.htrace_map[current_htrace][-1].input_id

            # list of inputs that produced a different HTrace
            input_ids_to_test: List[InputID] = [
                m.input_id for m in violation.measurements if m.htrace != current_htrace
            ]

            # create a primer that would cover all the conflicting inputs at the same time
            batch_primer, primed_ids = self.build_batch_primer(all_inputs,
                                                               current_input_id, current_htrace,
                                                               len(input_ids_to_test))
            if not batch_primer:
                STAT.priming_errors += 1
                # self.store_test_case(self.test_case, True)
                return False

            # insert the tested inputs into their places
            assert len(primed_ids) == len(input_ids_to_test)
            for input_id, primer_id in zip(input_ids_to_test, primed_ids):
                batch_primer[primer_id] = all_inputs[input_id]

            # try priming
            if not self.primer_is_effective(batch_primer, primed_ids, current_htrace):
                return True

        return False

    def build_batch_primer(self, inputs: List[Input], target_input_id: InputID,
                           expected_htrace: HTrace,
                           num_primed_inputs: int) -> Tuple[List[Input], List[InputID]]:
        # the first size to be tested
        primer_size = CONF.min_primer_size % len(inputs) + 1

        while True:
            # print(f"Trying primer {primer_size}")
            # build a set of priming inputs (i.e., multiprimer)
            if primer_size <= target_input_id:
                primer = inputs[target_input_id - primer_size:target_input_id + 1]
            else:
                primer = inputs[target_input_id - primer_size:] + inputs[:target_input_id + 1]
            assert len(primer) == primer_size + 1
            assert primer[-1].seed == inputs[target_input_id].seed

            batch_primer = primer * num_primed_inputs
            # print(target_input_id, primer_size, len(inputs), len(primer))
            primed_ids = list(
                range(primer_size, num_primed_inputs * (primer_size + 1), primer_size + 1))
            # print(primed_ids)

            # check if the hardware trace of the target_id matches
            # the hardware trace received with the primer
            if self.primer_is_effective(batch_primer, primed_ids, expected_htrace):
                return batch_primer, primed_ids

            # if we failed, try a larger primer
            new_size = primer_size * 2

            # if we just wrapped around, try all original preceding inputs as primer
            if new_size > target_input_id and primer_size < target_input_id:
                primer_size = target_input_id
            else:
                primer_size = new_size

            # if a larger primer is allowed, try adding more inputs
            if primer_size > CONF.max_primer_size:
                # otherwise, we failed to find a primer
                LOGGER.waring("fuzzer", "Failed to build a primer - max_primer_size reached")
                return [], []

            # run out of inputs to test?
            if primer_size >= len(inputs):
                LOGGER.waring("fuzzer", "Insufficient inputs to build a primer")
                return [], []
