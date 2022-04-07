"""
File: Fuzzing Orchestration

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List

from interfaces import CTrace, HTrace, Input, InputTaint, EquivalenceClass, TestCase, Generator, \
    InputGenerator, Model, Executor, Analyser, Coverage
from generator import get_generator
from input_generator import get_input_generator
from model import get_model
from executor import get_executor
from analyser import get_analyser
from coverage import get_coverage
from instruction_set import InstructionSet

from config import CONF
from service import STAT, LOGGER
from helpers import pretty_bitmap, bit_count, TWOS_COMPLEMENT_MASK_64


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
            CONF._no_generation = True
            CONF.gpr_blocklist = []
            CONF.instruction_blocklist = []

        self.instruction_set = InstructionSet(instruction_set_spec, CONF.supported_categories)
        self.work_dir = work_dir

    def start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool = False):
        start_time = datetime.today()
        LOGGER.start_fuzzing(num_test_cases, start_time)

        # create all main modules
        self.initialize_modules()

        # preserve the original ratio of inputs to the test case size
        input_ratio = num_inputs / CONF.test_case_size
        STAT.num_inputs = num_inputs

        for i in range(num_test_cases):
            # Generate a test case
            if not self.existing_test_case:
                test_case = self.generator.create_test_case('generated.asm')
            else:
                test_case = self.generator.parse_existing_test_case(self.existing_test_case)

            # Prepare inputs
            inputs: List[Input] = self.input_gen.generate(CONF.input_generator_seed, num_inputs)

            # Fuzz the test case
            violation = self.fuzzing_round(test_case, inputs)
            STAT.test_cases += 1
            self.coverage.update()

            if violation:
                self.report_violations(violation, self.model)
                self.store_test_case(test_case, False)
                STAT.violations += 1
                if not nonstop:
                    break

            # stop fuzzing after a timeout
            if timeout:
                now = datetime.today()
                if (now - start_time).total_seconds() > timeout:
                    if CONF.verbose:
                        print("\nTimeout expired")
                    break

            if STAT.test_cases % 100 == 0 and CONF.verbose >= 2:
                print(f"\nFUZZER: current duration: "
                      f"{(datetime.today() - start_time).total_seconds()}")

            # if we fuzz a fixed test case, no re-configuration will be necessary
            if self.existing_test_case:
                continue

            # if the configuration has changed, update num inputs and entropy
            if CONF.feedback_driven_generator and \
                    CONF.avg_mem_accesses >= pow(2, CONF.prng_entropy_bits):
                input_ratio *= 1.5
                CONF.prng_entropy_bits += 1
                if CONF.verbose >= 2:
                    print(f"FUZZER: increasing entropy: {CONF.prng_entropy_bits}")

            if STAT.effective_eq_classes / STAT.test_cases < 1:
                input_ratio *= 1.2

            if CONF.adaptive_input_number and \
                    num_inputs / CONF.test_case_size < input_ratio:
                num_inputs = int(input_ratio * CONF.test_case_size) + 1
                STAT.num_inputs = num_inputs
                if CONF.verbose >= 2:
                    print(f"FUZZER: increasing the number of inputs: {num_inputs}")

        LOGGER.finish()

    def fuzzing_round(self, test_case: TestCase, inputs: List[Input]) -> Optional[EquivalenceClass]:
        LOGGER.start_round()
        self.model.load_test_case(test_case)
        self.executor.load_test_case(test_case)
        self.coverage.load_test_case(test_case)

        # by default, we test without nested misprediction,
        # but retry with nesting upon a violation
        violations: List[EquivalenceClass] = []
        for nesting in [1, CONF.max_nesting]:
            boosted_inputs: List[Input] = self.boost_inputs(inputs, nesting)

            # get traces
            ctraces: List[CTrace]
            ctraces, _ = self.model.trace_test_case(boosted_inputs, nesting, False)
            htraces: List[HTrace] = self.executor.trace_test_case(boosted_inputs)

            # for debugging
            if CONF.verbose == 999:
                print("")
                nprinted = 10 if len(ctraces) > 10 else len(ctraces)
                for i in range(nprinted):
                    print("..............................................................")
                    print(pretty_bitmap(ctraces[i], ctraces[i] > pow(2, 64)))
                    print(pretty_bitmap(htraces[i]))

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
                LOGGER.higher_nesting()

        if CONF.no_priming:
            return violations[-1]

        # Try priming the inputs that disagree with the other ones within the same eq. class
        STAT.required_priming += 1
        while violations:
            LOGGER.priming(len(violations))
            violation: EquivalenceClass = violations.pop()
            if self.verify_with_priming(violation, boosted_inputs):
                break
        else:
            # all violations were cleaned. all good
            return None

        # Violation survived priming. Report it
        return violation

    def initialize_modules(self):
        """ create all main modules """
        self.generator = get_generator(self.instruction_set)
        self.input_gen: InputGenerator = get_input_generator()
        self.executor: Executor = get_executor()
        self.model: Model = get_model(self.executor.read_base_addresses())
        self.analyser: Analyser = get_analyser()
        self.coverage: Coverage = get_coverage(self.instruction_set, self.executor, self.model,
                                               self.analyser)

    def boost_inputs(self, inputs: List[Input], nesting: int) -> List[Input]:
        taints: List[InputTaint]
        _, taints = self.model.trace_test_case(inputs, nesting, True)

        # ensure that we have many inputs in each input classes
        boosted_inputs: List[Input] = list(inputs)  # make a copy
        for _ in range(CONF.inputs_per_class - 1):
            boosted_inputs += self.input_gen.extend_equivalence_classes(inputs, taints)
        return boosted_inputs

    def verify_with_priming(self, violation: EquivalenceClass, inputs: List[Input]) -> bool:
        ordered_htraces = sorted(
            violation.htrace_groups.keys(), key=lambda x: bit_count(x), reverse=False)
        original_groups = violation.htrace_groups

        for primer_htrace in ordered_htraces:
            # list of inputs to be tested
            primed_ids = []
            for key, group in original_groups.items():
                if key != primer_htrace:
                    primed_ids.extend(group)

            # create a multiprimer based on the last element in the group
            priming_group_member = original_groups[primer_htrace][-1]
            target_id = violation.original_positions[priming_group_member]
            multiprimer = self.get_min_primer(inputs, target_id, primer_htrace, len(primed_ids))
            if not multiprimer:
                return False
            primer_size = len(multiprimer) // len(primed_ids)

            # insert the tested inputs into their places
            for i, id_ in enumerate(primed_ids):
                multiprimer[(i + 1) * primer_size - 1] = violation.inputs[id_]

            # try swapping
            reproduced = self.check_multiprimer(multiprimer, primer_size, primer_htrace,
                                                CONF.priming_retries)
            if not reproduced:
                return True

            for id_ in primed_ids:
                violation.htraces[id_] |= primer_htrace
            violation.update_groups()

            if len(violation.htrace_groups) == 1:
                break

        return False

    def get_min_primer(self, inputs: List[Input], target_id, expected_htrace,
                       num_primed_inputs) -> List[Input]:
        # first size to be tested
        primer_size = CONF.min_primer_size % len(inputs) + 1

        while True:
            # build a set of priming inputs (i.e., multiprimer)
            primer_end = target_id + 1
            primer_start = primer_end - primer_size
            primer = inputs[primer_start:primer_end] if primer_start >= 0 else \
                inputs[primer_start:] + inputs[0:primer_end]

            multiprimer = []
            for _ in range(num_primed_inputs):
                multiprimer.extend(primer)

            # check if the hardware trace of the target_id matches
            # the hardware trace received with the primer
            primer_found = self.check_multiprimer(multiprimer, primer_size, expected_htrace, 1)

            if primer_found:
                return multiprimer

            # run out of inputs to test?
            if primer_size >= len(inputs):
                # maybe, we have too few executions; try with more
                primer_found = self.check_multiprimer(multiprimer, primer_size, expected_htrace,
                                                      CONF.priming_retries)
                if not primer_found:
                    print("Could not reproduce previous results with priming.")
                    STAT.broken_measurements += 1
                    return []
                return multiprimer

            # if a larger primer is allowed, try adding more inputs
            if primer_size <= CONF.max_primer_size:
                primer_size *= 2
                continue

            # otherwise, we failed to find a primer
            print("Failed to find a primer - max_primer_size reached")
            return []

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

    def check_multiprimer(self, inputs: List[Input], primer_size: int, expected_htrace: HTrace,
                          retries: int) -> bool:
        num_inputs = len(inputs) // primer_size
        num_measurements: int = CONF.num_measurements
        for i in range(retries):
            mismatch = False
            primed_traces: List[HTrace] = self.executor.trace_test_case(inputs, num_measurements)
            for j in range(num_inputs):
                id_ = (primer_size - 1) + j * primer_size
                if primed_traces[id_] != expected_htrace:
                    # print("violation")
                    # print(pretty_bitmap(primed_traces[id_]))
                    # print(pretty_bitmap(expected_htrace) + " [expected]")

                    if primed_traces[id_] < expected_htrace:
                        mismatch = True  # subset, try more repetitions
                        num_measurements += CONF.num_measurements
                        break

                    # check for subsets
                    mask = primed_traces[id_] ^ TWOS_COMPLEMENT_MASK_64
                    if expected_htrace & mask == 0:
                        # the primed measurement triggered more speculation. it's ok
                        mismatch = False
                        break
                    else:
                        mismatch = True
                        break
            if not mismatch:
                return True
        return False

    @staticmethod
    def report_violations(violation: EquivalenceClass, model: Model):
        print("\n\n================================ Violations detected ==========================")
        print("  Contract trace (hash):\n")
        if violation.ctrace <= pow(2, 64):
            print(f"    {violation.ctrace:064b}")
        else:
            print(f"    {violation.ctrace % violation.mod2p64:064b} [ns]\n"
                  f"    {(violation.ctrace >> 64) % violation.mod2p64:064b} [s]\n")
        print("  Hardware traces:")
        for group in violation.htrace_groups.values():
            inputs = [violation.inputs[i] for i in group]
            if len(inputs) < 4:
                print(f"   Inputs {inputs}:")
            else:
                print(f"   Inputs {inputs[:4]} (+ {len(inputs) - 4} ):")
            print(f"    {pretty_bitmap(violation.htraces[group[0]])}")
        print("")

        if CONF.verbose < 2:
            return

        # print details
        for group in violation.htrace_groups.values():
            print("===========================================")
            print(f"Input: {violation.inputs[group[0]]}, {violation.original_positions[group[0]]}")
            model.trace_test_case([violation.inputs[group[0]]], 1, False, True)
