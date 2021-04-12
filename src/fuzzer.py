"""
File: Fuzzing Orchestration

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import shutil
import random
from collections import defaultdict
from pathlib import Path
from datetime import datetime

from generator import Generator
from model import Model, get_model
from executor import Executor, get_executor
from analyser import Analyser, get_analyser
from input_generator import InputGenerator, RandomInputGenerator
from coverage import Coverage, get_coverage
from helpers import *
from custom_types import Dict, CTrace, HTrace, EquivalenceClass, EquivalenceClassMap, Input
from config import CONF


class Logger:
    def __init__(self, iterations: int, start_time):
        self.one_percent_progress = iterations / 100
        self.progress = 0
        self.progress_percent = 0
        self.msg = ""
        self.line_ending = '\n' if CONF.multiline_output else ''
        self.start_time = start_time
        if CONF.verbose:
            print(start_time.strftime('Starting at %H:%M:%S'))
            print("Abbreviations: \n"
                  " P-progress ; EC-effective input classes; EI-effective inputs; CO-coverage\n"
                  " Pr-test cases required priming ; B-broken measurement ;"
                  " V-violations\n")

    def start_round(self):
        if CONF.verbose:
            if STAT.test_cases > self.progress:
                self.progress += self.one_percent_progress
                self.progress_percent += 1
            msg = f"\rP: {STAT.test_cases} [{self.progress_percent}%] | "
            msg += STAT.get_brief()
            print(msg + "Normal execution            ", end=self.line_ending, flush=True)
            self.msg = msg

    def success(self):
        pass
        # if CONF.verbose:
        #     print(self.msg + "Normal execution                                 ",
        #           end=self.line_ending)

    def priming(self, num_violations: int):
        if CONF.verbose:
            print(self.msg + "Priming " + str(num_violations) + "                 ",
                  end=self.line_ending,
                  flush=True)

    def finish(self):
        # new line after the progress bar
        if CONF.verbose:
            now = datetime.today()
            print("")
            print(STAT)
            print(f"Duration: {(now - self.start_time).total_seconds():.1f}")
            print(datetime.today().strftime('Finished at %H:%M:%S'))


class Fuzzer:
    reconfiguration_round: int = 0

    def __init__(self, instruction_set_spec: str, work_dir: str, existing_test_case: str = None):
        self.work_dir = work_dir
        self.test_case = existing_test_case
        self.enable_generation = True if not existing_test_case else False
        self.instruction_set_spec = instruction_set_spec
        self.logger = None

    def start(self, num_test_cases: int, num_inputs_max: int, num_eq_classes: int, timeout: int,
              nonstop: bool = False):
        start_time = datetime.today()
        self.logger = Logger(num_test_cases, start_time)
        num_inputs = num_inputs_max if not num_eq_classes else 500
        STAT.num_inputs = num_inputs

        # create all main modules
        executor: Executor = get_executor()
        model: Model = get_model(executor.read_base_addresses())
        input_gen: InputGenerator = RandomInputGenerator()
        analyser: Analyser = get_analyser()

        # connect them with coverage
        coverage: Coverage = get_coverage()
        executor.set_coverage(coverage)
        model.set_coverage(coverage)
        input_gen.set_coverage(coverage)
        analyser.set_coverage(coverage)

        # create a test case generator
        if self.enable_generation:
            generator = Generator(self.instruction_set_spec)
            generator.set_coverage(coverage)

        for i in range(num_test_cases):
            # Generate a test case, if necessary
            if self.enable_generation:
                self.test_case = 'generated.asm'
                # noinspection PyUnboundLocalVariable
                generator.create_test_case(self.test_case)

            coverage.load_test_case(self.test_case)

            # Prepare inputs
            inputs: List[Input] = input_gen.generate(CONF.prng_seed, num_inputs)

            # Fuzz the test case
            has_violations = self.fuzzing_round(executor, model, analyser, inputs)
            STAT.test_cases += 1

            coverage.update()

            # violations?
            if has_violations:
                self.store_test_case(False)
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

            if num_inputs < num_inputs_max and \
                    (STAT.effective_eq_classes // (i + 1)) < num_eq_classes and \
                    STAT.single_entry_eq_classes > STAT.effective_eq_classes:
                num_inputs = int(num_inputs * 1.2)
                STAT.num_inputs = num_inputs
                continue

        self.logger.finish()

    def fuzzing_round(self, executor: Executor, model: Model, analyser: Analyser,
                      inputs: List[Input]) -> bool:
        self.logger.start_round()

        # Initial measurement
        model.load_test_case(self.test_case)
        ctraces: List[CTrace] = model.trace_test_case(inputs)

        executor.load_test_case(self.test_case)
        htraces: List[HTrace] = executor.trace_test_case(inputs)

        if CONF.verbose == 999:
            print("")
            nprinted = 10 if len(ctraces) > 10 else len(ctraces)
            for i in range(nprinted):
                print("..............................................................")
                print(pretty_bitmap(ctraces[i], ctraces[i] > pow(2, 64)))
                print(pretty_bitmap(htraces[i]))

        if CONF.self_test_mode and CONF.contract_observation_mode == 'l1d':
            for i, ctrace in enumerate(ctraces):
                if (ctrace % POW2_64) > htraces[i]:
                    print(f"\n> Broken measurement. Input id {i}; Input value: {inputs[i]}")
                    print(pretty_bitmap(ctraces[i], True))
                    print(pretty_bitmap(htraces[i]))
                    return False

        # Check for violations
        all_eq_classes: EquivalenceClassMap = analyser.build_equivalence_classes(inputs, ctraces,
                                                                                 htraces,
                                                                                 stats=True)
        violations: List[EquivalenceClass] = analyser.filter_violations(all_eq_classes)

        if not violations:
            self.logger.success()
            return False
        if CONF.no_priming:
            self.report_violations(violations[0])
            return True

        if violations:
            STAT.required_priming += 1

        # Try priming the inputs that disagree with the other ones within the same eq. class
        while violations:
            self.logger.priming(len(violations))
            violation: EquivalenceClass = violations.pop()
            if self.verify_with_priming(violation, executor, inputs):
                self.report_violations(violation)
                return True

        # all violations were cleaned. all good
        return False

    def verify_with_priming(self, violation: EquivalenceClass, executor: Executor,
                            inputs: List[Input]) -> bool:
        ordered_htraces = sorted(violation.htrace_groups.keys(),
                                 key=lambda x: bit_count(x),
                                 reverse=False)
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
            multiprimer = self.get_min_primer(executor, inputs, target_id,
                                              primer_htrace, len(primed_ids))
            if not multiprimer:
                return False
            primer_size = len(multiprimer) // len(primed_ids)

            # insert the tested inputs into their places
            for i, id_ in enumerate(primed_ids):
                multiprimer[(i + 1) * primer_size - 1] = violation.inputs[id_]

            # try swapping
            reproduced = self.check_multiprimer(executor,
                                                multiprimer,
                                                primer_size,
                                                primer_htrace,
                                                CONF.priming_retries)
            if not reproduced:
                return True

            for id_ in primed_ids:
                violation.htraces[id_] |= primer_htrace
            violation.update_groups()

            if len(violation.htrace_groups) == 1:
                break

        return False

    def get_min_primer(self, executor, inputs, target_id,
                       expected_htrace, num_primed_inputs) -> List[Input]:
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
            primer_found = self.check_multiprimer(executor, multiprimer,
                                                  primer_size, expected_htrace, 1)

            if primer_found:
                return multiprimer

            # run out of inputs to test?
            if primer_size >= len(inputs):
                # maybe, we have too few executions; try with more
                primer_found = self.check_multiprimer(executor, multiprimer, primer_size,
                                                      expected_htrace,
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

    def store_test_case(self, require_retires: bool):
        if not self.work_dir:
            return

        type_ = "retry" if require_retires else "violation"
        timestamp = datetime.today().strftime('%H%M%S-%d-%m-%y')
        name = type_ + timestamp + ".asm"
        Path(self.work_dir).mkdir(exist_ok=True)
        shutil.copy2(self.test_case, self.work_dir + "/" + name)

    @staticmethod
    def check_multiprimer(executor: Executor, inputs: List[int], primer_size: int,
                          expected_htrace: HTrace, retries: int) -> bool:
        num_inputs = len(inputs) // primer_size
        num_measurements: int = CONF.num_measurements
        for i in range(retries):
            mismatch = False
            primed_traces: List[HTrace] = executor.trace_test_case(inputs, num_measurements)
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
    def _shuffle(ids_to_shuffle: List[int], inputs: List[int], ctraces: List[CTrace],
                 htraces: List[HTrace]):
        """
        DEPRECATED
        Randomly shuffles inputs, but ensures that swapping happens only between inputs within
         one equivalence classes
        """
        trace_map = list(zip(inputs, ctraces, htraces))

        # build equivalence classes
        equivalence_classes: Dict[CTrace, List[int]] = defaultdict(list)
        for id_, ctrace in enumerate(ctraces):
            equivalence_classes[ctrace].append(id_)

        while ids_to_shuffle:
            # get the next id to swap
            violation_id: int = ids_to_shuffle.pop()
            eq_class = equivalence_classes[ctraces[violation_id]]
            eq_class.remove(violation_id)

            # find a swap candidate within the same eq. class
            options = []
            dominant = max(htraces[violation_id])
            for id_ in eq_class:
                if max(htraces[id_]) != dominant:
                    options.append(id_)
            if not options:
                continue
            id_to_swap = random.choice(options)

            # swap
            violation_map_entry = trace_map[violation_id]
            trace_map[violation_id] = trace_map[id_to_swap]
            trace_map[id_to_swap] = violation_map_entry

        new_inputs, new_ctraces, new_htraces = zip(*trace_map)
        return new_inputs, new_ctraces, new_htraces

    @staticmethod
    def report_violations(violation: EquivalenceClass):
        print("\n\n================================ Violations detected ==========================")
        print(f"  Contract trace (hash):\n")
        if violation.ctrace <= pow(2, 64):
            print(f"    {violation.ctrace:064b}")
        else:
            print(f"    {violation.ctrace % violation.mod2p64:064b} [ns]\n"
                  f"    {(violation.ctrace >> 64) % violation.mod2p64:064b} [s]\n")
        print(f"  Hardware traces:")
        for group in violation.htrace_groups.values():
            inputs = [violation.inputs[i] for i in group]
            if len(inputs) < 4:
                print(f"   Inputs {inputs}:")
            else:
                print(f"   Inputs {inputs[:4]} (+ {len(inputs) - 4} ):")
            print(f"    {pretty_bitmap(violation.htraces[group[0]])}")
        print("")
