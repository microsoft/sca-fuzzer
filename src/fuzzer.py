"""
File: Fuzzing Orchestration

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
from helpers import *
from custom_types import Dict, CTrace, HTrace, EquivalenceClass, EquivalenceClassMap, Input
from config import CONF


class Fuzzer:
    def __init__(self, instruction_set_spec: str, work_dir: str, existing_test_case: str = None):
        self.generator = Generator(instruction_set_spec)
        self.work_dir = work_dir
        self.test_case = existing_test_case
        self.enable_generation = True if not existing_test_case else False

    def start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool = False,
              verbose: bool = False):
        start_time = datetime.today()
        self._log_init(num_test_cases, start_time, verbose)
        STAT.inputs_per_test_case = num_inputs

        executor: Executor = get_executor()
        model: Model = get_model(executor.read_base_addresses())
        input_gen: InputGenerator = RandomInputGenerator()
        analyser: Analyser = get_analyser()

        for i in range(num_test_cases):
            # Generate a test case, if necessary
            if self.enable_generation:
                self.test_case = 'generated.asm'
                self.generator.create_test_case()
                self.generator.materialize(self.test_case)

            # Prepare inputs
            inputs: List[Input] = input_gen.generate(CONF.prng_seed, num_inputs)

            # Fuzz the test case
            has_violations = self.fuzzing_round(executor, model, analyser, inputs, verbose)
            STAT.test_cases += 1
            if has_violations:
                self.store_test_case(False)
                STAT.violations += 1
                if not nonstop:
                    break

            # stop fuzzing after a timeout
            if timeout:
                now = datetime.today()
                if (now - start_time).total_seconds() > timeout:
                    if verbose:
                        print("\nTimeout expired")
                    break

        self._log_finish()

    def fuzzing_round(self, executor: Executor, model: Model, analyser: Analyser,
                      inputs: List[Input],
                      verbose) -> bool:
        self._log_start()

        # Initial measurement
        model.load_test_case(self.test_case)
        ctraces: List[CTrace] = model.trace_test_case(inputs)

        executor.load_test_case(self.test_case)
        htraces: List[HTrace] = executor.trace_test_case(inputs)

        if CONF.self_test_mode and CONF.attacker_capability == 'l1d':
            for i, ctrace in enumerate(ctraces):
                if (ctrace % POW2_64) > htraces[i]:
                    print(f"> Broken measurement: {i} {inputs[i]}")
                    print(pretty_bitmap(ctraces[i], True))
                    print(pretty_bitmap(htraces[i]))
                    return False

        # Check for violations
        all_eq_classes: EquivalenceClassMap = analyser.build_equivalence_classes(inputs, ctraces,
                                                                                 htraces,
                                                                                 stats=True)
        violations: List[EquivalenceClass] = analyser.filter_violations(all_eq_classes)

        if not violations:
            self._log_success()
            return False
        if CONF.no_priming:
            self.report_violations(violations[0])
            return True

        if violations:
            STAT.required_priming += 1

        # Try priming the inputs that disagree with the other ones within the same eq. class
        while violations:
            self._log_priming(len(violations))
            violation: EquivalenceClass = violations.pop()
            broken_measurement = False
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

                # take one input from the priming group
                priming_group_member = original_groups[primer_htrace][-1]
                primer_end = violation.original_positions[priming_group_member]

                # find a small primer that produces the same traces
                primer_size = CONF.min_primer_size
                while True:
                    # build a set of priming inputs
                    primer_start = primer_end + 1 - primer_size
                    if primer_start < 0:
                        primer_start = 0
                        primer_size = primer_end + 1
                    primer = inputs[primer_start:primer_end + 1]

                    primed_input_sequence = []
                    for _ in primed_ids:
                        primed_input_sequence.extend(primer)

                    # verify that the hardware trace did not change
                    if self._trace_primed_input_sequence(executor, primed_input_sequence,
                                                         primer_size, primer_htrace, 1):
                        break

                    if primer_size > CONF.max_primer_size or primer_start == 0:
                        # maybe, we have too few executions. try more
                        primer_found = self._trace_primed_input_sequence(executor,
                                                                         primed_input_sequence,
                                                                         primer_size,
                                                                         primer_htrace,
                                                                         CONF.priming_retries)
                        if not primer_found:
                            broken_measurement = True
                        break

                    # try a larger primer
                    primer_size *= 2

                if broken_measurement:
                    STAT.broken_measurements += 1
                    break

                # insert the tested inputs into their places
                for i, id_ in enumerate(primed_ids):
                    primed_input_sequence[(i + 1) * primer_size - 1] = violation.inputs[id_]

                # try swapping
                reproduced = self._trace_primed_input_sequence(executor,
                                                               primed_input_sequence,
                                                               primer_size,
                                                               primer_htrace,
                                                               CONF.priming_retries)
                if not reproduced:
                    self.report_violations(violation)
                    return True

                for id_ in primed_ids:
                    violation.htraces[id_] |= primer_htrace
                violation.update_groups()
                if len(violation.htrace_groups) == 1:
                    break

        # all violations were cleaned. all good
        return False

    def store_test_case(self, require_retires: bool):
        if not self.work_dir:
            return

        type_ = "retry" if require_retires else "violation"
        timestamp = datetime.today().strftime('%H%M%S-%d-%m-%y')
        name = type_ + timestamp + ".asm"
        Path(self.work_dir).mkdir(exist_ok=True)
        shutil.copy2(self.test_case, self.work_dir + "/" + name)

    @staticmethod
    def _trace_primed_input_sequence(executor: Executor, inputs: List[int], primer_size: int,
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
        print(f"  Contract trace (hash):\n"
              f"    {violation.ctrace:064b}")
        print(f"  Hardware traces:")
        for group in violation.htrace_groups.values():
            inputs = [violation.inputs[i] for i in group]
            if len(inputs) < 4:
                print(f"   Inputs {inputs}:")
            else:
                print(f"   Inputs {inputs[:4]} (+ {len(inputs) - 4} ):")
            print(f"    {pretty_bitmap(violation.htraces[group[0]])}")
        print("")

    # Logging
    #
    def _log_init(self, iterations: int, start_time, verbose):
        self.one_percent_progress = iterations / 100
        self.progress = 0
        self.progress_percent = 0
        self.msg = ""
        self.max_iterations = iterations
        if verbose:
            print(start_time.strftime('Starting at %H:%M:%S'))

    def _log_start(self):
        if CONF.verbose:
            if STAT.test_cases > self.progress:
                self.progress += self.one_percent_progress
                self.progress_percent += 1
            msg = f"\rRounds: {STAT.test_cases}/{self.max_iterations} [{self.progress_percent}%] | "
            msg += STAT.get_brief()
            print(msg + "Normal execution                                 ", end='', flush=True)
            self.msg = msg

    def _log_success(self):
        if CONF.verbose:
            print(self.msg + "Normal execution                                 ", end='')

    def _log_priming(self, num_violations: int):
        if CONF.verbose:
            print(self.msg + "Priming " + str(num_violations), end='', flush=True)

    @staticmethod
    def _log_finish():
        # new line after the progress bar
        if CONF.verbose:
            print("")
            print(STAT)
            print(datetime.today().strftime('Finished at %H:%M:%S'))

# class ModelFuzzer(Fuzzer):
#     # TODO: there's too much code duplication here. Get rid of this class
#
#     def start(self, num_test_cases: int, num_inputs: int, timeout: int, nonstop: bool = False,
#               verbose: bool = False):
#         """
#         This function is almost identical to a normal fuzzer, except generator uses
#         a serializing mode
#         """
#         self._log_init(num_test_cases, datetime.today(), verbose)
#         executor: Executor = get_executor()
#         model: Model = get_model(executor.read_base_addresses())
#
#         for i in range(num_test_cases):
#             # Generate a test case, if necessary
#             if self.enable_generation:
#                 self.test_case = 'generated.asm'
#                 self.generator.create_test_case()
#                 self.generator.materialize(self.test_case, serial_mode=True)
#
#             # Load the test case
#             executor.load_test_case(self.test_case)
#             model.load_test_case(self.test_case)
#
#             # Prepare the input generator
#             executor.write_prng_state(CONF.prng_seed)
#
#             # Fuzz the test case
#             success = self.fuzzing_round(executor, model, num_inputs, verbose)
#             if not success:
#                 # All retries failed
#                 self.store_test_case()
#                 if not nonstop:
#                     break
#
#         self._log_finish(verbose)
