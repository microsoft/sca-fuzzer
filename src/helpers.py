"""
File: Various helper functions used by multiple parts of the project

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from subprocess import run
import csv
from config import CONF
from custom_types import List, HTrace


class NotSupportedException(Exception):
    pass


def assemble(infile, outfile):
    """
    Assemble the test case into a form understandable by nanoBench
    """
    run(f"as {infile} -o {outfile}", shell=True, check=True)
    run(f"objcopy {outfile} -O binary {outfile}", shell=True, check=True)


def load_measurement(measurement_file: str) -> List[HTrace]:
    with open(measurement_file, "r") as f:
        reader = csv.DictReader(f)
        assert 'CACHE_MAP' in reader.fieldnames

        # collect the measured cache state
        htraces = []
        for i, row in enumerate(reader):
            trace = int(row['CACHE_MAP'])
            if CONF.ignore_first_cache_line:
                trace &= 9223372036854775807
            htraces.append(trace)
        return htraces


def get_prng_state_after_iterations(seed: int, num_iterations: int) -> int:
    # each test case (and, accordingly, each iteration) generates 7 random values
    total_executions = num_iterations * 7
    state = seed
    mod = pow(2, 64)

    for i in range(0, total_executions):
        state = (state * 2891336453) % mod
        state = (state + 12345) % mod
    return state


def write_to_pseudo_file(value, path: str) -> None:
    run(f"sudo bash -c 'echo -n {value} > {path}'", shell=True, check=True)


def write_to_pseudo_file_bytes(value: bytes, path: str) -> None:
    with open(path, "wb") as f:
        f.write(value)


MASK_64BIT = pow(2, 64)
POW2_64 = pow(2, 64)
TWOS_COMPLEMENT_MASK_64 = pow(2, 64) - 1


def pretty_bitmap(bits: int, merged=False):
    if not merged:
        s = f"{bits:064b}"
    else:
        s = f"{bits % MASK_64BIT:064b} [ns]\n" \
            f"{(bits >> 64) % MASK_64BIT:064b} [s]"
    s = s.replace("0", "_").replace("1", "^")
    return s


def bit_count(n):
    count = 0
    while n:
        count += n & 1
        n >>= 1
    return count


class StatisticsCls:
    test_cases = 0
    num_inputs = 0
    effective_eq_classes = 0
    single_entry_eq_classes = 0
    required_priming = 0
    broken_measurements = 0
    violations = 0
    coverage = 0
    fully_covered: int = 0

    def __str__(self):
        total_clss = self.effective_eq_classes + self.single_entry_eq_classes

        s = "\n================================ Statistics ===================================\n"
        s += f"Test Cases: {self.test_cases}\n"
        s += f"Inputs per test case: {self.num_inputs}\n"
        s += f"Coverage:\n"
        s += f"  Patterns: {self.coverage}\n"
        s += f"  Fully covered: {self.fully_covered}\n"
        s += f"  Effectiveness: {self.effective_eq_classes / total_clss:.1f}\n"
        s += f"Effectiveness: \n"
        s += f"  Total Cls: {total_clss / self.test_cases:.1f}\n"
        s += f"  Effective Cls: {self.effective_eq_classes / self.test_cases:.1f}\n"
        s += f"Required priming: {self.required_priming}\n"
        s += f"Broken measurements: {self.broken_measurements}\n"
        s += f"Violations: {self.violations}\n"
        return s

    def get_brief(self):
        if self.test_cases == 0:
            return ""
        else:
            s = f"EC: {self.effective_eq_classes / self.test_cases:.1f} | "
            s += f"C: {self.coverage} | "
            s += f"I: {self.num_inputs} | "
            s += f"E: {self.effective_eq_classes / (self.effective_eq_classes + self.single_entry_eq_classes):.1f} | "
            s += f"P: {self.required_priming} | " \
                 f"BM: {self.broken_measurements} | " \
                 f"V: {self.violations} | "
            return s


STAT = StatisticsCls()
