#!/usr/bin/env python3
"""
File: Command Line Interface

Copyright (C) 2021 Oleksii Oleksenko
Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import os
import subprocess
import yaml
from typing import Dict
from argparse import ArgumentParser
from fuzzer import Fuzzer
from generator import Generator
from postprocessor import Postprocessor
from config import CONF


def check_config():
    # TODO: make this a part of CONF class
    assert CONF.prng_seed != 0  # deprecated?
    if CONF.max_outliers > 20:
        print("Are you sure you want to ignore so many outliers?")


def ensure_reliable_environment():
    # SMT disabled?
    if os.path.isfile('/sys/devices/system/cpu/cpu4/online'):
        print("WARNING: Hyperthreading is enabled! You may have false positives due to system noise.")

    # Disable prefetching
    subprocess.run('sudo modprobe msr', shell=True, check=True)
    subprocess.run('sudo wrmsr -a 0x1a4 15', shell=True, check=True)


def main():
    parser = ArgumentParser(description='', add_help=False)
    subparsers = parser.add_subparsers(dest='subparser_name')

    # Fuzzing
    parser_fuzz = subparsers.add_parser('fuzz')
    parser_fuzz.add_argument(
        "-s", "--instruction-set",
        type=str,
        required=True
    )
    parser_fuzz.add_argument(
        "-c", "--config",
        type=str,
        required=False
    )
    parser_fuzz.add_argument(
        "-n", "--num-test-cases",
        type=int,
        default=1,
        help="Number of test cases.",
    )
    parser_fuzz.add_argument(
        "-i", "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per test case.",
    )
    parser_fuzz.add_argument(
        "-e", "--num-equivalence-classes",
        type=int,
        default=0,
        help="Target number of equivalence classes. \n"
             "When set, the number of inputs is changed dynamically, \n"
             "to reach this number, but not more than --num-inputs",
    )
    parser_fuzz.add_argument(
        '-w', '--working-directory',
        type=str,
        default='',
    )
    parser_fuzz.add_argument(
        '-t', '--testcase',
        type=str,
        default=None,
        help="Use an existing test case"
    )
    parser_fuzz.add_argument(
        '--timeout',
        type=int,
        default=0,
        help="Run fuzzing with a time limit [seconds]. No timeout when set to zero."
    )
    parser_fuzz.add_argument(
        '--nonstop',
        action='store_true',
        help="Don't stop after detecting an unexpected result"
    )
    parser_fuzz.add_argument(
        '-v', '--verbose',
        action='store_true',
    )

    parser_gen = subparsers.add_parser(
        'generator-test',
        help="Generate all instructions in the instruction set and do not start fuzzing")
    parser_gen.add_argument(
        "-s", "--instruction-set",
        type=str,
        required=True
    )
    parser_gen.add_argument(
        "-c", "--config",
        type=str,
        required=False
    )

    parser_mini = subparsers.add_parser('minimize')
    parser_mini.add_argument(
        '--infile', '-i',
        type=str,
        required=True,
    )
    parser_mini.add_argument(
        '--outfile', '-o',
        type=str,
        required=True,
    )
    parser_mini.add_argument(
        "-c", "--config",
        type=str,
        required=False
    )
    parser_mini.add_argument(
        "-n", "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per test case.",
    )
    parser_mini.add_argument(
        "-f", "--add-fences",
        action='store_true',
        default=False,
        help="Add as many LFENCEs as possible, while preserving the violation.",
    )

    args = parser.parse_args()

    # Update configuration
    if getattr(args, 'verbose', 0):
        CONF.set('verbose', 1)
    if args.config:
        with open(args.config, "r") as f:
            config_update: Dict = yaml.safe_load(f)
        for var, value in config_update.items():
            CONF.set(var, value)
    check_config()

    # Generator test
    if args.subparser_name == "generator-test":
        binary_generator = Generator(args.instruction_set)
        binary_generator.create_test_case('generated.asm', test_mode=True)
        return

    # Fuzzing
    if args.subparser_name == 'fuzz':
        # Make sure we're ready for fuzzing
        ensure_reliable_environment()
        if args.working_directory and not os.path.isdir(args.working_directory):
            print("The working directory does not exist")
            exit(1)

        # Normal fuzzing mode
        fuzzer = Fuzzer(args.instruction_set, args.working_directory, args.testcase)
        fuzzer.start(
            args.num_test_cases,
            args.num_inputs,
            args.num_equivalence_classes,
            args.timeout,
            args.nonstop,
        )
        return

    # Test Case minimisation
    if args.subparser_name == "minimize":
        postprocessor = Postprocessor()
        postprocessor.minimize(args.infile, args.outfile, args.num_inputs, args.add_fences)
        return

    raise Exception("Unreachable")


if __name__ == '__main__':
    main()
