#!/usr/bin/env python3
"""
File: Command Line Interface

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
from config import CONF
from postprocessor import minimize


def check_config():
    assert CONF.prng_seed != 0  # deprecated?
    if CONF.max_outliers > 20:
        print("Are you sure you want to ignore so many outliers?")


def ensure_reliable_environment():
    # SMT disabled?
    if os.path.isfile('/sys/devices/system/cpu/cpu4/online'):
        print("Hyperthreading must be disabled, in BIOS!")
        exit(1)

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

    args = parser.parse_args()

    # Fuzzing
    if args.subparser_name == 'fuzz':
        # Make sure we're ready for fuzzing
        check_config()
        ensure_reliable_environment()
        if args.working_directory and not os.path.isdir(args.working_directory):
            print("The working directory does not exist")
            exit(1)

        # Update configuration
        if args.config:
            with open(args.config, "r") as f:
                config_update: Dict = yaml.safe_load(f)
            for var, value in config_update.items():
                CONF.set(var, value)

        if args.verbose:
            CONF.set('verbose', 1)

        # Normal fuzzing mode
        fuzzer = Fuzzer(args.instruction_set, args.working_directory, args.testcase)
        fuzzer.start(
            args.num_test_cases,
            args.num_inputs,
            args.timeout,
            args.nonstop,
            args.verbose,
        )
        return

    # Generator test
    if args.subparser_name == "generator-test":
        binary_generator = Generator(args.instruction_set)
        binary_generator.create_test_case(test_mode=True)
        binary_generator.materialize('generated.asm')
        return

    # Test Case minimisation
    if args.subparser_name == "minimize":
        minimize(args.infile, args.outfile)
        return

    raise Exception("Unreachable")


if __name__ == '__main__':
    main()
