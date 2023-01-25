#!/usr/bin/env python3
"""
File: Command Line Interface

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import os
import yaml
from typing import Dict
from argparse import ArgumentParser
from factory import get_minimizer, get_fuzzer
from fuzzer import Fuzzer
from config import CONF
from service import LOGGER


def main() -> int:
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
        help="Use an existing test case [DEPRECATED - see reproduce]"
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

    parser_analyser = subparsers.add_parser('analyse')
    parser_analyser.add_argument(
        '--ctraces',
        type=str,
        required=True,
    )
    parser_analyser.add_argument(
        '--htraces',
        type=str,
        required=True,
    )
    parser_analyser.add_argument(
        "-c", "--config",
        type=str,
        required=False
    )

    parser_reproduce = subparsers.add_parser('reproduce')
    parser_reproduce.add_argument(
        "-s", "--instruction-set",
        type=str,
        required=True
    )
    parser_reproduce.add_argument(
        "-c", "--config",
        type=str,
        required=False
    )
    parser_reproduce.add_argument(
        '-t', '--testcase',
        type=str,
        default=None,
        required=True,
        help="Path to the test case",
    )
    parser_reproduce.add_argument(
        '-i', '--inputs',
        type=str,
        nargs='*',
        default=None,
        help="Path to the directory with inputs"
    )
    parser_reproduce.add_argument(
        "-n",
        "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per test case. [IGNORED if --input-dir is set]",
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
    parser_mini.add_argument(
        "-s", "--instruction-set",
        type=str,
        required=True
    )

    parser_generator = subparsers.add_parser('generate')
    parser_generator.add_argument(
        "-s", "--instruction-set",
        type=str,
        required=True
    )
    parser_generator.add_argument(
        "-r", "--seed",
        type=int,
        default=0,
        help="Add seed to generate test case.",
    )
    parser_generator.add_argument(
        "-n", "--num-test-cases",
        type=int,
        default=5,
        help="Number of test cases.",
    )
    parser_generator.add_argument(
        "-i", "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per test case.",
    )
    parser_generator.add_argument(
        "-c", "--config",
        type=str,
        required=False
    )
    parser_generator.add_argument(
        '-w', '--working-directory',
        type=str,
        default='',
    )
    parser_generator.add_argument(
        '--permit-overwrite',
        action='store_true',
    )

    args = parser.parse_args()

    # Update configuration
    if args.config:
        CONF.config_path = args.config
        with open(args.config, "r") as f:
            config_update: Dict = yaml.safe_load(f)
        for var, value in config_update.items():
            setattr(CONF, var, value)
    LOGGER.set_logging_modes()

    # Fuzzing
    if args.subparser_name == 'fuzz':
        # Make sure we're ready for fuzzing
        if args.working_directory and not os.path.isdir(args.working_directory):
            SystemExit("The working directory does not exist")

        # Normal fuzzing mode
        fuzzer = get_fuzzer(args.instruction_set, args.working_directory, args.testcase, "")
        exit_code = fuzzer.start(
            args.num_test_cases,
            args.num_inputs,
            args.timeout,
            args.nonstop,
        )
        return exit_code

    # Reproducing a violation
    if args.subparser_name == 'reproduce':
        fuzzer = get_fuzzer(args.instruction_set, "", args.testcase, args.inputs)
        exit_code = fuzzer.start(1, args.num_inputs, 0, False)
        return exit_code

    # Stand-alone generator
    if args.subparser_name == "generate":
        fuzzer = get_fuzzer(args.instruction_set, args.working_directory, None, "")
        fuzzer.generate_test_batch(
            args.seed,
            args.num_test_cases,
            args.num_inputs,
            args.permit_overwrite
        )
        return 0

    # Trace analysis
    if args.subparser_name == 'analyse':
        fuzzer = Fuzzer.analyse_traces_from_files(args.ctraces, args.htraces)
        return 0

    # Test case minimisation
    if args.subparser_name == "minimize":
        minimizer = get_minimizer(args.instruction_set)
        minimizer.minimize(args.infile, args.outfile, args.num_inputs, args.add_fences)
        return 0

    raise Exception("Unreachable")


if __name__ == '__main__':
    exit_code = main()
    exit(exit_code)
