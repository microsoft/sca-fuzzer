"""
File: Function definitions for using Model-based Constant-time Fuzzer (McFuzz) as command-line tool
(Note: the actual CLI is accessed via mcfz.py)

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import Any
from argparse import ArgumentParser

from typing_extensions import get_args

from .config import Config, TestingStages
from .fuzzer import FuzzerCore
from .driller import Driller


def _parse_args() -> Any:  # pylint: disable=r0915
    parser = ArgumentParser(add_help=True)
    subparsers = parser.add_subparsers(dest='subparser_name', help="Subcommand to run")

    parser.add_argument(
        "--help-config",
        action='store_true',
        help="Print a help message for the configuration file format and defaults.",
    )

    # ==============================================================================================
    # Common arguments
    common_parser = ArgumentParser(add_help=False)
    common_parser.add_argument(
        "-c",
        "--config",
        type=str,
        required=True,
        help="Path to the configuration file (YAML) that will be used during fuzzing.",
    )

    # ==============================================================================================
    # All Phases Together: Fuzzing-based generation, boosting, tracing, and reporting
    all_phases = subparsers.add_parser('fuzz', add_help=True, parents=[common_parser])
    all_phases.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Fuzzing timeout, in seconds (default: 10)",
    )

    # ==============================================================================================
    # Stage 1: Fuzzing-based input generation (AFL++ interface)
    fuzz_gen = subparsers.add_parser('fuzz_gen', add_help=True, parents=[common_parser])
    fuzz_gen.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Fuzzing timeout, in seconds (default: 10)",
    )
    # TODO: target-cov is not used yet, but it will be used in the future to control the coverage
    # fuzz_gen.add_argument(
    #     "--target-cov",
    #     type=int,
    #     default=10,
    #     help="Target coverage to achieve, in percentage (default: 10)",
    # )

    # ==============================================================================================
    # Stage 2: Boosting - generate public-equivalent variants
    _ = subparsers.add_parser('boost', add_help=True, parents=[common_parser])
    # no arguments for now

    # ==============================================================================================
    # Stage 3: Collection of contract traces
    _ = subparsers.add_parser('trace', add_help=True, parents=[common_parser])
    # no arguments for now

    # ==============================================================================================
    # Stage 4: Analysis of traces and reporting of leaks
    report = subparsers.add_parser('report', add_help=True, parents=[common_parser])
    report.add_argument(
        "--num-traces",
        "-n",
        type=int,
        default=0,
        help="[Debug option] Process only the first N traces (default: 0, meaning all traces)",
    )

    # ==============================================================================================
    # Post-fuzzing: Diving deep into specific bugs
    details = subparsers.add_parser('details', add_help=True, parents=[common_parser])
    details.add_argument(
        "--pc",
        "-p",
        type=lambda x: int(x, 0),
        required=True,
        help="Program counter value (accepts decimal or hex, e.g., 12345 or 0x3039)",
    )
    details.add_argument(
        "--output-dir",
        "-o",
        type=str,
        required=True,
        help="Path to the directory to store the report with detailed information about\n"
        "the given violation as well as temporary files",
    )

    args = parser.parse_args()

    # Custom check for subparser name
    if not args.subparser_name and not args.help_config:
        parser.print_help()
        return None

    return args


def _validate_args(args: Any) -> bool:
    """
    Validate the command-line arguments, beyond the basic checks done by argparse.
    :param args: parsed CLI arguments
    :return: True if paths are valid, False otherwise
    """
    # placeholder for future validations

    return True


def main() -> int:
    """ Main function for the CLI """

    # pylint: disable=too-many-return-statements,too-many-branches
    # NOTE: disabling is justified here, as this function is the main entry point
    #       and it naturally has many branches due to different subcommands

    args = _parse_args()
    if args is None:
        return 1
    if not _validate_args(args):
        return 1

    # Config help requested
    if args.help_config:
        print(Config.help())
        return 0

    # Non-fuzzing modes:
    if args.subparser_name == 'details':
        config = Config(args.config, None)
        driller = Driller(config=config, output_dir=args.output_dir)
        driller.drill_down(pc_=args.pc)
        return 0

    # Fuzzing modes:
    assert args.subparser_name in get_args(TestingStages)
    config = Config(args.config, args.subparser_name)
    fuzzer = FuzzerCore(config)

    # Start the fuzzer in the mode requested by the user
    if args.subparser_name == 'fuzz_gen':
        fuzzer.fuzz_gen(
            target_cov=0,  # TODO: will be replaced with args.target_cov when implemented
            timeout_s=args.timeout,
        )
        return 0

    if args.subparser_name == 'boost':
        fuzzer.boost()
        return 0

    if args.subparser_name == 'trace':
        fuzzer.trace()
        return 0

    if args.subparser_name == 'report':
        fuzzer.report(num_traces=args.num_traces)
        return 0

    if args.subparser_name == 'fuzz':
        fuzzer.all(
            target_cov=0,  # TODO: will be replaced with args.target_cov when implemented
            timeout_s=args.timeout,
        )
        return 0

    print("ERROR: Unknown subcommand")
    return 1
