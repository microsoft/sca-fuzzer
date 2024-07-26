"""
File: Function definitions for using Revizor as command-line tool
(Note: the actual CLI is accessed via revizor.py)

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

import os
import unicorn
from argparse import ArgumentParser, ArgumentTypeError
from .factory import get_minimizer, get_fuzzer, get_downloader
from .config import CONF


def arg2bool(arg) -> bool:
    if isinstance(arg, bool):
        return arg
    if arg.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif arg.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise ArgumentTypeError('Boolean value expected.')


def main() -> int:
    parser = ArgumentParser(add_help=False)
    subparsers = parser.add_subparsers(dest='subparser_name')
    subparsers.required = True

    # ==============================================================================================
    # Common arguments
    common_parser = ArgumentParser(add_help=False)
    common_parser.add_argument(
        "-c",
        "--config",
        type=str,
        required=False,
        help="Path to the configuration file (YAML) that will be used during fuzzing.",
    )
    common_parser.add_argument(
        "-I",
        "--include-dir",
        type=str,
        default=".",
        required=False,
        help="Path to the directory containing configuration files that included by the main "
        " configuration file (received via --config).",
    )
    common_parser.add_argument(
        "-s",
        "--instruction-set",
        type=str,
        required=True,
        help="Path to the instruction set specification (JSON) file.",
    )

    # ==============================================================================================
    # Fuzzing
    parser_fuzz = subparsers.add_parser('fuzz', add_help=True, parents=[common_parser])
    parser_fuzz.add_argument(
        "-n",
        "--num-test-cases",
        type=int,
        default=1,
        help="Number of test cases.",
    )
    parser_fuzz.add_argument(
        "-i",
        "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per test case.",
    )
    parser_fuzz.add_argument(
        '-w',
        '--working-directory',
        type=str,
        default='.',
    )
    parser_fuzz.add_argument(
        '-t',
        '--testcase',
        type=str,
        default=None,
        help="Use an existing test case [DEPRECATED - see reproduce]")
    parser_fuzz.add_argument(
        '--timeout',
        type=int,
        default=0,
        help="Run fuzzing with a time limit [seconds]. No timeout when set to zero.")
    parser_fuzz.add_argument(
        '--nonstop', action='store_true', help="Don't stop after detecting an unexpected result")
    parser_fuzz.add_argument(
        '--save-violations',
        type=arg2bool,
        default=True,
        help="If set, store all detected violations in working directory.",
    )

    # ==============================================================================================
    # Template-based fuzzing
    parser_tfuzz = subparsers.add_parser('tfuzz', add_help=True, parents=[common_parser])
    parser_tfuzz.add_argument(
        "-n",
        "--num-test-cases",
        type=int,
        default=1,
        help="Number of test cases.",
    )
    parser_tfuzz.add_argument(
        "-i",
        "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per test case.",
    )
    parser_tfuzz.add_argument(
        '-w',
        '--working-directory',
        type=str,
        default='',
    )
    parser_tfuzz.add_argument(
        '-t',
        '--template',
        type=str,
        required=True,
        help="The template to use for generating test cases")
    parser_tfuzz.add_argument(
        '--timeout',
        type=int,
        default=0,
        help="Run fuzzing with a time limit [seconds]. No timeout when set to zero.")
    parser_tfuzz.add_argument(
        '--nonstop', action='store_true', help="Don't stop after detecting an unexpected result")
    parser_tfuzz.add_argument(
        '--enable-store-violations',
        type=arg2bool,
        default=True,
        help="If set, store all detected violations in working directory.",
    )

    # ==============================================================================================
    # Standalone interface to trace analysis
    parser_analyser = subparsers.add_parser('analyse', add_help=True, parents=[common_parser])
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

    # ==============================================================================================
    # Reproducing violation
    parser_reproduce = subparsers.add_parser('reproduce', add_help=True, parents=[common_parser])
    parser_reproduce.add_argument(
        '-t',
        '--testcase',
        type=str,
        default=None,
        required=True,
        help="Path to the test case",
    )
    parser_reproduce.add_argument(
        '-i',
        '--inputs',
        type=str,
        nargs='*',
        default=None,
        help="Path to the directory with inputs")
    parser_reproduce.add_argument(
        "-n",
        "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per test case. [IGNORED if --input-dir is set]",
    )

    # ==============================================================================================
    # Postprocessing interface
    parser_mini = subparsers.add_parser(
        'minimize',
        add_help=True,
        parents=[common_parser],
        help="Minimize a test case by executing a series of minimization passes. "
        "The set of passes is controlled via CLI arguments.",
    )
    parser_mini.add_argument(
        '--testcase',
        '-t',
        type=str,
        required=True,
        help="Path to the test case program that needs to be minimized.",
    )
    parser_mini.add_argument(
        "-i",
        "--num-inputs",
        type=int,
        required=True,
        help="Number of inputs to the program that will be used during minimization.",
    )
    parser_mini.add_argument(
        '--testcase-outfile',
        '-o',
        type=str,
        required=True,
        help="Output path for the minimized test case program.",
    )
    parser_mini.add_argument(
        '--input-outdir',
        type=str,
        default=None,
        help="Output directory for storing minimized inputs.",
    )
    parser_mini.add_argument(
        '--num-attempts',
        type=int,
        default=1,
        help="Number of attempts to minimize the test case.",
    )
    parser_mini.add_argument(
        '--enable-instruction-pass',
        type=arg2bool,
        default=True,
        help="Enable the instruction minimization pass that iteratively removes "
        "instructions while preserving the violation.",
    )
    parser_mini.add_argument(
        '--enable-simplification-pass',
        type=arg2bool,
        default=False,
        help="Enable the instruction simplification pass that replaces complex "
        "instructions with simpler ones while preserving the violation.",
    )
    parser_mini.add_argument(
        '--enable-nop-pass',
        type=arg2bool,
        default=False,
        help="Enable the NOP replacement pass that replaces instructions with NOPs "
        "while preserving the violation.",
    )
    parser_mini.add_argument(
        '--enable-constant-pass',
        type=arg2bool,
        default=False,
        help="Enable the constant simplification pass that replaces constants with 0s "
        "while preserving the violation.",
    )
    parser_mini.add_argument(
        '--enable-mask-pass',
        type=arg2bool,
        default=False,
        help="Enable the mask simplification pass that reduces the size of instrumentation "
        "masks while preserving the violation.",
    )
    parser_mini.add_argument(
        '--enable-label-pass',
        type=arg2bool,
        default=True,
        help="Enable the label removal pass that removes unused labels from the assembly file.",
    )
    parser_mini.add_argument(
        '--enable-fence-pass',
        type=arg2bool,
        default=False,
        help="Enable the fence insertion pass that adds LFENCEs after instructions "
        "while preserving the violation.",
    )
    parser_mini.add_argument(
        "--enable-input-seq-pass",
        type=arg2bool,
        default=False,
        help="Enable the input sequence minimization pass that removes inputs from "
        "the original generated sequence while preserving the violation.",
    )
    parser_mini.add_argument(
        "--enable-input-diff-pass",
        type=arg2bool,
        default=False,
        help="Enable the violating input difference minimization pass that removes "
        "inputs that do not contribute to the violation.",
    )
    parser_mini.add_argument(
        "--enable-source-analysis",
        type=arg2bool,
        default=False,
        help="Enable the speculation source identification pass that identifies the "
        "instructions that trigger speculation.",
    )
    parser_mini.add_argument(
        "--enable-comment-pass",
        type=arg2bool,
        default=False,
        help="Enable the violation comment pass that adds comments to the assembly file "
        "with details about the violation.",
    )

    # ==============================================================================================
    # Standalone interface to test case generation
    parser_generator = subparsers.add_parser('generate', add_help=True, parents=[common_parser])
    parser_generator.add_argument(
        "-r",
        "--seed",
        type=int,
        default=0,
        help="Add seed to generate test case.",
    )
    parser_generator.add_argument(
        "-n",
        "--num-test-cases",
        type=int,
        default=5,
        help="Number of test cases.",
    )
    parser_generator.add_argument(
        "-i",
        "--num-inputs",
        type=int,
        default=100,
        help="Number of inputs per test case.",
    )
    parser_generator.add_argument(
        '-w',
        '--working-directory',
        type=str,
        default='',
    )
    parser_generator.add_argument(
        '--permit-overwrite',
        action='store_true',
    )

    # ==============================================================================================
    # Loading of ISA specs
    parser_get_isa = subparsers.add_parser('download_spec', add_help=True)
    parser_get_isa.add_argument("-a", "--architecture", type=str, required=True)
    parser_get_isa.add_argument(
        '--outfile',
        '-o',
        type=str,
        required=True,
    )
    parser_get_isa.add_argument("--extensions", nargs="*", default=[])

    # ==============================================================================================
    # Invocations
    args = parser.parse_args()

    # Update configuration
    if getattr(args, 'config', None):
        CONF.load(args.config, args.include_dir)
    if getattr(args, 'testcase', None):
        CONF._no_generation = True

    # Check if the file and directory arguments are valid
    if getattr(args, 'testcase', None) and not os.path.isfile(args.testcase):
        print("[ERROR]", f"The test case file `{args.testcase}` does not exist")
        return 1
    if getattr(args, 'working_directory', None) and not os.path.isdir(args.working_directory):
        print("[ERROR]", f"The working directory `{args.working_directory}` does not exist")
        return 1
    if (getattr(args, 'enable_input_seq_pass', None)
        or getattr(args, 'enable_input_diff_pass', None)) \
            and not args.input_outdir:
        print(
            "[ERROR]", "Passes --enable-input-seq-pass and --enable-input-diff-pass "
            "require flag --input-outdir to be set.")
        return 1

    # Enforce the Unicorn version: New versions of Unicorn have a bug that causes false positives
    # in the fuzzer. This is a temporary workaround until the bug is fixed.
    if unicorn.__version__ != '1.0.3':  # type: ignore
        print(
            "[ERROR]", "The fuzzer requires Unicorn version 1.0.3. Please install it using "
            "`pip install unicorn==1.0.3`.")
        return 1

    # Fuzzing
    if args.subparser_name == 'fuzz' or args.subparser_name == 'tfuzz':
        testcase = args.testcase if args.subparser_name == 'fuzz' else args.template
        fuzzer = get_fuzzer(args.instruction_set, args.working_directory, testcase, "")
        if args.subparser_name == 'tfuzz':
            exit_code = fuzzer.start_from_template(args.num_test_cases, args.num_inputs,
                                                   args.timeout, args.nonstop, args.save_violations)
        elif testcase:
            # deprecated mode; will be removed soon (duplicates `reproduce`)
            exit_code = fuzzer.start_from_asm(args.num_test_cases, args.num_inputs, args.timeout,
                                              args.nonstop, args.save_violations)
        else:
            exit_code = fuzzer.start_random(args.num_test_cases, args.num_inputs, args.timeout,
                                            args.nonstop, args.save_violations)
        return exit_code

    # Reproducing a violation
    if args.subparser_name == 'reproduce':
        fuzzer = get_fuzzer(args.instruction_set, "", args.testcase, args.inputs)
        exit_code = fuzzer.start_from_asm(1, args.num_inputs, 0, False, False)
        return exit_code

    # Stand-alone generation
    if args.subparser_name == "generate":
        fuzzer = get_fuzzer(args.instruction_set, args.working_directory, None, "")
        fuzzer.generate_test_batch(args.seed, args.num_test_cases, args.num_inputs,
                                   args.permit_overwrite)
        return 0

    # Trace analysis
    if args.subparser_name == 'analyse':
        fuzzer = get_fuzzer(args.instruction_set, "", None, "")
        fuzzer.analyse_traces_from_files(args.ctraces, args.htraces)
        return 0

    # Test case minimization
    if args.subparser_name == "minimize":
        if (args.enable_input_seq_pass or args.enable_input_diff_pass) and not args.input_outdir:
            SystemExit("ERROR: Passes --enable-input-seq-pass and --enable-input-diff-pass \n"
                       "require flag --input_outdir to be set.")

        fuzzer = get_fuzzer(args.instruction_set, "", args.testcase, "")
        minimizer = get_minimizer(fuzzer, args.instruction_set)
        minimizer.run(
            test_case_asm=args.testcase,
            n_inputs=args.num_inputs,
            test_case_outfile=args.testcase_outfile,
            input_outdir=args.input_outdir,
            n_attempts=args.num_attempts,
            enable_instruction_pass=args.enable_instruction_pass,
            enable_simplification_pass=args.enable_simplification_pass,
            enable_nop_pass=args.enable_nop_pass,
            enable_constant_pass=args.enable_constant_pass,
            enable_mask_pass=args.enable_mask_pass,
            enable_label_pass=args.enable_label_pass,
            enable_fence_pass=args.enable_fence_pass,
            enable_input_seq_pass=args.enable_input_seq_pass,
            enable_input_diff_pass=args.enable_input_diff_pass,
            enable_source_analysis=args.enable_source_analysis,
            enable_comment_pass=args.enable_comment_pass,
        )
        return 0

    if args.subparser_name == "download_spec":
        get_downloader(args.architecture, args.extensions, args.outfile).run()  # type: ignore
        return 0

    raise Exception("Unreachable")


if __name__ == '__main__':
    print("[ERROR]", "This file is not meant to be run directly. Use `revizor.py` instead.")
    exit(1)
