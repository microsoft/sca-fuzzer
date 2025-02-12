""" File: Entry point for the postprocessing module.
    It selects the appropriate minimization passes based on the command-line arguments,
    and then runs them.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
import shutil
import os

from copy import deepcopy
from typing import List, NamedTuple, Dict, TYPE_CHECKING, Any, Type, Optional
from ..traces import Violation
from ..tc_components.test_case_code import TestCaseProgram
from ..tc_components.test_case_data import InputData
from ..config import CONF
from ..logs import warning, error, update_logging_after_config_change
from ..fuzzer import Fuzzer

from .instruction_passes import BaseInstructionMinimizationPass, InstructionRemovalPass, \
    InstructionSimplificationPass, NopReplacementPass, ConstantSimplificationPass, \
    MaskSimplificationPass, LabelRemovalPass, FenceInsertionPass
from .input_passes import BaseInputMinimizationPass, InputSequenceMinimizationPass, \
    DifferentialInputMinimizerPass
from .analysis_passes import AddViolationCommentsPass
from .progress_printer import ProgressPrinter

if TYPE_CHECKING:
    from ..isa_spec import InstructionSet

TMP_DIR = "/tmp/rvzr_minimize"


class PassDesc(NamedTuple):
    """ A named tuple to store the minimization pass description """
    cls_: Type[BaseInstructionMinimizationPass | BaseInputMinimizationPass]
    is_analysis_pass: bool


class Minimizer:
    """
    Main class for the postprocessing module. It selects the appropriate minimization passes
    based on the command-line arguments, and then runs them.
    """

    ignore_list: List[int]
    """ List of input IDs that will be ignored during minimization """

    pass_map: Dict[str, PassDesc]
    """ Mapping of pass names to their classes """

    _instruction_passes: List[Type[BaseInstructionMinimizationPass]]
    _input_passes: List[Type[BaseInputMinimizationPass]]
    _analysis_passes: List[Type[BaseInstructionMinimizationPass]]

    def __init__(self, fuzzer: Fuzzer, instruction_set_spec: InstructionSet):
        self._fuzzer = fuzzer
        self._progress = ProgressPrinter()
        self.instruction_set_spec = instruction_set_spec
        self.ignore_list = []

        # manage tmp directory
        if not os.path.exists(TMP_DIR):
            os.makedirs(TMP_DIR)

        # initialize the pass map
        self.pass_map = {
            "instruction_pass": PassDesc(InstructionRemovalPass, False),
            "simplification_pass": PassDesc(InstructionSimplificationPass, False),
            "nop_pass": PassDesc(NopReplacementPass, False),
            "constant_pass": PassDesc(ConstantSimplificationPass, False),
            "mask_pass": PassDesc(MaskSimplificationPass, False),
            "label_pass": PassDesc(LabelRemovalPass, False),
            "fence_pass": PassDesc(FenceInsertionPass, True),
            "input_seq_pass": PassDesc(InputSequenceMinimizationPass, False),
            "input_diff_pass": PassDesc(DifferentialInputMinimizerPass, False),
            "comment_pass": PassDesc(AddViolationCommentsPass, True),
        }

    def __del__(self) -> None:
        # remove tmp directory
        if os.path.exists(TMP_DIR):
            shutil.rmtree(TMP_DIR)

    def run(self, test_case_asm: str, n_inputs: int, test_case_outfile: str, input_outdir: str,
            n_attempts: int, **enabled_passes: Any) -> None:
        """
        Run the minimization passes based on the command-line arguments, passed as arguments
        to this function. It first reproduces the violation, then run input passes,
        then instruction passes, and finally the analysis passes. The resulting minimized program
        is stored into `test_case_outfile` and the resulting minimized input sequence is stored
        into `input_outdir`.

        :param test_case_asm: Path to the test case assembly file
        :param n_inputs: Number of inputs to use during the minimization
        :param test_case_outfile: Path to store the minimized test case
        :param input_outdir: Path to store the minimized inputs
        :param n_attempts: Number of attempts to run the instruction minimization passes
        :param enabled_passes: Dictionary of arguments to enable/disable the passes.
               Supported keys:
               - enable_instruction_pass
               - enable_simplification_pass
               - enable_nop_pass
               - enable_constant_pass
               - enable_mask_pass
               - enable_label_pass
               - enable_fence_pass
               - enable_input_seq_pass
               - enable_input_diff_pass
               - enable_comment_pass
        :return: None
        """
        self._reset(enabled_passes)

        # Parse the test case and inputs
        test_case = self._fuzzer.asm_parser.parse_file(test_case_asm, self._fuzzer.generator,
                                                       self._fuzzer.elf_parser)
        inputs = self._fuzzer.input_gen.generate(n_inputs, n_actors=test_case.n_actors())

        # Check if the violation can be reproduced
        violation = self._reproduce_org_violation(test_case, inputs)
        if not violation:
            return

        # Run the input minimization passes
        if self._input_passes:
            new_inputs = self._run_input_passes(test_case, inputs, violation, input_outdir)

            # Check if the violation can be reproduced with the new inputs
            new_violation = self._fuzzer.fuzzing_round(test_case, inputs, [])
            if new_violation:
                # Use new inputs in future passes
                inputs = new_inputs
                violation = new_violation

                # Disable boosting from now on:
                # The minimized input sequence is now guaranteed to be boosted
                CONF.inputs_per_class = 1
            else:
                warning("postprocessor", "Non-reproducible input sequence minimization. Reverting")

        # Set the non-violating inputs as the ignore list
        violating_ids = [m.input_id for m in violation.measurements]
        self.ignore_list = \
            [i for i in range(len(violation.input_sequence)) if i not in violating_ids]
        self._progress.pass_msg(f"Violating input IDs: {violating_ids}")

        # Run the instruction minimization passes
        for attempt in range(n_attempts):
            self._progress.global_msg(f"Minimization attempt {attempt + 1}/{n_attempts}")
            old_tc = deepcopy(test_case)
            test_case = self._run_instruction_passes(test_case, inputs, violation,
                                                     test_case_outfile)
            if test_case == old_tc:  # break if no progress was made
                break

        # Run the analysis passes
        test_case = self._run_instruction_passes(test_case, inputs, violation, test_case_outfile)

        # Get rid of unused labels
        if enabled_passes.get("enable_label_pass", False):
            self._instruction_passes = [LabelRemovalPass]
            test_case = self._run_instruction_passes(test_case, inputs, violation,
                                                     test_case_outfile)

        # Store the results
        self._progress.pass_start("Storing the results")
        test_case.save(test_case_outfile)

    def _reset(self, enabled_passes: Dict[str, Any]) -> None:
        # Check arguments
        assert CONF.instruction_set == "x86-64", "Postprocessor supports only x86-64 so far"

        # Get lists of enabled passes
        self._set_passes(enabled_passes)

        # Reset the ignore list
        self.ignore_list = []

        # Adjust the sample size to reduce non-reproducibility
        CONF.executor_sample_sizes = [CONF.executor_sample_sizes[-1]]

        # Make sure that fuzzing progress is not printed
        if "info" in CONF.logging_modes:
            CONF.logging_modes.remove("info")
            update_logging_after_config_change()

    def _reproduce_org_violation(self, test_case: TestCaseProgram,
                                 inputs: List[InputData]) -> Optional[Violation]:
        self._progress.pass_start("Reproducing the violation")
        for _ in range(CONF.minimizer_retries):
            violation = self._fuzzer.fuzzing_round(test_case, inputs, [])
            if violation:
                self._progress.pass_msg("Violation reproduced. Proceeding with minimization")
                return violation
        self._progress.pass_msg("Could not reproduce the violation. Exiting")
        return None

    def _set_passes(self, enabled_passes: Dict[str, Any]) -> None:
        passes: List[PassDesc] = \
            [v for k, v in self.pass_map.items() if enabled_passes.get(f"enable_{k}", False)]
        self._input_passes = [
            p.cls_ for p in passes if issubclass(p.cls_, BaseInputMinimizationPass)
        ]
        self._instruction_passes = [
            p.cls_
            for p in passes
            if issubclass(p.cls_, BaseInstructionMinimizationPass) and not p.is_analysis_pass
        ]
        self._analysis_passes = [
            p.cls_
            for p in passes
            if issubclass(p.cls_, BaseInstructionMinimizationPass) and p.is_analysis_pass
        ]

    def _run_input_passes(self, test_case: TestCaseProgram, inputs: List[InputData],
                          org_violation: Violation, outdir: str) -> List[InputData]:
        violation = org_violation

        for pass_cls in self._input_passes:
            # Create the pass object
            pass_ = pass_cls(self._fuzzer, self.instruction_set_spec, self._progress)
            self._progress.pass_start(pass_.name)

            # Run the pass
            new_inputs = pass_.run(test_case, inputs, violation)

            # Recreate the violation with the new input sequence
            new_violation = self._fuzzer.fuzzing_round(test_case, new_inputs, [])
            if new_violation:
                violation = new_violation
                inputs = new_inputs
            else:
                self._progress.pass_msg("[WARNING] Non-reproducible sequence minimization"
                                        ". Rolling back to the previous state")

        # Create the output directory, if not already exists
        if outdir and not os.path.exists(outdir):
            try:
                os.makedirs(outdir)
            except OSError:
                error(f"Creation of the directory {outdir} failed")
            outdir = os.path.abspath(outdir)

        # Store the results
        self._progress.pass_msg(f"Saving new inputs in '{outdir}'")
        for i, input_ in enumerate(inputs):
            input_.save(f"{outdir}/min_input_{i:04}.bin")

        return inputs

    def _run_instruction_passes(self, test_case: TestCaseProgram, inputs: List[InputData],
                                org_violation: Violation, outfile: str) -> TestCaseProgram:
        # create pass objects
        passes = self._instruction_passes
        pass_objs = [c(self._fuzzer, self.instruction_set_spec, self._progress) for c in passes]
        for pass_obj in pass_objs:
            pass_obj.set_ignore_list(self.ignore_list)
            pass_obj.set_violation(org_violation)

        # run passes
        for pass_obj in pass_objs:
            self._progress.pass_start(pass_obj.name)
            test_case = pass_obj.run(test_case, inputs)
            test_case.save(outfile)

        return test_case

    def _run_analysis_passes(self, test_case: TestCaseProgram, inputs: List[InputData],
                             org_violation: Violation, outfile: str) -> TestCaseProgram:
        # create pass objects
        passes = self._analysis_passes
        pass_objs = [c(self._fuzzer, self.instruction_set_spec, self._progress) for c in passes]
        for pass_obj in pass_objs:
            pass_obj.set_ignore_list(self.ignore_list)
            pass_obj.set_violation(org_violation)

        # run passes
        for pass_obj in pass_objs:
            self._progress.pass_start(pass_obj.name)
            test_case = pass_obj.run(test_case, inputs)
            test_case.save(outfile)

        return test_case
