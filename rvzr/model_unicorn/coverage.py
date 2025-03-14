"""
File: Class for tracking instruction coverage in fuzzing campaigns with Unicorn backend.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from collections import defaultdict

from typing import Dict, Optional
from typing_extensions import assert_never

from ..tc_components.instruction import Instruction, RegisterOp, MemoryOp, \
    ImmediateOp, LabelOp, AgenOp, FlagsOp, CondOp
from ..config import CONF

_SIGNATURE_CACHE: Dict[int, str] = {}


def _get_instruction_signature(instruction: Instruction) -> str:
    """
    Get a brief string representation of the instruction.
    Used as a unique identifier for the instruction when tracking coverage.
    """
    inst_identifier = id(instruction)

    # Cache the brief string to avoid recomputing it
    if inst_identifier in _SIGNATURE_CACHE:
        return _SIGNATURE_CACHE[inst_identifier]

    # Compute the brief string
    brief = instruction.name
    for o in instruction.operands:
        if isinstance(o, RegisterOp):
            brief += f" R{o.width}"
        elif isinstance(o, MemoryOp):
            brief += f" M{o.width}"
        elif isinstance(o, ImmediateOp):
            brief += f" I{o.width}"
        elif isinstance(o, LabelOp):
            brief += " L"
        elif isinstance(o, AgenOp):
            brief += f" A{o.width}"
        elif isinstance(o, FlagsOp):
            brief += " F"
        elif isinstance(o, CondOp):
            brief += " C"

        else:
            assert_never(o)

    _SIGNATURE_CACHE[inst_identifier] = brief
    return brief


class InstructionCoverage:
    """
    Tracks coverage of instructions executed on the model during a fuzzing campaign.
    """
    _cov: Dict[str, int]
    """ instruction coverage of the entire campaign """

    _local_cov: Optional[Dict[str, int]] = None
    """ instruction coverage of the current test case """

    def __init__(self) -> None:
        self._cov = defaultdict(int)

    def start_test_case(self) -> None:
        """
        Start tracking coverage for a new test case when CONF.coverage_type == "model_instructions".
        Otherwise, disable coverage tracking.
        """

        if CONF.coverage_type == "model_instructions":
            self._local_cov = defaultdict(int)
            return

        self._local_cov = None

    def add_instruction(self, inst: Instruction) -> None:
        """ Record the given instruction as covered (if coverage tracking is enabled) """
        if self._local_cov is None:
            return
        if inst.is_instrumentation:
            return
        self._local_cov[_get_instruction_signature(inst)] += 1

    def finish_test_case(self) -> None:
        """ Finish tracking coverage for the current test case """
        if self._local_cov is None:
            return

        for inst_name in self._local_cov.keys():
            self._cov[inst_name] += 1

    def report(self, path: str) -> None:
        """ Write the coverage data to a file """
        # Ensure that the last test case is included in the coverage report
        self.finish_test_case()

        # Sort the instructions by coverage count and write them to the file
        inst_names = sorted(self._cov.items(), key=lambda x: x[1], reverse=True)
        with open(path, "w") as f:
            for inst_name, count in inst_names:
                f.write(f"{inst_name:<20} {count}\n")
            if not inst_names:
                f.write("    No coverage data available")
