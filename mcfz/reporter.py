"""
File: Module responsible for Stage 3 of the fuzzing process: analysis of the collected traces
      and reporting of the results.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List, Tuple, Dict, Iterator, NewType, Union, Any, Set

import os
import json
from copy import deepcopy

from typing_extensions import assert_never

from .leak_detector import LeakageMap, LeakType, ClauseType, PC, LinesInTracePair
from .util.dwarf import ModulesInfo

if TYPE_CHECKING:
    from .config import Config, ReportVerbosity

# ==================================================================================================
# Local type definitions
# ==================================================================================================
CodeLine = NewType('CodeLine', str)
""" Location of a line in the source code, used to group leaks by code lines.
    It is a string in the format "filename:line_number", where
    * filename is the name of the source file,
    * line_number is the line number in the source file.
"""

LeakageLineMapVrb3 = Dict[ClauseType, Dict[
    LeakType,
    Dict[
        CodeLine,
        Dict[
            PC,
            List[LinesInTracePair],
        ],
    ],
]]
""" Map of unique leaky lines of code, indexed by leak type and code line.
    The value is a map of PCs where the leak was found, and a list of locations
    where the leak was found in the trace files.
"""

LeakageLineMapVrb2 = Dict[ClauseType, Dict[
    LeakType,
    Dict[
        CodeLine,
        List[PC],
    ],
]]
""" A variant of LeakageLineMap for the lower verbosity level (verbosity 2). """

LeakageLineMapVrb1 = Dict[ClauseType, Dict[
    LeakType,
    List[CodeLine],
]]
""" A variant of LeakageLineMap for the lowest verbosity level (verbosity 1). """

LeakageLineMap = Union[
    LeakageLineMapVrb3,
    LeakageLineMapVrb2,
    LeakageLineMapVrb1,
]


# ==================================================================================================
# Reporting of the analysis results
# ==================================================================================================
def _convert_int_keys_to_hex(o: Any) -> Any:
    """Recursively convert all integer dictionary keys to hex strings."""
    if isinstance(o, dict):
        return {
            (hex(k) if isinstance(k, int) else k): _convert_int_keys_to_hex(v) for k, v in o.items()
        }
    if isinstance(o, list):
        return [_convert_int_keys_to_hex(item) for item in o]
    if isinstance(o, int):
        return hex(o)
    return o


class _ReportPrinter:
    """
    Class responsible for printing the analysis results to a report file.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._modules_info = ModulesInfo(os.path.join(config.stage3_wd, "mappings.txt"))

    def final_report(self, leakage_map: LeakageMap, report_dir: str) -> None:
        """ Print the global map of leaks to the trace log """
        all_levels: List[ReportVerbosity] = [1, 2, 3]
        # all_levels: List[ReportVerbosity] = [1]
        for verbosity in all_levels:
            leakage_line_map = self._group_by_code_line(leakage_map, verbosity)
            leakage_line_map = self._filter_allowlist(leakage_line_map)
            report_file = os.path.join(report_dir, f"report_verbosity_{verbosity}.json")
            self._write_report(report_file, leakage_line_map)

    def _write_report(self, report_file: str, leakage_line_map: LeakageLineMap) -> None:
        """
        Write the report to the given file in a json format:
        {
            "seq": {
                "I": {
                    "file:line": {
                        "0x12345678": ["trace1:10:20", "trace2:15:25"],
                        ...
                    },
                    ...
                },
                "D": {
                    ...
                }
            },
            "cond": {
                "I": {
                    ...
                },
                "D": {
                    ...
                }
            }
        }
        """
        report_dict = _convert_int_keys_to_hex(leakage_line_map)
        with open(report_file, "w") as f:
            json.dump(report_dict, f, indent=4, sort_keys=True)

    def _group_by_code_line(self, leakage_map: LeakageMap,
                            verbosity: ReportVerbosity) -> LeakageLineMap:
        """
        Transform a LeakageMap object into a LeakageLineMap object by
        grouping all instructions that map to the same line in the source code and filtering
        them based on the verbosity level.

        Use DWARF information to get the source code line for each instruction address.

        :param leakage_map: Map of leaks found in the traces, indexed by leak type and PC.
        :param verbosity: Amount of information to include in the report
               (see Config.report_verbosity for details).
        :return: Map of unique leaks, grouped by source code line.
        """
        if verbosity == 1:
            return self._group_by_code_line_vrb1(leakage_map)
        if verbosity == 2:
            return self._group_by_code_line_vrb2(leakage_map)
        if verbosity == 3:
            return self._group_by_code_line_vrb3(leakage_map)
        assert_never(verbosity)

    def _iter_leaks_with_code_lines(self, leakage_map: LeakageMap) \
            -> Iterator[Tuple[ClauseType, LeakType, CodeLine, PC, List[LinesInTracePair]]]:
        """Yield (leak_type, code_line, pc, trace_locations) for each leak in the map."""
        for clause_type in leakage_map:
            for leak_type in leakage_map[clause_type]:
                per_type_map = leakage_map[clause_type][leak_type]
                for pc in per_type_map:
                    source_code_line = CodeLine(self._modules_info.resolve_address(pc))
                    yield clause_type, leak_type, source_code_line, pc, per_type_map[pc]

    def _filter_cond(self, leakage_line_map: Dict[ClauseType, Any], leak_type: LeakType) \
            -> Dict[CodeLine, Any]:
        """Remove all COND violations that were also found architecturally (SEQ)"""
        # Calculate the set difference between cond violations and seq violations
        seq_violations = leakage_line_map['seq'][leak_type].keys()
        cond_violations = leakage_line_map['cond'][leak_type].keys()
        diff = set(cond_violations) - set(seq_violations)
        # Keep only entries that are part of the set difference
        old_entries = leakage_line_map['cond'][leak_type]
        filtered = {diff_code_line: old_entries[diff_code_line] for diff_code_line in diff}
        return filtered

    def _group_by_code_line_vrb3(self, leakage_map: LeakageMap) -> LeakageLineMapVrb3:
        leakage_line_map: LeakageLineMapVrb3 = {}
        for clause, leak_type, code_line, pc, locs in self._iter_leaks_with_code_lines(leakage_map):
            per_type_map = leakage_line_map.setdefault(clause, {}).setdefault(leak_type, {})
            per_line_map = per_type_map.setdefault(code_line, {})
            per_line_map.setdefault(pc, []).extend(locs)
        # Remove COND violations that were also found with SEQ
        for leak_type in leakage_line_map.get('seq', {}).keys():
            if leak_type in leakage_line_map.get('cond', {}).keys():
                leakage_line_map['cond'][leak_type] = self._filter_cond(leakage_line_map, leak_type)
        # Sort all trace location lists
        for per_clause in leakage_line_map.values():
            for per_type in per_clause.values():
                for per_line in per_type.values():
                    for loc_list in per_line.values():
                        loc_list.sort()

        return leakage_line_map

    def _group_by_code_line_vrb2(self, leakage_map: LeakageMap) -> LeakageLineMapVrb2:
        leakage_line_map: LeakageLineMapVrb2 = {}
        # Insert all violations
        for clause, leak_type, code_line, pc, _ in self._iter_leaks_with_code_lines(leakage_map):
            per_type_map = leakage_line_map.setdefault(clause, {}).setdefault(leak_type, {})
            per_type_map.setdefault(code_line, []).append(pc)
        # Remove COND violations that were also found with SEQ
        for leak_type in leakage_line_map.get('seq', {}).keys():
            if leak_type in leakage_line_map.get('cond', {}).keys():
                leakage_line_map['cond'][leak_type] = self._filter_cond(leakage_line_map, leak_type)
        # Sort all PC lists
        for per_clause in leakage_line_map.values():
            for per_type in per_clause.values():
                for pc_list in per_type.values():
                    pc_list.sort()

        return leakage_line_map

    def _group_by_code_line_vrb1(self, leakage_map: LeakageMap) -> LeakageLineMapVrb1:
        leakage_line_map: LeakageLineMapVrb1 = {}
        # Insert all violations
        for clause, leak_type, code_line, _, _ in self._iter_leaks_with_code_lines(leakage_map):
            leakage_line_map.setdefault(clause, {}).setdefault(leak_type, set()).add(code_line)
        # Order them
        for leak_type in leakage_line_map.get('seq', {}).keys():
            seq: set[CodeLine] = leakage_line_map.get('seq', {}).get(leak_type, set())
            # Of the COND violations, only keep the ones that are not also SEQ violations
            if leak_type in leakage_line_map.get('cond', {}).keys():
                cond: set[CodeLine] = leakage_line_map.get('cond', {}).get(leak_type, set())
                leakage_line_map['cond'][leak_type] = sorted(list(cond - seq))
            # For
            leakage_line_map['seq'][leak_type] = sorted(list(seq))

        return leakage_line_map

    def _is_allowlisted(self, code_line: str, allowlist: Set[str]) -> bool:
        return any(code_line == entry or code_line.endswith("/" + entry) for entry in allowlist)

    def _filter_allowlist(self, leakage_line_map: LeakageLineMap) -> LeakageLineMap:
        """
        Filter the leakage line map by the allowlist of source code lines.
        The allowlist is a list of source code lines that should be excluded from the report.
        Entries support partial path matching: ``filename.c:123`` in the allowlist will match
        ``/path/to/filename.c:123`` in the leakage map.
        """
        allowlist_file = self._config.allowlist
        if not allowlist_file:
            return leakage_line_map

        # Read the allowlist file and create a set of allowed source code lines
        with open(allowlist_file, "r") as f:
            allowlist = {line.strip() for line in f if line.strip()}

        # Filter the leakage line map by the allowlist
        filtered_leakage_line_map: LeakageLineMap = deepcopy(leakage_line_map)
        for clause_type in leakage_line_map:
            for leak_type in leakage_line_map[clause_type]:
                per_type_map = leakage_line_map[clause_type][leak_type]
                filtered_per_type = filtered_leakage_line_map[clause_type][leak_type]
                if isinstance(per_type_map, list) and isinstance(filtered_per_type, list):
                    # Verbosity 1: remove allowlisted entries from the list
                    for cl in per_type_map:
                        if self._is_allowlisted(cl, allowlist):
                            filtered_per_type.remove(cl)
                elif isinstance(per_type_map, dict) and isinstance(filtered_per_type, dict):
                    # Verbosity 2 or 3: remove allowlisted entries from the dict
                    for code_line in per_type_map:
                        if self._is_allowlisted(code_line, allowlist):
                            filtered_per_type.pop(code_line)

        return filtered_leakage_line_map


# ==================================================================================================
# Public interface to the analysis and reporting module
# ==================================================================================================
class Reporter:
    """
    Class responsible for processing the collected contract traces, detecting leaks exposed in them,
    and building a final report with the results of the analysis.
    """

    def __init__(self, config: Config) -> None:
        self._config = config

        # check that mappings.txt was created (it's a common source of errors)
        if not os.path.isfile(os.path.join(self._config.stage3_wd, "mappings.txt")):
            raise FileNotFoundError(
                "Module mappings file 'mappings.txt' not found in stage 3 working directory "
                f"'{self._config.stage3_wd}'.")

    def generate_report(self, leakage_map: LeakageMap) -> None:
        """
        Generate a report of the leaks found in the fuzzing campaign.
        """
        printer = _ReportPrinter(self._config)
        printer.final_report(leakage_map, self._config.stage4_wd)
