"""
File: Module responsible for Stage 3 of the fuzzing process: analysis of the collected traces
      and reporting of the results.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, List, Tuple, Dict, Iterator, NewType, Set, Optional
from datetime import datetime, timezone

import os
import json

from typing_extensions import TypedDict

from .leak_detector import LeakageMap, LeakType, ClauseType, PC, Witness
from .util.dwarf import ModulesInfo

if TYPE_CHECKING:
    from .config import Config, ReportVerbosity

# ==================================================================================================
# Local type definitions
# ==================================================================================================
SCHEMA_VERSION = "1"
""" Version of the report JSON schema emitted by this module. """

CodeLine = NewType('CodeLine', str)
""" Location of a line in the source code, used to group leaks by code lines.
    It is a string in the format "filename:line_number", where
    * filename is the name of the source file,
    * line_number is the line number in the source file.
"""


class LeakRecordBase(TypedDict):
    """ Fields present in a leak record at every verbosity level. """
    clause: ClauseType
    type: LeakType
    file: str
    line: int


class LeakRecord(LeakRecordBase, total=False):
    """ A single leak. ``pcs`` is added at verbosity >= 2, ``witnesses`` at verbosity >= 3. """
    pcs: List[str]
    witnesses: Dict[str, List[Witness]]


class ReportMetadata(TypedDict):
    """ Provenance information shared by all report files of a single run. """
    tool: str
    generated_at: str
    target: str
    allowlist: Optional[str]


class ReportSummary(TypedDict):
    """ Aggregate leak counts. """
    total_leaks: int
    by_clause: Dict[str, int]
    by_type: Dict[str, int]


class Report(TypedDict):
    """ Top-level structure of a report file (identical across verbosity levels). """
    schema_version: str
    verbosity: int
    metadata: ReportMetadata
    summary: ReportSummary
    leaks: List[LeakRecord]


CanonicalMap = Dict[ClauseType, Dict[LeakType, Dict[CodeLine, Dict[str, List[Witness]]]]]
""" Internal grouping of leaks: clause -> leak type -> code line -> PC (hex) -> witnesses. """


# ==================================================================================================
# Reporting of the analysis results
# ==================================================================================================
class _ReportPrinter:
    """
    Class responsible for printing the analysis results to a report file.
    """

    _CLAUSE_ORDER: Dict[str, int] = {'seq': 0, 'cond': 1}
    _TYPE_ORDER: Dict[str, int] = {'I': 0, 'D': 1}

    def __init__(self, config: Config) -> None:
        self._config = config
        self._modules_info = ModulesInfo(os.path.join(config.stage3_wd, "mappings.txt"))

    def final_report(self, leakage_map: LeakageMap, report_dir: str) -> None:
        """
        Build the canonical leak structure once and emit it at every verbosity level.

        All three reports share the same self-describing schema (metadata + summary + a flat
        ``leaks`` list); higher verbosity levels only add more detail to each leak record, never
        change the shape of existing fields.
        """
        canonical = self._build_canonical(leakage_map)
        self._filter_allowlist(canonical)
        metadata = self._build_metadata()

        all_levels: List[ReportVerbosity] = [1, 2, 3]
        for verbosity in all_levels:
            report = self._build_report(canonical, verbosity, metadata)
            report_file = os.path.join(report_dir, f"report_verbosity_{verbosity}.json")
            self._write_report(report_file, report)

    def _write_report(self, report_file: str, report: Report) -> None:
        """ Write a report to ``report_file`` as indented JSON. """
        with open(report_file, "w") as f:
            json.dump(report, f, indent=4)

    def _build_metadata(self) -> ReportMetadata:
        """ Collect provenance information shared by all report files of this run. """
        return {
            "tool": "mcfz",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": self._config.bin_native,
            "allowlist": self._config.allowlist,
        }

    def _build_canonical(self, leakage_map: LeakageMap) -> CanonicalMap:
        """
        Group all leaks by execution clause, leak type, source code line, and PC.

        Source code lines are resolved from instruction addresses via DWARF information.
        COND (speculative) violations on a code line that was also found under SEQ
        (architecturally) are dropped, since the architectural finding subsumes them.

        :param leakage_map: Map of leaks found in the traces, indexed by clause, type, and PC.
        :return: Nested map clause -> type -> code line -> PC (hex) -> list of trace witnesses.
        """
        canonical: CanonicalMap = {}
        for clause, leak_type, code_line, pc, locs in self._iter_leaks_with_code_lines(leakage_map):
            per_line = canonical.setdefault(clause, {}).setdefault(leak_type, {}) \
                .setdefault(code_line, {})
            per_line.setdefault(hex(pc), []).extend(locs)
        self._remove_cond_dups(canonical)
        return canonical

    def _remove_cond_dups(self, canonical: CanonicalMap) -> None:
        """ Remove COND violations on code lines that were also found under SEQ. """
        seq = canonical.get('seq', {})
        cond = canonical.get('cond', {})
        for leak_type in seq:
            if leak_type not in cond:
                continue
            seq_lines = set(seq[leak_type].keys())
            cond[leak_type] = {
                code_line: witnesses
                for code_line, witnesses in cond[leak_type].items()
                if code_line not in seq_lines
            }

    def _iter_leaks_with_code_lines(self, leakage_map: LeakageMap) \
            -> Iterator[Tuple[ClauseType, LeakType, CodeLine, PC, List[Witness]]]:
        """Yield (clause, leak_type, code_line, pc, trace_locations) for each leak in the map."""
        for clause_type in leakage_map:
            for leak_type in leakage_map[clause_type]:
                per_type_map = leakage_map[clause_type][leak_type]
                for pc in per_type_map:
                    source_code_line = CodeLine(self._modules_info.resolve_address(pc))
                    yield clause_type, leak_type, source_code_line, pc, per_type_map[pc]

    def _build_report(self, canonical: CanonicalMap, verbosity: ReportVerbosity,
                      metadata: ReportMetadata) -> Report:
        """ Project the canonical structure into a report at the given verbosity level. """
        leaks = self._build_leaks(canonical, verbosity)
        return {
            "schema_version": SCHEMA_VERSION,
            "verbosity": verbosity,
            "metadata": metadata,
            "summary": self._build_summary(leaks),
            "leaks": leaks,
        }

    def _build_leaks(self, canonical: CanonicalMap, verbosity: ReportVerbosity) -> List[LeakRecord]:
        """
        Flatten the canonical structure into a sorted list of leak records.

        Verbosity controls how much detail each record carries:
            * 1 - clause, leak type, and source code location only;
            * 2 - also the PCs of the leaking instructions;
            * 3 - also the trace witnesses for each PC.
        """
        records: List[LeakRecord] = []
        for clause in canonical:
            for leak_type in canonical[clause]:
                for code_line, pc_map in canonical[clause][leak_type].items():
                    file_name, line = self._split_code_line(code_line)
                    record: LeakRecord = {
                        "clause": clause,
                        "type": leak_type,
                        "file": file_name,
                        "line": line,
                    }
                    if verbosity >= 2:
                        record["pcs"] = sorted(pc_map.keys(), key=lambda p: int(p, 16))
                    if verbosity >= 3:
                        record["witnesses"] = {
                            pc:
                                sorted(
                                    pc_map[pc],
                                    key=lambda w: (w["trace"], w["line"], w["ref_line"]))
                            for pc in sorted(pc_map.keys(), key=lambda p: int(p, 16))
                        }
                    records.append(record)
        records.sort(key=lambda r: (self._CLAUSE_ORDER[r["clause"]], self._TYPE_ORDER[r["type"]], r[
            "file"], r["line"]))
        return records

    def _build_summary(self, leaks: List[LeakRecord]) -> ReportSummary:
        """ Count the leak records by execution clause and by leak type. """
        by_clause: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        for leak in leaks:
            by_clause[leak["clause"]] = by_clause.get(leak["clause"], 0) + 1
            by_type[leak["type"]] = by_type.get(leak["type"], 0) + 1
        return {
            "total_leaks": len(leaks),
            "by_clause": by_clause,
            "by_type": by_type,
        }

    def _split_code_line(self, code_line: CodeLine) -> Tuple[str, int]:
        """ Split a "file:line" code location into its file and integer line components. """
        file_name, sep, line_str = code_line.rpartition(":")
        if not sep:
            return code_line, 0
        try:
            return file_name, int(line_str)
        except ValueError:
            return code_line, 0

    def _is_allowlisted(self, code_line: str, allowlist: Set[str]) -> bool:
        return any(code_line == entry or code_line.endswith("/" + entry) for entry in allowlist)

    def _filter_allowlist(self, canonical: CanonicalMap) -> None:
        """
        Remove allowlisted source code lines from the canonical structure in place.

        The allowlist is a file of source code lines that should be excluded from the report.
        Entries support partial path matching: ``filename.c:123`` in the allowlist will match
        ``/path/to/filename.c:123`` in the leakage map.
        """
        allowlist_file = self._config.allowlist
        if not allowlist_file:
            return

        # Read the allowlist file and create a set of allowed source code lines
        with open(allowlist_file, "r") as f:
            allowlist = {line.strip() for line in f if line.strip()}

        # Remove every allowlisted code line from every clause/type bucket
        for clause in canonical:
            for leak_type in canonical[clause]:
                per_type = canonical[clause][leak_type]
                for code_line in list(per_type.keys()):
                    if self._is_allowlisted(code_line, allowlist):
                        del per_type[code_line]


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
