"""
Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
# pylint: disable=missing-function-docstring  # justification: test conventions
# pylint: disable=missing-class-docstring  # justification: test conventions
# pylint: disable=protected-access  # justification: tests inject fakes to drive final_report()

import json
import os
import shutil
import tempfile
import unittest
from typing import Any, Dict, Optional

from mcfz.config import Config
from mcfz.leak_detector import LeakageMap, PC, Witness
from mcfz.reporter import _ReportPrinter
from mcfz.util.dwarf import ModulesInfo


def _witness(trace: str = "t", line: int = 1, ref_line: int = 1) -> Witness:
    return {"trace": trace, "line": line, "ref_line": ref_line}


class _FakeModulesInfo(ModulesInfo):
    """Boundary stub for DWARF-based address resolution. Maps each PC to a fixed 'file:line'
    string, standing in for ModulesInfo.resolve_address so the reporter can be exercised without a
    real target binary and mappings file."""

    # pylint: disable=super-init-not-called  # justification: bypass DWARF/file loading
    def __init__(self, pc_to_line: Dict[int, str]) -> None:
        self._pc_to_line = pc_to_line

    def resolve_address(self, address: int) -> str:
        return self._pc_to_line[address]


class _ReporterTestCase(unittest.TestCase):
    """Drives _ReportPrinter through its final_report() entry point -- which accepts the public
    LeakageMap type and writes the documented report JSON -- and reads the emitted reports back.

    Assertions therefore target the report schema (the reporter's observable contract) instead of
    the private helper methods that produce it, so internal refactors (renaming, inlining, or
    reorganizing those helpers) do not force the tests to change.
    """

    def _emit(self,
              leakage_map: LeakageMap,
              pc_to_line: Dict[int, str],
              allowlist_path: Optional[str] = None) -> Dict[int, Dict[str, Any]]:
        """Run the reporter over ``leakage_map`` and return the parsed report for each verbosity
        level (keyed 1, 2, 3). ``pc_to_line`` fixes the DWARF resolution of each PC; an optional
        ``allowlist_path`` points at an allowlist file."""
        config: Config = object.__new__(Config)
        config.bin_native = "target.bin"
        config.allowlist = allowlist_path

        printer = object.__new__(_ReportPrinter)
        printer._config = config
        printer._modules_info = _FakeModulesInfo(pc_to_line)

        report_dir = tempfile.mkdtemp()
        try:
            printer.final_report(leakage_map, report_dir)
            reports: Dict[int, Dict[str, Any]] = {}
            for verbosity in (1, 2, 3):
                path = os.path.join(report_dir, f"report_verbosity_{verbosity}.json")
                with open(path) as f:
                    reports[verbosity] = json.load(f)
            return reports
        finally:
            shutil.rmtree(report_dir, ignore_errors=True)


class TestReportAllowlist(_ReporterTestCase):
    """Allowlisted source lines are dropped from the report; entries support partial-path matching.
    Observed through the report's ``leaks`` list rather than the private matcher."""

    def setUp(self) -> None:
        self._temp_dir = tempfile.mkdtemp()

    def tearDown(self) -> None:
        shutil.rmtree(self._temp_dir, ignore_errors=True)

    def _allowlist(self, entry: str) -> str:
        path = os.path.join(self._temp_dir, "allowlist.txt")
        with open(path, "w") as f:
            f.write(entry + "\n")
        return path

    def _leak_count(self, resolved_line: str, allowlist_entry: str) -> int:
        """Emit a report for a single leak whose source location resolves to ``resolved_line``,
        filtered by an allowlist containing exactly ``allowlist_entry``, and return the number of
        leaks left in the report."""
        leakage_map: LeakageMap = {"seq": {"D": {PC(0x1000): [_witness()]}}}
        reports = self._emit(leakage_map, {0x1000: resolved_line}, self._allowlist(allowlist_entry))
        return len(reports[1]["leaks"])

    def test_exact_match_is_filtered(self) -> None:
        self.assertEqual(self._leak_count("filename.c:123", "filename.c:123"), 0)

    def test_full_path_match_is_filtered(self) -> None:
        self.assertEqual(self._leak_count("/path/to/filename.c:123", "filename.c:123"), 0)

    def test_partial_path_match_is_filtered(self) -> None:
        self.assertEqual(self._leak_count("/path/to/lib/file.c:42", "lib/file.c:42"), 0)

    def test_full_absolute_path_entry_is_filtered(self) -> None:
        self.assertEqual(
            self._leak_count("/full/path/to/some/file.c:34232", "/full/path/to/some/file.c:34232"),
            0)

    def test_different_filename_is_not_filtered(self) -> None:
        # 'file.c:123' must not match 'otherfile.c:123'
        self.assertEqual(self._leak_count("/path/to/otherfile.c:123", "file.c:123"), 1)

    def test_different_line_is_not_filtered(self) -> None:
        self.assertEqual(self._leak_count("/path/to/filename.c:456", "filename.c:123"), 1)

    def test_unrelated_path_is_not_filtered(self) -> None:
        self.assertEqual(self._leak_count("/path/to/somefile.c:123", "otherfile.c:123"), 1)


class TestReportSchema(_ReporterTestCase):

    def test_report_declares_schema_shape(self) -> None:
        leakage_map: LeakageMap = {"seq": {"D": {PC(0x1): [_witness()]}}}
        report = self._emit(leakage_map, {0x1: "a.c:1"})[1]
        self.assertEqual(
            set(report), {"schema_version", "verbosity", "metadata", "summary", "leaks"})
        self.assertEqual(report["verbosity"], 1)
        self.assertEqual(report["metadata"]["target"], "target.bin")  # wired from config.bin_native

    def test_code_line_split_into_file_and_line(self) -> None:
        # The resolved 'file:line' location becomes the report's `file` and `line` fields,
        # including paths that themselves contain ':' and the 'undefined:0' fallback.
        leakage_map: LeakageMap = {
            "seq": {
                "D": {
                    PC(0x1): [_witness()],
                    PC(0x2): [_witness()],
                    PC(0x3): [_witness()],
                }
            }
        }
        pc_to_line = {
            0x1: "lib/3des.c:259",
            0x2: "/a/b/aesasm-gas.asm:273",
            0x3: "undefined:0",
        }
        leaks = self._emit(leakage_map, pc_to_line)[1]["leaks"]
        file_line = sorted((leak["file"], leak["line"]) for leak in leaks)
        self.assertEqual(file_line, [("/a/b/aesasm-gas.asm", 273), ("lib/3des.c", 259),
                                     ("undefined", 0)])

    def test_verbosity_levels_add_detail(self) -> None:
        # PCs chosen so numeric and lexical ordering disagree: 0x9 < 0x10 numerically,
        # but '0x10' < '0x9' lexically. Both resolve to the same source line, so they group into
        # one leak whose `pcs`/`witnesses` appear only at higher verbosity.
        leakage_map: LeakageMap = {
            "seq": {
                "D": {
                    PC(0x9): [_witness(line=2, ref_line=2)],
                    PC(0x10): [_witness(line=1, ref_line=1)],
                }
            }
        }
        reports = self._emit(leakage_map, {0x9: "lib/3des.c:259", 0x10: "lib/3des.c:259"})

        v1 = reports[1]["leaks"]
        self.assertEqual(v1, [{"clause": "seq", "type": "D", "file": "lib/3des.c", "line": 259}])

        v2 = reports[2]["leaks"]
        self.assertEqual(v2[0]["pcs"], ["0x9", "0x10"])  # sorted numerically, not lexically
        self.assertNotIn("witnesses", v2[0])

        v3 = reports[3]["leaks"]
        self.assertEqual(list(v3[0]["witnesses"].keys()), ["0x9", "0x10"])
        self.assertEqual(v3[0]["witnesses"]["0x10"], [{"trace": "t", "line": 1, "ref_line": 1}])

    def test_leaks_sorted_by_clause_then_type(self) -> None:
        leakage_map: LeakageMap = {
            "cond": {
                "D": {
                    PC(0x20): [_witness()]
                }
            },
            "seq": {
                "I": {
                    PC(0x10): [_witness()]
                },
                "D": {
                    PC(0x11): [_witness()]
                },
            },
        }
        pc_to_line = {0x20: "b.c:2", 0x10: "a.c:1", 0x11: "a.c:1"}
        leaks = self._emit(leakage_map, pc_to_line)[1]["leaks"]
        order = [(leak["clause"], leak["type"]) for leak in leaks]
        # seq before cond, and within seq I before D
        self.assertEqual(order, [("seq", "I"), ("seq", "D"), ("cond", "D")])

    def test_summary_counts_by_clause_and_type(self) -> None:
        leakage_map: LeakageMap = {
            "seq": {
                "D": {
                    PC(0x1): [_witness()]
                },
                "I": {
                    PC(0x2): [_witness()]
                },
            },
            "cond": {
                "D": {
                    PC(0x3): [_witness()]
                }
            },
        }
        pc_to_line = {0x1: "a.c:1", 0x2: "b.c:2", 0x3: "c.c:3"}
        summary = self._emit(leakage_map, pc_to_line)[1]["summary"]
        self.assertEqual(summary["total_leaks"], 3)
        self.assertEqual(summary["by_clause"], {"seq": 2, "cond": 1})
        self.assertEqual(summary["by_type"], {"D": 2, "I": 1})

    def test_cond_leak_subsumed_by_seq_is_dropped(self) -> None:
        # A COND (speculative) leak on a source line that also leaks under SEQ (architecturally)
        # is redundant and must not appear in the report.
        leakage_map: LeakageMap = {
            "seq": {
                "D": {
                    PC(0x1): [_witness()]
                }
            },
            "cond": {
                "D": {
                    PC(0x2): [_witness()],  # same source line as the seq leak -> dropped
                    PC(0x3): [_witness()],  # distinct source line -> kept
                }
            },
        }
        pc_to_line = {0x1: "a.c:1", 0x2: "a.c:1", 0x3: "b.c:2"}
        leaks = self._emit(leakage_map, pc_to_line)[1]["leaks"]
        cond_files = sorted(leak["file"] for leak in leaks if leak["clause"] == "cond")
        # 'a.c' is dropped from cond because it was also found under seq; 'b.c' remains
        self.assertEqual(cond_files, ["b.c"])


if __name__ == "__main__":
    unittest.main()
