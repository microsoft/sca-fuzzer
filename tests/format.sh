#!/usr/bin/env bash
#
# format.sh -- Format Python, C/C++, and shell sources in place.
#
# Intended to be run by agents (or developers) before committing changes, to
# bring the code into compliance with this repository's formatting conventions.
#
# What it does:
#   1. Formats Python sources in place with yapf (repo style).
#   2. Formats C/C++ sources in place with clang-format (each tree's own
#      .clang-format is auto-discovered).
#   3. Formats shell sources in place with shfmt.
#
# This script only edits files; it does NOT compile, run tests, or perform any
# static analysis. For the lint/type/style checks (mypy, flake8, pylint,
# clang-tidy, shellcheck), use ./tests/style-check.sh instead.
#
# Usage (always run from the repository root):
#   ./tests/format.sh [--check] [file ...]
#
#   --check   Verify formatting without modifying files (CI mode).
#   file ...  Restrict formatting to the given files (split by extension).
#             When omitted, the default source trees are formatted.
#
# Exit code: 0 if every step passed, 1 otherwise.

set -uo pipefail

# ==================================================================================================
# Constants & globals
# ==================================================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." &> /dev/null && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

# yapf style, identical to the one documented in .github/copilot-instructions.md.
YAPF_STYLE='{based_on_style: yapf, column_limit: 100, indent_width: 4, DISABLE_ENDING_COMMA_HEURISTIC: 0, SPLIT_BEFORE_ARITHMETIC_OPERATOR: True, SPLIT_BEFORE_LOGICAL_OPERATOR: True}'

# shfmt flags: indent=4, binary ops start next line, redirect follows command,
# keep column alignment of assignments.
SHFMT_ARGS=(-i 4 -bn -sr -kp)

# Python source trees formatted by default (relative to the repo root).
PY_DIRS=("rvzr" "mcfz" "tests")

# C/C++ source trees formatted by default. Each has its own .clang-format.
C_DIRS=("rvzr/executor_km" "rvzr/model_dynamorio/adapter" "rvzr/model_dynamorio/backend"
    "rvzr/model_dynamorio/leak_detector")

# Shell source trees formatted by default (relative to the repo root).
SH_DIRS=(".github/scripts" "tests")

# Run mode: when true, formatting phases verify without modifying files.
CHECK_ONLY=false

overall_ok=true

py_files=()
c_files=()
sh_files=()

# Result accumulators for the summary table.
fmt_py_status=""
fmt_py_detail=""
fmt_c_status=""
fmt_c_detail=""
fmt_sh_status=""
fmt_sh_detail=""

# ==================================================================================================
# Helpers
# ==================================================================================================

function parse_args() {
    local positional=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
        --check)
            CHECK_ONLY=true
            shift
            ;;
        -h | --help)
            sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
        *)
            positional+=("$1")
            shift
            ;;
        esac
    done
    POSITIONAL_ARGS=("${positional[@]}")
}

# Populate py_files, c_files, and sh_files, either from explicit arguments or by
# scanning the default source trees. Build artifacts are always excluded.
function collect_files() {
    if [[ ${#POSITIONAL_ARGS[@]} -gt 0 ]]; then
        for f in "${POSITIONAL_ARGS[@]}"; do
            case "$f" in
            *.py) py_files+=("$f") ;;
            *.c | *.h | *.cpp | *.hpp) c_files+=("$f") ;;
            *.sh | *.bash) sh_files+=("$f") ;;
            *) echo "Skipping unsupported file type: $f" >&2 ;;
            esac
        done
        return
    fi

    local dir
    for dir in "${PY_DIRS[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r -d '' f; do
            py_files+=("$f")
        done < <(find "$dir" -name '*.py' -type f -print0 | sort -z)
    done

    for dir in "${C_DIRS[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r -d '' f; do
            c_files+=("$f")
        done < <(find "$dir" \
            \( -name '*.c' -o -name '*.h' -o -name '*.cpp' -o -name '*.hpp' \) \
            ! -path '*/build/*' ! -path '*/CMakeFiles/*' -type f -print0 | sort -z)
    done

    for dir in "${SH_DIRS[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r -d '' f; do
            sh_files+=("$f")
        done < <(find "$dir" \( -name '*.sh' -o -name '*.bash' \) -type f -print0 | sort -z)
    done
}

# ==================================================================================================
# Formatting phases
# ==================================================================================================

# Format a single file with the given tool. When CHECK_ONLY is true, verify
# formatting without modifying the file; otherwise rewrite it in place. Returns 0
# when the file is already formatted (check) or was rewritten successfully
# (write), non-zero otherwise.
function format_one() {
    local tool="$1" f="$2"
    case "$tool" in
    yapf)
        if $CHECK_ONLY; then
            [[ -z "$(yapf -d --style="$YAPF_STYLE" "$f" 2> /dev/null)" ]]
        else
            yapf -i --style="$YAPF_STYLE" "$f" 2> /dev/null
        fi
        ;;
    clang-format)
        if $CHECK_ONLY; then
            clang-format --dry-run -Werror "$f" &> /dev/null
        else
            clang-format -i "$f" 2> /dev/null
        fi
        ;;
    shfmt)
        if $CHECK_ONLY; then
            shfmt -d "${SHFMT_ARGS[@]}" "$f" &> /dev/null
        else
            shfmt -w "${SHFMT_ARGS[@]}" "$f" 2> /dev/null
        fi
        ;;
    esac
}

# Shared driver for a single language. Prints the phase header and outcome, and
# reports the result through the status/detail nameref arguments.
#
# Args: label tool noun files_var status_var detail_var
function run_formatter() {
    local label="$1" tool="$2" noun="$3"
    local -n _files="$4" _status="$5" _detail="$6"

    echo ""
    echo "===== $label ====="

    if [[ ${#_files[@]} -eq 0 ]]; then
        _status="SKIPPED"
        _detail="No $noun files found"
        echo "$_status: $_detail"
        return
    fi

    if ! command -v "$tool" &> /dev/null; then
        _status="FAIL"
        _detail="Tool not found: $tool"
        overall_ok=false
        echo "$_status: $_detail"
        return
    fi

    local failures=() f
    for f in "${_files[@]}"; do
        format_one "$tool" "$f" || failures+=("$f")
    done

    if [[ ${#failures[@]} -eq 0 ]]; then
        _status="PASS"
        if $CHECK_ONLY; then
            _detail="Checked ${#_files[@]} file(s)"
        else
            _detail="Formatted ${#_files[@]} file(s)"
        fi
    else
        _status="FAIL"
        if $CHECK_ONLY; then
            _detail="Needs formatting: ${failures[*]}"
        else
            _detail="Failed on: ${failures[*]}"
        fi
        overall_ok=false
    fi
    echo "$_status: $_detail"
}

function format_python() {
    run_formatter "Python formatting (yapf)" "yapf" "Python" \
        py_files fmt_py_status fmt_py_detail
}

function format_c() {
    run_formatter "C/C++ formatting (clang-format)" "clang-format" "C/C++" \
        c_files fmt_c_status fmt_c_detail
}

function format_shell() {
    run_formatter "Shell formatting (shfmt)" "shfmt" "shell" \
        sh_files fmt_sh_status fmt_sh_detail
}

# ==================================================================================================
# Summary
# ==================================================================================================

function print_summary() {
    echo ""
    echo "===== Summary ====="
    printf "| %-18s | %-7s | %s\n" "Step" "Status" "Details"
    printf "| %-18s | %-7s | %s\n" "------------------" "-------" "-------------------------------"
    printf "| %-18s | %-7s | %s\n" "Python formatting" "$fmt_py_status" "$fmt_py_detail"
    printf "| %-18s | %-7s | %s\n" "C/C++ formatting" "$fmt_c_status" "$fmt_c_detail"
    printf "| %-18s | %-7s | %s\n" "Shell formatting" "$fmt_sh_status" "$fmt_sh_detail"
    echo ""

    if $overall_ok; then
        echo -e "${BOLD}Overall: ${GREEN}PASS${RESET}"
        exit 0
    else
        echo -e "${BOLD}Overall: ${RED}FAIL${RESET}"
        exit 1
    fi
}

# ==================================================================================================
# Main
# ==================================================================================================

function main() {
    parse_args "$@"
    cd "$REPO_ROOT" || exit 1

    collect_files
    format_python
    format_c
    format_shell
    print_summary
}

main "$@"
