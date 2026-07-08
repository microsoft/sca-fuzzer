#!/usr/bin/env bash
#
# style-check.sh -- Static type and code-style checks for the repository.
#
# This is the single source of truth for the project's static checks. It runs:
#   * Type checking:  mypy --strict        (rvzr/; strict also adds tests/, mcfz/)
#   * Code style:     flake8               (whole repo)
#                   - clang-tidy           (DynamoRIO backend, when built)
#                   - shellcheck           (tests/*.sh, .github/scripts/*.sh)
#                   - pylint               (strict only: rvzr/, tests/, mcfz/)
#
# tests/runtests.sh delegates its type_check and code_style_check stages to this
# script, so the enforced rules never drift between the two.
#
# Usage (run from the repository root):
#   ./tests/style-check.sh [--type-check] [--code-style] [--strict]
#
#   --type-check   Run only the type-checking phase.
#   --code-style   Run only the code-style phase.
#                  When neither flag is given, both phases run.
#   --strict       Enable the optional strict checks (unit-test typing, pylint).
#
# Exit code: 0 if every check passed, 1 otherwise.

# Note: deliberately no `set -e` -- each check appends `|| OVERALL_OK=false` so
# a failure is recorded but the run continues, reporting every check in one pass.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)"
if [[ -z "$REPO_ROOT" ]]; then
    echo "style-check.sh: failed to determine repository root" >&2
    exit 1
fi

# ==================================================================================================
# Argument parsing
# ==================================================================================================
function parse_args() {
    RUN_TYPE_CHECK=false
    RUN_CODE_STYLE=false
    STRICT=false
    local explicit_phase=false

    while [[ $# -gt 0 ]]; do
        case $1 in
        --type-check)
            RUN_TYPE_CHECK=true
            explicit_phase=true
            shift
            ;;
        --code-style)
            RUN_CODE_STYLE=true
            explicit_phase=true
            shift
            ;;
        --strict)
            STRICT=true
            shift
            ;;
        -h | --help)
            sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^#\s\?//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
        esac
    done

    # Default: run both phases when none was explicitly requested.
    if [[ "$explicit_phase" = false ]]; then
        RUN_TYPE_CHECK=true
        RUN_CODE_STYLE=true
    fi
}

# ==================================================================================================
# Helpers
# ==================================================================================================
# Set to false by any check that fails; the final exit status is derived from it.
OVERALL_OK=true

# List the files with uncommitted changes, as repo-root-relative paths
# (staged + unstaged + untracked).
function changed_files() {
    {
        # Tracked changes (staged and unstaged), excluding deletions so that
        # removed files are not handed to clang-tidy (which would error on them).
        git diff --name-only --diff-filter=d HEAD
        # Untracked, non-ignored files.
        git ls-files --others --exclude-standard
    } | sort -u
}

# Run clang-tidy over a directory, restricted to its changed files. Skips the
# directory when its build dir is missing or nothing relevant changed. Following
# Option B, a change to any header forces a full re-check of the directory, since
# clang-tidy diagnostics for a header often surface in the source files that
# include it. Runs one clang-tidy process per file in parallel.
#
#   $1 name       human-readable label (for skip messages)
#   $2 dir        directory to check (e.g. rvzr/model_dynamorio/backend)
#   $3 src_ext    source extension (c or cpp)
#   $4 hdr_ext    header extension (h or hpp)
#   $5 changed    newline-separated changed files (repo-root-relative)
#   $6.. extra    extra arguments passed to clang-tidy
function run_clang_tidy() {
    local name="$1" dir="$2" src_ext="$3" hdr_ext="$4" changed="$5"
    shift 5

    [[ -d "$dir/build" ]] || return

    # Select the changed source/header files under the directory.
    local changed_here
    changed_here="$(printf '%s\n' "$changed" | grep -E "^$dir/.*\.($src_ext|$hdr_ext)$" || true)"
    if [[ -z "$changed_here" ]]; then
        echo "[$name] No changes; skipping clang-tidy"
        return
    fi

    # Note: plain grep (no -q) so it reads all of its input; under `set -o
    # pipefail`, a `grep -q` that exits early would make printf see EPIPE and
    # could mark the pipeline as failed even on a successful match.
    local files
    if printf '%s\n' "$changed_here" | grep -E "\.$hdr_ext$" > /dev/null; then
        # Header change -> full re-check of the directory (Option B).
        files="$(find "$dir" -name "*.$src_ext" -or -name "*.$hdr_ext" | grep -v 'CMakeFiles' || true)"
    else
        files="$changed_here"
    fi

    # Feed the file list via a here-string (not a pipe) so the OVERALL_OK
    # assignment runs in the current shell rather than a subshell. xargs -r skips
    # invoking clang-tidy entirely when the file list is empty.
    xargs -r -P"$(nproc)" -n1 \
        clang-tidy --quiet "$@" -p "$dir/build/" --config-file="$dir/.clang-tidy" <<< "$files" \
                                                                                              || OVERALL_OK=false
}

function run_mypy() {
    MYPYPATH=rvzr/ python3 -m mypy --strict "$@" \
        --no-warn-unused-ignores --untyped-calls-exclude=elftools
}

# Python files (excluding caches) under the given roots, as a flat list. Used
# for proper packages (rvzr/) where basenames never collide across modules.
function py_files() {
    find "$@" -type f -name '*.py' -not -path '*/__pycache__/*' 2> /dev/null | sort
}

# Directories (non-recursive) under the given roots that contain Python files.
# mypy and pylint are invoked per-directory so that files sharing a basename
# across packages (e.g. tests/x86_tests/model_common.py and
# tests/arm64/model_common.py) do not collide as duplicate modules.
function py_dirs() {
    find "$@" -type f -name '*.py' -not -path '*/__pycache__/*' \
        -exec dirname {} \; 2> /dev/null | sort -u
}

# ==================================================================================================
# Type checking
# ==================================================================================================
function type_check() {
    echo ""
    echo "===== MyPy ====="
    local files
    mapfile -t files < <(py_files rvzr)
    run_mypy "${files[@]}" || OVERALL_OK=false

    if [[ "$STRICT" = true ]]; then
        echo ""
        echo "===== STRICT CHECK: MyPy (Tests & McFuzz) ====="
        local dir dirs
        mapfile -t dirs < <(py_dirs tests mcfz)
        for dir in "${dirs[@]}"; do
            run_mypy "$dir"/*.py || OVERALL_OK=false
        done
    fi
}

# ==================================================================================================
# Code style
# ==================================================================================================
function code_style_check() {
    echo ""
    echo "===== Code Style Checking with flake8 ====="
    flake8_check || OVERALL_OK=false

    if [[ "$STRICT" = true ]]; then
        echo ""
        echo "===== STRICT CHECK: PyLint ====="
        pylint_check || OVERALL_OK=false
    fi

    echo ""
    echo "===== [DR] Code Style & Linting with clang-tidy ====="
    dr_clang_tidy || OVERALL_OK=false

    echo ""
    echo "===== Shell Script Linting with shellcheck ====="
    shell_lint || OVERALL_OK=false

    echo ""
    echo "===== Directive Disable Justification Check ====="
    justification_check || OVERALL_OK=false
}

function flake8_check() {
    python3 -m flake8 --max-line-length 100 --ignore E402,W503 . \
        --count --show-source --statistics
}

function pylint_check() {
    local files dir dirs root

    # rvzr and mcfz are proper packages (__init__.py throughout), so each is
    # linted in a single invocation with the main config; cross-file checks
    # (e.g. duplicate-code) then span the whole package.
    for root in rvzr mcfz; do
        # TEMPORARY: exclude rvzr/config.py and rvzr/fuzzer.py (the filter only
        # matches rvzr paths, so it is a no-op for mcfz).
        mapfile -t files < <(py_files "$root" | grep -Ev '^rvzr/(config|fuzzer)\.py$')
        [[ ${#files[@]} -gt 0 ]] || continue
        python3 -m pylint --rcfile=.pylintrc "${files[@]}" || OVERALL_OK=false
    done

    # tests is not a uniform package -- some subdirs lack __init__.py, so files
    # sharing a basename (e.g. arm64/model_common.py vs x86_tests/model_common.py)
    # would collide in a single run.
    mapfile -t dirs < <(py_dirs tests)
    for dir in "${dirs[@]}"; do
        python3 -m pylint --rcfile=tests/.pylintrc "$dir"/*.py || OVERALL_OK=false
    done
}

function dr_clang_tidy() {
    local dr_dir="rvzr/model_dynamorio"

    if [[ ! -d "$dr_dir/adapter/build" ]] && [[ ! -d "$dr_dir/backend/build" ]] \
                                                                                && [[ ! -d "$dr_dir/leak_detector/build" ]]; then
        echo "[DR] No build directory for DR backend found; skipping clang-tidy check"
        return
    fi

    # clang-tidy needs a libstdc++-*-dev package for the C++ standard headers.
    # Plain grep (no -q) reads all input, which is safe under `set -o pipefail`.
    if ! dpkg -l 2> /dev/null | grep 'libstdc++-.*-dev' > /dev/null; then
        echo "[DR] No libstdc++-*-dev package found; skipping clang-tidy check"
        return
    fi

    # Diff-based: only lint files with uncommitted changes.
    local changed
    changed="$(changed_files)"

    run_clang_tidy adapter "$dr_dir/adapter" c h "$changed"
    run_clang_tidy backend "$dr_dir/backend" cpp hpp "$changed" --use-color
    run_clang_tidy leak_detector "$dr_dir/leak_detector" cpp h "$changed" --use-color
}

# Extra shellcheck arguments. Empty means the default severity, which reports
# every level (error, warning, info, style).
SHELLCHECK_ARGS=()

# Lint the project's own shell scripts with shellcheck. Every script is checked
# so that all findings are reported in a single pass.
function shell_lint() {
    if ! command -v shellcheck &> /dev/null; then
        echo "[shellcheck] not installed; skipping shell script lint"
        return
    fi

    local all_output="" failed=false f output
    for f in tests/*.sh .github/scripts/*.sh; do
        [[ -f "$f" ]] || continue
        if ! output=$(shellcheck "${SHELLCHECK_ARGS[@]}" "$f" 2>&1); then
            all_output+="$output"$'\n'
            failed=true
        fi
    done
    if $failed; then
        echo "$all_output"
        return 1
    fi
}

# Ensure every disable directive carries a justification, keeping
# suppressions self-documenting. A justification is a `justification:` keyword on
# the same line as the directive, or on the line immediately above or below it.
function justification_check() {
    # 1. Shell:
    # Note: The directive keyword is held in a variable (and the prose is hyphenated) so
    # that this scanner does not flag its own source.
    local disable_kw="disable" marker
    marker="shellcheck $disable_kw"
    local failed=false f lines i n
    for f in tests/*.sh .github/scripts/*.sh; do
        [[ -f "$f" ]] || continue
        mapfile -t lines < "$f"
        n=${#lines[@]}
        for ((i = 0; i < n; i++)); do
            [[ "${lines[i]}" == *"$marker"* ]] || continue
            # Gather the directive line plus its neighbours (guarding the bounds,
            # since ${lines[-1]} would wrap to the last element).
            local context="${lines[i]}"
            ((i > 0)) && context+=$'\n'"${lines[i - 1]}"
            ((i + 1 < n)) && context+=$'\n'"${lines[i + 1]}"
            [[ "$context" == *justification:* ]] && continue
            echo "$f:$((i + 1)): shellcheck-disable directive lacks a 'justification:' comment"
            failed=true
        done
    done

    # 2. Pylint: scan the project's Python sources (the same roots pylint lints).
    # The directive keyword is assembled from $disable_kw so this scanner does
    # not flag its own source.
    marker="pylint: $disable_kw"
    local pyfiles
    mapfile -t pyfiles < <(py_files rvzr mcfz tests)
    for f in "${pyfiles[@]}"; do
        [[ -f "$f" ]] || continue
        mapfile -t lines < "$f"
        n=${#lines[@]}
        for ((i = 0; i < n; i++)); do
            [[ "${lines[i]}" == *"$marker"* ]] || continue
            local context="${lines[i]}"
            ((i > 0)) && context+=$'\n'"${lines[i - 1]}"
            ((i + 1 < n)) && context+=$'\n'"${lines[i + 1]}"
            [[ "$context" == *justification:* ]] && continue
            echo "$f:$((i + 1)): pylint-disable directive lacks a 'justification:' comment"
            failed=true
        done
    done

    if $failed; then
        return 1
    fi
}

# ==================================================================================================
# Main
# ==================================================================================================
function main() {
    parse_args "$@"
    cd "$REPO_ROOT" || exit 1

    if [[ "$RUN_TYPE_CHECK" = true ]]; then
        type_check
    fi
    if [[ "$RUN_CODE_STYLE" = true ]]; then
        code_style_check
    fi

    echo ""
    if [[ "$OVERALL_OK" = true ]]; then
        echo "===== Style check: PASS ====="
        exit 0
    else
        echo "===== Style check: FAIL ====="
        exit 1
    fi
}

main "$@"
