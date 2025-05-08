#!/usr/bin/env bash

function parse_args() {
    POSITIONAL_ARGS=()

    while [[ $# -gt 0 ]]; do
        case $1 in
        --strict)
            STRICT=true
            shift
            ;;
        --ignore-errors)
            IGNORE_ERRORS=true
            shift
            ;;
        --skip-km-tests)
            SKIP_KM_TESTS=true
            shift
            ;;
        -* | --*)
            echo "Unknown option $1"
            exit 1
            ;;
        esac
    done
}

function type_check() {
    local enable_strict=$1

    echo ""
    echo "===== MyPy ====="
    cd $SCRIPT_DIR/.. || exit
    MYPYPATH=rvzr/ python3 -m mypy --strict $ALL_PY --no-warn-unused-ignores --untyped-calls-exclude=elftools
    cd - >/dev/null || exit

    if [ "$enable_strict" = true ]; then
        echo ""
        cd $SCRIPT_DIR/.. || exit
        echo "===== STRICT CHECK: MyPy (Unit Tests) ====="
        MYPYPATH=rvzr/ python3 -m mypy --strict tests/unit_*.py --no-warn-unused-ignores --untyped-calls-exclude=elftools
        MYPYPATH=rvzr/ python3 -m mypy --strict tests/x86_tests/unit_*.py --no-warn-unused-ignores --untyped-calls-exclude=elftools
        MYPYPATH=rvzr/ python3 -m mypy --strict tests/arm64/unit_*.py --no-warn-unused-ignores --untyped-calls-exclude=elftools
        cd - >/dev/null || exit
    fi

}

function code_style_check() {
    local enable_strict=$1

    echo ""
    echo "===== Code Style Checking with flake8 ====="
    cd $SCRIPT_DIR/.. || exit
    python3 -m flake8 --max-line-length 100 --ignore E402,W503 . --count --show-source --statistics
    cd - >/dev/null || exit

    if [ "$enable_strict" = true ]; then
        echo ""
        cd $SCRIPT_DIR/.. || exit
        echo "===== STRICT CHECK: PyLint ====="
        python3 -m pylint --rcfile=.pylintrc $ALL_PY
        cd - >/dev/null || exit
    fi

    echo ""
    echo "===== [DR] Code Style & Linting with clang-tidy ====="
    cd $SCRIPT_DIR/../rvzr/model_dynamorio || exit
    if [ -d "adapter/build" ]; then
        find . -name "*.c" -or -name "*.h" | grep -v "CMakeFiles"  | xargs clang-tidy --quiet --p adapter/build/ --config-file=adapter/.clang-tidy
    else
        echo "[DR] No build directory for DR adapter found; skipping clang-tidy check"
    fi
    if [ -d "backend/build" ]; then
        find . -name "*.cpp" -or -name "*.hpp" | grep -v "CMakeFiles" | xargs clang-tidy --quiet --config-file=backend/.clang-tidy -p backend/build
    else
        echo "[DR] No build directory for DR backend found; skipping clang-tidy check"
    fi
    cd - >/dev/null || exit
}

function core_unit_tests() {
    echo ""
    echo "===== Core Unit Tests ====="
    cd $SCRIPT_DIR/.. || exit
    python3 -m unittest tests.unit_analyser -v
    echo "-------------"
    python3 -m unittest tests.unit_docs -v
    echo "-------------"
    python3 -m unittest tests.unit_isa_loader
    echo "-------------"
    python3 -m unittest tests.unit_stats
    echo "-------------"
    python3 -m unittest tests.unit_tc_components
    cd - >/dev/null || exit
}

function package_install_test() {
    echo ""
    echo "===== Package installation ====="

    # skip if no internet connection
    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        echo "No internet connection, skipping package installation test"
        return
    fi

    cd $SCRIPT_DIR/.. || exit
    python3 -m pip uninstall revizor-fuzzer -y
    python3 -m build
    python3 -m pip install dist/*.whl
    cd - >/dev/null || exit
    cd $SCRIPT_DIR/ || exit
    set +e
    out=$(python3 -c "import rvzr; rvzr.cli.main()" 2>&1)
    set -e
    if [[ "$out" != *"usage: "* ]]; then
        echo "> ERROR: Package installation test failed"
        exit 1
    else
        echo "> Package installation test passed"
    fi
    cd - >/dev/null || exit
}

function km_tests() {
    if [ "$SKIP_KM_TESTS" != true ]; then
        echo ""
        echo "===== Executor kernel module ====="
        cd $SCRIPT_DIR || exit
        ./kernel_module.bats
        cd - >/dev/null || exit
    fi
}

function arch_unit_tests() {
    # Note: we intentionally do not use the 'discover' option because it causes cross-contamination
    # of config options between unit tests

    if [ "$ARCH" == "x86_64" ]; then
        echo ""
        echo "===== x86 unit tests ====="
        cd $SCRIPT_DIR/.. || exit
        python3 -m unittest tests.x86_tests.unit_isa_loader -v
        echo "-------------"
        python3 -m unittest tests.x86_tests.unit_generators -v
        echo "-------------"
        python3 -m unittest tests.x86_tests.unit_model_unicorn -v
        echo "-------------"
        python3 -m unittest tests.x86_tests.unit_taint_tracker -v
        echo "-------------"
        python3 -m unittest tests.x86_tests.unit_model_dr -v
        echo "-------------"
        cd - >/dev/null || exit
        # exit
    else
        echo ""
        echo "===== arm64 unit tests ====="
        cd $SCRIPT_DIR/.. || exit
        cd $SCRIPT_DIR/.. || exit
        python3 -m unittest tests.arm64.unit_isa_loader -v
        echo "-------------"
        python3 -m unittest tests.arm64.unit_generators -v
        echo "-------------"
        # python3 -m unittest tests.arm64.unit_model_unicorn -v
        # echo "-------------"
        # python3 -m unittest tests.arm64.unit_taint_tracker -v
        # echo "-------------"
        # python3 -m unittest tests.arm64.unit_model_dr -v
        # echo "-------------"
        cd - >/dev/null || exit
        # exit
    fi
}

function acceptance_tests() {
    if [ "$SKIP_KM_TESTS" != true ]; then
        echo ""
        echo "===== Acceptance tests ====="
        cd $SCRIPT_DIR || exit
        ./acceptance.bats
        cd - >/dev/null || exit
    fi
}

function main() {
    parse_args $@

    if [ "$IGNORE_ERRORS" != "true" ]; then
        set -e
    fi

    if [ "$STRICT" = true ]; then
        echo "Including optional tests"
    fi

    VENDOR="$(lscpu | grep Vendor | awk '{print $3}')"
    ARCH="$(lscpu | grep Architecture | awk '{print $2}')"

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
    ALL_PY=$(find rvzr/ -name "*.py" | grep -v "config" | grep -v "fuzzer")

    type_check $STRICT
    code_style_check $STRICT
    package_install_test
    core_unit_tests
    km_tests
    arch_unit_tests
    acceptance_tests
}

main $@
