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

parse_args $@

if [ "$IGNORE_ERRORS" != "true" ]; then
    set -e
fi

if [ "$STRICT" = true ]; then
    echo "Including optional tests"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
ALL_PY=$(find src/ -name "*.py" | grep -v "config" | grep -v "fuzzer")

echo ""
echo "===== MyPy ====="
cd $SCRIPT_DIR/.. || exit
MYPYPATH=src/ python3 -m mypy --strict $ALL_PY --no-warn-unused-ignores --untyped-calls-exclude=elftools
cd - >/dev/null || exit

if [ "$STRICT" = true ]; then
    echo ""
    cd $SCRIPT_DIR/.. || exit
    echo "===== STRICT CHECK: MyPy (Unit Tests) ====="
    MYPYPATH=src/ python3 -m mypy --strict tests/unit_*.py --no-warn-unused-ignores --untyped-calls-exclude=elftools
    MYPYPATH=src/ python3 -m mypy --strict tests/x86_tests/unit_*.py --no-warn-unused-ignores --untyped-calls-exclude=elftools
    cd - >/dev/null || exit

    echo ""
    cd $SCRIPT_DIR/.. || exit
    echo "===== STRICT CHECK: PyLint ====="
    python3 -m pylint --rcfile=.pylintrc $ALL_PY
    cd - >/dev/null || exit
fi
# exit

echo ""
echo "===== Code Style Checking with flake8 ====="
cd $SCRIPT_DIR/.. || exit
python3 -m flake8 --max-line-length 100 --ignore E402,W503 . --count --show-source --statistics
cd - >/dev/null || exit

echo ""
echo "===== Core Unit Tests ====="
cd $SCRIPT_DIR/.. || exit
python3 -m unittest discover tests -p "unit_*.py" -v
cd - >/dev/null || exit
# exit

if [ "$SKIP_KM_TESTS" != true ]; then
    echo ""
    echo "===== x86 kernel module ====="
    cd $SCRIPT_DIR || exit
    ./x86_tests/kernel_module.bats
    cd - >/dev/null || exit
fi

echo ""
echo "===== x86 unit tests ====="
cd $SCRIPT_DIR/.. || exit
# Note: we intentionally do not use the 'discover' option because it causes cross-contamination
# of config options between unit tests
python3 -m unittest tests.x86_tests.unit_generators -v
echo "-------------"
python3 -m unittest tests.x86_tests.unit_isa_loader -v
echo "-------------"
python3 -m unittest tests.x86_tests.unit_model_unicorn -v
echo "-------------"
python3 -m unittest tests.x86_tests.unit_taint_tracker -v
echo "-------------"
cd - >/dev/null || exit
# exit

if [ "$SKIP_KM_TESTS" != true ]; then
    echo ""
    echo "===== x86 acceptance tests ====="
    cd $SCRIPT_DIR || exit
    ./x86_tests//acceptance.bats
    cd - >/dev/null || exit
fi
