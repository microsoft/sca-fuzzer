#!/usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

TARGET="${1:-"x86-64"}"

echo ""
echo "===== Type Checking with mypy ====="
cd $SCRIPT_DIR/.. || exit
python3 -m mypy cli.py --ignore-missing-imports 
cd - > /dev/null || exit

echo ""
echo "===== Core Unit Tests ====="
cd $SCRIPT_DIR || exit
python3 -m unittest discover . -p "unit_*.py" -v
cd - > /dev/null || exit

if [[ "$TARGET" == "x86-64" ]] ; then
    echo ""
    echo "===== x86 kernel module ====="
    cd $SCRIPT_DIR/../x86 || exit
    ./tests/kernel_module.bats
    cd - > /dev/null || exit
    echo ""
    echo "===== x86 unit tests ====="
    cd $SCRIPT_DIR/../x86 || exit
    python3 -m unittest discover tests -p "unit_*.py" -v
    cd - > /dev/null || exit

    echo ""
    echo "===== x86 acceptance tests ====="
    cd $SCRIPT_DIR/.. || exit
    ./x86/tests/acceptance/acceptance.bats
    cd - > /dev/null || exit

    exit 0
fi

if [[ "$TARGET" == "arm64" ]] ; then
    echo ""
    echo "===== ARM64 unit tests ====="
    cd $SCRIPT_DIR/../arm64 || exit
    python3 -m unittest discover tests -p "unit_*.py" -v
    cd - || exit

    echo ""
    echo "===== ARM64 acceptance tests ====="
    cd $SCRIPT_DIR/.. || exit
    ./arm64/tests/acceptance.bats
    cd - > /dev/null || exit
fi
