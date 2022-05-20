#!/usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo ""
echo "===== Type Checking with mypy ====="
echo ""
cd $SCRIPT_DIR/.. || exit
python3 -m mypy cli.py --ignore-missing-imports 
cd - > /dev/null || exit

echo ""
echo "===== Core Unit Tests ====="
cd $SCRIPT_DIR || exit
python3 -m unittest discover unittests -p "unit_*.py" -v
cd - > /dev/null || exit

echo ""
echo "===== x86 tests ====="
echo ""
cd $SCRIPT_DIR/../x86 || exit
./tests/kernel_module.bats
echo "x86 unittests"
python3 -m unittest discover tests -p "unit_*.py" -v
cd - || exit

echo ""
echo "===== Acceptance Tests ====="
echo ""
cd $SCRIPT_DIR/.. || exit
./tests/acceptance.bats
cd - || exit