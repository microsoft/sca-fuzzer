#!/usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo ""
echo "===== Type Checking with mypy ====="
cd $SCRIPT_DIR/.. || exit
python3 -m mypy cli.py
cd - > /dev/null || exit

echo ""
echo "===== Code Style Checking with flake8 ====="
cd $SCRIPT_DIR/.. || exit
python3 -m flake8 --max-line-length 100 --ignore E402,W503 .
cd - > /dev/null || exit

echo ""
echo "===== Core Unit Tests ====="
cd $SCRIPT_DIR/../.. || exit
python3 -m unittest discover src/tests -p "unit_*.py" -v
cd - > /dev/null || exit

echo ""
echo "===== x86 kernel module ====="
cd $SCRIPT_DIR/../x86 || exit
./tests/kernel_module.bats
cd - > /dev/null || exit

echo ""
echo "===== x86 unit tests ====="
cd $SCRIPT_DIR/../.. || exit
python3 -m unittest discover src/x86/tests -p "unit_*.py" -v
cd - > /dev/null || exit

echo ""
echo "===== x86 acceptance tests ====="
cd $SCRIPT_DIR/.. || exit
./x86/tests/acceptance/acceptance.bats
cd - > /dev/null || exit
