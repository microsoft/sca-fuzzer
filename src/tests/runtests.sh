#!/usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo ""
echo "===== Type Checking with mypy ====="
echo ""
cd $SCRIPT_DIR/.. || exit
python3 -m mypy cli.py --ignore-missing-imports 
cd - > /dev/null || exit

echo ""
echo "===== Unit Tests ====="
echo ""
cd $SCRIPT_DIR || exit
python3 -m unittest discover unittests -p "unit_*.py"
cd - > /dev/null || exit


echo ""
echo "===== Acceptance Tests ====="
echo ""
cd $SCRIPT_DIR/.. || exit
./tests/acceptance.bats
cd - || exit
