#!/usr/bin/env bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

echo ""
echo "===== Types Checking with mypy ====="
echo ""
cd $SCRIPT_DIR/.. || exit
python3 -m mypy cli.py
cd - > /dev/null || exit

echo ""
echo "===== Unit Tests ====="
echo ""
cd $SCRIPT_DIR || exit
python3 -m unittest -v generators.py
cd - > /dev/null || exit


echo ""
echo "===== Acceptance Tests ====="
echo ""
cd $SCRIPT_DIR/.. || exit
./tests/acceptance.bats
cd - || exit
