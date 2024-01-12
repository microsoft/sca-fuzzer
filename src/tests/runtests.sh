#!/usr/bin/env bash

if [ "$1" == "" ] || [ $1 != "--ignore-errors" ]; then
    set -e
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

echo ""
echo "===== Type Checking with mypy ====="
cd $SCRIPT_DIR/../.. || exit
MYPYPATH=src/ python3 -m mypy src/*.py src/x86/*.py --exclude src/tests/unit_isa_loader.py \
    --exclude src/x86/tests/unit_model.py --exclude src/x86/tests/unit_executor.py \
    --exclude src/x86/tests/unit_generators.py
cd - >/dev/null || exit

echo ""
echo "===== Code Style Checking with flake8 ====="
cd $SCRIPT_DIR/.. || exit
python3 -m flake8 --max-line-length 100 --ignore E402,W503 .
cd - >/dev/null || exit

echo ""
echo "===== Core Unit Tests ====="
cd $SCRIPT_DIR/../.. || exit
python3 -m unittest discover src/tests -p "unit_*.py" -v
cd - >/dev/null || exit

echo ""
echo "===== x86 kernel module ====="
cd $SCRIPT_DIR/../x86 || exit
./tests/kernel_module.bats
cd - >/dev/null || exit

echo ""
echo "===== x86 unit tests ====="
cd $SCRIPT_DIR/../.. || exit
# Note: we intentionally do not use the 'discover' option because it causes cross-contamination
# of config options between unit tests
python3 -m unittest src.x86.tests.unit_executor -v
echo "-------------"
python3 -m unittest src.x86.tests.unit_generators -v
echo "-------------"
python3 -m unittest src.x86.tests.unit_isa_loader -v
echo "-------------"
python3 -m unittest src.x86.tests.unit_model -v
echo "-------------"
cd - >/dev/null || exit

echo ""
echo "===== x86 acceptance tests ====="
cd $SCRIPT_DIR/.. || exit
./x86/tests/acceptance.bats
cd - >/dev/null || exit
