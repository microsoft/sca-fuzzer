#!/usr/bin/env bash
set -e

if [ -z "${REVIZOR_DIR}" ]; then
    echo "Env. variable REVIZOR_DIR must be set!"
    exit 1
fi
if [ -z "${WORK_DIR}" ]; then
    echo "Env. variable WORK_DIR must be set!"
    exit 1
fi
SCRIPT=$(realpath $0)
SCRIPT_DIR=$(dirname $SCRIPT)
NUM_TESTS=1000

cd "$REVIZOR_DIR" || exit

timestamp=$(date '+%y-%m-%d-%H-%M')

instructions='instruction_sets/x86/base.xml'

exp_dir="$WORK_DIR/fail-$timestamp"
mkdir -p "$exp_dir"
touch "$exp_dir"/experiment.log
config="$SCRIPT_DIR/direct.yaml"

echo "./cli.py fuzz -s $instructions -n $NUM_TESTS -i 10000 -v --nonstop -w $exp_dir -c $config"
#

for config in "$SCRIPT_DIR/l1d.yaml" "$SCRIPT_DIR/mem.yaml" "$SCRIPT_DIR/ct.yaml"; do
    echo "----------------------------------------------------"
    echo "$config" | tee -a $exp_dir/experiment.log
    echo "" > $exp_dir/tmp.log
    echo " > $test_case" | tee -a $exp_dir/tmp.log
    echo "./cli.py fuzz -s $instructions -t $test_case -i 10000 -v -c $config"
    ./cli.py fuzz -s $instructions -t "$test_case" -i 10000 -v -c $config 2>&1 | tee -a $exp_dir/tmp.log
done

cd - || exit
