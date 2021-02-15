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

timestamp=$(date '+%y-%m-%d-%H-%M')
instructions='instruction_sets/x86/base.xml'
exp_dir="$WORK_DIR/$timestamp"
log="$exp_dir"/experiment.log

mkdir -p "$exp_dir"
touch "$log"

cd "$REVIZOR_DIR" || exit

# For baseline measurement
name="ct-seq"
echo "----------------------------------------------------"
echo "$name" 2>&1 | tee -a "$log"
config="$SCRIPT_DIR/$name.yaml"

echo "./cli.py fuzz -s $instructions -n $NUM_TESTS -i 10000 -v --nonstop -w $exp_dir -c $config"
./cli.py fuzz -s $instructions -n $NUM_TESTS -i 10000 -v --nonstop -w $exp_dir -c $config 2>&1 | tee -a $exp_dir/experiment.log

#for name in ct-seq ct-bpas; do
#    echo "----------------------------------------------------"
#    echo "$name" 2>&1 | tee -a "$log"
#    config="$SCRIPT_DIR/$name.yaml"
#
#    echo "./cli.py fuzz -s $instructions -n $NUM_TESTS -i 10000 -v --nonstop-c $config"
#    ./cli.py fuzz -s $instructions -n $NUM_TESTS -i 10000 -v --nonstop -c $config 2>&1 | tee -a $exp_dir/experiment.log
#done

cd - || exit
