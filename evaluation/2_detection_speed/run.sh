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
exp_dir="$WORK_DIR/fail-$timestamp"
log="$exp_dir"/experiment.log

mkdir -p "$exp_dir"
touch "$log"

cd "$REVIZOR_DIR" || exit

#for name in v1-ct-bpas v4-ct-seq v4-ct-cond ; do
for name in v4-ct-cond ; do
    echo "----------------------------------------------------"
    echo "$name" 2>&1 | tee -a "$log"
    config="$SCRIPT_DIR/$name.yaml"

    echo "./cli.py fuzz -s $instructions -n $NUM_TESTS -i 10000 -v --nonstop -w $exp_dir -c $config"
    ./cli.py fuzz -s $instructions -n $NUM_TESTS -i 10000 -v --nonstop -w $exp_dir -c $config 2>&1 | tee -a $exp_dir/experiment.log
done

#echo "Is patch disabled?"
#for name in v1-ct-seq; do
#    echo "----------------------------------------------------"
#    echo "$name" 2>&1 | tee -a "$log"
#    config="$SCRIPT_DIR/$name.yaml"
#
#    echo "./cli.py fuzz -s $instructions -n $NUM_TESTS -i 10000 -v --nonstop -w $exp_dir -c $config"
#    ./cli.py fuzz -s $instructions -n $NUM_TESTS -i 10000 -v --nonstop -w $exp_dir -c $config 2>&1 | tee -a $exp_dir/experiment.log
#done

cd - || exit
