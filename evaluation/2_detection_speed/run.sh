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
log="$WORK_DIR/$timestamp/experiment.log"

mkdir -p "$WORK_DIR/$timestamp"
touch $log

cd "$REVIZOR_DIR" || exit

for name in v1-ct-seq v1-ct-bpas v4-ct-seq v4-ct-cond mds-ct-seq mds-ct-bpas mds-ct-cond ; do
    echo "--------------------------------------------------------------------"
    echo "Running $name" 2>&1 | tee -a "$log"
    exp_dir="$WORK_DIR/$timestamp/$name"
    config="$SCRIPT_DIR/$name.yaml"

    mkdir -p "$exp_dir"

    echo "./cli.py fuzz -s $instructions -n $NUM_TESTS -i 10000 -v --nonstop -w $exp_dir -c $config"
    ./cli.py fuzz -s $instructions -n $NUM_TESTS -i 10000 -v --nonstop -w $exp_dir -c $config 2>&1 | tee -a $log
#    ./cli.py fuzz -s $instructions -n $NUM_TESTS -i 10000 -v -w $exp_dir -c $config 2>&1 | tee -a $log
done

cd - || exit
