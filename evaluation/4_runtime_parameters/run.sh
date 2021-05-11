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
TIMEOUT=$(( 24 * 3600 ))

timestamp=$(date '+%y-%m-%d-%H-%M')
instructions='instruction_sets/x86/base.xml'

cd "$REVIZOR_DIR" || exit

for name in bm-cond-bpas bm-bpas bm-seq bc-seq; do
    echo "--------------------------------------------------------------------"
    echo "Running $name"
    exp_dir="$WORK_DIR/$timestamp/$name"
    log="$exp_dir"/experiment.log
    config="$SCRIPT_DIR/$name.yaml"

    mkdir -p "$exp_dir"
    touch "$exp_dir"/experiment.log

    ./cli.py fuzz -s $instructions -n 100000 -i 100 -v --nonstop --timeout $TIMEOUT -w $exp_dir -c $config 2>&1 | tee -a $log
    awk '/Test Cases:/{tc=$3} /P:/{i+=$12} /Effective Cls:/{eq=$3} /Patterns:/{p=$2} /Fully covered:/{fc=$3} /Finished/{printf "%d, %d, %d, %d, %d\n", tc, i / tc, eq , p, fc}' $log
done

cd - || exit
