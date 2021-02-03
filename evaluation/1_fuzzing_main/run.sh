#!/usr/bin/env bash

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
TIMEOUT=3600

cd "$REVIZOR_DIR" || exit

timestamp=$(date '+%y-%m-%d-%H-%M')

for name in bcm-cond-bpas bm-cond-bpas bm-bpas bc-seq lfence-bc-seq; do
    echo "--------------------------------------------------------------------"
    echo "Running $name"
    exp_dir="$WORK_DIR/$timestamp/$name"
    mkdir -p "$exp_dir"
    touch "$exp_dir"/experiment.log

    echo "./cli.py fuzz -s instruction_sets/x86/base.xml -n 100000 -i 10000 -v --nonstop --timeout $TIMEOUT -w $exp_dir -c $SCRIPT_DIR/${name}.yaml 2>&1 | tee -a $exp_dir/experiment.log"
    ./cli.py fuzz -s instruction_sets/x86/base.xml -n 100000 -i 10000 -v --nonstop \
    --timeout $TIMEOUT -w $exp_dir \
    -c $SCRIPT_DIR/${name}.yaml 2>&1 | tee -a $exp_dir/experiment.log
done

cd - || exit
