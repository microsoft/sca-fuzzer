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
NUM_TESTS=10000

timestamp=$(date '+%y-%m-%d-%H-%M')
instructions='instruction_sets/x86/base.xml'
log="$WORK_DIR/$timestamp/experiment.log"

mkdir -p "$WORK_DIR/$timestamp"
touch $log

function time_to_violation() {
    pushd "$REVIZOR_DIR" > /dev/null

    local inst=$1
    local conf=$2
    local max_rounds=$3
    local inputs=$4
    local full_log=$5
    local result=$6
    local name=$7
    local wd=$8

    ./cli.py fuzz -s $inst -c $conf -n $max_rounds -i $inputs -v -w $wd  | tee tmp.txt
    cat tmp.txt >> $full_log
    cat tmp.txt | awk '/Test Cases:/{tc=$3} /Patterns:/{p=$2} /Fully covered:/{fc=$3} /Longest uncovered:/{lu=$3} /Duration:/{dur=$2} /Finished/{printf "%s, %d, %d, %d, %d, %d\n", name, tc, p, fc, lu, dur}' name=$name >> $result

    popd > /dev/null
}

#for name in v4-ct-seq v4-ct-cond v1-ct-seq v1-ct-bpas mds-ct-seq mds-ct-bpas mds-ct-cond ; do
for name in v1-ct-seq v1-ct-bpas mds-ct-seq mds-ct-bpas mds-ct-cond v4-ct-cond v4-ct-seq ; do
    # v1-ct-cond v4-ct-bpas v1-arch-seq
    echo "--------------------------------------------------------------------"
    echo "Running $name" 2>&1 | tee -a "$log"
    exp_dir="$WORK_DIR/$timestamp/$name"
    result="$WORK_DIR/$timestamp/result.txt"
    conf="$WORK_DIR/$timestamp/conf.yaml"
    cp "$SCRIPT_DIR/$name.yaml" $conf

    cp "$SCRIPT_DIR/$name.yaml" $conf
    echo "prng_entropy_bits: 2
feedback_driven_generator: true" >> $conf

    mkdir -p "$exp_dir"

    for i in $(seq 0 9); do
        time_to_violation $instructions $conf $NUM_TESTS 50 $log $result "$name,$i" $exp_dir
    done
done

# datamash -t, --headers  groupby 1  mean 7 < result.txt | awk 'BEGIN{FS=","} //{print $1, $2 / 60, $2 % 60}'
