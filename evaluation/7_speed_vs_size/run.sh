#!/usr/bin/env bash
set -e

# Make sure the required env variables are set
if [ -z "${REVIZOR_DIR}" ]; then
    echo "Env. variable REVIZOR_DIR must be set!"
    exit 1
fi
if [ -z "${WORK_DIR}" ]; then
    echo "Env. variable WORK_DIR must be set!"
    exit 1
fi

# Create the experiment directory and log files
SCRIPT=$(realpath $0)
SCRIPT_DIR=$(dirname $SCRIPT)

timestamp=$(date '+%y-%m-%d-%H-%M')
instructions='instruction_sets/x86/base.xml'
log="$WORK_DIR/$timestamp/experiment.log"
result="$WORK_DIR/$timestamp/result.txt"

mkdir -p "$WORK_DIR/$timestamp"
touch $log
touch $result

# Experiment configuration parameters
MAX_ROUNDS=10000
SAMPLE_SIZE=30

DEFAULT_SIZE=16
DEFAULT_MEM_ACCESSES=8
DEFAULT_BB=3
DEFAULT_INPUTS=100
DEFAULT_ENTROPY=3

# A function that runs fuzzing with a given configuration until a violation
# and records the elapsed time
function time_to_violation() {
    pushd "$REVIZOR_DIR" > /dev/null

    local inst=$1
    local conf=$2
    local max_rounds=$3
    local inputs=$4
    local full_log=$5
    local name=$6
    local wd=$7

    ./cli.py fuzz -s $inst -c $conf -n $max_rounds -i $inputs -v -w $wd > tmp.txt
#    ./cli.py fuzz -s $inst -c $conf -n $max_rounds -i $inputs -v -w $wd | tee tmp.txt
    cat tmp.txt >> $full_log
    $SCRIPT_DIR/parse.awk name=$name tmp.txt >> $result

    popd > /dev/null
}


for name in v1-ct-seq mds-ct-seq v4-ct-seq ; do
# mds-ct-seq v4-ct-seq
#for name in v1-ct-seq v1-ct-bpas mds-ct-seq mds-ct-bpas mds-ct-cond v4-ct-seq v4-ct-cond ; do
#for name in v4-ct-cond v4-ct-seq mds-ct-seq mds-ct-bpas mds-ct-cond v1-ct-seq v1-ct-bpas  ; do
    # v1-ct-cond v4-ct-bpas v1-arch-seq
    conf="$WORK_DIR/$timestamp/conf.yaml"
    exp_dir="$WORK_DIR/$timestamp/$name"
    mkdir -p "$exp_dir"

    for entropy in 2 4 6 8 10; do
        size=$DEFAULT_SIZE
        mem_accesses=$DEFAULT_MEM_ACCESSES
        blocks=$DEFAULT_BB
        inputs=$DEFAULT_INPUTS

        # parametrize the configuration
        cp "$SCRIPT_DIR/$name.yaml" $conf
        echo "no_priming: true
feedback_driven_generator: false
adaptive_input_number: false
test_case_size: $size
avg_mem_accesses: $mem_accesses
min_bb_per_function: $blocks
max_bb_per_function: $blocks
prng_entropy_bits: $entropy" >> $conf

        echo "Running $name,$size,$mem_accesses,$blocks,$entropy" 2>&1 | tee -a "$log"
        for i in $(seq 1 $SAMPLE_SIZE); do
            printf "%s " $i
            time_to_violation $instructions $conf $MAX_ROUNDS $inputs $log "$name,$size,$mem_accesses,$blocks,$entropy" $exp_dir
        done
        printf "\n" ; ./process_results.sh $result $SAMPLE_SIZE
        echo ""
    done

    ./process_results.sh $result $SAMPLE_SIZE
done
