#!/usr/bin/env bash
set -e

SCRIPT=$(realpath $0)
SCRIPT_DIR=$(dirname $SCRIPT)
MAX_ROUNDS=10000

timestamp=$(date '+%y-%m-%d-%H-%M')
revizor_src='../../../'
instructions="$revizor_src/x86/base.json"

# RESULTS_DIR="results"
exp_dir="$RESULTS_DIR/$timestamp"
mkdir $exp_dir

log="$exp_dir/experiment.log"
touch $log
result="$exp_dir/aggregated.txt"
touch $result

# Defaults
MEM_IN_PAIRS="false"
AVOID_DATA_DEP="false"
INPUT_ENTROPY=4
INPUTS_PER_CLS=2
BB_PER_FUNCTION=2
TC_SIZE=24
NUM_MEM=12

# Experiment Configuration
REPS=9


function time_to_violation() {
    local conf=$1
    local name=$2

    ${revizor_src}/cli.py fuzz -s $instructions -c $conf -n $MAX_ROUNDS -i 50 -w $exp_dir > "$exp_dir/tmp.txt"
    cat "$exp_dir/tmp.txt" >> $log
    cat "$exp_dir/tmp.txt" | awk '/Test Cases:/{tc=$3} /Duration:/{dur=$2} /Finished/{printf "%s, %d, %d\n", name, tc, dur}' name=$name >> $result
#    cat tmp.txt | awk '/Test Cases:/{tc=$3} /Patterns:/{p=$2} /Fully covered:/{fc=$3} /Longest uncovered:/{lu=$3} /Duration:/{dur=$2} /Finished/{printf "%s, %d, %d, %d, %d, %d\n", name, tc, p, fc, lu, dur}' name=$name >> $result

}

function measure_detection_times() {
    printf "" > $result
    for name in v1 v4 mds ; do
        echo "  - Running $name" | tee -a "$log"
        template="$SCRIPT_DIR/$name.yaml"
        conf="$SCRIPT_DIR/conf.yaml"

        cp $template $conf
        echo "input_gen_entropy_bits: $INPUT_ENTROPY
min_bb_per_function: $BB_PER_FUNCTION
max_bb_per_function: $BB_PER_FUNCTION
program_size: $TC_SIZE
avg_mem_accesses: $NUM_MEM
avoid_data_dependencies: $AVOID_DATA_DEP
generate_memory_accesses_in_pairs: $MEM_IN_PAIRS
inputs_per_class: $INPUTS_PER_CLS" >> $conf

        for i in $(seq 1 $REPS); do
            time_to_violation $conf "$name,$i"
            tail -n1 $result
        done
    done
    echo ""
    echo "Summary"
    echo "Name, Mean, Standard Deviation"
    datamash -t, groupby 1 mean 3 sstdev 3 < $result
}

echo "================================================================"
echo "Baseline"
measure_detection_times

echo "================================================================"
echo "Memory in pairs"
MEM_IN_PAIRS="true"
measure_detection_times
MEM_IN_PAIRS="false"

echo "================================================================"
echo "Avoid data dependencies"
AVOID_DATA_DEP="true"
measure_detection_times
AVOID_DATA_DEP="false"

echo "================================================================"
echo "Input Entropy"
old_val=$INPUT_ENTROPY
for INPUT_ENTROPY in $(seq 2 2 8); do
    echo "- $INPUT_ENTROPY"
    measure_detection_times
done
INPUT_ENTROPY=$old_val

echo "================================================================"
echo "Inputs per Eq Class"
old_val=$INPUTS_PER_CLS
for INPUTS_PER_CLS in $(seq 4 2 8); do
    echo "- $INPUTS_PER_CLS"
    measure_detection_times
done
INPUTS_PER_CLS=$old_val

echo "================================================================"
echo "BB per function"
old_val=$BB_PER_FUNCTION
for BB_PER_FUNCTION in $(seq 2 1 5); do
    echo "- $BB_PER_FUNCTION"
    measure_detection_times
done
BB_PER_FUNCTION=$old_val

echo "================================================================"
echo "Test Case Size"
old_val=$TC_SIZE
for TC_SIZE in $(seq 16 8 48); do
    echo "- $TC_SIZE"
    measure_detection_times
done
TC_SIZE=$old_val

echo "================================================================"
echo "Number of mem. acceses per test case"
old_val=$NUM_MEM
for NUM_MEM in $(seq 4 4 20); do
    echo "- $NUM_MEM"
    measure_detection_times
done
NUM_MEM=$old_val
