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

timestamp=$(date '+%y-%m-%d-%H-%M')
instructions='instruction_sets/x86/base.xml'
exp_dir="$WORK_DIR/$timestamp"
log="$timestamp-experiment.log"

mkdir -p "$exp_dir"
touch "$log"

cd "$REVIZOR_DIR" || exit

# For baseline measurement
echo "----------------------------------------------------"
echo "$name" 2>&1 | tee -a "$log"
name="spectre_v1.asm"
tc="$SCRIPT_DIR/$name"

for name in "spectre_v1.1.asm" "spectre_v4.asm"; do
    for c in "1.yaml" "2.yaml" "3.yaml" "4.yaml" "5.yaml" "6.yaml" "7.yaml" "8.yaml" "9.yaml" "10.yaml" ; do
        config="$SCRIPT_DIR/$c"
        echo "$name -> $config"
        for i in 1 2 4 8 16 32 64 128 256 512 1024 2048 4096; do
            ./cli.py fuzz -s $instructions -t $tc -i $i -c $config > tmp.log
            if grep "Violation" tmp.log; then
                echo $i
                break
            fi
        done
    done
done

cd - || exit
