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

mkdir -p "$WORK_DIR/$timestamp"

for name in v1-arch-seq v1-ctr-seq v1-ct-seq   ; do
    echo "--------------------------------------------------------------------"
    echo "Running $name"
    exp_dir="$WORK_DIR/$timestamp/$name"
    conf="$WORK_DIR/$timestamp/$name.yaml"
    mkdir -p "$exp_dir"
    cp "$SCRIPT_DIR/$name.yaml" $conf

    pushd "$REVIZOR_DIR" > /dev/null
    ./cli.py fuzz -s $instructions -c $conf -n $NUM_TESTS -i 500 -v -w $exp_dir | tee $exp_dir/log.txt
    popd > /dev/null
done

# datamash -t, --headers  groupby 1  mean 7 < result.txt | awk 'BEGIN{FS=","} //{print $1, $2 / 60, $2 % 60}'
