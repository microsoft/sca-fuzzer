#!/usr/bin/env bash

function assert_violation() {
    local cmd="$@"
    log=$(mktemp)

    bash -c "$cmd" > $log
    status=$?
    output=$(cat $log)
    if [[ "$status" -eq 1 && "$output" = *"=== Violations detected ==="* ]]; then
        echo "Detection: OK"
    else
        echo "Detection: FAIL"
        echo "Command: $cmd"
        echo "Exit code: $status"
        echo "Output: '$output'"
        exit 1
    fi
}

function assert_no_violation() {
    local cmd="$@"

    log=$(mktemp)

    bash -c "$cmd" > $log
    status=$?
    output=$(cat $log)
    if [[ "$status" -eq 0 && "$output" != *"=== Violations detected ==="* ]]; then
        echo "Filtering: OK"
    else
        echo "Filtering: FAIL"
        echo "Command: $cmd"
        echo "Exit code: $status"
        echo "Output: '$output'"
        exit 1
    fi
}

SCRIPT_DIR=$(dirname $(realpath $0))

cmd="rvzr $cli fuzz -s $SCRIPT_DIR/../base.json --save-violations f -I $SCRIPT_DIR/x86_tests/configs -t $SCRIPT_DIR/x86_tests/asm/spectre_v1.asm -c $SCRIPT_DIR/x86_tests/configs/ct-seq.yaml -i 20"
assert_violation "$cmd"

cmd="rvzr $cli fuzz -s $SCRIPT_DIR/../base.json --save-violations f -I $SCRIPT_DIR/x86_tests/configs -t $SCRIPT_DIR/x86_tests/asm/spectre_v1.asm -c $SCRIPT_DIR/x86_tests/configs/ct-cond.yaml -i 20"
assert_no_violation "$cmd"
