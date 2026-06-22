#!/usr/bin/env bash

function assert_violation() {
    local cmd="$*"
    log=$(mktemp)

    bash -c "$cmd" > "$log"
    status=$?
    output=$(cat "$log")
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
    local cmd="$*"

    log=$(mktemp)

    bash -c "$cmd" > "$log"
    status=$?
    output=$(cat "$log")
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

SCRIPT_DIR=$(dirname "$(realpath "$0")")

# Detect the architecture of the CPU under test and select the matching
# asm tests and configs.
if grep -q "vendor_id" /proc/cpuinfo; then
    ASM_DIR="$SCRIPT_DIR/x86_tests/asm"
    CONF_DIR="$SCRIPT_DIR/x86_tests/configs"
elif grep -q "CPU implementer" /proc/cpuinfo; then
    ASM_DIR="$SCRIPT_DIR/arm64/asm"
    CONF_DIR="$SCRIPT_DIR/arm64/configs"
else
    echo "Could not determine CPU architecture from /proc/cpuinfo"
    exit 1
fi

cmd="./revizor.py fuzz -s $SCRIPT_DIR/../base.json --save-violations f -I $CONF_DIR -t $ASM_DIR/spectre_v1.asm -c $CONF_DIR/ct-seq.yaml -i 20"
assert_violation "$cmd"

cmd="./revizor.py fuzz -s $SCRIPT_DIR/../base.json --save-violations f -I $CONF_DIR -t $ASM_DIR/spectre_v1.asm -c $CONF_DIR/ct-cond.yaml -i 20"
assert_no_violation "$cmd"
