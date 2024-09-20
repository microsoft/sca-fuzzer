#!/usr/bin/env bats
# set -o errexit -o pipefail -o nounset

PRESERVE_TMP=${PRESERVE_TMP:-0}
CPU_MODEL=$(cat /proc/cpuinfo | grep "model" | head -n 1 | cut -d: -f2 | tr -d ' ')

# ------------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------------
function setup() {
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../../" >/dev/null 2>&1 && pwd)"
    ASM_DIR="$PROJECT_ROOT/tests/x86_tests/asm"
    CONF_DIR="$PROJECT_ROOT/tests/x86_tests/configs"

    ISA="$PROJECT_ROOT/base.json"
    if [ ! -f "$ISA" ]; then
        echo "Could not find 'base.json' in $ISA"
        echo "Follow the instructions in README.md to download it, and copy into this directory."
        false
    fi

    cli="$PROJECT_ROOT/revizor.py"
    cli_opt="python3 -OO $PROJECT_ROOT/revizor.py"
    fuzz_opt="$cli fuzz -s $ISA --save-violations f -I $CONF_DIR"

    # tmp directory for tests
    TEST_DIR=$(mktemp -d)
}

function teardown() {
    if [ "$PRESERVE_TMP" -eq 0 ]; then
        rm -rf $TEST_DIR
    fi
}

function assert_violation() {
    # Check if the given test produces a contract violation
    local cmd="$@"

    run bash -c "$cmd"
    echo "Command: $cmd"
    echo "Exit code: $status"
    echo "Output: '$output'"
    [[ "$status" -eq 1 && "$output" = *"=== Violations detected ==="* ]]
}

function assert_no_violation() {
    local cmd="$@"

    run bash -c "$cmd"
    echo "Command: $cmd"
    echo "Exit code: $status"
    echo "Output: '$output'"
    [[ "$status" -eq 0 && "$output" != *"=== Violations detected ==="* ]]
}

function assert_violation_or_arch_fail() {
    # Check if the given test produces a contract violation OR an architectural failure
    local cmd="$@"

    run bash -c "$cmd"
    echo "Command: $cmd"
    echo "Exit code: $status"
    echo "Output: '$output'"
    if [[ "$output" == *" Architectural violation "* ]]; then
        return
    fi

    [[ "$status" -eq 1 && "$output" = *"=== Violations detected ==="* ]]
}

function intel_only() {
    if cat /proc/cpuinfo | grep "AMD"; then
        skip
    fi
}

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

@test "Architectural Test: Model and Executor are initialized with the same values (registers)" {
    assert_no_violation "$fuzz_opt -t $ASM_DIR/model_match.asm -c $CONF_DIR/arch.yaml -i 20"
}

@test "Architectural Test: Model and Executor are initialized with the same values (memory)" {
    assert_no_violation "$fuzz_opt -t $ASM_DIR/model_match_memory.asm -c $CONF_DIR/arch.yaml -i 20"
}

@test "Architectural Test: Model and Executor are initialized with the same values (flags)" {
    assert_no_violation "$fuzz_opt -t $ASM_DIR/model_flags_match.asm -c $CONF_DIR/arch.yaml -i 20"
}

@test "Architectural Test: Model and Executor are initialized with the same values (SIMD registers)" {
    assert_no_violation "$fuzz_opt -t $ASM_DIR/model_flags_match.asm -c $CONF_DIR/arch.yaml -i 20"
}

@test "Architectural Test: 100 Random Test Cases" {
    assert_no_violation "$fuzz_opt -c $CONF_DIR/arch.yaml -n 100 -i 10"
}

@test "ArchDiff Test: 10 Random Test Cases" {
    assert_no_violation "$fuzz_opt -c $CONF_DIR/archdiff.yaml -n 10 -i 10"
}

@test "Test Basics: Sequence of direct jumps" {
    assert_no_violation "$fuzz_opt -c $CONF_DIR/ct-seq.yaml -t $ASM_DIR/direct_jumps.asm -i 100"
}

@test "Test Basics: Long in-reg test case" {
    assert_no_violation "$fuzz_opt -c $CONF_DIR/ct-seq.yaml -t $ASM_DIR/large_arithmetic.asm -i 100"
}

@test "Test Basics: Sequence of calls" {
    assert_no_violation "$fuzz_opt -c $CONF_DIR/ct-seq.yaml -t $ASM_DIR/calls.asm -i 100"
}

@test "Detection [spectre-type]: Spectre V1; load variant" {
    assert_violation "$fuzz_opt -t $ASM_DIR/spectre_v1.asm -c $CONF_DIR/ct-seq.yaml  -i 20"
    assert_no_violation "$fuzz_opt -t $ASM_DIR/spectre_v1.asm -c $CONF_DIR/ct-cond.yaml -i 20"
}

@test "Detection [spectre-type]: Spectre V1; store variant" {
    intel_only
    assert_violation "$fuzz_opt -t $ASM_DIR/spectre_v1.1.asm -c $CONF_DIR/ct-seq.yaml -i 20"
    assert_no_violation "$fuzz_opt -t $ASM_DIR/spectre_v1.1.asm -c $CONF_DIR/ct-cond.yaml -i 20"
}

@test "Detection [spectre-type]: Spectre V1; nested variant" {
    assert_violation "$fuzz_opt -t $ASM_DIR/spectre_v1_n2.asm -c $CONF_DIR/ct-seq.yaml -i 20"
    assert_no_violation "$fuzz_opt -t $ASM_DIR/spectre_v1_n2.asm -c $CONF_DIR/ct-cond.yaml -i 20"
}

@test "Detection [spectre-type]: Spectre V2 (BTI)" {
    assert_violation "$fuzz_opt -t $ASM_DIR/spectre_v2.asm -c $CONF_DIR/ct-seq.yaml -i 20"
}

@test "Detection [spectre-type]: Spectre V4 (SSBP)" {
    assert_violation "$fuzz_opt -t $ASM_DIR/spectre_v4.asm -c $CONF_DIR/ssbp-detect.yaml -i 100"
    assert_no_violation "$fuzz_opt -t $ASM_DIR/spectre_v4.asm -c $CONF_DIR/ssbp-verif.yaml  -i 100"

    # used default config to test SSBP patch (it is enabled by default)
    assert_no_violation "$fuzz_opt -t $ASM_DIR/spectre_v4.asm -c $CONF_DIR/ct-seq.yaml -i 100"
}

@test "Detection [spectre-type]: Spectre V5 (return misprediction)" {
    assert_violation "$fuzz_opt -t $ASM_DIR/spectre_ret.asm -c $CONF_DIR/ct-seq.yaml -i 10"
}

@test "Detection [meltdown-type]: #DE-zero speculation" {
    assert_violation "$fuzz_opt -t $ASM_DIR/fault-div-zero-speculation.asm -c $CONF_DIR/div-detect.yaml -i 3"
    # assert_no_violation "$fuzz_opt -t $ASM_DIR/fault-div-zero-speculation.asm -c $CONF_DIR/div-verif.yaml -i 3"
}

@test "Detection [meltdown-type]: #DE-overflow speculation" {
    assert_violation "$fuzz_opt -t $ASM_DIR/fault-div-overflow-speculation.asm -c $CONF_DIR/div-detect.yaml -i 3"
    # assert_no_violation "$fuzz_opt -t $ASM_DIR/fault-div-overflow-speculation.asm -c $CONF_DIR/div-verif.yaml -i 3"
}

@test "Detection [meltdown-type]: #PF-present speculation" {
    intel_only
    if [ $CPU_MODEL -ge 140 ]; then
        skip
    fi
    assert_violation "$fuzz_opt -t $ASM_DIR/fault_load.asm -c $CONF_DIR/l1tf-p.yaml -i 5"
    assert_no_violation "$fuzz_opt -t $ASM_DIR/fault_load.asm -c $CONF_DIR/l1tf-p-verif.yaml -i 5"
}

@test "Detection [meltdown-type]: #PF-writable speculation" {
    intel_only
    if [ $CPU_MODEL -ge 140 ]; then
        skip
    fi
    assert_violation "$fuzz_opt -t $ASM_DIR/fault_rmw.asm -c $CONF_DIR/l1tf-p.yaml -i 5"
    assert_no_violation "$fuzz_opt -t $ASM_DIR/fault_rmw.asm -c $CONF_DIR/l1tf-p-verif.yaml -i 5"
}

@test "Detection [meltdown-type]: #PF-smap speculation" {
    intel_only
    if ! grep "smap" /proc/cpuinfo >/dev/null; then
        skip
    fi
    # Note: an arch. violation is expected here if SMAP is disabled in the kernel
    assert_violation_or_arch_fail "$fuzz_opt -t $ASM_DIR/fault_load.asm -c $CONF_DIR/meltdown.yaml -i 5"
    assert_no_violation "$fuzz_opt -t $ASM_DIR/fault_load.asm -c $CONF_DIR/meltdown-verif.yaml -i 5"
}

@test "Detection [meltdown-type]: #BR speculation (MPX)" {
    if ! grep "mpx" /proc/cpuinfo >/dev/null; then
        skip
    fi
    # Note: an arch. violation is expected here if MPX is disabled in the kernel
    assert_violation_or_arch_fail "$fuzz_opt -t $ASM_DIR/fault_BR.asm -c $CONF_DIR/mpx.yaml -i 2"
    assert_no_violation "$fuzz_opt -t $ASM_DIR/fault_BR.asm -c $CONF_DIR/mpx-verif.yaml -i 2"
}

@test "Sequential handling: #DB-instruction" {
    assert_no_violation "$fuzz_opt -t $ASM_DIR/fault_INT1.asm -c $CONF_DIR/exceptions.yaml -i 100"
}

@test "Sequential handling: #BP" {
    assert_no_violation "$fuzz_opt -t $ASM_DIR/fault_INT3.asm -c $CONF_DIR/exceptions.yaml -i 100"
}

@test "Sequential handling: #UD" {
    assert_no_violation "$fuzz_opt -t $ASM_DIR/fault_UD.asm -c $CONF_DIR/exceptions.yaml -i 100"
}

@test "Feature: Storing and loading test cases" {
    assert_no_violation "$cli_opt generate -s $ISA -c $CONF_DIR/ct-seq.yaml -w $TEST_DIR -n 1 -i 2"
    assert_no_violation "$cli_opt reproduce -s $ISA -c $CONF_DIR/ct-seq.yaml -t $TEST_DIR/tc0/program.asm -i $TEST_DIR/tc0/input*.bin"
}

@test "Architectural Test: Multi-actor test case" {
    assert_no_violation "$fuzz_opt -t $ASM_DIR/actor_switch.asm -c $CONF_DIR/arch-actors.yaml -i 20"
}

@test "Feature: VM test case" {
    if cat /proc/cpuinfo | grep -e "vmx" -e "svm" >/dev/null; then
        echo "1" >/sys/x86_executor/enable_hpa_gpa_collisions
        assert_no_violation "$fuzz_opt -t $ASM_DIR/vm_switch.asm -c $CONF_DIR/vm-switch.yaml -i 20"

        echo "Testing page table allocation..."
        run cat /sys/x86_executor/dbg_guest_page_tables
        if [ $status -ne 0 ]; then
            echo "Page table allocation test failed: $output"
        fi
        [[ $status -eq 0 ]]
    else
        skip
    fi
}

@test "Feature: Macro fault handler" {
    local cmd="$fuzz_opt -t $ASM_DIR/macro_fault_handler.asm -c $CONF_DIR/fault-handler.yaml -i 1"
    run bash -c "$cmd"
    echo "Command: $cmd"
    echo "Exit code: $status"
    echo "Output: '$output'"
    [[ "$status" -eq 0 && "$output" = *"^.......^...^..................................................^"* ]]
}
