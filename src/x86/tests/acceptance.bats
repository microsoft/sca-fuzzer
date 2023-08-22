#!/usr/bin/env bats

PRESERVE_TMP=${PRESERVE_TMP:-0}

# ------------------------------------------------------------------------------
# Templates
# ------------------------------------------------------------------------------
BASE="
input_gen_seed: 1234567
program_generator_seed: 1234567
"

ARCH_BASE="
$BASE
fuzzer: architectural
enable_priming: false
memory_access_zeroed_bits: 0
inputs_per_class: 1

instruction_categories:
- BASE-BINARY
- BASE-BITBYTE
- BASE-CMOV
- BASE-COND_BR
- BASE-CONVERT
- BASE-DATAXFER
- BASE-FLAGOP
- BASE-LOGICAL
- BASE-MISC
- BASE-NOP
- BASE-POP
- BASE-PUSH
- BASE-SEMAPHORE
- BASE-SETCC
- BASE-STRINGOP
- BASE-WIDENOP
- SSE-SSE
- SSE-DATAXFER
- SSE-MISC
- SSE2-DATAXFER
- SSE2-MISC
- CLFLUSHOPT-CLFLUSHOPT
- CLFSH-MISC
"

CT_SEQ="
contract_observation_clause: ct
contract_execution_clause:
  - seq
"

CT_COND="
contract_observation_clause: ct
contract_execution_clause:
  - cond
"

CT_DEH="
contract_observation_clause: ct
contract_execution_clause:
  - delayed-exception-handling
"

LOGGING_OFF="
logging_modes:
  -
"

# ------------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------------
function setup() {
    PROJECT_ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/../../../" >/dev/null 2>&1 && pwd)"
    ASM_DIR="$PROJECT_ROOT/src/x86/tests/asm"
    cli_opt="python3 -OO $PROJECT_ROOT/revizor.py"

    ISA="$PROJECT_ROOT/src/x86/base.json"
    if [ ! -f "$ISA" ]; then
        echo "Could not find 'base.json' in $ISA."
        echo "Follow the instructions in README.md to download it, and copy into this directory."
        false
    fi

    # tmp directory for tests
    TEST_DIR=$(mktemp -d)

    # create common config files
    CT_SEQ_CONF=$(mktemp -p $TEST_DIR)
    echo "$BASE $CT_SEQ" >>$CT_SEQ_CONF

    CT_COND_CONF=$(mktemp -p $TEST_DIR)
    echo "$BASE $CT_COND" >>$CT_COND_CONF
}

function teardown() {
    if [ "$PRESERVE_TMP" -eq 0 ]; then
        rm -rf $TEST_DIR
    fi
}

function run_without_violation {
    local cmd=$1
    tmp_config=$(mktemp -p $TEST_DIR)
    cat <<EOF >>$tmp_config
logging_modes:
  -
EOF
    run bash -c "$cmd -c $tmp_config"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
    rm $tmp_config
}

function assert_violation() {
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
    [[ "$status" -eq 0 && "$output" != *"=== Violations detected ==="*  ]]
}

function intel_only() {
    if cat /proc/cpuinfo | grep "AMD"; then
        skip
    fi
}

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

@test "Architectural Test: Model and Executor are initialized with the same values" {
    tmp_config=$(mktemp -p $TEST_DIR)
    echo "$ARCH_BASE" >>$tmp_config
    assert_no_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/model_flags_match.asm -c $tmp_config -i 20"
}

@test "Architectural Test: Model and Executor have the same FLAGS value" {
    tmp_config=$(mktemp -p $TEST_DIR)
    echo "$ARCH_BASE" >>$tmp_config
    assert_no_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/model_flags_match.asm -c $tmp_config -i 20"
}

@test "Architectural Test: Model and Executor have the same XMM values" {
    tmp_config=$(mktemp -p $TEST_DIR)
    echo "$ARCH_BASE" >>$tmp_config
    assert_no_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/model_match_xmm.asm -c $tmp_config -i 20"
}

@test "Architectural Test: 100 Random Test Cases" {
    tmp_config=$(mktemp -p $TEST_DIR)
    cat <<EOF >>$tmp_config
$ARCH_BASE
program_size: 300
avg_mem_accesses: 150
max_bb_per_function: 3
min_bb_per_function: 3
EOF
    assert_no_violation "$cli_opt fuzz -s $ISA -c $tmp_config -n 100 -i 10"
}

@test "Test Basics: Sequence of direct jumps" {
    assert_no_violation "$cli_opt fuzz -s $ISA -c $CT_SEQ_CONF -t $ASM_DIR/direct_jumps.asm -i 100"
}

@test "Test Basics: Long in-reg test case" {
    assert_no_violation "$cli_opt fuzz -s $ISA -c $CT_SEQ_CONF -t $ASM_DIR/large_arithmetic.asm -i 100"
}

@test "Test Basics: Sequence of calls" {
    assert_no_violation "$cli_opt fuzz -s $ISA -c $CT_SEQ_CONF -t $ASM_DIR/calls.asm -i 100"
}

@test "Detection [spectre-type]: Spectre V1; load variant" {
    assert_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/spectre_v1.asm -i 20"
    assert_no_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/spectre_v1.asm -c $CT_COND_CONF -i 20"
}

@test "Detection [spectre-type]: Spectre V1; store variant" {
    intel_only
    assert_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/spectre_v1.1.asm -i 20"
    assert_no_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/spectre_v1.1.asm -c $CT_COND_CONF -i 20"
}

@test "Detection [spectre-type]: Spectre V1; nested variant" {
    assert_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/spectre_v1_n2.asm -i 20"
    assert_no_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/spectre_v1_n2.asm -c $CT_COND_CONF -i 20"
}

@test "Detection [spectre-type]: Spectre V2 (BTI)" {
    assert_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/spectre_v2.asm -i 20"
}

@test "Detection [spectre-type]: Spectre V4 (SSBP)" {
    tmp_config=$(mktemp -p $TEST_DIR)
    printf "$BASE \ninput_gen_seed: 400 \nx86_executor_enable_ssbp_patch: false " >$tmp_config
    assert_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/spectre_v4.asm -c $tmp_config -i 100"

    printf "$BASE \ncontract_execution_clause:\n  - bpas " >>$tmp_config
    assert_no_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/spectre_v4.asm -c $tmp_config  -i 100"

    # used default config to test SSBP patch (it is enabled by default)
    assert_no_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/spectre_v4.asm -i 100"
}

@test "Detection [spectre-type]: Spectre V5 (return misprediction)" {
    assert_violation "$cli_opt fuzz -s $ISA -t $ASM_DIR/spectre_ret.asm -i 10"
}

@test "Detection [meltdown-type]: MDS/LVI" {
    intel_only
    tmp_config=$(mktemp -p $TEST_DIR)
    printf "$CT_DEH $LOGGING_OFF \npermitted_faults:\n  - assist-accessed\n" >$tmp_config

    if cat /proc/cpuinfo | grep "mds"; then
        cmd="$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/mds.asm -i 100"
        assert_violation $cmd

        printf "contract_execution_clause:\n  - vspec-all-memory-assists\n" >>$tmp_config
        assert_no_violation $cmd
    else
        cmd="$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/lvi.asm -i 20"
        assert_violation $cmd

        printf "contract_execution_clause:\n  - nullinj-assist\n" >>$tmp_config
        assert_no_violation $cmd
    fi
}

@test "Detection [meltdown-type]: #DE-zero speculation" {
    tmp_config=$(mktemp -p $TEST_DIR)
    printf "$CT_DEH $LOGGING_OFF \npermitted_faults:\n  - DE-zero\n" >$tmp_config
    assert_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault-div-zero-speculation.asm -i 3"

    printf "contract_execution_clause:\n  - vspec-ops-div\n" >>$tmp_config
    assert_no_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault-div-zero-speculation.asm -i 3"
}

@test "Detection [meltdown-type]: #DE-overflow speculation" {
    tmp_config=$(mktemp -p $TEST_DIR)
    printf "$CT_DEH $LOGGING_OFF \npermitted_faults:\n  - DE-overflow\n" >$tmp_config
    assert_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault-div-overflow-speculation.asm -i 3"

    printf "contract_execution_clause:\n  - vspec-ops-div\n" >>$tmp_config
    assert_no_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault-div-overflow-speculation.asm -i 3"
}

@test "Detection [meltdown-type]: #PF-present speculation" {
    tmp_config=$(mktemp -p $TEST_DIR)
    printf "$CT_DEH $LOGGING_OFF \npermitted_faults:\n  - PF-present\n" >$tmp_config
    assert_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault_load.asm -i 5"

    printf "contract_execution_clause:\n  - nullinj-fault\n" >>$tmp_config
    assert_no_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault_load.asm -i 3"
}

@test "Detection [meltdown-type]: #PF-writable speculation" {
    tmp_config=$(mktemp -p $TEST_DIR)
    printf "$CT_DEH $LOGGING_OFF \npermitted_faults:\n  - PF-writable\n" >$tmp_config
    assert_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault_rmw.asm -i 5"

    printf "contract_execution_clause:\n  - nullinj-fault\n" >>$tmp_config
    assert_no_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault_rmw.asm -i 5"
}

@test "Detection [meltdown-type]: #PF-smap speculation" {
    tmp_config=$(mktemp -p $TEST_DIR)
    printf "$CT_DEH $LOGGING_OFF \npermitted_faults:\n  - PF-smap\n" >$tmp_config
    assert_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault_load.asm -i 5"

    printf "contract_execution_clause:\n  - nullinj-fault\n" >>$tmp_config
    assert_no_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault_rmw.asm -i 5"
}

@test "Detection [meltdown-type]: #BR speculation (MPX)" {
    if grep "BNDCU" $ISA > /dev/null ; then
        tmp_config=$(mktemp -p $TEST_DIR)
        printf "$CT_SEQ $LOGGING_OFF \npermitted_faults:\n  - BR\n" >$tmp_config
        assert_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault_BR.asm -i 2"

        printf "$CT_DEH" >>$tmp_config
        assert_no_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault_BR.asm -i 2"
    else
        skip
    fi
}

@test "Sequential handling: #DB-instruction" {
    tmp_config=$(mktemp -p $TEST_DIR)
    printf "$CT_SEQ $LOGGING_OFF \npermitted_faults:\n  - DB-instruction\n" >$tmp_config
    assert_no_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault_INT1.asm -i 100"
}

@test "Sequential handling: #BP" {
    tmp_config=$(mktemp -p $TEST_DIR)
    printf "$CT_SEQ $LOGGING_OFF \npermitted_faults:\n  - BP\n" >$tmp_config
    assert_no_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault_INT3.asm -i 100"
}

@test "Sequential handling: #UD" {
    tmp_config=$(mktemp -p $TEST_DIR)
    printf "$CT_SEQ $LOGGING_OFF \npermitted_faults:\n  - UD\n" >$tmp_config
    assert_no_violation "$cli_opt fuzz -s $ISA -c $tmp_config -t $ASM_DIR/fault_UD.asm -i 100"
}

@test "Feature: Storing and loading test cases" {
    tmp_config=$(mktemp -p $TEST_DIR)
    printf "$LOGGING_OFF" >$tmp_config
    assert_no_violation "$cli_opt generate -s $ISA -c $tmp_config -w $TEST_DIR -n 1 -i 2"
    assert_no_violation "$cli_opt reproduce -s $ISA -c $tmp_config -t $TEST_DIR/tc0/program.asm -i $TEST_DIR/tc0/input*.bin"
}

