#!/usr/bin/env bats
INSTRUCTION_SET='x86/isa_spec/base.json'

EXTENDED_TESTS=0
cli_opt="python3 -OO ./cli.py"

@test "Model and Executor are initialized with the same values" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/model_match.asm -c tests/model_match.yaml -i 100"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Model and Executor are initialized with the same FLAGS value" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/model_flags_match.asm -c tests/model_match.yaml -i 100"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

function run_without_violation {
    local cmd=$1
    tmp_config=$(mktemp)
cat << EOF >> $tmp_config
logging_modes:
  - 
EOF
    run bash -c "$cmd -c $tmp_config"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
    rm $tmp_config
}

@test "Fuzzing: A sequence of NOPs" {
    run_without_violation "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/nops.asm -i 100"
}

@test "Fuzzing: A sequence of direct jumps" {
    run_without_violation "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/direct_jumps.asm -i 100"
}

@test "Fuzzing: A long in-reg test case" {
    run_without_violation "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/large_arithmetic.asm -i 10"
}

@test "Fuzzing: A sequence of calls" {
    run_without_violation "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/calls.asm -i 100"
}

@test "Detection: Spectre V1 - BCB load - P" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/spectre_v1.asm -i 20"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V1 - BCB load - N" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/spectre_v1.asm -c tests/ct-cond.yaml -i 20"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V1.1 - BCB store" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/spectre_v1.1.asm -i 100"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V2 - BTI - P" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/spectre_v2.asm -i 20"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V4 - SSBP - P" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/spectre_v4.asm -c tests/ct-seq-ssbp-patch-off.yaml -i 200"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V4 - SSBP - N (patch off)" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/spectre_v4.asm -c tests/ct-bpas-ssbp-patch-off.yaml -i 200"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V4 - SSBP - N (patch on)" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/spectre_v4.asm -i 200"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V5-ret" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/spectre_ret.asm -i 10"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Nested misprediction" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/spectre_v4_n2.asm -i 200 -c tests/ct-bpas-n1-ssbp-patch-off.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]

    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/spectre_v4_n2.asm -i 200 -c tests/ct-bpas-ssbp-patch-off.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: MDS-SB" {
    if cat /proc/cpuinfo | grep "mds" ; then
        run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/mds.asm -i 100 -c tests/mds.yaml"
        echo "$output"
        [ "$status" -eq 0 ]
        [[ "$output" = *"=== Violations detected ==="* ]]
    else
        run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t tests/lvi.asm -i 100 -c tests/mds.yaml"
        echo "$output"
        [ "$status" -eq 0 ]
        [[ "$output" = *"=== Violations detected ==="* ]]
    fi
}

@test "False Positive: Input-independent branch misprediction" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v1_independent.asm -i 100"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Analyser: Priming" {
    skip
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/priming.asm -i 100 -c tests/priming.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Priming"* ]]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Model: ARCH-SEQ" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v1_arch.asm -i 20 -c tests/arch-seq.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Model: Rollback on LFENCE and spec. window" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/rollback_fence_and_expire.asm -i 10 -c tests/rollback_fence_and_expire.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"[s]"* ]]
}

# ==================================================================================================
# Extended tests - take long time, but test deeper
# ==================================================================================================
@test "Extended: False positives from generated samples" {
    if [ $EXTENDED_TESTS -eq 0 ]; then
        skip
    fi

    for test_case in tests/generated-fp/* ; do
        echo "Testing $test_case"
        run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t $test_case -i 10000 -c tests/ct-cond-bpas.yaml"
        echo "$output"
        [ "$status" -eq 0 ]
        [[ "$output" != *"=== Violations detected ==="* ]]
    done
}

@test "Priming: False Positive due to small min_primer_size" {
    if [ $EXTENDED_TESTS -eq 0 ]; then
        skip
    fi

    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/generated/priming-19-03-21.asm -i 500 -c tests/generated/priming-19-03-21.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}