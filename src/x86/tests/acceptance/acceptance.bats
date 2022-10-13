#!/usr/bin/env bats
INSTRUCTION_SET='x86/isa_spec/base.json'

EXTENDED_TESTS=0
cli_opt="python3 -OO ./cli.py"


@test "Model and Executor are initialized with the same values" {
    tmpfile=$(mktemp /tmp/revizor-test.XXXXXX.o)
    ./cli.py fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/model_match.asm -c x86/tests/acceptance/model_match.yaml -i 20 > $tmpfile
    run bash -c "cat $tmpfile | awk 'BEGIN{new=0} /    /{new=1} /\^/{if (new==1) {new = 0; prev=\$2} else {if (prev != \$2) {print \"mismatch\"; exit 1; }}} END{print \"finished\"}'"

    echo "Output: $output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"mismatch"* ]]
    [[ "$output" == *"finished" ]]
    rm $tmpfile
}

@test "Model and Executor are initialized with the same FLAGS value" {
    tmpfile=$(mktemp /tmp/revizor-test.XXXXXX.o)
    ./cli.py fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/model_flags_match.asm -c x86/tests/acceptance/model_match.yaml -i 20 > $tmpfile
    run bash -c "cat $tmpfile | awk 'BEGIN{new=0} /    /{new=1} /\^/{if (new==1) {new = 0; prev=\$2} else {if (prev != \$2) {print \"mismatch\"; exit 1; }}} END{print \"finished\"}'"

    echo "Output: $output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"mismatch"* ]]
    [[ "$output" == *"finished" ]]
    rm $tmpfile
}

@test "Architectural Fuzzing" {
    local cmd=$1
    tmp_config=$(mktemp)
cat << EOF >> $tmp_config
fuzzer: architectural
contract_observation_clause: ct
contract_execution_clause:
  - seq
enable_priming: false
input_gen_entropy_bits: 20
memory_access_zeroed_bits: 0
inputs_per_class: 1
program_size: 300
avg_mem_accesses: 150
max_bb_per_function: 3
min_bb_per_function: 3
logging_modes:
  -
EOF
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -c $tmp_config -n 10 -i 100"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
    rm $tmp_config
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
    [[ "$output" != *"=== Violations detected ==="* ]]
    rm $tmp_config
}

@test "Fuzzing: A sequence of direct jumps" {
    run_without_violation "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/direct_jumps.asm -i 100"
}

@test "Fuzzing: A long in-reg test case" {
    run_without_violation "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/large_arithmetic.asm -i 10"
}

@test "Fuzzing: A sequence of calls" {
    run_without_violation "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/calls.asm -i 100"
}

@test "Detection: Spectre V1 - BCB load - P" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/spectre_v1.asm -i 20"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V1 - BCB load - N" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/spectre_v1.asm -c x86/tests/acceptance/ct-cond.yaml -i 20"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V1.1 - BCB store" {
    if cat /proc/cpuinfo | grep "AMD" ; then
        skip
    fi

    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/spectre_v1.1.asm -i 100"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V2 - BTI - P" {
    if cat /proc/cpuinfo | grep "AMD" ; then
        skip
    fi

    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/spectre_v2.asm -i 20"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V4 - SSBP - P" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/spectre_v4.asm -c x86/tests/acceptance/ct-seq-ssbp-patch-off.yaml -i 200"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V4 - SSBP - N (patch off)" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/spectre_v4.asm -c x86/tests/acceptance/ct-bpas-ssbp-patch-off.yaml -i 200"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V4 - SSBP - N (patch on)" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/spectre_v4.asm -i 200"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V5-ret" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/spectre_ret.asm -i 10"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Nested misprediction" {
    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/spectre_v4_n2.asm -i 200 -c x86/tests/acceptance/ct-bpas-n1-ssbp-patch-off.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]

    run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/spectre_v4_n2.asm -i 200 -c x86/tests/acceptance/ct-bpas-ssbp-patch-off.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: MDS-SB" {
    if cat /proc/cpuinfo | grep "AMD" ; then
        skip
    fi

    if cat /proc/cpuinfo | grep "mds" ; then
        run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/mds.asm -i 100 -c x86/tests/acceptance/mds.yaml"
        echo "$output"
        [ "$status" -eq 0 ]
        [[ "$output" = *"=== Violations detected ==="* ]]
    else
        run bash -c "$cli_opt fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/lvi.asm -i 100 -c x86/tests/acceptance/mds.yaml"
        echo "$output"
        [ "$status" -eq 0 ]
        [[ "$output" = *"=== Violations detected ==="* ]]
    fi
}

@test "False Positive: Input-independent branch misprediction" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/spectre_v1_independent.asm -i 100"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Analyser: Priming" {
    skip
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t x86/tests/acceptance/priming.asm -i 100 -c x86/tests/acceptance/priming.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" == *"Priming"* ]]
    [[ "$output" != *"=== Violations detected ==="* ]]
}


# ==================================================================================================
# Extended tests - take long time, but test deeper
# ==================================================================================================
@test "Extended: False positives from generated samples" {
    if [ $EXTENDED_TESTS -eq 0 ]; then
        skip
    fi

    for test_case in x86/tests/acceptance/generated-fp/* ; do
        echo "Testing $test_case"
        run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t $test_case -i 10000 -c x86/tests/acceptance/ct-cond-bpas.yaml"
        echo "$output"
        [ "$status" -eq 0 ]
        [[ "$output" != *"=== Violations detected ==="* ]]
    done
}
