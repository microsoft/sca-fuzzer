#!/usr/bin/env bats
REPS=1000
REPS_SPECTRE=100

INSTRUCTION_SET='instruction_sets/x86/base.xml'

FAST_TEST=1

@test "Executor: Hardware tracing with F+R" {
    bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/evict_second_line.asm -c tests/ct-seq-fr.yaml  -i 3"
    run cat measurement.txt
    [ "$status" -eq 0 ]
    [[ "$output" == *"2305843009213693952"* ]]
}

@test "Executor: Hardware tracing with P+P" {
    bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/evict_second_line.asm -c tests/ct-seq-pp.yaml -i 3"
    run cat measurement.txt
    [ "$status" -eq 0 ]
    [[ "$output" == *"2305843009213693953"* ]]
}

@test "Executor: Hardware tracing with E+R" {
    bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/evict_second_line.asm -c tests/ct-seq-er.yaml -i 3"
    run cat measurement.txt
    [ "$status" -eq 0 ]
    [[ "$output" == *"2305843009213693952"* ]]
}

@test "Model and Executor are initialized with the same register and memory values" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/model_match.asm -c tests/model_match.yaml -i 1000"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Model and Executor are initialized with the same FLAGS value" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/model_flags_match.asm -c tests/model_match.yaml -i 1000"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Fuzzing: Empty test case [F+R]" {
    skip
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/empty.asm -i 1000 -c tests/ct-seq-fr.yaml "
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Fuzzing: Empty test case [P+P]" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/empty.asm -c tests/ct-seq-pp.yaml -i 1000"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Fuzzing: A sequence of NOPs" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/nops.asm -i 1000"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Fuzzing: A sequence of direct jumps" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/direct_jumps.asm -i 1000"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}


@test "Fuzzing: A long measurement period" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/large_arithmetic.asm -i 1000"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Fuzzing: A sequence of CALLs" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/calls.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Fuzzing: A sequence of valid loads (cache hits)" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/valid_loads.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Fuzzing: A sequence of valid loads (cache misses)" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/valid_loads_with_miss.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Fuzzing: A sequence of valid stores (cache hits)" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/valid_stores.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Fuzzing: An empty test case template" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/empty_template.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Detection: Spectre V1 - BCB load - P" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v1.asm -i 20"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V1 - BCB load - N" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v1.asm -c tests/ct-cond.yaml -i 20"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V1.1 - BCB store" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v1.1.asm -i 20"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V2 - BTI - P" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v2.asm -i 20"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V4 - SSBP - P" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v4.asm -c tests/ct-seq-ssbp-patch-off.yaml -i 100"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V4 - SSBP - N (patch off)" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v4.asm -c tests/ct-bpas-ssbp-patch-off.yaml -i 100"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V4 - SSBP - N (patch on)" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v4.asm -i 100"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V5-ret" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_ret.asm -i 10"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Nested misprediction" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v4_n2.asm -i 100 -c tests/ct-bpas-ssbp-patch-off.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]

    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v4_n2.asm -i 100 -c tests/ct-bpas-n2-ssbp-patch-off.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: MDS-SB" {
    if cat /proc/cpuinfo | grep "mds" ; then
        run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/mds.asm -i 100 -c tests/mds.yaml"
        echo "$output"
        [ "$status" -eq 0 ]
        [[ "$output" = *"=== Violations detected ==="* ]]
    else
        skip
    fi
}

@test "False Positive: Input-independent branch misprediction" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v1_independent.asm -i $REPS_SPECTRE"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "False Positive: Generated samples" {
    if [ $FAST_TEST -eq 1 ]; then
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

@test "Analyser: Priming" {
    skip
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_nested.asm -i 1000 -c tests/ct-cond.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Priming ==="* ]]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Model: ARCH-SEQ" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v1_arch.asm -i 1000 -c tests/arch-seq.yaml"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}