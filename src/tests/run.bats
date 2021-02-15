#!/usr/bin/env bats
REPS=1000
REPS_SPECTRE=100
REPS_FP=1000
REPS_GENERATED=10000

INSTRUCTION_SET='instruction_sets/x86/base.xml'

FAST_TEST=1

@test "Executor: Can detect evictions" {
    bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/evict_second_line.asm -i 3"
    run cat measurement.txt
    [ "$status" -eq 0 ]
    [[ "$output" == *"0,2305843009213693952"* ]]
}

@test "Model: One load based on the PRNG value" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/random_load.asm -i $REPS_SPECTRE"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Model: Emulation of FLAGS" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/cmov.asm -i $REPS_SPECTRE"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Environment: Empty sample" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/empty.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Environment: A sequence of NOPs" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/nops.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Environment: A sequence of fences" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/fences.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Environment: A sequence of direct jumps" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/direct_jumps.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}


@test "Environment: A long measurement period" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/large_arithmetic.asm -i $REPS_SPECTRE"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Environment: A sequence of RDRANDs" {
    skip
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/rdrand.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Environment: A sequence of CALLs" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/calls.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Environment: A sequence of valid loads (cache hits)" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/valid_loads.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Environment: A sequence of valid loads (cache misses)" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/valid_loads_with_miss.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Environment: A sequence of valid stores (cache hits)" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/valid_stores.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Environment: An empty test case template" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/empty_template.asm -i $REPS"
    echo "$output"
    [ "$status" -eq 0 ]
    [ "$output" = "" ]
}

@test "Detection: Spectre V1 - BCB load" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v1.asm -i $REPS_SPECTRE"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V1.1 - BCB store" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v1.1.asm -i $REPS_SPECTRE"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V2 - BTI" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v2.asm -i $REPS_SPECTRE"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "Detection: Spectre V4 - SSBP" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v4.asm -i 1000"
    echo "$output"
    [ "$status" -eq 0 ]

    # if the microcode patch against SSBP is disabled
    [[ "$output" = *"=== Violations detected ==="* ]]

    # enabled
#    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Detection: Return misprediction" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_ret.asm -i $REPS_SPECTRE"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "False Positive: Input-independent branch misprediction" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_v1_independent.asm -i $REPS_SPECTRE"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "False Positive: Cross-training between inputs" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/spectre_nested.asm -i $REPS_FP -c ./tests/ct-cb.yaml"
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
        run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t $test_case -i $REPS_GENERATED -c ./tests/ct-cb-sbp.yaml"
        echo "$output"
        [ "$status" -eq 0 ]
        [[ "$output" != *"=== Violations detected ==="* ]]
    done
}
