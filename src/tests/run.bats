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

@test "Executor: Noise Level" {
    # execute one dummy run to set Executor into the default config and to load the test case
    bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/valid_loads_with_miss.asm -i 1"

    nruns=10000
    printf "" > inputs.bin
    for i in $(seq 1 $nruns); do
        echo -n -e '\x00\x00\x00\x00\x00\x00\x00\x01' >> inputs.bin
    done

    for mode in "F+R" "P+R" "E+R"; do
        echo $mode
        echo $mode > /sys/x86-executor/measurement_mode
        echo "$nruns" > /sys/x86-executor/n_inputs
        cat inputs.bin > /sys/x86-executor/inputs
        run cat /sys/x86-executor/n_inputs
        [[ "$output" != "0" ]]

        cat /proc/x86-executor | sort | uniq | wc -l > tmp.txt
        run cat tmp.txt
        cat tmp.txt
        [ $output -lt 20 ]
    done
#    [ 1 -eq 0 ]
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

@test "Model: Rollback on LFENCE and spec. window" {
    run bash -c "./cli.py fuzz -s $INSTRUCTION_SET -t tests/rollback_fence_and_expire.asm -i 2 -c tests/rollback_fence_and_expire.yaml -v"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"__^_____________________________________________________________ [s]"* ]]
    [[ "$output" != *"_^______________________________________________________________ [s]"* ]]
    [[ "$output" != *"_^^_____________________________________________________________ [s]"* ]]
}

@test "Generator: Self-test" {
    run bash -c "./cli.py generator-test -s $INSTRUCTION_SET -c tests/all-instr.yaml"
    [ "$status" -eq 0 ]
    [[ "$output" == "" ]]
}