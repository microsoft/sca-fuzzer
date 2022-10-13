#!/usr/bin/env bats

INPUT_SIZE=$((4096 * 3))
NOP_OPCODE='\x90'

function setup_suite {
    sudo modprobe msr
    sudo wrmsr -a 0x1a4 15
}

@test "x86 executor: Loading a test case" {
    echo -n -e $NOP_OPCODE >/sys/x86_executor/test_case

    run bash -c 'echo "1" >/sys/x86_executor/n_inputs'
    [ "$status" -eq 0 ]

    printf '%0.s\x01' $(seq 1 $INPUT_SIZE) > tmp.bin
    run bash -c 'cat tmp.bin > /sys/x86_executor/inputs'
    [ "$status" -eq 0 ]
    rm tmp.bin

    run cat /sys/x86_executor/inputs
    [ "$status" -eq 0 ]
    echo "Output: $output"
    [[ "$output" -eq "1" ]]
}

@test "x86 executor: Printing base addresses" {
    run cat /sys/x86_executor/print_sandbox_base
    echo "Output: $output"
    [[ "$output" != "0" ]]
    run cat /sys/x86_executor/print_code_base
    echo "Output: $output"
    [[ "$output" != "0" ]]
}

@test "x86 executor: Controlling warmups" {
    echo "50" > /sys/x86_executor/warmups
    run cat /sys/x86_executor/warmups
    [[ "$output" -eq "50" ]]
}

function load_test_case() {
    local test_file=$1

    tmpbin=$(mktemp /tmp/revizor-test.XXXXXX.o)

    as "$test_file" -o "$tmpbin"
    strip --remove-section=.note.gnu.property "$tmpbin"
    objcopy "$tmpbin" -O binary "$tmpbin"

    cat $tmpbin >/sys/x86_executor/test_case
    echo "1" >/sys/x86_executor/n_inputs
    printf '%0.s\x01' $(seq 1 $INPUT_SIZE) > /sys/x86_executor/inputs
    run cat /sys/x86_executor/inputs
    [[ "$output" -eq "1" ]]

    rm "$tmpbin"
}

@test "x86 executor: Controlling patches" {
    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)
    echo "NOP" > $tmpasm
    load_test_case $tmpasm

    run bash -c 'echo "1" > /sys/x86_executor/enable_ssbp_patch'
    [ "$status" -eq 0 ]
    run cat /sys/x86_executor/trace
    [ "$status" -eq 0 ]

    run bash -c 'echo "0" > /sys/x86_executor/enable_ssbp_patch'
    [ "$status" -eq 0 ]
    run cat /sys/x86_executor/trace
    [ "$status" -eq 0 ]
}


@test "x86 executor: Hardware tracing with P+P" {
    echo "P+P" > /sys/x86_executor/measurement_mode
    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)

    echo "NOP" > $tmpasm
    load_test_case $tmpasm
    run cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"9223372036854775808,0"* ]]

    echo "MOVQ %r14, %rax; add \$512, %rax; movq (%rax), %rax" > $tmpasm
    load_test_case $tmpasm
    run cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"9259400833873739776,0"* ]]

    rm "$tmpasm"
}

@test "x86 executor: Hardware tracing with F+R" {
    echo "F+R" > /sys/x86_executor/measurement_mode
    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)

    echo "NOP" > $tmpasm
    load_test_case $tmpasm
    run cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"0,0"* ]]

    echo "MOVQ %r14, %rax; add \$512, %rax; movq (%rax), %rax" > $tmpasm
    load_test_case $tmpasm
    run cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"36028797018963968,0"* ]]

    rm "$tmpasm"
}

@test "x86 executor: Hardware tracing with E+R" {
    echo "E+R" > /sys/x86_executor/measurement_mode
    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)

    echo "NOP" > $tmpasm
    load_test_case $tmpasm
    run cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"0,0"* ]]

    echo "MOVQ %r14, %rax; add \$512, %rax; movq (%rax), %rax" > $tmpasm
    load_test_case $tmpasm
    run cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"36028797018963968,0"* ]]

    rm "$tmpasm"
}

@test "x86 executor: Hardware tracing with GPR" {
    echo "GPR" > /sys/x86_executor/measurement_mode
    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)

    echo "mov \$1, %rax; mov \$2, %rbx; mov \$3, %rcx; mov \$4, %rdx; mov \$5, %rsi; mov \$6, %rdi;" > $tmpasm
    load_test_case $tmpasm
    run cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"1,2,3,4,5,6"* ]]

    rm "$tmpasm"
}

@test "x86 executor: Noise Level" {
    # execute one dummy run to set Executor into the default config and to load the test case
    nruns=10000
    threshold=$((nruns - 2))

    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)
    tmpbin=$(mktemp /tmp/revizor-test.XXXXXX.o)
    tmpinput=$(mktemp /tmp/revizor-test.XXXXXX.bin)
    tmpresult=$(mktemp /tmp/revizor-test.XXXXXX.txt)

    echo "NOP" > $tmpasm
    as "$tmpasm" -o "$tmpbin"

    strip --remove-section=.note.gnu.property "$tmpbin"
    objcopy "$tmpbin" -O binary "$tmpbin"

    dd if=/dev/zero of="$tmpinput" bs=$INPUT_SIZE count=$nruns status=none

    for mode in "P+P" "F+R" "E+R"; do
        # echo $mode
        echo $mode > /sys/x86_executor/measurement_mode
        cat $tmpbin >/sys/x86_executor/test_case
        echo "$nruns" >/sys/x86_executor/n_inputs
        cat $tmpinput > /sys/x86_executor/inputs
        run cat /sys/x86_executor/inputs
        [[ "$output" -eq "1" ]]

        echo "" > $tmpresult

        # START=$(date +%s.%N)
        while true; do
            run cat /sys/x86_executor/trace
            [ "$status" -eq 0 ]
            echo "$output" >> $tmpresult
            if [[ "$output" == *"done"* ]]; then
                break
            fi
        done
        # END=$(date +%s.%N)
        # echo "$END - $START" | bc

        # cat $tmpresult | awk '/,/{print $1}' | sort | uniq -c | sort -r | awk '//{print $1}'
        run bash -c "cat $tmpresult | awk '/,/{print \$1}' | sort | uniq -c | sort -r | awk '//{print \$1}' | head -n1"
        [ $output -ge $threshold ]
    done
    rm $tmpasm
    rm "$tmpbin"
    rm "$tmpinput"
    rm "$tmpresult"
}

@test "x86 executor: Noisy stores" {
    # execute one dummy run to set Executor into the default config and to load the test case
    nruns=10000
    threshold=$((nruns - 2))

    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)
    tmpbin=$(mktemp /tmp/revizor-test.XXXXXX.o)
    tmpinput=$(mktemp /tmp/revizor-test.XXXXXX.bin)
    tmpresult=$(mktemp /tmp/revizor-test.XXXXXX.txt)

    echo "MOVQ %r14, %rax; add \$512, %rax; movq \$128, (%rax)" > $tmpasm
    as "$tmpasm" -o "$tmpbin"

    strip --remove-section=.note.gnu.property "$tmpbin"
    objcopy "$tmpbin" -O binary "$tmpbin"

    dd if=/dev/zero of="$tmpinput" bs=$INPUT_SIZE count=$nruns status=none

    mode="P+P"
    echo $mode > /sys/x86_executor/measurement_mode
    cat $tmpbin >/sys/x86_executor/test_case
    echo "$nruns" >/sys/x86_executor/n_inputs
    cat $tmpinput > /sys/x86_executor/inputs
    run cat /sys/x86_executor/inputs
    [[ "$output" -eq "1" ]]

    echo "" > $tmpresult

    while true; do
        run cat /sys/x86_executor/trace
        [ "$status" -eq 0 ]
        echo "$output" >> $tmpresult
        if [[ "$output" == *"done"* ]]; then
            break
        fi
    done

    run bash -c "cat $tmpresult | awk '/,/{print \$1}' | sort | uniq -c | sort -r | awk '//{print \$1}' | head -n1"
    [ $output -ge $threshold ]

    rm $tmpasm
    rm "$tmpbin"
    rm "$tmpinput"
    rm "$tmpresult"
}

@test "x86 executor: Detection of machine clears" {
    echo "P+P" > /sys/x86_executor/measurement_mode
    echo "1" > /sys/x86_executor/enable_mds
    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)

    echo "MOVQ %r14, %rax; add \$4096, %rax; movq (%rax), %rax" > $tmpasm
    load_test_case $tmpasm
    run cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" != *",0,"* ]]

    rm "$tmpasm"
}
