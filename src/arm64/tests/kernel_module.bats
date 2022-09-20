#!/usr/bin/env bats

INPUT_SIZE=$((4096 * 3))
NOP_OPCODE='\x1f\x20\x03\xd5'

function load_test_case() {
    local test_file=$1

    tmpbin=$(mktemp /tmp/revizor-test.XXXXXX.o)

    as "$test_file" -o "$tmpbin"
    strip --remove-section=.note.gnu.property "$tmpbin"
    objcopy "$tmpbin" -O binary "$tmpbin"

    cat $tmpbin >/sys/arm64_executor/test_case
    echo "1" >/sys/arm64_executor/n_inputs
    printf '%0.s\x01' $(seq 1 $INPUT_SIZE) > /sys/arm64_executor/inputs
    run cat /sys/arm64_executor/inputs
    [[ "$output" -eq "1" ]]

    rm "$tmpbin"
}


@test "arm64 executor: Loading a test case" {
    echo -n -e $NOP_OPCODE >/sys/arm64_executor/test_case

    run bash -c "cat /sys/arm64_executor/test_case > bin.o ; objdump -D -b binary -m aarch64 bin.o"
    [ "$status" -eq 0 ]
    [[ "$output" == *"d503201f"* ]]
    [[ "$output" != *"udf"* ]]

    run bash -c 'echo "1" >/sys/arm64_executor/n_inputs'
    [ "$status" -eq 0 ]

    printf '%0.s\x01' $(seq 1 $INPUT_SIZE) > tmp.bin
    run bash -c 'cat tmp.bin > /sys/arm64_executor/inputs'
    [ "$status" -eq 0 ]
    rm tmp.bin

    run cat /sys/arm64_executor/inputs
    [ "$status" -eq 0 ]
    echo "Output: $output"
    [[ "$output" -eq "1" ]]
}

@test "arm64 executor: Printing base addresses" {
    run cat /sys/arm64_executor/print_sandbox_base
    echo "Output: $output"
    [[ "$output" != "0" ]]
    run cat /sys/arm64_executor/print_code_base
    echo "Output: $output"
    [[ "$output" != "0" ]]
}

@test "arm64 executor: Controlling warmups" {
    echo "50" > /sys/arm64_executor/warmups
    run cat /sys/arm64_executor/warmups
    [[ "$output" -eq "50" ]]
}

@test "arm64 executor: Hardware tracing with F+R" {
    echo "F+R" > /sys/arm64_executor/measurement_mode
    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)

    echo "add x0, x0, #0" > $tmpasm
    load_test_case $tmpasm
    run cat /sys/arm64_executor/trace
    echo "Output: $output"
    [[ "$output" == "0"* ]]

    echo "add x1, x30, #512; ldrh w2, [x1], #0" > $tmpasm
    load_test_case $tmpasm
    run cat /sys/arm64_executor/trace
    echo "Output: $output"
    [[ "$output" == "36028797018963968"* ]]

    rm "$tmpasm"
}

@test "arm64 executor: Noise Level" {
    # execute one dummy run to set Executor into the default config and to load the test case
    nruns=10000
    threshold=$((nruns - 2))

    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)
    tmpbin=$(mktemp /tmp/revizor-test.XXXXXX.o)
    tmpinput=$(mktemp /tmp/revizor-test.XXXXXX.bin)
    tmpresult=$(mktemp /tmp/revizor-test.XXXXXX.txt)

    echo "add x1, x30, #512; ldrh w2, [x1], #0" > $tmpasm
    as "$tmpasm" -o "$tmpbin"

    strip --remove-section=.note.gnu.property "$tmpbin"
    objcopy "$tmpbin" -O binary "$tmpbin"

    dd if=/dev/zero of="$tmpinput" bs=$INPUT_SIZE count=$nruns status=none

    for mode in "F+R"; do
        # echo $mode
        echo $mode > /sys/arm64_executor/measurement_mode
        cat $tmpbin >/sys/arm64_executor/test_case
        echo "$nruns" >/sys/arm64_executor/n_inputs
        cat $tmpinput > /sys/arm64_executor/inputs
        run cat /sys/arm64_executor/inputs
        [[ "$output" -eq "1" ]]

        echo "" > $tmpresult

        while true; do
            run cat /sys/arm64_executor/trace
            [ "$status" -eq 0 ]
            echo "$output" >> $tmpresult
            if [[ "$output" == *"done"* ]]; then
                break
            fi
        done

        run bash -c "cat $tmpresult | awk '/[1-9]/{print \$1}' | sort | uniq -c | sort -r | awk '//{print \$1}' | head -n1"
        [[ "$output" -gt "$threshold" ]]
    done
    rm $tmpasm
    rm "$tmpbin"
    rm "$tmpinput"
    rm "$tmpresult"
}
