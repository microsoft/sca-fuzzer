#!/usr/bin/env bats

INPUT_SIZE=$((4096 * 3))
NOP_OPCODE='\x1f\x20\x03\xd5'


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
