#!/usr/bin/env bats

INPUT_SIZE=$((4096 * 3))

INPUT_META='\x00\x03\x00\x00\x00\x00\x00\x00''\x00\x00\x00\x00\x00\x00\x00\x00'

setup() {
    # get the containing directory of this file
    DIR="$(cd "$(dirname "$BATS_TEST_FILENAME")" >/dev/null 2>&1 && pwd)"
}

hex2bin32() {
    local v=$1
    printf "\\\x%02x" $((v & 255)) $((v >> 8 & 255)) $((v >> 16 & 255)) $((v >> 24 & 255))
}

function load_input() {
    local create_only=$1
    local nruns=$2
    local dest_file=$3
    local header="\x01\x00\x00\x00\x00\x00\x00\x00$(hex2bin32 $nruns)\x00\x00\x00\x00"

    printf $header >$dest_file
    printf $INPUT_META >>$dest_file
    printf '%0.s\x00' $(seq 1 $INPUT_SIZE) >>$dest_file

    if [ $create_only = false ]; then
        cat $dest_file >/sys/x86_executor/inputs
        rm $dest_file
    fi
}

function load_test_case() {
    local create_only=$1
    local asm_file=$2
    local dest_file=$3

    ${DIR}/asm_to_bin_testcase.py $asm_file $dest_file

    if [ $create_only = false ]; then
        cat $dest_file >/sys/x86_executor/test_case
        rm $dest_file
    fi
}

function set_default_config() {
    echo "0" >/sys/x86_executor/enable_dbg_gpr_mode
    echo "1" >/sys/x86_executor/enable_ssbp_patch
    echo "0" >/sys/x86_executor/enable_prefetcher
}


@test "x86 executor: Loading a test case" {
    printf "nop\n" >tmp.asm
    load_test_case true tmp.asm tmp.bin

    run bash -c 'cat tmp.bin > /sys/x86_executor/test_case'
    [ "$status" -eq 0 ]
    rm tmp.bin

    load_input true 1 input.bin
    run bash -c 'cat input.bin > /sys/x86_executor/inputs'
    [ "$status" -eq 0 ]
    rm input.bin

    run cat /sys/x86_executor/inputs
    [ "$status" -eq 0 ]
    echo "Output: $output"
    [[ "$output" -eq "1" ]]
}

@test "x86_executor: Tracing" {
    run taskset -c 0 cat /sys/x86_executor/trace
    [ "$status" -eq 0 ]
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
    echo "50" >/sys/x86_executor/warmups
    run cat /sys/x86_executor/warmups
    [[ "$output" -eq "50" ]]
}

@test "x86 executor: Controlling patches" {
    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)
    tmpbin=$(mktemp /tmp/revizor-test.XXXXXX.o)
    tmpinput=$(mktemp /tmp/revizor-test.XXXXXX.bin)
    echo "nop" >$tmpasm
    load_test_case false $tmpasm $tmpbin
    load_input false 1 $tmpinput

    run bash -c 'echo "1" > /sys/x86_executor/enable_ssbp_patch'
    [ "$status" -eq 0 ]
    run taskset -c 0 cat /sys/x86_executor/trace
    [ "$status" -eq 0 ]

    run bash -c 'echo "0" > /sys/x86_executor/enable_ssbp_patch'
    [ "$status" -eq 0 ]
    run taskset -c 0 cat /sys/x86_executor/trace
    [ "$status" -eq 0 ]

    run bash -c 'echo "1" > /sys/x86_executor/enable_prefetcher'
    [ "$status" -eq 0 ]
    run taskset -c 0 cat /sys/x86_executor/trace
    [ "$status" -eq 0 ]

    run bash -c 'echo "0" > /sys/x86_executor/enable_prefetcher'
    [ "$status" -eq 0 ]
    run taskset -c 0 cat /sys/x86_executor/trace
    [ "$status" -eq 0 ]
}

@test "x86 executor: Hardware tracing with P+P" {
    set_default_config
    echo "P+P" >/sys/x86_executor/measurement_mode

    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)
    tmpbin=$(mktemp /tmp/revizor-test.XXXXXX.o)
    tmpinput=$(mktemp /tmp/revizor-test.XXXXXX.bin)
    echo "nop" >$tmpasm
    load_test_case false $tmpasm $tmpbin
    load_input false 1 $tmpinput

    run taskset -c 0 cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"9223372036854775808,"* ]]

    echo "movq %r14, %rax; add \$512, %rax; movq (%rax), %rax" >$tmpasm
    load_test_case false $tmpasm $tmpbin
    load_input false 1 $tmpinput

    run taskset -c 0 cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"9259400833873739776,"* ]]
}

@test "x86 executor: Hardware tracing with F+R" {
    set_default_config
    echo "F+R" >/sys/x86_executor/measurement_mode

    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)
    tmpbin=$(mktemp /tmp/revizor-test.XXXXXX.o)
    tmpinput=$(mktemp /tmp/revizor-test.XXXXXX.bin)
    echo "nop" >$tmpasm
    load_test_case false $tmpasm $tmpbin
    load_input false 1 $tmpinput

    run taskset -c 0 cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"9223372036854775808,"* ]]

    echo "movq %r14, %rax; add \$512, %rax; movq (%rax), %rax" >$tmpasm
    load_test_case false $tmpasm $tmpbin
    load_input false 1 $tmpinput

    run taskset -c 0 cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"9259400833873739776,"* ]]
}

@test "x86 executor: Hardware tracing with E+R" {
    set_default_config
    echo "E+R" >/sys/x86_executor/measurement_mode

    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)
    tmpbin=$(mktemp /tmp/revizor-test.XXXXXX.o)
    tmpinput=$(mktemp /tmp/revizor-test.XXXXXX.bin)
    echo "nop" >$tmpasm
    load_test_case false $tmpasm $tmpbin
    load_input false 1 $tmpinput

    run taskset -c 0 cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"9223372036854775808,"* ]]

    echo "movq %r14, %rax; add \$512, %rax; movq (%rax), %rax" >$tmpasm
    load_test_case false $tmpasm $tmpbin
    load_input false 1 $tmpinput

    run taskset -c 0 cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"9259400833873739776,"* ]]
}

@test "x86 executor: Hardware tracing with GPR" {
    set_default_config
    echo "1" >/sys/x86_executor/enable_dbg_gpr_mode

    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)
    tmpbin=$(mktemp /tmp/revizor-test.XXXXXX.o)
    tmpinput=$(mktemp /tmp/revizor-test.XXXXXX.bin)
    echo "mov \$1, %rax; mov \$2, %rbx; mov \$3, %rcx; mov \$4, %rdx; mov \$5, %rsi; mov \$6, %rdi;" >$tmpasm
    load_test_case false $tmpasm $tmpbin
    load_input false 1 $tmpinput

    run taskset -c 0 cat /sys/x86_executor/trace
    echo "Output: $output"
    [[ "$output" == *"1,2,3,4,5,6"* ]]
}

@test "x86 executor: Noise Level" {
    set_default_config

    # execute one dummy run to set Executor into the default config and to load the test case
    nruns=1000
    threshold=900

    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)
    tmpbin=$(mktemp /tmp/revizor-test.XXXXXX.o)
    tmpinput=$(mktemp /tmp/revizor-test.XXXXXX.bin)
    tmpresult=$(mktemp /tmp/revizor-test.XXXXXX.txt)

    echo "movq (%r14), %rax" >$tmpasm
    load_test_case true "$tmpasm" "$tmpbin"

    printf "\x01\x00\x00\x00\x00\x00\x00\x00$(hex2bin32 $nruns)\x00\x00\x00\x00" >/sys/x86_executor/inputs
    printf $INPUT_META >>/sys/x86_executor/inputs
    dd if=/dev/zero of="$tmpinput" bs=$INPUT_SIZE count=$nruns status=none
    cat $tmpinput >/sys/x86_executor/inputs

    run cat /sys/x86_executor/inputs
    [[ "$output" -eq "1" ]]

    for mode in "P+P" "F+R" "E+R"; do
        # echo $mode
        echo $mode >/sys/x86_executor/measurement_mode
        cat "$tmpbin" >/sys/x86_executor/test_case

        echo "" >$tmpresult

        # START=$(date +%s.%N)
        while true; do
            run taskset -c 0 cat /sys/x86_executor/trace
            [ "$status" -eq 0 ]
            echo "$output" >>$tmpresult
            if [[ "$output" == *"done"* ]]; then
                break
            fi
        done
        # END=$(date +%s.%N)
        # echo "$END - $START" | bc

        # cat $tmpresult | awk -F, '/,/{print $1}' | sort | uniq -c | sort -r -b -n
        run bash -c "cat $tmpresult | awk -F, '/,/{print \$1}' | sort | uniq -c | sort -r -b -n | awk '//{print \$1}' | head -n1"
        echo "$mode: $output"
        [ $output -ge $threshold ]
    done
    rm $tmpasm
    rm "$tmpbin"
    rm "$tmpinput"
    rm "$tmpresult"
}

@test "x86 executor: Noisy stores" {
    set_default_config

    # execute one dummy run to set Executor into the default config and to load the test case
    nruns=1000
    threshold=900

    tmpasm=$(mktemp /tmp/revizor-test.XXXXXX.asm)
    tmpbin=$(mktemp /tmp/revizor-test.XXXXXX.o)
    tmpinput=$(mktemp /tmp/revizor-test.XXXXXX.bin)
    tmpresult=$(mktemp /tmp/revizor-test.XXXXXX.txt)

    echo "movq %r14, %rax; add \$512, %rax; movq \$128, (%rax)" >$tmpasm
    load_test_case true $tmpasm $tmpbin

    printf "\x01\x00\x00\x00\x00\x00\x00\x00$(hex2bin32 $nruns)\x00\x00\x00\x00" >/sys/x86_executor/inputs
    printf $INPUT_META >>/sys/x86_executor/inputs
    dd if=/dev/zero of="$tmpinput" bs=$INPUT_SIZE count=$nruns status=none
    cat $tmpinput >/sys/x86_executor/inputs

    mode="P+P"
    echo $mode >/sys/x86_executor/measurement_mode
    cat $tmpbin >/sys/x86_executor/test_case

    run cat /sys/x86_executor/inputs
    [[ "$output" -eq "1" ]]

    echo "" >$tmpresult

    while true; do
        run taskset -c 0 cat /sys/x86_executor/trace
        [ "$status" -eq 0 ]
        echo "$output" >>$tmpresult
        if [[ "$output" == *"done"* ]]; then
            break
        fi
    done

    run bash -c "cat $tmpresult | awk -F, '/,/{print \$1}' | sort | uniq -c | sort -r | awk '//{print \$1}' | head -n1"
    echo "$mode: $output"
    [ $output -ge $threshold ]

    rm $tmpasm
    rm "$tmpbin"
    rm "$tmpinput"
    rm "$tmpresult"
}
