#!/usr/bin/env bats
INSTRUCTION_SET='arm64/isa_spec/base.json'

EXTENDED_TESTS=0
cli_opt="python3 -OO ./cli.py fuzz -s $INSTRUCTION_SET -c arm64/tests/test-spectre.yaml -i 10"

@test "Violation: Spectre V1 - BCB" {
    run bash -c "$cli_opt -n 100 -t arm64/tests/spectre_v1.asm"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "No Violation: Spectre V1 - BCB [no LDR under speculation]" {
    run bash -c "$cli_opt -n 100 -t arm64/tests/spectre_v1_no_load.asm"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Violation: Spectre V2 - BTI" {
    run bash -c "$cli_opt -n 100 -t arm64/tests/spectre_v2.asm"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "No Violation: Spectre V2 - BTI [no LDR under speculation]" {
    run bash -c "$cli_opt -n 100 -t arm64/tests/spectre_v2_no_load.asm"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "No Violation: Spectre V2 - BTI [CSEL variant]" {
    run bash -c "$cli_opt -n 100 -t arm64/tests/spectre_v2_csel.asm"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Violation: Spectre V4 - SSBP" {
    run bash -c "$cli_opt -n 100 -t arm64/tests/spectre_v4.asm"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}

@test "No Violation: Spectre V4 - SSBP [dependent register store/load]" {
    run bash -c "$cli_opt -n 100 -t arm64/tests/spectre_v4_with_dep.asm"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" != *"=== Violations detected ==="* ]]
}

@test "Fuzzing Detection: Spectre V1-like" {
    run bash -c "$cli_opt -n 1000"
    echo "$output"
    [ "$status" -eq 0 ]
    [[ "$output" = *"=== Violations detected ==="* ]]
}