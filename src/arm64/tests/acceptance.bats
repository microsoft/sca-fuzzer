#!/usr/bin/env bats
INSTRUCTION_SET='arm64/isa_spec/base.json'

EXTENDED_TESTS=0
cli_opt="python3 -OO ./cli.py"

@test "Placeholder" {
    run bash -c "echo 0"
    [ "$status" -eq 0 ]
    [[ "$output" = *"0"* ]]
}
