"""
File: All kinds of postprocessing actions performed after a violation has been detected.
Currently, only test case minimization. In future, may contain test case analysis of the
 contract violation (i.e., vulnerability), and similar actions.

Copyright (C) 2020 Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from subprocess import run, PIPE


def minimize(test_case: str, outfile: str):
    minimised = "/tmp/minimised.asm"

    # Get file contents and its size
    with open(test_case, "r") as f:
        instructions = f.readlines()
        size = len(instructions)

    # Check if we can reproduce the violation
    result = run(f"./cli.py fuzz "
                 f"-s instruction_sets/x86/base.xml "
                 f"-t {test_case} -i 6000 -v -c ./custom_conf.yaml",
                 shell=True, check=True, stdout=PIPE, stderr=PIPE)

    if "Unexpected" not in result.stdout.decode():
        print("Could not reproduce.")
        exit(1)
    else:
        print(".", end=" ")

    # Try removing instructions, one at a time
    done = False
    cursor = size
    while not done:
        cursor -= 1

        # Preserve those instructions used for sandboxing
        if "0b111111000000" in instructions[cursor] or ", R14" in instructions[cursor]:
            continue

        # Leave the input generation code in place
        # Currently, it's 58 lines long
        if cursor < 34:
            done = True

        # Progress
        print(cursor, end=" ", flush=True)

        # Create a test case with one line missing
        run(f"touch {minimised}", shell=True, check=True)
        with open(minimised, "r+") as f:
            f.seek(0)
            for i, line in enumerate(instructions):
                if i == cursor:
                    continue  # skip one line
                f.write(line)
            f.truncate()

        # Run and check if the vuln. is still there
        result = run(f"./cli.py fuzz "
                     f"-s instruction_sets/x86/base.xml "
                     f"-t {minimised} -i 6000 -v -c ./custom_conf.yaml",
                     shell=True, check=True, stdout=PIPE, stderr=PIPE)

        if "Unexpected" in result.stdout.decode():
            print(".", end=" ")
            del instructions[cursor]
            size -= 1
        else:
            print("-", end=" ")

    print("Done")
    with open(outfile, "w") as f:
        for line in instructions:
            f.write(line)
