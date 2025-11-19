#!/usr/bin/env python3
"""
File: create_rdbf_file.py
      Creates an RDBF test case file from an assembly source file.
      On details of the RDBF file format, see docs/devel/binary-formats.md

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
import sys


def main(dest_file: str, n_inputs: int, n_actors: int):
    # Open the destination file for writing
    with open(dest_file, 'wb') as f:
        # Write the header
        f.write(n_actors.to_bytes(8, byteorder='little'))  # Number of actors
        f.write(n_inputs.to_bytes(8, byteorder='little'))  # Number of inputs

        # Write metadata for each actor and input
        for _ in range(n_actors * n_inputs):
            f.write((4096 * 3).to_bytes(8, byteorder='little'))  # Section size
            f.write((0).to_bytes(8, byteorder='little'))  # Reserved

        # Write data sections for each actor and input
        for _ in range(n_inputs):
            for _ in range(n_actors):
                # Write main_area, faulty_area, and reg_init_region (each 4096 bytes)
                f.write(b'\x00' * 4096)  # main_area
                f.write(b'\x00' * 4096)  # faulty_area
                f.write(b'\x00' * 4096)  # reg_init_region

    return 0


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <dest_file> <n_inputs> <n_actors>")
        sys.exit(1)
    try:
        n_inputs = int(sys.argv[2])
    except ValueError:
        print(f"Invalid number of inputs: {sys.argv[2]}")
        sys.exit(1)
    try:
        n_actors = int(sys.argv[3])
    except ValueError:
        print(f"Invalid number of actors: {sys.argv[3]}")
        sys.exit(1)

    sys.exit(main(sys.argv[1], n_inputs, n_actors))
