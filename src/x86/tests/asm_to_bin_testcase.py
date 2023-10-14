#!/usr/bin/env python3
import sys
import os
import subprocess


def write_actor_metadata(f, entry):
    f.write((entry[0]).to_bytes(8, byteorder='little'))  # id
    f.write((entry[1]).to_bytes(8, byteorder='little'))  # mode
    f.write((entry[2]).to_bytes(8, byteorder='little'))  # data permissions
    f.write((entry[3]).to_bytes(8, byteorder='little'))  # code permissions


def write_st_entry(f, entry):
    f.write((entry[0]).to_bytes(8, byteorder='little'))
    f.write((entry[1]).to_bytes(8, byteorder='little'))
    f.write((entry[2]).to_bytes(8, byteorder='little'))
    f.write((entry[3]).to_bytes(8, byteorder='little'))


def write_metadata_entry(f, entry):
    f.write((entry[0]).to_bytes(8, byteorder='little'))
    f.write((entry[1]).to_bytes(8, byteorder='little'))
    f.write((entry[2]).to_bytes(8, byteorder='little'))


def main(asm_file: str, obj_file: str):
    n_actors = 1
    n_symbols = 3

    # compile the assembly file
    tmpbin = asm_file + '.o'
    subprocess.run(['as', asm_file, '-o', tmpbin])
    subprocess.run(['strip', '--remove-section=.note.gnu.property', tmpbin])
    subprocess.run(['objcopy', tmpbin, '-O', 'binary', tmpbin])
    main_size = os.path.getsize(tmpbin)

    # create the test case file
    with open(obj_file, 'wb') as f:
        # write the test case header
        f.write((n_actors).to_bytes(8, byteorder='little'))
        f.write((n_symbols).to_bytes(8, byteorder='little'))

        # write actor metadata
        write_actor_metadata(f, (0, 0, 0x8000000000000063, 0))

        # write the symbol table
        # - symbol 1: main
        write_st_entry(f, (0, 0, 0, 0))
        # - symbol 2: MACRO_MEASUREMENT_START
        write_st_entry(f, (0, 0, 1, 0))
        main_size += 5
        # - symbol 3: MACRO_MEASUREMENT_END
        write_st_entry(f, (0, main_size, 2, 0))
        main_size += 5

        # write the section metadata
        write_metadata_entry(f, (0, main_size, 0))

        # write the code
        f.write(b'\x0f\x1f\x44\x00\x01')  # nop - MACRO_MEASUREMENT_START
        with open(tmpbin, 'rb') as bin_file:
            code = bin_file.read()
            f.write(code)
        f.write(b'\x0f\x1f\x44\x00\x01')  # nop - MACRO_MEASUREMENT_END


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: %s <asm_file> <dest_file>" % sys.argv[0])
        sys.exit(1)

    sys.exit(main(sys.argv[1], sys.argv[2]))
