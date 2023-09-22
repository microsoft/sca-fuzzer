#!/usr/bin/env python3
import sys
import os
import subprocess


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

        # write the symbol table
        # - symbol 1: main
        f.write((0).to_bytes(8, byteorder='little'))
        f.write((0).to_bytes(8, byteorder='little'))
        f.write((0).to_bytes(8, byteorder='little'))
        # - symbol 2: MACRO_MEASUREMENT_START
        f.write((0).to_bytes(8, byteorder='little'))
        f.write((0).to_bytes(8, byteorder='little'))
        f.write((1).to_bytes(8, byteorder='little'))
        main_size += 5
        # - symbol 3: MACRO_MEASUREMENT_END
        f.write((0).to_bytes(8, byteorder='little'))
        f.write((main_size).to_bytes(8, byteorder='little'))
        f.write((2).to_bytes(8, byteorder='little'))
        main_size += 5

        # write the section metadata
        f.write((0).to_bytes(8, byteorder='little'))
        f.write((main_size).to_bytes(8, byteorder='little'))
        f.write((0).to_bytes(8, byteorder='little'))

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
