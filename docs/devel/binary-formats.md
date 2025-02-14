# Binary Formats in Revizor

This document describes the structure of the custom binary formats used by Revizor to transfer
test cases and their data between different components. For example, these formats are used
to pass generated test cases from the executor (python) class to the executor kernel module.

Such custom formats are necessary because the components are implemented in different programming languages and different technologies, so passing objects directly is not possible. Using one of the standard formats (e.g., ELF) is also not an option because test cases in Revizor have special structure (e.g., multiple actors in different execution modes, some instructions are macros, etc.) and this structure is not supported by the standard formats.

The formats are designed to as simple as possible to minimize the overhead of serialization and deserialization.

Table of Contents
=================
- [Binary Formats in Revizor](#binary-formats-in-revizor)
- [Table of Contents](#table-of-contents)
  - [Revizor Code Binary Format (RCBF)](#revizor-code-binary-format-rcbf)
  - [Revizor Data Binary Format (RDBF)](#revizor-data-binary-format-rdbf)



## Revizor Code Binary Format (RCBF)

RCBF is a structured representation of the complete test case binary, together with its metadata.
The structure is as follows:

``` text
|---------------------------------------|
| n_actors (8 bytes)                    | HEADER       |
| n_symbols (8 bytes)                   |
| ------------------------------------- |
| actor metadata:                       | ACTOR TABLE  |
| - id (8 bytes)                        |
| - mode (8 bytes)                      |
| - pl (8 bytes)                        |
| - data_permissions (8 bytes)          |
| - data_ept_permissions (8 bytes)      |
| - code_permissions (8 bytes)          |
| x n_actors                            |
| ------------------------------------- |
| symbol entry:                         | SYMBOL TABLE |
| - owner (8 bytes)                     |
| - offset (8 bytes)                    |
| - id (8 bytes)                        |
| - args (8 bytes)                      |
| x n_symbols                           |
| ------------------------------------- |
| section metadata entry:               | METADATA     |
| - owner (8 bytes)                     |
| - size (8 bytes)                      |
| - reserved (8 bytes)                  |
| x n_actors                            |
| ------------------------------------- |
| code section:                         | DATA         |
| - code (char *)                       |
| x n_actors                            |
| ------------------------------------- |
```

The file begins with a header containing the number of actors (it is also the number of sections) and the number of symbols in the test case.
The term "symbol" in this context refers to any location in the test case that can be referenced.
Two common types of symbols are functions (specifically, function entry points) and macros.

Next, the file contains the actor table, which is an array of actor metadata entries, one for each actor in the test case.
The actor metadata entry contains the actor's ID, execution mode, protection level, data permissions, EPT data permissions, and code permissions.

After the actor table, the file contains the symbol table, which is an array of symbol entries, one for each symbol in the test case.
The symbol entry contains the ID the section to which the symbol belongs, the offset of the symbol within the section, the symbol's ID, and the number of arguments the symbol takes (if it is a macro).

The file continues with the table of metadata for each section in the test case.
Each metadata entry contains the ID of the actor that owns the section and the size of the section.

Finally, the file contains a sequence of code sections, one for each actor in the test case.
These sections contain the actual assembled binary for each of the sections in the test case.

## Revizor Data Binary Format (RDBF)

RDBF is a structured representation of the data used to initialize sandbox memory and registers before executing the test case.

Note that this format combines multiple inputs into a single file. This is done because typically, a single test case program is executed multiple times with different inputs, and so it is more efficient to send a batch of inputs at once.


``` text
|---------------------------------------|
| n_actors (8 bytes)                    | HEADER
| n_inputs (8 bytes)                    |
| ------------------------------------- |
| section metadata entry:               | METADATA |
| - section_size (8 bytes)              |
| - reserved (8 bytes)                  |
| x (n_actors * n_inputs)               |
| ------------------------------------- |
| input:                                | DATA     |
| - data section:                       |
| -- main_area (4096 bytes)             |
| -- faulty_area (4096 bytes)           |
| -- reg_init_region (4096 bytes)       |
| - x n_actors                          |
| x n_inputs                            |
| ------------------------------------- |
```

The file begins with a section containing the number of actors (equal to the number of sections) and the number of inputs in the batch.

Next, the file contains the table of metadata for each data section, which only contains the size of the section.

Finally, the file contains a sequence of data sections, one for each actor in the test case and each input in the batch. The data sections are arranged to mirror the data layout in the sandbox memory (see the [sandbox memory layout](sandbox.md) document for more information).

