# Binary Formats in Revizor

!!! info "Advanced Topic"
    This is an advanced topic describing internal implementation details of Revizor. You are unlikely to need this information unless you are extending or modifying Revizor's core components.

This document describes the structure of the custom binary formats used by Revizor to transfer test cases and their data between different components, specifically for transferring generated test cases and their inputs to the executor kernel module and to the DynamoRIO-based model backend.

Such custom formats are necessary because the components are implemented in different programming languages and different technologies, so passing objects directly is not possible. Using one of the standard formats (e.g., ELF) is also not an option because test cases in Revizor have special structure (e.g., multiple actors in different execution modes, some instructions are macros, etc.) and this structure is not supported by the standard formats.

The formats are designed to as simple as possible to minimize the overhead of serialization and deserialization.

## Revizor Code Binary Format (RCBF)

RCBF is a structured representation of the complete test case binary, together with its metadata.
The structure is as follows:

``` yaml title="RCBF Structure" linenums="1"
HEADER (16 bytes total)
  n_actors:                8 bytes  # Number of Actors in the test case (also equals the number of code sections)
  n_symbols:               8 bytes  # Number of symbols in the test case

ACTOR TABLE (48 x n_actors bytes)
  actor_entry:             # (repeated n_actors times)
    id:                    8 bytes  # Unique identifier for the actor
    mode:                  8 bytes  # Execution mode of the actor
    pl:                    8 bytes  # Protection level
    data_permissions:      8 bytes  # Data access permissions
    data_ept_permissions:  8 bytes  # EPT (Extended Page Table) data permissions
    code_permissions:      8 bytes  # Code execution permissions

SYMBOL TABLE (32 x n_symbols bytes)
  symbol_entry:            # (repeated n_symbols times)
    owner:                 8 bytes  # ID of the actor that owns this symbol
    offset:                8 bytes  # (Offset of the symbol within its section
    id:                    8 bytes  # (Symbol's unique identifier
    args:                  8 bytes  # (Number of arguments the symbol takes (relevant for macros)

METADATA (24 x n_actors bytes)
  metadata_entry:
    owner:                 8 bytes  # (ID of the actor that owns this section
    size:                  8 bytes  # (Size of the code section in bytes
    reserved:              8 bytes  # (Reserved for future use

DATA (8 kB x n_actors bytes)
  code_section:            # (repeated n_actors times)
    code:                  8 kB     # (Actual assembled binary code for the section
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


``` yaml title="RDBF Structure" linenums="1"
HEADER (16 bytes)
  n_actors:               8 bytes  # Number of Actors in the test case (also equals the number of data sections)
  n_inputs:               8 bytes  # Number of inputs in the batch

METADATA (16 x n_actors bytes)
  metadata_entry:         # (repeated n_actors x n_inputs times)
    section_size:         8 bytes  # Size of the data section
    reserved:             8 bytes  # Reserved for future use

DATA (12 x n_actors x n_inputs KB)
  input:                  # (repeated n_inputs times)
    data_section:         # (repeated n_actors times)
      main_area:          4 KB  # Main data area
      faulty_area:        4 KB  # Faulty page area
      reg_init_region:    4 KB  # Register initialization area
```

The file begins with a section containing the number of actors (equal to the number of sections) and the number of inputs in the batch.

Next, the file contains the table of metadata for each data section, which only contains the size of the section.

Finally, the file contains a sequence of data sections, one for each actor in the test case and each input in the batch. The data sections are arranged to mirror the data layout in the sandbox memory (see the [sandbox memory layout](sandbox.md) document for more information).

