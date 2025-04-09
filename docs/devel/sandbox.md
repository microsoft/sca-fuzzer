# Test Case Sandbox

This document describes the isolated environment for executing test cases, which is referred to as the *sandbox*. The sandbox contains the test case code and data, and the test case code is confined to access memory only within the sandbox.

The sandbox is implemented by all modules that execute test cases, including the executor (kernel module) and all model backends (Unicorn, DynamoRIO).
To ensure that the executions are consistent across all modules, the sandbox is structured in the same way in all the modules.

This document describes the memory layout of the sandbox, the initialization of the sandbox memory, and the fault isolation mechanism.

## Memory Layout

The sandbox memory is divided into two main areas: the data sandbox and the code sandbox.
Each actor in the test case has its own sub-area for its data and code, and the layout of these areas is the same for all actors.

### Data Layout

```plaintext
|----------|--------------------|
| ACTOR 0  | MACRO STACK        | 64 B
|          |--------------------|
|          | UNDERFLOW PAD      | 4032 B
|          |--------------------|
|          | MAIN AREA          | 4096 B
|          |--------------------|
|          | FAULTY AREA        | 4096 B
|          |--------------------|
|          | GPR AREA           | 64 B
|          |--------------------|
|          | SIMD AREA          | 256 B
|          |--------------------|
|          | OVERFLOW PAD       | 3776 B
|----------|--------------------|
| ... (repeat for all actors in the test case)

```

The data area is divided into the following regions:
* **Main and Faulty Areas**: These are the two regions of memory that are accessible by the test case code.
  This is enforced by the test case generator, which instruments all memory accesses to ensure that they fall within these regions (see [code-generation](code-generation.md) for more details).
  Both areas are initialized with the input data from the [RBDF](binary-formats.md).
  The main area always has default permissions (RW), while the faulty area has permissions can be configured to cause a fault when accessed.
  This configuration originates from the [config file](../user/config.md).
* **GPR and SIMD Areas**: These regions store the values that will be used by the modules to initialize the general-purpose registers (GPR) and SIMD registers before executing the test case and when switching between actors.
  Both areas are initialized with the input data from the [RBDF](binary-formats.md).
* **Over- and Underflow Pads**: These two zero-initialized regions surround the actors' data areas, and their purpose is to determinize the hardware traces on the executor.
  Namely, they are needed for the cases when the CPU speculatively bypasses the sandboxing instrumentation inserted by the test case generator, and the bypass leads to an out-of-bounds memory access.
  As the pads are zero-initialized, the bypassed memory accesses will produce deterministic results.
* **Macro stack**: This region is used to implement complex macros (e.g., VMENTER) that need to save and restore data on the stack with a guarantee that this data won't be corrupted by the following (randomly-generated) instructions (see [macros](macros.md) for more details.)

### Code Layout

```plaintext
|----------|--------------------|
| ACTOR 0  | MAIN CODE AREA     | 8192 B
|          |--------------------|
|          | MACRO CODE AREA    | 4096 B
|----------|--------------------|
| ... (repeat for all actors in the test case)
```

The code area is divided into two regions:
* **Main Code Area**: This region contains the binary of the actor's code.
  The code comes from the [RCDF](binary-formats.md) file.
  The first instruction in the code area of actor 0 is the entry point of the test case, and the last instruction of actor 0 is the exit point of the test case.
* **Macro Code Area**: This region contains code of the expanded macros for each actor.
  (see [macros](macros.md) for more details on the macro expansion process.)

### References

* Executor: [rvzr/executor_km/include/sandbox_manager.h](https://github.com/microsoft/sca-fuzzer/tree/main/rvzr/executor_km/include/sandbox_manager.h)
* Unicorn backend: [rvzr/sandbox.py](https://github.com/microsoft/sca-fuzzer/tree/main/rvzr/sandbox.py)

## Sandbox Initialization

The sandbox is initialized based on the test case code (normally in RCBD format) and the input data (normally in RDBF format).
The following diagram shows the mapping between the RCBF/RDBF files and the sandbox memory layout:

```plaintext
                                        |--------------------|
                   zero initialized ->  | MACRO STACK        |
                                        |--------------------|
                   zero initialized ->  | UNDERFLOW PAD      |
                                        |--------------------|
      RDBF.data[actor_id].main_area ->  | MAIN AREA          |
                                        |--------------------|
    RDBF.data[actor_id].faulty_area ->  | FAULTY AREA        |
                                        |--------------------|
RDBF.data[actor_id].reg_init_region ->  | GPR AREA           |
                                        |--------------------|
RDBF.data[actor_id].reg_init_region ->  | SIMD AREA          |
                                        |--------------------|
                   zero initialized ->  | OVERFLOW PAD       |
                                        |--------------------|


     RCBF.tc_section[actor_id].code ->  | MAIN CODE AREA     |
                                        |--------------------|
     expanded macro code (executor) ->  | MACRO CODE AREA    |
```

## Fault Isolation

UNDER CONSTRUCTION
