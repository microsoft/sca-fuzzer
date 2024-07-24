# Register Allocation

The test cases are executed in a sandboxed environment, some of the registers are reserved for internal use, and some are available for use in the test cases.
Below is a list of registers and their purpose.

## `R15`

Contains the base address of the UTILITY area in the [sandbox](./docs/sandbox.md).

If the test case does not enter a VM, the register value remains constant during the execution of the test cases.
Otherwise, the register value is updated to point to the UTILITY area of the currently active VM when the `switch_h2g` macro is called, and it is restored to the original value when the `switch_g2h` macro is called.

The register is used by internal functions, such as the implementation of Prime+Probe.

## `R14`

Contains the base address of the current actor's [sandbox](./docs/sandbox.md) (namely, it points to the base of the actor's MAIN area).

At the beginning of the test case execution, the register is set to the base address of the MAIN area of the first actor (actor `main`). The register value is updated to point to the MAIN area of the currently active actor when a macro from the `landing_*` group of macros is called. It is also updated by the `fault_handler` macro.

The register is used in test cases as a part of the sandboxing mechanism.
For example, all generated memory accesses are relative to the value stored in `R14`, and have the form of `[R14 + offset]`.


## `R13` (`HTRACE_REGISTER` constant in the kernel module)

Contains either intermediate or final result of the hardware trace measurements.

Before entering the test case, the register is set to 0.
When a `measurement_start` macro is executed, the register is (optionally) set to the starting value,
such a initial reading of time stamp counter when the `TSC` mode is used.
When a `measurement_end` macro is executed, the register is updated with the final value of the measurement and contains the resulting hardware trace.

## `R12` (`STATUS_REGISTER` constant in the kernel module)

Contains a compressed status of the test case execution:

Bits[0:7] contain a measurement status.
At the beginning of the test case execution, the bits are set to 0.
When `measurement_start` macro is executed, the bits are set to 1.
When `measurement_end` macro is executed, the bits are set to 2.
If the measurement status is not 2 at the end of the test case execution, the kernel module will report an error.

Bits[8:31] are unused.

Bits[32:63] contain a counter of SMI (System Management Interrupt) events.
The counter is set automatically before entering the test case (`READ_SMI_START`), and updated when the test case finishes (`READ_SMI_END`).
If the difference between the readings is not 0, the kernel module will report an error.

## `R11`

The register is used as a temporary buffer by some of the macros.

Before entering the test case, the register is set to 0.
When certain macros are executed (e.g., `set_k2u_target`), the register will contain temporary values.
The register should not be used in the test case, as the temporary value may be consumed by latter macros.

## `R10, R9, R8`

Stores the values of performance counters.
`R10` stores the value of performance counter #1, `R9` stores the value of performance counter #2, and `R8` stores the value of performance counter #3.

Before entering the test case, the registers are set to 0.
When a `measurement_start` macro is executed, the registers are (optionally) set to the starting values.
When a `measurement_end` macro is executed, the registers are updated with the final values of the measurements.


## Other General Purpose Registers

The remaining registers (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `rflags`) are available for use in the test cases and can be modified freely.
A special case are `rsp` and `rbp`, which can be used in the test cases, but their values must always remain within the sandbox (see [Sandbox](./docs/sandbox.md)).

## Vector Registers

Vector registers (`xmm0`-`xmm15`) are also available for use in the test cases.
However, only `xmm0-xmm7` are initialized with input-based values, and the remaining registers are always zero-initialized.

Large-size vector registers (`ymm` and `zmm`) are not supported.
