# Actors

Actors represent distinct security domains within a test case. They could be thought as sub-test-cases, each with its own code, data, execution context, and privilege level.

The main use case for actors is to test interactions and isolation boundaries between security domains. A typical example would be testing kernel-to-user isolation by defining a two-actor test case: one actor runs in kernel mode (the "main" actor), and the other runs in user mode (the "user" actor). The user actor attempts to observe information about the main actor's execution, simulating an attacker trying to leak sensitive kernel data.

By using this mechanism, Revizor can stress-test isolation boundaries by executing lots of randomly generated code on both sides of the boundary and checking for secret-dependent observations on the attacker side.
This mechanism discovered several critical vulnerabilities in production CPUs, most notably Transient Scheduler Attacks in AMD processors, and enables testing of mitigations for Meltdown, Foreshadow, and MDS.

## What is an Actor?

An actor consists of three components:

- Code region associated with a specific execution context
- Private data memory with configurable permissions and properties
- Execution context defined by CPU mode (host/guest), privilege level (kernel/user), and system configuration

Every test case starts with a default actor called `main` that runs in host kernel mode. This actor can transition to other actors using dedicated `switch_*` macros.

## Actor Configuration

Actors are defined in the configuration file under the `actors` section:

```yaml
actors:
  - main:                       # Default main actor
    - mode: "host"              # Always host for main;
                                # changing to "guest" will produce an error
    - privilege_level: "kernel" # Always kernel for main;
                                # changing to "user" will produce an error

  - user:                       # Example user-mode actor
    - mode: "host"
    - privilege_level: "user"
    - data_properties:          # Custom page table properties of the faulty page
      - writable: false         # Faulty page of the user actor is read-only
```


!!! note "Related Documentation"
    See the [configuration documentation](../ref/config.md#actor) for a full list of available options.

## Actor Templates

Multi-actor execution requires template-based mode. Templates define actors along with their code and data sections.

Transitions between actors use dedicated macros for setting entry and exit points, switching contexts, and defining landing locations. Macros are available for kernel-user transitions (`.set_k2u_target`, `.switch_k2u`, etc.) and host-guest transitions (`.set_h2g_target`, `.switch_h2g`, etc.).

!!! note "Related Documentation"
    See [Macro Reference](../ref/macros.md#transition-macros) for detailed descriptions of all transition macros.


## Actor Non-Interference Contract

Revizor uses the Actor Non-Interference contract to verify isolation between security domains. The contract designates one or more actors as observers (attackers) and verifies that observer execution does not depend on data from victim actors.

The contract permits leakage of victim memory access addresses and control flow, but prohibits leakage of data values. This design filters cache-based leakage typically considered benign in modern systems while detecting unexpected microarchitectural leaks. Victim actors follow the ct-seq contract, while observers can expose all their own data.

A violation occurs when observer traces depend on victim data beyond permitted address and control-flow information.

!!! note "Additional Reading"
    The Actor Non-Interference contract is explained in detail in the paper called [Enter, Exit, Page Fault, Leak: Testing Isolation Boundaries for Microarchitectural Leaks](https://www.microsoft.com/en-us/research/wp-content/uploads/2025/07/Enter-Exit-SP26.pdf).


## Example Usage

The following example demonstrates kernel-to-user isolation testing with the Actor Non-Interference contract.

Template with kernel and user actors:

```asm
.intel_syntax noprefix

# ---------------- Main (Kernel) Actor ---------
.section .data.main
.function_main_0:
    # Set up user transition
    .macro.set_k2u_target.user.function_user_0:
    .macro.set_u2k_target.main.function_main_1:

    # Generate random kernel code
    .macro.random_instructions.32.0:

    # Transition to user mode
    .macro.switch_k2u.user.0:

.function_main_1:
    .macro.landing_u2k.main_1:
    # Back in kernel, clean up and exit
    nop

.test_case_exit:

# ---------------- User Actor -----------------
.section .data.user
.function_user_0:
    .macro.landing_k2u.user_0:

    # Start measurement in user mode
    .macro.measurement_start:

    # Generate random user code
    .macro.random_instructions.16.1:

    # End measurement
    .macro.measurement_end:

    # Return to kernel
    .macro.switch_u2k.main.0:

```

Configuration file:

```yaml
actors:
  - main:
      mode: host
      privilege_level: kernel
  - user:
      mode: host
      privilege_level: user
      observer: true              # User is the attacker
      data_properties:
        writable: false           # Trigger page faults on writes

contract_observation_clause: load+store+pc
contract_execution_clause: noninterference
```

In this configuration, the user actor attempts to observe information from the kernel (main actor). The contract specifies that the user can observe memory addresses and control flow (load+store+pc) but not data values. Any leakage beyond this triggers a violation.

