# Actors

Actors in Revizor are a concept that allows to test for information leaks across different security domains, such as leakage from OS kernel to user space, or from one virtual machine to another. They represent distinct execution contexts with specific isolation properties, enabling the detection of microarchitectural vulnerabilities across these boundaries.

Despite the relative complexity of their usage, actors have proven to be the most powerful feature of Revizor, as they allowed us to discover a number of critical vulnerabilities in real-world CPUs, most notably the Transient Scheduler Attacks (TSA) in AMD CPUs. This concept also allows to test mitigations against such high-profile vulnerabilities like Meltdown, Foreshadow, and MDS.

## What is an Actor?

An actor is an abstraction that encompasses:

- **Code region**: A part of the test case program that is associated with a specific execution context
- **Data region**: Private data memory with configurable permissions and properties
- **Execution context**: CPU mode (host/guest), privilege level (kernel/user), and system configuration

In other words, a test case can be split into multiple isolated sections with associated data and CPU configurations, and each such section is called an actor.

Every test case in Revizor always contains one actor by default, called `main`, which is executed in the host kernel mode and contains the entry and exit points of the test case. Any additional actors are optional, and can be reached only through special macros that handle transitions between different execution contexts.

## Actor Configuration

Actors are defined in the configuration file under the `actors` section:

```yaml
actors:
  - main:                      # Default main actor
    - mode: "host"              # Always host for main;
                                # changing to "guest" will produce an error
    - privilege_level: "kernel" # Always kernel for main;
                                # changing to "user" will produce an error

  - user:                      # Example user-mode actor
    - mode: "host"
    - privilege_level: "user"
    - data_properties:        # Custom page table properties of the faulty page
      - writable: false       # Faulty page of the user actor is read-only
```

Available properties for each actor include:

* `mode`: Virtualization mode of the actor
    - `host`: Normal, non-virtualized execution
    - `guest`: Runs in a virtual machine (each guest actor is another VM)
* `privilege_level`: CPL of the actor
    - `kernel`: Ring 0 execution (CPL=0)
    - `user`: Ring 3 execution (CPL=3)
* `data_properties`: A list of properties that define the permissions and attributes of the actor's faulty data area (see [sandbox](../devel/sandbox.md) for an explanation of the faulty area).
    - `present`: Page present bit (true for present, false for not present)
    - `writable`: Page writable bit (true for writable, false for read-only)
    - `user`: User/Supervisor bit (true for user-accessible, false for supervisor-only)
    - `accessed`: A-bit value of the page table entry (true if 1, false if 0)
    - `dirty`: D-bit value of the page table entry (true if 1, false if 0)
    - `reserved_bit`: Reserved bit (true if 1, false if 0)
    - `executable`: Execute bit (true if executable, false if not)
    - `randomized`: If true, the properties are randomized per test case execution (use `false` for deterministic testing)
* `data_ept_properties`: A list of properties that define the Extended Page Table (EPT) attributes for guest actors. The list of properties is similar to `data_properties`, but applies to the EPT entries instead of the page table entries.
* `observer`: A boolean flag indicating whether the actor is an observer. Used to determine the threat model when testing [Non-Interference contracts](#actor-non-interference-contract).
    - `true`: Actor is an attacker that can observe data leaks
    - `false`: Actor is a victim or neutral party that does not observe leaks

## Actor Templates

Multi-actor execution is supported only in the [template-based mode](../user/templates.md), where actors are defined in the test case template. Each actor can have its own code and data sections, and transitions between actors are handled by macros.

For example, a template with two actors (kernel and user) might look like this:

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

### Transition Macros

The following macros are available for performing transitions between actors.

**Kernel-User transitions:**

`.set_k2u_target`: Set the target for the user entry point; must be executed in a kernel actor

* argument 1: Name of the user actor
* argument 2: Name of the user function to jump to

`.set_u2k_target`: Set the target for the kernel return point; must be executed in a kernel actor

* argument 1: Name of the kernel actor
* argument 2: Name of the kernel function to jump to

`.switch_k2u`: Perform the transition from kernel to user mode; must be executed in a kernel actor

- argument 1: Name of the user actor

`.switch_u2k`: Perform the transition from user to kernel mode; must be executed in a user actor

- argument 1: Name of the kernel actor

`.landing_k2u`: Define the landing point in user mode

- no arguments

`.landing_u2k`: Define the landing point in kernel mode

- no arguments

**Host-Guest transitions:**

`.set_h2g_target`: Set the target for the guest VM entry point; must be executed in a host actor

- argument 1: Name of the guest actor
- argument 2: Name of the guest function to enter

`.set_g2h_target`: Set the target for the host VM exit point; must be executed in a guest actor

- argument 1: Name of the host actor
- argument 2: Name of the host function to return to

`.switch_h2g`: Perform the transition from host to guest mode; must be executed in a host actor

- argument 1: Name of the guest actor

`.switch_g2h`: Perform the transition from guest to host mode; must be executed in a guest actor

- argument 1: Name of the host actor

`.landing_h2g`: Define the landing point in guest mode

- no arguments

`.landing_g2h`: Define the landing point in host mode

- no arguments

## Actor Non-Interference Contract

The typical scenario for actors is to test isolation between different security domains. For this purpose, Revizor provides a special contract called **Actor Non-Interference**.

Actor Non-Interference contract assumes that (at least one) actor is an observer, and the contract states that the traces collected by the observer actor do not contain any information from the non-observer actors. Or in simpler terms, the observer's execution should not depend on the execution of non-observer actors. And conversely, if Revizor finds a test case where the observer's traces depend on some data from a non-observer actor, it will report a violation.

In practice, we use a slightly modified version of the contract which permits leakage of the non-observer actor's memory accesses and control flow, but not of the raw data values. Essentially, it means that the non-observer actors follow the classical `ct-seq` contract while the observer actor expose all their data. This is done to filter out cases of cross-domain leakage through the cache state, which are typically assumed benign in current software systems. You can read more about the contract and the motivation behind it our paper [Enter, Exit, Page Fault, Leak: Testing Isolation Boundaries for Microarchitectural Leaks](https://aka.ms/enter-exit-leak).

