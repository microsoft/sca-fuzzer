# Tutorial 4: Testing Security Domain Isolation with Revizor

In the previous tutorials, we used random test generation to find Spectre V1 and LVI-Null by testing against contracts. While contract violations are interesting, the most critical security issues often arise from failures in isolation between different security domains—such as user vs kernel mode, or different virtual machines.

In this tutorial, we'll explore how to use Revizor's template-based fuzzing and multi-actor testing features to evaluate isolation guarantees. Specifically, we'll test whether privileged kernel code can leak information to unprivileged user code through speculative execution.

### Preliminaries

Through this tutorial, you should become familiar with three concepts: actors, templates, and actor non-interference. These concepts are covered in detail in the [Topic Guide: Actors](../../topics/actors.md) and [Howto: Use Templates](../../howto/use-templates.md), but we'll provide a brief overview here.

**Actors** are an abstraction that separates a test case into multiple components, each with its own code, execution context, privilege level, and memory space. This allows us to model scenarios where different parts of the test case run under different security domains. For example, we can define a `kernel` actor that runs in kernel mode and a `user` actor that runs in user mode. While they will have separate memory spaces and are isolated through privilege separation by the CPU, information could still leak from the kernel actor to the user actor through side channels; Revizor helps us detect such leaks.

**Templates** are assembly files that define the high-level structure of test cases. They allow us to specify hard-coded parts of the test case and its actors, while still leaving room for random instruction generation.

Templates are essential for testing isolation because they define how different actors interact. For example, a template can specify that the user actor calls into the kernel actor, which processes secret data, and then returns control to the user actor for observation. This structure is unlikely to be generated through pure randomness, so templates enable targeted testing of specific attack patterns.

**Actor Non-Interference Contract** is a specialized contract that checks whether one actor's execution can influence another actor's observations. In our case, we want to ensure that the kernel actor's processing of secret data does not affect what the user actor can observe through side channels. If the user actor's hardware trace differs based on the kernel actor's secret data, that's a non-interference violation, indicating a potential isolation failure.

### Plan the campaign

Let's imagine we want to test whether a CPU properly enforces isolation between kernel and user mode. Specifically, we want to check if privileged kernel code can leak information to unprivileged user code through speculative execution side channels—attacks like Meltdown exploit exactly this type of isolation failure.

For this campaign, we'll use a two-actor setup: a kernel actor (the victim) that processes secret data, and a user actor (the attacker) that attempts to observe those secrets through side channels. Rather than relying on pure random generation, we'll use a template that explicitly encodes the interaction pattern: the kernel processes data, then transfers control to user mode, where observation code runs. This template-based approach ensures we're testing the specific isolation boundary we care about.

We'll pair this multi-actor test structure with the Actor Non-Interference contract. This contract checks whether the user actor's hardware traces (cache state, timing, etc.) differ based on the kernel actor's input data. If they do, it means information crossed the privilege boundary—a clear isolation failure. Unlike model-based contracts that compare hardware against an idealized model, non-interference testing directly verifies that one actor cannot observe another actor's secrets, which is precisely the security property we want to enforce.

With this campaign plan, we are trying to answer a specific question: "Can unprivileged code observe secrets from privileged code through speculative side channels?"


### Create the configuration file

```yaml
# contract for isolation testing
contract_observation_clause: ct-ni

# instruction categories
instruction_categories:
  - BASE-BINARY

# actor configuration
actors:
  - main:
      - privilege_level: "kernel"
      - observer: false
  - user:
      - privilege_level: "user"
      - observer: true

# filters
enable_speculation_filter: true
enable_observation_filter: true
enable_fast_path_model: true
```

This configuration introduces several important concepts. The `contract_observation_clause` is set to `ct-ni`, which tells Revizor to use the Actor Non-Interference check instead of the standard model-based testing.

The `actors` section defines two execution contexts. The `main` actor runs in kernel mode (`mode: kernel`) and has `observer: false`, meaning it's the victim whose secrets might leak. The `user` actor runs in user mode (`mode: user`) and has `observer: true`, meaning it's the attacker trying to observe kernel secrets through side channels.

For more details on actor configuration, see [Topic Guide: Actors](../../topics/actors.md).

### Create the template

Now we need a template that exercises the kernel-user boundary. Create `template.asm`:

``` asm
.intel_syntax noprefix

# ----------------------------- Kernel-mode Actor (Victim) -------------------
.section .data.main
.function_main_1:
    # random code of the victim
    .macro.random_instructions.16.8.main_1:

    # switch to user actor to observe
    .macro.set_k2u_target.user.function_user_1:
    .macro.set_u2k_target.main.function_main_2:
    .macro.switch_k2u.user.1:

.macro.fault_handler:
    # one more call to the user to complete the measurement in case of a fault
    .macro.set_k2u_target.user.function_user_2:
    .macro.set_u2k_target.main.function_main_3:
    .macro.switch_k2u.user.2:

# return point for the user actor
.function_main_2:
    .macro.landing_u2k.main_2:

# exit
.function_main_3:
    .macro.landing_u2k.main_3:
    nop

# ----------------------------- User-mode Actor ------------------------------
.section .data.user
.function_user_1:
    # reset registers to ensure we're not observing leftover state
    .macro.landing_k2u.user_1:
    xor rax, rax  # noremove
    mov rax, qword ptr [r14 + 0x2000] # noremove
    mov rbx, qword ptr [r14 + 0x2008] # noremove
    mov rcx, qword ptr [r14 + 0x2010] # noremove
    mov rdx, qword ptr [r14 + 0x2018] # noremove
    mov rsi, qword ptr [r14 + 0x2020] # noremove
    mov rdi, qword ptr [r14 + 0x2028] # noremove
    lfence

    # attacker code to observe side effects
    .macro.measurement_start:
    .macro.random_instructions.16.8.user_1:
    .macro.measurement_end.1:

    # switch back to kernel actor
    .macro.switch_u2k.main.1:

# second measurement call; for the cases when the first one was bypassed by a fault
.function_user_2:
    .macro.landing_k2u.user_2:
    .macro.measurement_end.2:
    .macro.switch_u2k.main.2:
    lfence

# ----------------------------- Exit -----------------------------------------
.section .data.main
.test_case_exit:
```

Let's break down this template block by block to understand how it orchestrates the kernel-user isolation test:

**Kernel Actor - Initial Execution (`function_main_1`)**

```asm
.section .data.main
.function_main_1:
    .macro.random_instructions.16.8.main_1:
```

The template begins in the kernel actor's code space (`.section .data.main`). The `.macro.random_instructions.16.8.main_1` macro generates 16 random instructions with an average of 8 memory accesses. This randomized kernel code represents the victim's execution.

**Transition Setup - Kernel to User**

```asm
    .macro.set_k2u_target.user.function_user_1:
    .macro.set_u2k_target.main.function_main_2:
    .macro.switch_k2u.user.1:
```

These macros configure and execute a privilege level transition. The `set_k2u_target` macro specifies that when dropping to user mode, execution should begin at `function_user_1` in the `user` actor. The `set_u2k_target` macro specifies that when returning to kernel mode, execution should resume at `function_main_2` in the `main` actor. Finally, `switch_k2u` performs the actual privilege drop, transferring control to user mode. The `.1` suffix is a unique label for this transition.

**Kernel Actor - Return Point (`function_main_2`)**

```asm
.function_main_2:
    .macro.landing_u2k.main_2:
    .macro.fault_handler:
```

This is where the kernel resumes after the user actor returns control. The `landing_u2k` macro handles the privilege escalation transition, restoring the kernel execution context. The `fault_handler` macro designates this location as the exception handler—if any faults occur during execution (in either actor), control transfers here.

**Second Transition - Kernel to User Again**

```asm
    .macro.set_k2u_target.user.function_user_2:
    .macro.set_u2k_target.main.function_main_3:
    .macro.switch_k2u.user.2:
```

The kernel performs another transition to user mode, this time to `function_user_2`. This is necessary because, if the random code in the user actor triggers a fault, the `measurement_end` may never be reached, and the hardware trace would be corrupted. By splitting the measurement into two parts, we ensure that even if a fault occurs during the first measurement, we can still capture whatever trace was collected up to that point.

**Kernel Actor - Exit (`function_main_3`)**

```asm
.function_main_3:
    .macro.landing_u2k.main_3:
    nop
```

The final kernel return point. After the second user-mode measurement completes, execution returns here and falls through to the test case exit.

**User Actor - First Observation (`function_user_1`)**

```asm
.section .data.user
.function_user_1:
    .macro.landing_k2u.user_1:
    xor rax, rax  # noremove
    mov rax, qword ptr [r14 + 0x2000] # noremove
    mov rbx, qword ptr [r14 + 0x2008] # noremove
    ...
    lfence
```

This is where the attacker code executes. The `landing_k2u` macro handles the privilege drop transition, setting up the user execution context. The explicit register initialization loads fresh values from memory (via `r14`, which points to the sandbox memory). The `# noremove` comments prevent Revizor's minimization passes from removing these instructions—they're essential for resetting architectural state. The `lfence` ensures these loads complete before observation begins, preventing them from affecting the measurement.

**User Actor - Measurement**

```asm
    .macro.measurement_start:
    .macro.random_instructions.16.8.user_1:
    .macro.measurement_end.1:
```

The `measurement_start` macro marks where hardware trace collection begins. Only code between `measurement_start` and `measurement_end` contributes to the observed side-channel trace. The random instructions here represent attacker code that might be sensitive to cache state, timing variations, or other microarchitectural side effects left by the kernel's execution. The `.1` suffix distinguishes this measurement from the second one.

**User Actor - Return to Kernel**

```asm
    .macro.switch_u2k.main.1:
```

The `switch_u2k` macro performs a privilege escalation, returning control to the kernel actor. This transition was pre-configured earlier by the `set_u2k_target` macro.

**User Actor - Second Observation (`function_user_2`)**

```asm
.function_user_2:
    .macro.landing_k2u.user_2:
    .macro.measurement_end.2:
    .macro.switch_u2k.main.2:
    lfence
```

The second user-mode entry point completes the measurement that was started in `function_user_1`.

### Run the isolation test

Execute the multi-actor fuzzing campaign:

```bash
./revizor.py tfuzz -s base.json -c config.yaml -t template.asm -n 1000 -i 10 -w .
```

We're running 1000 test cases with 10 inputs each. Multi-actor testing often requires more iterations to find violations because we're looking for interactions between actors, which adds complexity.

The fuzzer will run and search for isolation violations. On most systems, you will not find a violation; isolation mechanisms are generally robust. We will need to try harder to find issues.

```
Duration: 60.5
Finished at 08:44:40
```

### Adding Faults

Now let's add a little more complexity to the experiment. We will make the attacker "active" by allowing the user actor to try and access the memory of the kernel actor. This simulates an attacker that attempts to read privileged memory, which should be blocked by the CPU's privilege separation.

To do this, we will use a generator pass that is specifically designed for this purpose. The `user-to-kernel-access` pass randomly selects a memory access from the user actor's code and modifies it to access the kernel actor's memory space. This creates a faulting access that the CPU should prevent.

Update the configuration file to include this generator pass:

```yaml
faults_allowlist:
  - user-to-kernel-access

# actor configuration
actors:
  - main:
      - privilege_level: "kernel"
      - observer: false
      - fault_blocklist:
        - user-to-kernel-access
  - user:
      - privilege_level: "user"
      - observer: true
```

Note that we also added a `fault_blocklist` to the kernel actor. This is done to prevent redundant work on the generator side; there is no point in making kernel access its own memory.

### Run the fuzzer with faults enabled

Run the fuzzer again with the updated configuration:

```bash
./revizor.py tfuzz -s base.json -c config.yaml -t template.asm -n 5000 -i 10 -w .
```

This time, with the user actor actively trying to access kernel memory, we have a higher chance of provoking isolation violations.

If you're testing a system vulnerable to Meltdown, you should see a violation reported:

```
================================ Violations detected ==========================
Violation Details:

-----------------------------------------------------------------------------------
                             HTrace                              | ID:3   | ID:13 |
-----------------------------------------------------------------------------------
^^.^.......^.........^..^.........................^............^ | 627    | 0     |
^^.^...^...^............^.........................^............^ | 0      | 627   |
```

Validate and minimize the violation, as we've done in the previous tutorials.

As a result, you should obtain a minimized test case that contains a typical Meltdown pattern: the user actor attempts to read kernel memory, which causes a fault, but speculative execution allows some of the kernel data to leak through side channels, and thus impact the user's hardware traces.

!!! success "What We've Learned"
    In this tutorial, we've progressed from random fuzzing to structured testing:

    - **Templates provide structure**: When testing specific attack scenarios, templates let us encode the essential pattern while still benefiting from randomization
    - **Macros control generation**: The macro system gives fine-grained control over what code gets generated and where
    - **Multi-actor testing**: Revizor can test isolation between different privilege levels or security domains using the actor system
    - **Noninterference contract**: This specialized contract detects when one actor's data influences another actor's observations

### What's Next?

This concludes our tutorials on using Revizor for security testing. Note that all examples in the tutorials were simplified for clarity. If you wish to explore more realistic scenarios, refer to our guide on [Design a Campaign](../../howto/design-campaign.md) or check an advanced tutorial on [Detecting TSA-SQ](./tsa-sq.md).

Proceed to [Tutorial 5](./05-extending.md) to learn how you can extend various components of Revizor to fit your research needs.
