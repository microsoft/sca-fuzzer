# Primer on Speculation Contracts

> Author: Oleksii Oleksenko | Last Updated: 2025-04-01

Below is a brief primer on the theoretical foundations of speculation contracts and model-based relational testing—concepts that underlie the Revizor tool. This primer provides a high-level overview of the topic, introducing the concepts of noninterference, speculation contracts, and model compliance.

This document is intended for those new to the topic, particularly people without a background in information-flow analysis. For a more detailed and technical explanation, refer to the[original contracts paper](https://arxiv.org/pdf/2006.03841).

## Information-Flow Properties

We will start with the basics: the concepts of confidentiality and noninterference, which are fundamental to understanding how speculation contracts work.

Traditionally, security mechanisms like access control and encryption have focused on protecting data at rest or in transit. However, these mechanisms do not address the problem of **information flow** within a system. For example, consider a program that reads a secret input and then writes it to a public output (e.g., a file or a network socket). Even if the program is secure in the sense that it does not allow unauthorized access to the secret data, it may still leak the secret through its public output. This is where **information-flow security** comes into play.

Information-flow security is concerned with how data moves through a computation and how it can be observed by an attacker. The goal is to ensure that secret (high-security) information does not leak to observers who lack clearance (note: this research field originates from the military, hence the jargon). An *end-to-end confidentiality policy* might be stated as: *“No secret input data can be inferred by an attacker through observations of system output.”* In other words, even if an adversary can see all public outputs of a computation, they should learn nothing about the secret inputs.

**Information-flow properties** generally classify program variables or inputs/outputs into security levels (e.g., `High` for secret, `Low` for public). The key property for confidentiality is that *no information flows from High to Low.* But how can information flow? There are two primary routes:

- **Explicit flows:** These occur when confidential data is directly assigned or passed into a public variable or output. For example, in code, writing `low = high` is an explicit flow from a high variable to a low variable (an obvious violation of confidentiality). Any mechanism that directly transfers the bits of a secret into a publicly observable sink is an explicit flow. Such flows are usually straightforward to detect.

- **Implicit flows:** These occur indirectly, through the control structure of the program. An implicit flow arises when the *control path* taken by a program (e.g., which branch of an `if` or how many loop iterations) depends on a secret, thereby implicitly leaking information. Consider this pseudocode example:

  ```pseudo
  if (H == 0) {
      L = 0;
  } else {
      L = 1;
  }
  ```
  Here `H` is a high (secret) input and `L` is a low (public) output. There is no direct assignment of `H` to `L`. However, an observer of `L` can deduce information about `H`. In fact, this program sets `L` to 0 if `H` was 0; otherwise, it sets `L` to 1—effectively copying the one-bit information “is H zero?” into `L`. This is an **implicit flow** of information from `H` to `L` through the control structure (the `if` condition on `H`). It has *“the same effect as the explicit flow”* of directly assigning that bit. Even if a runtime mechanism prevents explicit `H->L` assignment (flagging it as a security violation), the mere fact that the `if` condition was true or false can leak `H`. For instance, if no assignment to `L` occurs because `H != 0`, an attacker might notice that `L` retains its old value and thereby infer something about `H`. Implicit flows are more subtle and require analyzing the program’s structure to detect where control decisions depend on secrets.

## Noninterference: Definition and Examples

**Noninterference** is a formal property that captures the idea of perfect confidentiality: changes in secret data have *no observable effect* on public outputs. This term was formalized by Goguen and Meseguer in 1982 as a simple but powerful security policy: *“one group of users ... has no effect on what the second group of users can see.”* In practice, we often phrase it in terms of `High` and `Low` data: *"a system is noninterferent if variations in High inputs cause no differences in Low outputs"*. Equivalently, confidential inputs do not interfere with the publicly visible state of the system.

To make this more concrete, imagine we run a program twice with two different secret inputs but the same public inputs. If **no attacker can distinguish** the two runs by observing anything public, then the program satisfies the noninterference property. The “attacker” here is assumed to have complete access to all Low outputs. Noninterference essentially demands that for any two secrets `H1` and `H2` and any public input `L`, the program’s behavior from an attacker’s perspective is identical when run on `(H1, L)` versus `(H2, L)`. Formally, if we denote by `LowOut(H, L)` the observable output (and behavior) given public input `L` and secret `H`, then noninterference means: for all `L, H1, H2`, if `H` is the same, then `LowOut(H1, L) = LowOut(H2, L)`. In Goguen and Meseguer’s original formulation, this was expressed via state machine runs and equivalence relations on states, but the intuition remains the same.

**Definition 1 (Noninterference)**: A program `P` is noninterferent if, for all public inputs `L` and all secret inputs `H1`, `H2`, if `H1 = H2`, then `LowOut(P, H1, L) = LowOut(P, H2, L)`.

Here are some examples to illustrate this principle:

- *Example 1 (Interfering program)*: Suppose our program simply copies a secret to output: `Low = High`. Running it with two different secrets clearly yields different public outputs (e.g., `Low` becomes 5 in one run and 7 in another). An attacker would distinguish these runs, so the program is **not** noninterferent—it blatantly leaks information.

- *Example 2 (Noninterfering program)*: A trivial example of a noninterferent program is one that produces no output dependent on the secret. For instance:

  ```pseudo
  // High = secret input, Low = public output
  Low = 0
  ```
  This program ignores `High` entirely and always sets `Low` to 0. No matter what the secret input is, the public output is constant (0), so an attacker gains no information about `High`. Indeed, any two runs are indistinguishable (both runs output 0). This satisfies noninterference (albeit by doing nothing useful with the secret).

- *Example 3 (Allowed benign dependency)*: It is possible for a program to use secret data internally yet still be noninterferent as long as the final low outputs don’t reveal those secrets. For instance:

  ```pseudo
  temp = High * 0   // multiply secret by 0
  Low  = temp
  ```

  Here the program *did* read the secret (`High`) and even manipulated it, but it “washed out” the secret by multiplying by 0. The value assigned to `Low` is always 0. From an external view, this is just like the previous example—no dependence of `Low` on `High`. Noninterference is concerned only with *what can be observed by the attacker*, not with whether the program internally used the secret. As long as any use of the secret eventually has no effect on outputs, the policy holds.

One important insight is that noninterference is relative to a given specification of what is “observable.” If you consider only the functional outputs as observable, a program might be noninterferent in that model. But if in reality the attacker can observe more (like timing), then a program that was secure in theory might be insecure in practice. This leads us to examine how *side channels* break the assumptions of basic noninterference.

## Beyond Direct Outputs: Side Channels

The original works on information-flow properties focused on direct outputs of a program (e.g., writing to a file or a network socket). However, in practice, attackers can extract information from more than just the “official” outputs of a program. For example, the attacker might observe how long a computation takes or measure the power consumption of a device. Lampson (1973) introduced the concept of **side channels** to describe these additional sources of information leakage. Side channels are unintended channels through which secret data can be inferred by observing the system’s behavior, even if the direct outputs are secure.

These side channels can reveal information about the secret inputs, and so we must include them in the definition of noninterference. Similarly to how we defined `LowOut` as the observable output, we can define `Trace(H, L)` as the observable side-channel information. For example, a trace might be the execution time of a program or its cache access pattern. Noninterference then requires that the traces of two runs with different secrets are indistinguishable to an attacker. This is a stronger requirement than just looking at the functional outputs.

**Definition 2 (Side-Channel Noninterference)**: Given a side channel that produces a trace `Trace`, a program `P` is noninterferent with respect to this side channel if, for all public inputs `L` and all secret inputs `H1`, `H2`, if `H1 = H2`, then `Trace(P, H1, L) = Trace(P, H2, L)`.

Here are some examples of side channels and how they can violate noninterference:

- *Example 4 (Timing side channel)*: Consider a program that reads a secret password and compares it to a known password, as in the following code:

```c
bool check_password(const char *attempt, const char *actual) {
    for (int i = 0; i < length(actual); i++) {
        if (attempt[i] != actual[i]) {
            return false;  // mismatch found, return early
        }
    }
    return true; // all characters matched
}
```

  If the attacker can measure how long the function takes to reject a guess, they can infer the password one character at a time. This leakage surfaces as a violation of the noninterference property with respect to timing observations. A counterexample to **Definition 2** might be: Let's say we have two inputs with the same `High` value `actual1="aaa"` but different `Low` values `attempt1="abc"` and `attempt2="aab"`. The traces of these inputs will be `trace1 = Trace(attempt1, actual1) = 1` and `trace2 = Trace(attempt2, actual1) = 2`, respectively. These inputs constitute a violation of **Definition 2**, as `trace1 != trace2` even though the two inputs have the same `High` value.

- *Example 5 (Cache side channel)*: Consider a program that uses a secret value to index into an array, as in the following code:

```c
int multiply(const char *array, int low, int high) {
    char x = array[high];
    return x * low;
}
```

  Recent works on *microarchitectural side channels* have discovered that memory accesses of such a program could reveal information to an attacker running on the same hardware. For example, by using a Prime+Probe or Flush+Reload attack, an attacker can observe the cache access pattern and thus infer the secret value. If we assume a typical L1D cache, then the accessed cache line ID is based on the memory access address `addr` as `line_id = (addr % 0x1000) // 0x40`. For such a cache, a counterexample to **Definition 2** would be two inputs, `input1={array=0x10000, low=1, high=0x40}` and `input2={array=0x10000, low=1, high=0x80}`. These inputs will access different addresses in the cache, `addr1 = 0x10000 + 0x40 = 0x10040` and `addr2 = 0x10000 + 0x80 = 0x10080`, respectively. As a result, the cache traces will be different: `trace1 = Trace(input1) = (0x10040 % 0x1000) // 0x40 = 1` and `trace2 = Trace(input2) = (0x10080 % 0x1000) // 0x40 = 2`. Since we have two inputs that match on the `High` value but differ on the cache trace, this constitutes a violation of **Definition 2**.

## Speculation Contracts: Dealing with the Complexity of Modern Hardware

Despite its completeness, the above formalization of side-channel noninterference is too simplistic to faithfully capture the side effects of program execution on modern, highly optimized hardware, especially CPUs. There are two key challenges:

- *Challenge 1 - Noisy and Non-Deterministic Traces*: The traces observed by the attacker over a side channel are typically noisy, non-deterministic, and depend on the microarchitectural state of the CPU. For example, cache access patterns can be influenced by other programs running on the machine, the operating system and its interrupts, and can depend on microarchitectural buffers like store buffers or branch history tables. This means that the `Trace` function is not a simple deterministic function of the program inputs, but a complex function of many factors, some of which affect the result concurrently and in a non-deterministic fashion.

- *Challenge 2 - Unknown Side Channels*: Modern CPUs have a plethora of side channels, including cache timing, branch prediction, speculative execution, and many others. To ensure complete confidentiality, we need to check that the program does not leak information over *any* of them. This is a challenging, if not impossible, task, as we do not know the full set of possible side channels when it comes to commercial hardware with proprietary microarchitectures. For example, a CPU might have an obscure microarchitectural optimization that vastly expands possibilities for information leaks, as was the case with Spectre and Meltdown vulnerabilities. Therefore, to test for noninterference comprehensively, we need a way to discover and reason about all possible side channels that could leak information.

As a solution to these challenges, Guarnieri et al. (2021) introduced the concept of **speculation contracts**. A speculation contract is a simplified and deterministic model of the hardware, designed to capture the information that a given program *could* leak over side channels when executed with the given inputs. The key term here is "could"—the contract is not meant to exactly predict the side-channel traces, but instead, it errs on the side of caution, overestimating the possible leaks to achieve deterministic and noise-free traces. As such, a contract provides a conservative approximation of the `Trace` function, which solves the first challenge. The introduction of this intermediary model also allows us to discover and reason about unknown side channels, which will be discussed in the next sections.

### Contract Traces

At a high level, a contract implements a function `ContractTrace` that maps a program `P` and its inputs `H, L` to a contract trace `ctrace`:

```
ctrace = ContractTrace(P, H, L)
```

The contract trace is a sequence of all data that is exposed when a program is executed according to a contract. It captures the side-channel observations that *could be visible* if the CPU followed the speculation contract’s rules for a given program execution.

A speculation contract works by defining two key aspects for every instruction in the CPU's ISA:

1. **Observation Clause**: For each instruction that may have an observable side effect, the contract declares an observation clause. It describes the data exposed by the instruction.

2. **Execution Clause**: For each instruction whose semantics may be affected by hardware optimizations (e.g., speculative execution), the contract declares an execution clause. It describes the effect of such optimizations, but without specifying the exact mechanism of the optimization.

The following examples illustrate how a contract can be used to model side-channel leaks on a CPU.

### Example 6: Memory Observation Contract, MEM-SEQ

Let's imagine a CPU with a shared data cache and no other optimizations (i.e., no speculation). A co-located attacker can recover the addresses of loads/stores by observing which of the cache sets changed their state via a cache timing side-channel attack (e.g., Prime+Probe). We can encode these expectations in an observation clause for loads and stores by specifying that they expose their address. Since the CPU does not speculate, the execution clause for all instructions is empty.

|            | Observation Clause | Execution Clause |
|------------|--------------------|------------------|
| Load       | Expose Address     | -                |
| Store      | Expose Address     | -                |
| Other      | -                  | -                |

We call this contract MEM-SEQ (memory leakage with sequential execution).

Note that MEM-SEQ intentionally overestimates the leaks by assuming that the attacker can observe the complete address of loads/stores (in contrast to a subset of bits that are actually leaked in practice) and that all loads/stores expose information (in reality, they might be masked by noise or other factors). This overestimation is intentional to ensure that the contract is conservative and captures all possible leaks.

Let's now consider how we can produce a contract trace using MEM-SEQ. We will use a slightly modified version of the `multiply` function from **Example 5**:

```c
int multiply(const char *array, int low, int high) {
    char x = array[high];  // MEM-SEQ exposes: &array[high]
    char y = array[low];   // MEM-SEQ exposes: &array[low]
    return x * y;
}
```

The input is `input={array=0x10000, low=1, high=2}`.

The model collects a trace by executing the program line-by-line according to the rules in the table above (in practice, this is usually done using a modified CPU emulator). The first line has a load from memory, so the model records the address `0x10002` as exposed. The second line has another load, so the model records the address `0x10001` as exposed. The contract trace for this program execution would be `ctrace=[0x10002, 0x10001]`.

Finally, this model can be used to check for noninterference by comparing contract traces with matching Low values. If we have two inputs, `input1={array=0x10000, low=0x1, high=0x2}` and `input2={array=0x10000, low=0x1, high=0x3}`, the contract traces will be `ctrace1=[0x10002, 0x10001]` and `ctrace2=[0x10003, 0x10001]`, respectively. Since `ctrace1 != ctrace2`, this constitutes a violation of the noninterference property with respect to the MEM-SEQ contract.

### Example 7: Branch Prediction Contract, MEM-COND

Now let's consider a more complex scenario, with a CPU that implements branch prediction—a common form of speculative execution. In this case, the CPU may incorrectly predict branch targets and execute instructions that are not part of the correct control flow. We can model this behavior in a contract by introducing an execution clause for conditional jumps that specifies the mispredicted target. To make the example useful, we will assume that the CPU also has a data cache, so the observation clause for loads and stores remains the same as in MEM-SEQ.

|            | Observation Clause | Execution Clause  |
|------------|--------------------|-------------------|
| Load       | Expose Address     | -                 |
| Store      | Expose Address     | -                 |
| Cond. Jump | -                  | Mispredict Target |
| Other      | -                  | -                 |

We call this contract MEM-COND (memory leakage with conditional branch misprediction). Let's consider a program that has a conditional branch:

```c
int conditional_multiply(char *array, int low, int high) {
    int z = array[low];  // MEM-COND exposes: &array[low]
    if (z < 10) {        // assume z = 10
        z *= array[high];  // MEM-COND exposes: &array[high]
    }
    return z;
}
```

and the input is `input={array=0x10000, low=1, high=2}`.

The first line has a load, so it exposes its address, `0x10001`. For the sake of this example, let's assume this load returns `10`, so the next branch is not supposed to be taken. However, according to MEM-COND, branches take the wrong target, so the model executes the third line anyway. This line is a load, so it exposes the address `0x10002`. After this, the program terminates, and the resulting trace is `ctrace=[0x10001, 0x10002]`. Similarly to the previous example, traces like this can be used to check for noninterference w.r.t. MEM-COND.

As a side note, this program is a good example of how speculation impacts the results of noninterference analysis. If we consider two inputs, `input1={array=0x10000, low=1, high=2}` and `input2={array=0x10000, low=1, high=3}`, their contract traces on MEM-COND will be `ctrace1=[0x10001, 0x10002]` and `ctrace2=[0x10001, 0x10003]`, which constitutes a violation of noninterference. However, if we return back to MEM-SEQ, the contract traces would be `ctrace1=[0x10001]` and `ctrace2=[0x10001]`, which match and thus do not violate noninterference.

## Building and Testing Speculation Contracts

Speculation contracts are typically built by hand, with the initial versions based on public knowledge of the CPU's microarchitecture and its side-channel vulnerabilities. However, in the case of commercial hardware, the exact details of the microarchitecture are often proprietary and not publicly disclosed. In these cases, the contract could—and often will—be incomplete. This is where the testing of speculation contracts becomes crucial: the initial "draft" of a contract is tested against the real hardware to ensure that it captures all side-channel leaks that the CPU exhibits. If the contract misses something, it is refined based on the results of the testing, and the process is repeated until the contract is deemed safe to use.

But how do we test a speculation contract? A naive approach might be to directly compare the traces produced by the model with the traces collected from the real CPU for the same program and inputs. However, this approach is generally not feasible because the contract traces intentionally overestimate the hardware traces, so mismatches are expected. Moreover, the model might expose information differently than the real hardware (e.g., the model might expose load/store addresses, while the hardware exposes cache set indexes), meaning direct comparison is often impossible.

Instead, a more precise approach is to compare *the information contained in the traces*. The idea is to check that the information exposed by the model is a strict superset of the information exposed by the real hardware. This is done by verifying that all inputs producing identical contract traces for a given program also produce identical hardware traces. If this property holds for all possible programs and inputs (ignore the complexity question for now), then any program that would be noninterferent with respect to the real hardware is guaranteed to be noninterferent with respect to the speculation contract. At this point, the model is safe to use as a proxy for real hardware when analyzing side-channel leaks.

To formalize this idea, let's introduce a new function `HardwareTrace` to denote the trace collected from the real hardware, and it will take an extra argument `Ctx` to capture the fact that real-world hardware traces depend on the microarchitectural state (e.g., on the state of branch predictors).

**Definition 3: Contract Compliance**
A CPU complies with a speculation contract if, for all programs `P`, all input pairs `(H1, L), (H2, L)`, and all initial microarchitectural states `Ctx`, if `ContractTrace(P, H1, L) = ContractTrace(P, H2, L)`, then `HardwareTrace(P, H1, L, Ctx) = HardwareTrace(P, H2, L, Ctx)`.

and conversely

**Definition 4: Contract Violation**
A CPU violates a speculation contract if there exists a program `P`, a microarchitectural state `Ctx`, and two inputs `(H1, L), (H2, L)` that agree on their contract traces but disagree on the hardware traces: `ContractTrace(P, H1, L) = ContractTrace(P, H2, L)` and `HardwareTrace(P, H1, L, Ctx) != HardwareTrace(P, H2, L, Ctx)`.

In this case, we call the tuple `(P, Ctx, H1, H2)` a contract counterexample. The counterexample demonstrates that an adversary can learn more information from hardware traces than what the contract specifies. A counterexample indicates a potential microarchitectural leakage that was not accounted for by the contract.

## Model-Based Relational Testing and Revizor

All the principles above are combined in our tool, Revizor. On one hand, Revizor provides a framework for building models for various speculation contracts, with some of the common contracts bundled in the tool. These models can be used to analyze the confidentiality properties of programs and to discover potential side-channel vulnerabilities. On the other hand, Revizor provides a way to test real hardware (currently only CPUs) against these models, using the property in **Definition 3**. This allows it to discover unknown side-channel vulnerabilities in hardware.

However, in the implementation of Revizor, we encountered a number of practical challenges in making **Definition 3** usable.

The first issue was the search space. Testing all possible programs and inputs is literally impossible. Instead, Revizor relies on a sampling-based approach, similar to fuzzing, where it randomly selects a subset of programs and inputs to test. Specifically, Revizor generates small (50-100 instructions long) programs, creates random inputs for them, collects both the contract and hardware traces for these inputs, and checks whether any of the traces constitute a contract counterexample. This process is called *Model-based Relational Testing*, and it is detailed further in the [Architecture Overview](devel/overview.md).

This approach works well in practice because any given hardware optimization can typically be triggered by many different programs, and we need to find only one instance to detect a violation. Evidence of this is the [list of trophies](https://microsoft.github.io/sca-fuzzer/) Revizor has already amassed.

The second issue we encountered is nondeterminism. As mentioned earlier, hardware traces can be non-deterministic due to various factors like interrupts or other programs running on the machine. To handle this, we use statistical methods: Revizor collects hardware traces for each program-input pair multiple times and then compares their distributions. If the distributions of the traces are statistically similar, Revizor considers the traces to be equivalent. This approach helps us account for noise in the hardware traces while still making reliable decisions about contract compliance.

---

### Sources and Further Reading

- J. A. Goguen and J. Meseguer. *Security Policies and Security Models*. IEEE Symposium on Security and Privacy, 1982. (Origin of noninterference as a security policy formalism.)
- A. Sabelfeld and A. C. Myers. *Language-Based Information-Flow Security*. IEEE Journal on Selected Areas in Communications, 21(1), 2003. (Survey of information-flow security, implicit/explicit flows, covert channels, etc.)
- J. B. Almeida et al. *Verifying Constant-Time Implementations*. USENIX Security Symposium, 2016. (Constant-time programming principles and the ct-verif tool for automated verification.)
- M. Guarnieri, B. Köpf, J. Reineke, P. Vila. *Hardware-Software Contracts for Secure Speculation*. IEEE Symposium on Security and Privacy, 2021. (Original paper on speculation contracts.)
- O. Oleksenko, C. Fetzer, B. Köpf, M. Silberstein. *Revizor: Testing Black-box CPUs against Speculation Contracts*. ACM International Conference on Architectural Support for Programming Languages and Operating Systems (ASPLOS), 2022. (Paper describing Model-based Relational Testing and Revizor.)

