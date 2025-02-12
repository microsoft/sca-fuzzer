# How Revizor works

<!-- Table of Contents:
- [How Revizor works](#how-revizor-works)
  - [Revizor in a nutshell](#revizor-in-a-nutshell)
  - [Speculation Contracts](#speculation-contracts)
    - [Microarchitectural Leakage and Hardware Traces](#microarchitectural-leakage-and-hardware-traces)
    - [What's a Speculation Contract?](#whats-a-speculation-contract)
  - [Model-based Relational Testing](#model-based-relational-testing)
  - [Revizor](#revizor) -->


## Revizor in a nutshell

Revizor is a tool for detecting unexpected microarchitectural leakage in CPUs.
Microarchitectural leakage means the information that an attacker could learn by launching a microarchitectural side-channel attack (e.g., [Spectre or Meltdown](https://meltdownattack.com/)).
The *expected* microarchitectural leakage is the leakage that we already know about (i.e., known microarchitectural vulnerabilities).
We describe the expected leakage in a form of a Speculation Contract (see below).
Accordingly, the *unexpected* leakage is any leakage not described pby a contract - we call it a *contract violation*.
Revizor's task is to find such violations.


## Speculation Contracts

Below is a brief intro to Contracts. You can find a more detailed description in the [original paper](https://arxiv.org/abs/2006.03841) and in the Background section of the [Revizor paper](https://arxiv.org/pdf/2105.06872.pdf).

### Microarchitectural Leakage and Hardware Traces

Consider two programs, an attacker and a victim.
The attacker launches a microarchitectural side-channel attack (e.g., a cache side channel) to spy on the victim and learn some of its data.
A *hardware trace* is a sequence of all the observations made through this side-channel after each instruction during the victim's execution.
In other words, hardware trace is the result for a side-channel attack.

We abstractly represent the hardware trace as the output of a function

𝐻𝑇𝑟𝑎𝑐𝑒 = 𝐴𝑡𝑡𝑎𝑐𝑘(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎,𝐶𝑡𝑥)

that takes three input parameters:
(1) the victim program 𝑃𝑟𝑜𝑔;
(2) the input 𝐷𝑎𝑡𝑎 processed by the victim’s program (i.e., the architectural state including registers and main memory);
(3) the microarchitectural context 𝐶𝑡𝑥 in which it executes.
The information exposed by a hardware trace depends on the assumed side-channel and threat model.

Example: If the threat model includes attacks on a data cache, 𝐻𝑇𝑟𝑎𝑐𝑒 is composed of the cache set indexes used by 𝑃𝑟𝑜𝑔’s loads and stores.
If it includes attacks on an instruction cache, 𝐻𝑇𝑟𝑎𝑐𝑒 contains the addresses of executed instructions.

A program *leaks* information via side-channels when its hardware traces depend on the inputs (𝐷𝑎𝑡𝑎):
We assume the attacker knows 𝑃𝑟𝑜𝑔 and can manipulate 𝐶𝑡𝑥, hence any difference between the hardware traces implies difference in 𝐷𝑎𝑡𝑎, which effectively exposes information to the attacker.

### What's a Speculation Contract?

A speculation contract specifies the information that can be exposed by a CPU during a program execution under a given threat model.
For each instruction in the CPU ISA (or a subset thereof), a contract describes the information exposed by the instruction’s (observation clause) and the externally-observable speculation that the instruction may trigger (execution clause).
When a contract covers a subset of ISA, the leakage of unspecified instructions is undefined.

Example: consider the contract summarized in the next table:

|            | Observation Clause | Execution Clause  |
| ---------- | ------------------ | ----------------- |
| Load       | Expose Address     | -                 |
| Store      | Expose Address     | -                 |
| Cond. Jump | -                  | Mispredict Target |
| Other      | -                  | -                 |

We call this contract MEM-COND.
Through the observation clauses of loads and stores, the contract prescribes that addresses of all memory access may be exposed (hence MEM).
The execution clause of conditional branches describes their misprediction, thus the contract prescribes that branch targets may be mispredicted (hence COND).
This way, the contract models a data cache side channel on a CPU with branch prediction.

A contract trace 𝐶𝑇𝑟𝑎𝑐𝑒 contains the sequence of all the observations the contract allows to be exposed after each instruction during a program execution, including the instructions executed speculatively.
Conversely, the information that is not exposed via 𝐶𝑇𝑟𝑎𝑐𝑒 is supposed to be kept secret.

We abstractly represent a contract as a function 𝐶𝑜𝑛𝑡𝑟𝑎𝑐𝑡 that maps the program 𝑃𝑟𝑜𝑔 and its input 𝐷𝑎𝑡𝑎 to a contract trace 𝐶𝑇𝑟𝑎𝑐𝑒:

𝐶𝑇𝑟𝑎𝑐𝑒 = 𝐶𝑜𝑛𝑡𝑟𝑎𝑐𝑡(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎)

Example: Consider the following program:

```python
z = array1[x] # base of array1 is 0x100
if y < 10:
    z = array2[y] # base of array2 is 0x200
```
It is executed with an input `data={x=10,y=20}`.
The MEM-COND contract trace is `ctrace=[0x110,0x220]`, representing that the load at line 1 exposes the accessed address during normal execution, and the load at line 3 exposes its address during speculative execution triggered by the branch at line 2.

A CPU complies with a contract when its hardware traces (collected on the actual CPU) leak at most as much information as the contract traces.
Formally, we require that whenever any two executions of any program have the same contract trace (implying the difference between inputs is not exposed), the respective hardware traces should also match.

A CPU complies with a 𝐶𝑜𝑛𝑡𝑟𝑎𝑐𝑡 if, for all programs 𝑃𝑟𝑜𝑔, all input pairs (𝐷𝑎𝑡𝑎,𝐷𝑎𝑡𝑎′), and all initial microarchitectural states 𝐶𝑡𝑥:

𝐶𝑜𝑛𝑡𝑟𝑎𝑐𝑡(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎) = 𝐶𝑜𝑛𝑡𝑟𝑎𝑐𝑡(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎′)
-> 𝐴𝑡𝑡𝑎𝑐𝑘(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎,𝐶𝑡𝑥) = 𝐴𝑡𝑡𝑎𝑐𝑘(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎′,𝐶𝑡𝑥)

Conversely, a CPU violates a contract if there exists a program 𝑃𝑟𝑜𝑔, a microarchitectural state Ctx, and two inputs 𝐷𝑎𝑡𝑎,𝐷𝑎𝑡𝑎′ that agree on their contract traces but disagree on the hardware traces.
We call the tuple (𝑃𝑟𝑜𝑔,𝐶𝑡𝑥,𝐷𝑎𝑡𝑎,𝐷𝑎𝑡𝑎′) a contract counterexample.
The counterexample witnesses that an adversary can learn more information from hardware traces than what the contract specifies.
A counterexample indicates a potential microarchitectural vulnerability that was not accounted for by the contract.

## Model-based Relational Testing

To find contract violations, we use the following approach, which we call Model-based Relational Testing (MRT).

The next figure show the main components of MRT:

![MRT](../assets/arch.png)

**Test case and input generation**.
We sample the search space of programs, inputs and microarchitectural states to find counterexamples.
The generated instruction sequences (test cases) are comprised of the ISA subset described by the contract.
The test cases and respective inputs to them are generated to achieve high diversity and to increase speculation or leakage potential.

**Collecting contract traces.**
We implement an executable Model of the contract to allow automatic collection of contract traces for standard binaries.
For this, we modify a functional CPU emulator to implement speculative control flow based on a contract’s execution
clause, and to record traces based on its observation clause.

**Collecting hardware traces.**
We collect hardware traces by executing the test case on the CPU under test and measuring the observable microarchitectural state changes during the execution according to the threat model.
The executor employs several methods to achieve consistent and repeatable measurements.

**Relational Analysis.**
Based on the collected contract and hardware traces, we identify contract violations.
Namely, we search for pairs of inputs that match the following:

```
ContractTrace1 == ContractTrace2
               and
HardwareTrace1 != HardwareTrace2
```

This requires relational reasoning:
* We partition inputs into groups, which we call input classes.
All inputs within a class have the same contract trace.
Thus, input classes correspond to the equivalence classes of equality on contract traces.
Classes with a single (ineffective) input are discarded.
* For each class, we check if all inputs within a class have the same hardware trace.

If the check fails on any of the classes, we found a counterexample that witnesses contract violation.

## Revizor

Revizor implements the MRT approach for black-box CPUs.
The implementation details are described in [Revizor Architecture](./architecture.md).
