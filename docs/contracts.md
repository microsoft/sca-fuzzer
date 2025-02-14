# Speculation Contracts and Leakage Models

Below is a brief intro to speculation contracts. You can find a more detailed description in the [original paper](https://arxiv.org/pdf/2006.03841) and in the Background section of the [Revizor paper](https://boriskoepf.de/papers/Revizor_Micro.pdf).


## Microarchitectural Leakage and Hardware Traces

We will start with basic definitions and terminology.

Consider two programs, an attacker and a victim.
Both programs run on the same hardware and they share microarchitectural resources, such as caches.
This sharing gives the attacker ability to launch a side-channel attack (e.g., a cache side channel) to spy on the victim and learn some of its data.

A *hardware trace* is a sequence of all the observations made by the attacker through a given side channel while the victim program executes (or after the victim finishes running).
To put it simply, a hardware trace is the result for a side-channel attack.

We can abstractly represent the hardware trace as the output of a function Attack:

𝐻𝑇𝑟𝑎𝑐𝑒 = 𝐴𝑡𝑡𝑎𝑐𝑘(𝑃𝑟𝑜𝑔, 𝐷𝑎𝑡𝑎, 𝐶𝑡𝑥)

The function takes three input parameters:
 the victim program 𝑃𝑟𝑜𝑔; the input 𝐷𝑎𝑡𝑎 processed by the victim’s program (i.e., the architectural state including registers and main memory); the microarchitectural context 𝐶𝑡𝑥 in which it executes.

The information exposed by a hardware trace depends on the assumed side-channel.

    Example
    -------

    For a Prime+Probe data cache side channel, 𝐻𝑇𝑟𝑎𝑐𝑒 is composed of
    the cache set indexes used by 𝑃𝑟𝑜𝑔’s loads and stores.

A program *leaks* information via side-channels when its hardware traces depend on the inputs (𝐷𝑎𝑡𝑎):
We assume the attacker knows 𝑃𝑟𝑜𝑔 and can manipulate 𝐶𝑡𝑥, hence any difference between the hardware traces implies difference in 𝐷𝑎𝑡𝑎, which effectively exposes information to the attacker.

## What's a Speculation Contract?

A speculation contract (or just *contract*) is a specification of the expected information leakage on a given CPU under a given side channel (or a class of side channels).
To this end, a contract describes two aspects for every instruction in the CPU's ISA:

1) Observation Clause: Which information can be exposed when the given instruction executes?
2) Execution Clause: How can the CPU modify the normal semantics of the given instruction?

The observation clause describes the information observed via a side channel, while the execution clause describes the externally-observable effects of CPU optimizations, such a speculative execution.

    Example
    -------

    Consider a contract summarized in the next table

    |            | Observation Clause | Execution Clause  |
    | ---------- | ------------------ | ----------------- |
    | Load       | Expose Address     | -                 |
    | Store      | Expose Address     | -                 |
    | Cond. Jump | -                  | Mispredict Target |
    | Other      | -                  | -                 |

    We call this contract MEM-COND. Through the observation clauses of
    loads and stores, the contract prescribes that addresses of all memory
    access may be exposed (hence MEM). The execution clause of conditional branches
    describes their misprediction, thus the contract prescribes that branch
    targets may be mispredicted (hence COND). This way, the contract models
    a data cache side channel on a CPU with branch prediction.

A *contract trace* is a sequence of all data that is exposed when a program is executed according to a contract.

Notably, this format of the specification allows us to precisely define the security guarantees of a given CPU: Any information that is exposed in a contract trace should be treated as potentially leaked, while the information that is *not exposed* in a contract trace is expected to remain private to the victim program.

We can abstractly represent a contract as a function 𝐶𝑜𝑛𝑡𝑟𝑎𝑐𝑡 that maps the program 𝑃𝑟𝑜𝑔 and its input 𝐷𝑎𝑡𝑎 to a contract trace 𝐶𝑇𝑟𝑎𝑐𝑒:

𝐶𝑇𝑟𝑎𝑐𝑒 = 𝐶𝑜𝑛𝑡𝑟𝑎𝑐𝑡(𝑃𝑟𝑜𝑔, 𝐷𝑎𝑡𝑎)

    Example
    -------

    Consider the following program, executed according to MEM-COND contract

    z = array1[x] # base of array1 is 0x100
    if y < 10:
        z = array2[y] # base of array2 is 0x200

    Also assume that the program is executed with an input data={x=10,y=20}.

    The first line exposes the address 0x110 (0x100 + 10) during normal execution.
    The branch on the second line is mispredicted, and the load at the third line
    exposes the address 0x220 (0x200 + 20) during speculative execution. This results
    in a contract trace `ctrace=[0x110,0x220]`.

## Contract Violation

A CPU complies with a contract when its hardware traces (collected on the actual CPU) leak at most as much information as the contract traces.
Formally, we require that whenever any two executions of any program have the same contract trace (implying the difference between inputs is not exposed), the respective hardware traces should also match.

**Definition**: A CPU complies with a 𝐶𝑜𝑛𝑡𝑟𝑎𝑐𝑡 if, for all programs 𝑃𝑟𝑜𝑔, all input pairs (𝐷𝑎𝑡𝑎,𝐷𝑎𝑡𝑎′), and all initial microarchitectural states 𝐶𝑡𝑥:

    𝐶𝑜𝑛𝑡𝑟𝑎𝑐𝑡(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎) = 𝐶𝑜𝑛𝑡𝑟𝑎𝑐𝑡(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎′)
    -> 𝐴𝑡𝑡𝑎𝑐𝑘(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎,𝐶𝑡𝑥) = 𝐴𝑡𝑡𝑎𝑐𝑘(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎′,𝐶𝑡𝑥)

Conversely, a CPU violates a contract if there exists a program 𝑃𝑟𝑜𝑔, a microarchitectural state Ctx, and two inputs 𝐷𝑎𝑡𝑎,𝐷𝑎𝑡𝑎′ that agree on their contract traces but disagree on the hardware traces.

    𝐶𝑜𝑛𝑡𝑟𝑎𝑐𝑡(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎) = 𝐶𝑜𝑛𝑡𝑟𝑎𝑐𝑡(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎′)
    -> 𝐴𝑡𝑡𝑎𝑐𝑘(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎,𝐶𝑡𝑥) != 𝐴𝑡𝑡𝑎𝑐𝑘(𝑃𝑟𝑜𝑔,𝐷𝑎𝑡𝑎′,𝐶𝑡𝑥)

We call the tuple (𝑃𝑟𝑜𝑔, 𝐶𝑡𝑥, 𝐷𝑎𝑡𝑎, 𝐷𝑎𝑡𝑎′) a contract counterexample.
The counterexample witnesses that an adversary can learn more information from hardware traces than what the contract specifies.
A counterexample indicates a potential microarchitectural vulnerability that was not accounted for by the contract.

## Speculative Leakage Models

Speculative leakage model (or just model) is a software implementation of a speculation contract.
It is a software model of the CPU that takes a program and its input, executes it according to the contract execution clauses, collects traces according to the contract's observation clauses, and returns the contract trace.

A leakage model can be built on top of any software that can execute programs, and that can modify their behavior, such as emulators, binary instrumentation tools, or even as compiler passes.
Revizor currently includes two backends for leakage models: a [Unicorn-based backend](devel/unicorn-model.md) that works on top of a CPU emulator, and [DynamoRIO-based backend](devel/dr-model.md) that works through dynamic binary instrumentation.

A model implements an observation clause by calling a hook function every time the relevant instruction is executed.
For example, if the observation clause is `MEM`, the model will register a callback executed before every memory access instruction, which will record the address of the memory access.

The execution clauses are implemented via a checkpoint-rollback mechanism.
The model registers a callback for every instruction executed in the program.
When the callback is called, the model checks if the instruction is in the execution clause.
If it is, the model takes a checkpoint of the program state, modifies the state according to the execution clause (e.g., flips the branch condition in case of `COND`), and continues the execution.
The following calls to the callback count the number of executed instructions.
When the number reaches the limit (e.g., 256 to mirror the size of ROB), the model restores the checkpoint and continues the execution from the original state.
