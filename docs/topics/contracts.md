# Contracts

A speculation contract is a formal specification of known microarchitectural leakage in CPUs.
A contract serves to provide a precise and unambiguous documentation of all known sources of
side-channel leaks on a given CPU (or a family of CPUs). For example, if a contract targets
a modern Intel or AMD CPU, it will typically include a specification of the leaks caused by
cache side channels and by various speculative vulnerabilities such as Spectre and Meltdown.

Contracts emerged as a solution to a fundamental problem: modern CPUs have complex
microarchitectural optimizations that create side channels, but these mechanisms are often
proprietary and poorly documented. Contracts provide a systematic way to reason about these leaks
without requiring complete knowledge of the underlying hardware.

In the context of Revizor, contracts serve as a reference model against which the actual CPU
behavior is compared; any deviation from the contract indicates a previously-unknown
microarchitectural behavior, which may represent a security vulnerability.

## Contract Structure

A speculation contract consists of two types of clauses that together describe the information a
program exposes during execution.

The *observation clause* specifies what data becomes observable for each instruction. For example, a
contract might declare that load and store instructions expose their target addresses. This models
the information an attacker could learn by monitoring a cache-based side channel such as
Prime+Probe. The observation clause captures side effects without specifying the attack mechanism.

The *execution clause* specifies how hardware optimizations affect program execution. For
speculative execution, the clause describes which instructions execute transiently even when they
should not execute architecturally. For instance, the clause might specify that conditional
branches temporarily take the wrong target. The execution clause models optimization behavior
without describing the implementation details.

Contracts intentionally overestimate leakage. Rather than precisely modeling what leaks occur,
contracts capture everything that could potentially leak given the specified hardware behaviors.
This conservative approach ensures that contracts remain valid even when the exact timing or
conditions of leaks are unknown.

## Example Contracts

The `CT-SEQ` contract models a CPU with caching but no speculation. It represents a baseline level
of leakage present in any cached architecture where memory operations leave observable traces but
instructions execute in program order.

Below is a pseudo-code representation of the `CT-SEQ` contract:

``` yaml
CT-SEQ:
  observation_clause:
    load(address)  -> expose(address)
    store(address) -> expose(address)
    * -> none  # all other instructions expose no information
  execution_clause:
    * -> none  # no optimizations; all instructions execute in program order
```

The `CT-COND` contract extends `CT-SEQ` by adding speculative execution of branches. The observation
clause remains the same, but the execution clause permits conditional jumps to mispredict their
targets and speculatively execute wrong-path instructions. This contract models Spectre-style
vulnerabilities where misprediction causes transient execution that leaves observable cache
footprints.

``` yaml
CT-COND:
  observation_clause:
    load(address)  -> expose(address)
    store(address) -> expose(address)
    * -> none
  execution_clause:
    jump.cond(target) ->  # emulate branch misprediction
        jump.inverted_cond(target)
    * -> none
```

More complex contracts can model other optimizations. A contract for exception handling might allow
faulting user-to-kernel loads to transiently return privileged values before the fault
is architecturally recognized, this modelling Meltdown-style vulnerabilities:

``` yaml
CT-MELTDOWN:
  observation_clause:
    load(address)  -> expose(address)
    store(address) -> expose(address)
    * -> none
  execution_clause:
    jump.cond(target) ->
        jump.inverted_cond(target)
    load(address) ->  # transiently return kernel data thus emulating Meltdown
        if (in_user_mode() && is_kernel_address(address)) {
            return load_privileged(address)
        }
    * -> none
```

## Contract Traces

When a program executes according to a contract, it produces a contract trace. The trace is a
sequence of all observations specified by the observation clause during the execution path
determined by the execution clause. For `CT-SEQ`, the trace contains load and store addresses in
program order. For `CT-COND`, the trace includes addresses from speculatively executed instructions
on mispredicted paths.

Contract traces are deterministic and noise-free, unlike actual hardware measurements. This
property makes them suitable as a reference for comparison. A program executed repeatedly with the
same inputs always produces the same contract trace, even though real hardware traces may vary due
to timing effects and concurrent activity.

For example, consider the following program:

``` asm  linenums="1"
# addr1 = 0x100; addr2 = 0x200;
# *addr1 = 1;    *addr2 = 2
load rax, [addr1]  # expose(0x100)
cmp rax, 0         # 1 != 0
je label_zero      # speculatively mispredicted under CT-COND
    load rbx, [addr2]  # expose(0x200) under CT-COND (but not under CT-SEQ)
label_zero:
```

When this program is executed under `CT-SEQ`, only one load occurs (line 3), producing the trace:

```
ctrace_seq = [ mem:0x100 ]
```

However, under `CT-COND`, the mispredicted branch causes the second load (line 6) to execute,
thus producing a trace with two observations:

```
ctrace_cond = [ mem:0x100, mem:0x200 ]
```


## Contract Compliance

A CPU complies with a contract when the information it leaks never exceeds what the contract
permits. More formally, compliance means that whenever two inputs produce identical contract
traces, they must also produce indistinguishable hardware traces given the same initial
microarchitectural state. This definition ensures that an attacker observing hardware cannot learn
more than the contract allows.

Compliance does not require that hardware traces match contract traces exactly. The contract might
expose complete addresses while hardware only leaks cache set indices. The contract might include
data from speculative paths that hardware does not actually execute. These differences are
acceptable as long as the information content of hardware traces does not exceed contract traces.

A violation occurs when two inputs produce identical contract traces but distinguishable hardware
traces. This indicates that hardware leaks information not captured by the contract, revealing an
unexpected microarchitectural behavior. The violating program serves as evidence of a potential
security vulnerability.


## Contract Evolution

Contracts are not static specifications. When Revizor discovers a violation, the user is free to
update the contract to reflect the newly observed behavior. This way a contract serves as a "filter"
that allows us to automatically distinguish between the leaks that we already know about (and thus
aren't interested in detecting) versus the leaks that are genuinely new and that we may want to
investigate further.

Moreover, the process may go both ways: if the hardware behavior is determined to be a bug,
and the vendor issues a patch, the contract may be updated to remove the previously-allowed leakage,
which in turn will allow Revizor to detect regressions if the patch is later undone or
incompletely applied.

This iterative process gradually refines contracts to match actual hardware behavior. Initial
contracts are based on public documentation and known vulnerabilities. Testing reveals gaps where
hardware leaks more than expected. After investigation, either the contract expands or the
hardware receives a patch. Over time, the contract converges toward a complete specification of
the CPU's microarchitectural leakage.

The contract framework also enables testing of proposed mitigations. Before deploying a patch,
vendors can verify its effectiveness by running Revizor with the updated configuration. If
violations persist, the mitigation is incomplete. This proactive approach helps prevent the
deployment of ineffective patches that provide false security.

## What's Next?

* See the [primer](../intro/03_primer.md) for a deeper dive into non-interference and contract-based testing.
* See the [model documentation](models.md) for details on how Revizor implements contracts.
