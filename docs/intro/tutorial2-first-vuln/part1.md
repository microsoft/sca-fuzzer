# Tutorial 2: Detecting Your First Vulnerability (Part 1)

This tutorial is the first step into actual vulnerability detection. You'll learn how to set up a fuzzing campaign that tests conditional branches. And, most likely, it will end with a detection of Spectre V1.

### Testing Workflow

Before we begin with actual testing, let's take a step back and consider how a typical testing workflow looks like.

The process of using Revizor normally constitutes of the following steps:

1. **Design the campaign** by selecting which instructions to test and choosing an appropriate contract that defines what behavior we consider a violation.
2. **Create a configuration file** that captures these decisions.
3. **Run the fuzzer** to generate and execute random test cases.
4. **Validate the violation** to ensure it's genuine and not a false positive.
5. **Minimize the test case** to remove unnecessary complexity, making it easier to understand.
6. **Analyze the minimized program** to identify the root cause of the vulnerability.

In the following, we will go step-by-step through this workflow.

### Plan the campaign

Let's imagine we have a new CPU and want to determine if conditional branches produce any information leakage on it. These instructions are infamous for causing Spectre V1, therefore it is always useful to start with them when testing a new CPU.

The first step is planning our fuzzing campaign strategically.

For effective testing, we'll focus on a minimal instruction subset rather than the entire ISA. Spectre V1 requires only two capabilities: conditional branches (to trigger misprediction) and memory accesses (to leak information through side channels). By limiting our instruction set to just arithmetic operations and conditional branches, we accomplish two goals. First, the fuzzer will find violations faster because there are fewer instruction combinations to explore. Second, when we do find a violation, it will be much easier to analyze because the test case will be simpler.

!!! warning
    Note that this focused approach is *not* representative of a real fuzzing campaign. This tutorial is intentionally simplified to help with understanding. In a real campaign, you'll need to find balance between having a broad scope (increases changes of finding unknown vulnerabilities) and having focus on specific CPU features (simplifies root-cause analysis). For more guidance on campaign design, see [How to Design a Fuzzing Campaign](../../howto/design-campaign.md).

We'll pair this minimal instruction set with the strictest possible contract—one that forbids any speculation whatsoever. This means Revizor will flag any speculative behavior as a violation. While this contract is more restrictive than what modern CPUs actually guarantee, it's perfect for our purposes. Since we're only testing conditional branches and simple arithmetic, any speculation we detect will almost certainly be Spectre V1.

With this campaign plan, we are trying to answer a specific question: "Does this CPU leak information through conditional branches?"

### Create the configuration file

Now that we've planned our campaign, let's translate it into a configuration file. Create a YAML file with the following content:

```yaml
# tested instructions
instruction_categories:
  - BASE-BINARY
  - BASE-COND_BR

# contract
contract_observation_clause: loads+stores+pc
contract_execution_clause:
  - no_speculation

# enable perf. optimizations
enable_speculation_filter: true
enable_observation_filter: true
enable_fast_path_model: true
```

The `instruction_categories` section implements our decision to use a minimal instruction set. We're including `BASE-BINARY` for arithmetic operations like addition and comparison, and `BASE-COND_BR` for conditional branches like `jz` and `jne`. These two categories give the fuzzer everything it needs to express Spectre V1 patterns.

The contract configuration consists of two clauses. The `contract_observation_clause` tells Revizor what microarchitectural side effects to track. We're using `loads+stores+pc`, which observes memory access addresses and the program counter—exactly what an attacker would monitor through cache timing attacks. The `contract_execution_clause` defines what execution behavior is allowed. By setting it to `no_speculation`, we're telling Revizor that any speculative execution is a violation.

The performance optimization flags at the bottom significantly speed up fuzzing without affecting correctness. The `enable_speculation_filter` skips test cases that don't trigger speculation at all. The `enable_observation_filter` skips test cases that leave no observable traces. The `enable_fast_path_model` allows Revizor to reuse contract traces across similar inputs, reducing the model execution overhead.

For a complete reference of all configuration options, see the [Configuration Reference](../../ref/config.md).

### What's Next?

[Part 2](part2.md) will walk you through running the campaign.
