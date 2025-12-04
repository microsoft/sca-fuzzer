# Tutorial 3: Testing faults with Revizor (Part 1)

Having detected Spectre V1, let's now apply the same methodology to find a different vulnerability class. Meltdown-style vulnerabilities exploit speculative execution around exception handling rather than branch misprediction.

!!! important
    This tutorial relies on the knowledge about sandboxed execution and the memory layout of the sandbox. If you haven't read about it yet, please refer to the [Sandbox Reference](../../ref/sandbox.md) and the [Actors and Isolation Topic Guide](../../topics/actors.md) before proceeding.

### Plan the campaign

The key difference in this campaign is the speculation source. Instead of conditional branches, we'll test page faults. Meltdown and related vulnerabilities occur when a CPU speculatively executes instructions that follow a faulting memory access, potentially leaking data from inaccessible memory regions.

From the practical standpoint, the key difference that we will need to configure the [sandbox](../../ref/sandbox.md) to make it possible for the test case to trigger page faults. Namely, we will make one of the pages accessible by the test cases non-readable.

### Create the configuration file

Our configuration for this campaign makes three important changes from the Spectre V1 setup. First, we remove `BASE-COND_BR` from the instruction categories since we already know conditional branches cause Spectre V1 violations. This focuses our testing on other speculation sources.

Second, we add an `actors` section with `data_properties` to configure the sandbox memory layout. Revizor's sandbox allocates each actor two 4KB memory regions: a main area with normal read-write permissions and a faulty area where we can configure special permissions. By setting `present: false` in the data properties, we mark the faulty area as non-present in the page tables. When the test case attempts to access this region, the CPU will raise a page fault, giving us the exception-based speculation source we want to test.

Third, we change the contract execution clause to `delayed-exception-handling`. Modern CPUs implement out-of-order execution, so data-independent instructions after a fault may execute before the exception is recognized. This is expected behavior and would cause trivial violations under the strict `no_speculation` contract. The `delayed-exception-handling` clause accommodates this expected speculation, allowing Revizor to focus on more interesting leaks. For more details on contract selection, see [How to Choose a Contract](../../howto/choose-contract.md).

```yaml
# contract
contract_observation_clause: loads+stores+pc
contract_execution_clause:
  - delayed-exception-handling

# tested instructions
instruction_categories:
  - BASE-BINARY
  # - BASE-COND_BR

actors:
  - main:
    - data_properties:
      - present: false

enable_speculation_filter: true
enable_observation_filter: true
enable_fast_path_model: true
```


### What's Next?

[Part 2](part2.md) will walk you through running the campaign.
