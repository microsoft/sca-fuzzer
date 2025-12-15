# Glossary

This glossary defines key terms used throughout the Revizor documentation. The entries are ordered in such a way that more fundamental concepts appear first, building up to more complex ideas. So, you can should be able to get a good understanding of the terminology by reading the glossary top-down.

---

####<a name="noninterference"></a>Noninterference
: A formal property that captures perfect confidentiality, stating that changes in secret data have no observable effect on public outputs. A program satisfies noninterference if variations in secret inputs cause no differences in public outputs. In Revizor's context, this property is checked with respect to side-channel observations and speculation contracts.

!!! info "Related Documentation"
    - [Primer: Information-Flow Properties](intro/03-primer.md#information-flow-properties)
    - [Primer: Noninterference Definition](intro/03-primer.md#noninterference-definition-and-examples)

---

####<a name="information-flow"></a>Information Flow
: The movement of data through a computation. Information-flow security is concerned with how data moves through a system and how it can be observed by an attacker. For example, if a program contains a data-dependent memory access `array[secret_index]`, the value of `secret_index` influences which memory location is accessed. In turn, if the attacker can observe the cache lines being accessed by this program, the execution of the array access will reveal (leak) information about `secret_index` through side channels. This creates an information flow from the secret data (`secret_index`) to the attacker's observations (cache state).

!!! info "Related Documentation"
    - [Primer: Information-Flow Properties](intro/03-primer.md#information-flow-properties)
    - [Primer: Side Channels](intro/03-primer.md#beyond-direct-outputs-side-channels)

---

####<a name="speculation-contract"></a>Speculation Contract (aka Leakage Contract)
: A formalization of how we expect the CPU to behave and what information we expect it to leak when any given program is executed. A simplified and deterministic model of CPU hardware designed to capture the information that a given program could leak over side channels when executed with given inputs. A speculation contract defines two key aspects for every instruction: an observation clause (describing what data is exposed) and an execution clause (describing how hardware optimizations like speculative execution affect the instruction). Speculation contracts intentionally overestimate possible leaks to ensure conservative and deterministic traces.

!!! info "Related Documentation"
    - [Topic: Contracts](topics/contracts.md)
    - [Primer: Speculation Contracts](intro/03-primer.md#speculation-contracts-dealing-with-the-complexity-of-modern-hardware)
    - [How-to: Choose a Contract](howto/choose-contract.md)

---

####<a name="observation-clause"></a>Observation Clause
: Part of a speculation contract that specifies what information an instruction exposes through side channels when executed. For example, an observation clause might specify that a load instruction exposes the memory address it accesses.

!!! info "Related Documentation"
    - [Topic: Contracts - Contract Structure](topics/contracts.md#contract-structure)
    - [Primer: Speculation Contracts](intro/03-primer.md#speculation-contracts-dealing-with-the-complexity-of-modern-hardware)

---

####<a name="execution-clause"></a>Execution Clause
: Part of a speculation contract that specifies how hardware optimizations (particularly speculative execution) affect an instruction's semantics. For example, an execution clause might specify that a conditional branch may mispredict its target and execute down the wrong path.

!!! info "Related Documentation"
    - [Topic: Contracts - Contract Structure](topics/contracts.md#contract-structure)
    - [Primer: Speculation Contracts](intro/03-primer.md#speculation-contracts-dealing-with-the-complexity-of-modern-hardware)

---

####<a name="leakage-model"></a>Leakage Model
: An implementation of a speculation contract. This model is used to compare the actual CPU behavior against the specification defined by the contract. It predicts what information flow is allowed through side channels for any given test case.

!!! info "Related Documentation"
    - [Topic: Leakage Models](topics/models.md)
    - [Internals: Model Architecture](internals/architecture/model.md)
    - [Internals: Unicorn Backend](internals/model-backends/model-unicorn.md)
    - [Internals: DynamoRIO Backend](internals/model-backends/model-dr.md)

---

####<a name="contract-trace"></a>Contract Trace (CTrace)
: The output of a leakage model. A CTrace is a recording of all exposed information when a given program is executed on the leakage model (e.g., a sequence of memory addresses accessed). This trace represents the expected information flow according to the contract.

!!! info "Related Documentation"
    - [Topic: Contracts - Contract Traces](topics/contracts.md#contract-traces)
    - [Topic: Leakage Models - Trace Representation](topics/models.md#trace-representation)
    - [Topic: Trace Analysis](topics/trace-analysis.md)

---

####<a name="executor"></a>Executor
: The component responsible for running programs on real hardware and collecting attacker-observable microarchitectural changes. This component acts as the counterpart to the leakage model; that is, while the model represents our expectations of the CPU behavior, the executor captures the actual behavior of the CPU under test.

!!! info "Related Documentation"
    - [Internals: Executor Architecture](internals/architecture/exec.md)
    - [Reference: Configuration Options](ref/config.md)

---

####<a name="hardware-trace"></a>Hardware Trace (HTrace)
: The output of the executor. An HTrace is a recording of microarchitectural state changes (like cache evictions, readings of the time stamp counter, etc.) observed during a program execution. These traces are used to capture the information flows on the CPU under test, both the expected and unexpected ones.

!!! info "Related Documentation"
    - [Topic: Trace Analysis](topics/trace-analysis.md)
    - [Internals: Executor Architecture](internals/architecture/exec.md)

---

####<a name="test-case-program"></a>Test Case Program
: A small assembly program, either generated automatically by Revizor or written manually by the user. Test case programs are intended to be executed on the target CPU to collect hardware traces, and on the leakage model to collect contract traces.

!!! info "Related Documentation"
    - [Topic: Test Case Generation](topics/test-case-generation.md)
    - [Internals: Code Generator Architecture](internals/architecture/code.md)
    - [Reference: Binary Formats - RCBF](ref/binary-formats.md)

---

####<a name="test-case-data"></a>Test Case Data (aka Test Case Input)
: A blob of data used to initialize memory and registers for the execution of a test case program. Test case data can be generated automatically by Revizor or provided manually by the user.

!!! info "Related Documentation"
    - [Topic: Test Case Generation](topics/test-case-generation.md)
    - [Internals: Data Generator Architecture](internals/architecture/data.md)
    - [Reference: Binary Formats - RDBF](ref/binary-formats.md)

---

####<a name="sandbox"></a>Sandbox (or Test Case Sandbox)
: An isolated execution environment where test case programs are run on the target CPU and on the model. On the technical level, a sandbox constitutes of a dedicated region of memory where the test case program and data are loaded, as well as a set of mechanisms to isolate the test case execution from the rest of the system (e.g., by disabling interrupts, overriding MSRs, etc.).

!!! info "Related Documentation"
    - [Reference: Sandbox](ref/sandbox.md)
    - [Reference: Registers](ref/registers.md)

---

####<a name="model-based-relational-testing"></a>Model-based Relational Testing (MRT)
: The core methodology of Revizor. It involves randomly generating test programs and inputs to them, executing them with the executor and the model, collecting the corresponding hardware and contract traces, identifying the information flows in both, and comparing them to find unexpected leaks.

!!! info "Related Documentation"
    - [Primer: Model-Based Relational Testing](intro/03-primer.md#model-based-relational-testing-and-revizor)
    - [Topic: Trace Analysis](topics/trace-analysis.md)
    - [Internals: Fuzzer Architecture](internals/architecture/fuzz.md)

---

####<a name="violation"></a>Violation
: A situation where hardware traces expose some information that is not exposed in the contract traces for the same test case. This indicates that the CPU is leaking some information not specified by the contract, which may represent a security vulnerability.

!!! info "Related Documentation"
    - [Topic: Trace Analysis](topics/trace-analysis.md)
    - [Primer: Contract Violation](intro/03-primer.md#building-and-testing-speculation-contracts)
    - [How-to: Root-Cause a Violation](howto/root-cause-a-violation.md)

---

####<a name="violation-artifact"></a>Violation Artifact (aka Contract Counterexample)
: A bundle consisting of a test case program, two inputs that trigger the violation (plus extra inputs to set the uarch state, if needed), the corresponding hardware and contract traces, and a collection of configuration files to reproduce the violation. Violation artifacts are generated automatically by Revizor when a violation is detected.

!!! info "Related Documentation"
    - [Reference: Binary Formats](ref/binary-formats.md)
    - [How-to: Root-Cause a Violation](howto/root-cause-a-violation.md)
    - [How-to: Minimize Test Cases](howto/minimize.md)

---

####<a name="minimization"></a>Minimization
: A post-processing mode that takes a violation artifact and performs transformation passes to simplify the program and data while preserving the violation. The goal is to produce a minimal artifact that is easier to understand and analyze, using program passes (instruction removal/simplification), input passes (sequence/diff minimization), and analysis passes (source analysis).

!!! info "Related Documentation"
    - [How-to: Minimize Test Cases](howto/minimize.md)
    - [Reference: Minimization Passes](ref/minimization-passes.md)
    - [Internals: Minimization Architecture](internals/architecture/mini.md)

---

####<a name="multi-stage-filtering"></a>Multi-stage Filtering
: A pipeline of validation stages applied to potential violations to rule out false positives. A violation must survive all stages to be reported.

!!! info "Related Documentation"
    - [Internals: Fuzzer Architecture](internals/architecture/fuzz.md)
    - [Reference: Configuration Options](ref/config.md)

---

####<a name="priming-test"></a>Priming Test
: One of the most important validation stages. It is motivated by the following problem: when hardware traces are collected for a sequence of many inputs, the execution of the program with earlier inputs will affect the microarchitectural state for later inputs (e.g., the branch predictor state). This can lead to false positives, where two inputs that should be indistinguishable according to the contract produce different hardware traces simply because they were executed in different microarchitectural states (e.g., one input triggered a misprediction while the other did not). These case don't actually represent a violation because the difference in traces is not caused by the data difference, but rather by the sequence of executions.

The priming test mitigates this problem by re-executing the violating inputs in a different sequence, by swapping the order of inputs that trigger a violation. If the violation disappears when the order is swapped, it indicates that the difference in traces was due to inconsistent microarchitectural state rather than a true violation. Otherwise, we have evidence that the violation is genuine.

!!! info "Related Documentation"
    - [Reference: Configuration Options - enable_priming](ref/config.md#enable_priming)
    - [Internals: Fuzzer Architecture](internals/architecture/fuzz.md)

---

####<a name="contract-compliance"></a>Contract Compliance
: A CPU complies with a speculation contract if, for all possible programs and input pairs that produce identical contract traces, the corresponding hardware traces are also identical. This ensures that the contract captures all information that the hardware can leak. While testing all possible programs is infeasible, Revizor approximates this by randomly sampling the search space with a large number of test cases.

!!! info "Related Documentation"
    - [Topic: Trace Analysis - Contract Compliance Property](topics/trace-analysis.md#contract-compliance-property)
    - [Topic: Contracts - Contract Compliance](topics/contracts.md#contract-compliance)
    - [Primer: Contract Compliance](intro/03-primer.md#building-and-testing-speculation-contracts)

---

####<a name="contract-equivalence-class"></a>Contract Equivalence Class (ContractEqClass)
: A group of inputs that produce identical contract traces for a given test case program. According to the leakage model, these inputs should be indistinguishable when executed.

!!! info "Related Documentation"
    - [Topic: Trace Analysis - Deterministic Trace Comparison](topics/trace-analysis.md#deterministic-trace-comparison)
    - [Internals: Analyser Architecture](internals/architecture/analysis.md)

---

####<a name="hardware-equivalence-class"></a>Hardware Equivalence Class (HardwareEqClass)
: A group of inputs that produce statistically similar hardware traces for a given test case program. These inputs are actually indistinguishable on real hardware.

!!! info "Related Documentation"
    - [Topic: Trace Analysis - Statistical Trace Comparison](topics/trace-analysis.md#statistical-trace-comparison)
    - [Internals: Analyser Architecture](internals/architecture/analysis.md)

---

####<a name="boosting"></a>Boosting (aka Contract-driven Input Generation)
: A data generation optimization technique that uses taint analysis to generate inputs more likely to trigger contract violations. The boosted generator identifies which input bytes affect the contract trace and generates new inputs by mutating the non-tainted bytes. This way, we can deterministically and efficiently create any number of inputs that produce the same contract trace (i.e., form one ContractEqClass), increasing the chances of finding violations.

!!! info "Related Documentation"
    - [Internals: Data Generator Architecture](internals/architecture/data.md)
    - [Reference: Configuration Options](ref/config.md)

---

####<a name="fuzzer"></a>Fuzzer
: The main orchestrator in Revizor that manages core components (CodeGenerator, DataGenerator, Model, Executor, and Analyser) and coordinates the fuzzing loop. When a potential violation is found, the Fuzzer runs it through a multi-stage filtering pipeline to eliminate false positives.

!!! info "Related Documentation"
    - [Internals: Fuzzer Architecture](internals/architecture/fuzz.md)
    - [Reference: Configuration Options](ref/config.md)

---

####<a name="analyser"></a>Analyser
: The component that compares contract traces with hardware traces to detect violations. It uses an equivalence class approach where it groups inputs by contract traces (ContractEqClasses) and then checks if they split into multiple hardware equivalence classes (HardwareEqClasses), which would indicate a violation.

!!! info "Related Documentation"
    - [Topic: Trace Analysis](topics/trace-analysis.md)
    - [Internals: Analyser Architecture](internals/architecture/analysis.md)
    - [Reference: Configuration Options - analyser](ref/config.md)

---

####<a name="actor"></a>Actor
: A partition of the sandbox representing a distinct execution context with specific isolation properties (e.g., a VM). An actor encompasses a code region, a data region with configurable permissions, and an execution context (CPU mode, privilege level, and system configuration). Actors enable testing for information leaks across different security domains.

!!! info "Related Documentation"
    - [Topic: Actors](topics/actors.md)
    - [Reference: Sandbox](ref/sandbox.md)

---

####<a name="actor-non-interference"></a>Actor Non-Interference
: A specialized type mode of testing in Revizor, where, on top of testing for standard contract violations, the tool also checks that there are no information flows between different actors in a multi-actor test case. This mode is used to verify isolation properties between security domains, ensuring that secret data in one actor does not influence observable behavior in another actor.

!!! info "Related Documentation"
    - [Topic: Actors](topics/actors.md)

---

####<a name="observer-actor"></a>Observer Actor
: An actor marked as an observer in the configuration, representing an attacker that can observe data leaks in multi-actor testing scenarios. This is used in conjunction with the Actor Non-Interference mode to check that secret data in other actors does not influence the traces in the observer actor.

!!! info "Related Documentation"
    - [Topic: Actors](topics/actors.md)
    - [Reference: Configuration Options](ref/config.md)

---

####<a name="rcbf"></a>RCBF (Revizor Code Binary Format)
: A custom binary format used to transfer test case programs between Revizor components. The format contains a header, actor table, symbol table, metadata, and code sections for each actor.

!!! info "Related Documentation"
    - [Reference: Binary Formats - RCBF](ref/binary-formats.md)

---

####<a name="rdbf"></a>RDBF (Revizor Data Binary Format)
: A custom binary format used to transfer input data between Revizor components. The format contains initialization data for sandbox memory and registers, and can combine multiple inputs into a single file for batch processing.

!!! info "Related Documentation"
    - [Reference: Binary Formats - RDBF](ref/binary-formats.md)

---

####<a name="template"></a>Template
: An assembly file that combines regular assembly instructions with placeholders to define a test case structure for the code generator. Such templates are used in a special template mode of Revizor, where the programs are generated by populating the placeholders with random instructions instead of generating programs from scratch.

!!! info "Related Documentation"
    - [How-to: Use Templates](howto/use-templates.md)
    - [Reference: Configuration Options](ref/config.md)

---

####<a name="macro"></a>Macro
: A special pseudo-instruction in test case programs that can be treated differently depending on whether the test case is executed by the model or the executor. One prominent example is VM transition macros, which handle switching between actors. A special type of macro is also used to implement the placeholders in templates.

!!! info "Related Documentation"
    - [How-to: Use Macros](howto/use-macros.md)
    - [Reference: Macro Reference](ref/macros.md)

---

