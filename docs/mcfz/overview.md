# MCFuzz at a Glance

!!! warning "Experimental"
    MCFuzz is experimental. Its interfaces, configuration options, and harness
    contract may change.

!!! info "MCFuzz is separate from Revizor"
    This page describes MCFuzz, not Revizor. Revizor is a hardware fuzzer that
    finds microarchitectural leaks in CPUs. MCFuzz is a software fuzzer that
    finds side-channel leaks in compiled programs. The two tools share one
    leakage model but address different problems. For
    CPU fuzzing, see [Revizor at a Glance](../intro/01-overview.md) instead.

## What is MCFuzz?

MCFuzz (*Model-based Constant-time Fuzzer*) tests whether a compiled
cryptographic library leaks secrets, such as keys, through microarchitectural
side channels.

Cryptographic code is expected to be *constant-time*: its observable behavior,
which branches it takes and which memory addresses it accesses, must not depend
on secret data. When that behavior depends on a secret, an attacker who observes
the side effects through cache timing, branch prediction, or a similar channel
can recover the secret. Speculative execution enlarges this attack surface:
since Spectre, code that is constant-time in its architectural execution can
still leak on a mispredicted path.

MCFuzz runs the target library as an ordinary fuzzer would, but it detects leaks
rather than crashes. It takes the compiled binary, executes it under a chosen
leakage model, and reports the source lines at which secret-dependent behavior
occurs.

## Why MCFuzz?

Maintainers of cryptographic libraries currently have limited testing options. The tools
in routine use, such as `ctgrind` and MemSan, detect only classical
constant-time violations and do not account for speculative (Spectre-style)
leaks. The few tools that do account for speculation are hardly practical for use in continuous testing:
symbolic execution does not scale to a whole library, static analyzers lack the precision
cryptography requires, and language-based verification such as Jasmin requires
rewriting the library in a specialized language. None of these supports the
routine, end-to-end testing already applied to ordinary bugs.

MCFuzz addresses these limitations with four properties:

* **One tool, many leakage models.** MCFuzz tests the target against a
  [*hardware-software contract*](../glossary.md#speculation-contract-aka-leakage-contract),
  a specification of what a given CPU is assumed to leak. The contract is a
  parameter of the tool rather than a fixed assumption. The default contract
  detects classical constant-time violations; other contracts detect speculative
  (Spectre-style) leaks or leaks from other microarchitectural optimizations.
  Supporting new hardware behavior requires a new contract, not a new tool.
* **Secret-aware.** The user declares which inputs are secret and which are
  public. MCFuzz then reports only leaks that depend on secrets, which keeps
  false positives from public data low.
* **Tests real binaries.** MCFuzz executes the compiled program, so it detects
  leaks introduced by the compiler and supports libraries that use hand-written
  assembly and hardware crypto instructions such as AES-NI.
* **Compatible with existing workflows.** MCFuzz is a fuzzer with a harness,
  a form of testing that libraries already use. It requires no source
  annotations and no rewrite of the library.

## How Does It Work?

MCFuzz detects cases where changing only the secret changes the program's
observable behavior. This is the property of
[**non-interference**](../intro/03-primer.md#noninterference-definition-and-examples): two runs with
the same public inputs but different secrets must produce the same
microarchitectural *trace*. If the traces differ, MCFuzz records a leak and
identifies the responsible source line.

MCFuzz operates in four automated stages:

![The four MCFuzz stages: input exploration, input boosting, contract tracing,
and detection.](../assets/stages.png)

1. **Input exploration.** A coverage-guided fuzzer, AFL++, explores the input
   space of the [harness](harness.md) and builds a diverse, high-coverage
   corpus. MCFuzz then minimizes this corpus so the later, costlier stages run
   only on the inputs that matter.
2. **Input boosting.** For each corpus input, MCFuzz keeps the public bytes
   fixed and randomizes the secret bytes, producing a group of
   *public-equivalent inputs*. Every input in the group should produce the same
   trace.
3. **Contract tracing.** A tracer runs each input under the chosen
   [contract](../glossary.md#speculation-contract-aka-leakage-contract) and
   records the attacker-observable trace. The tracer is built on
   [DynamoRIO](../internals/model-backends/model-dr.md), which uses native
   execution and code caching to keep the overhead low enough for real
   libraries. The same mechanism emulates speculative effects, such as branch
   misprediction, with a checkpoint-mispredict-rollback technique.
4. **Detection.** MCFuzz takes each corpus input's trace as a reference and
   compares it against the traces of its public-equivalent group. A divergence
   in an instruction address or a memory address is a leak, which MCFuzz maps
   back to the source line and writes to a JSON report.

The pipeline is split for performance. Coverage-guided fuzzing runs at close to
native speed, so stage 1 maximizes coverage across the whole library. Tracing is
expensive, especially under a speculative contract, so stages 3 and 4 run only
on the minimized corpus that already covers the program. This design lets MCFuzz
test whole libraries end-to-end, rather than isolated functions, within time and
memory budgets that suit continuous testing on commodity multi-core hardware.

## Limitations

MCFuzz is a fuzzer, not a verifier. A run without findings means no leak was
detected among the explored inputs, not a proof that the code is constant-time.
MCFuzz reasons only about the side channels its contract describes, and its
results are only as sound as the contract is a faithful and conservative model
of the hardware.

Declassified values, such as ciphertext, and blinded values can produce false
positives. The expected way to handle it is to allowlist the locations of
the known false positives.

## The Harness

MCFuzz does not test arbitrary programs directly. The code under test is wrapped
in a [harness](harness.md) that exposes a fixed interface and, through a
plain-text policy file, marks which inputs are secret (for example,
`key: private`, `plaintext: public`). The harness is the adapter MCFuzz drives
during fuzzing, and it holds the secrecy policy. Much of the effort of writing
one consists of porting the test cases and fuzzing harnesses the library already
provides. See the [harness guide](harness.md) for the interface it must satisfy.

## Where to Next?

* To start using MCFuzz, see the [Quick Start](quick-start.md).
* To wrap a library, see the [harness guide](harness.md).
