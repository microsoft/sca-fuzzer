# The Fuzzing Harness

MCFuzz does not test a cryptographic library directly. For each target it drives
a user-written **harness**: a program that adapts the fuzzer's raw input
to the library's API and declares which inputs are secret. This document
specifies the requirements a harness must satisfy and the properties it must
uphold.

A complete, working example lives in `mcfz/reference_harness`. It links a
stand-in library with a deliberate leak and is referenced throughout this
document.

The primary goal of the harness is to provide a central entry point to the library under test.
Beyond that, it must also satisfy the following requirements:

## Requirement 1: Input format

MCFuzz expects the harness to read its input from a single binary file produced
by the fuzzer. This file has the following layout:

```
| Section | Field                     | Size (bits) |
| ------- | ------------------------- | ----------- |
| Config  | Interface type            | 8           |
|         | Emulation mode            | 8           |
|         | Private-to-public ratio   | 8           |
|         | Unused                    | 40          |
|         | Interface-specific config | 64          |
| Data    | Private                   | variable    |
|         | Public                    | variable    |
```

The configuration section selects which algorithm to run. The harness is free to
interpret this section as it sees fit for the given target, but it should
generally use the section's data to decide which part of the library's API to
call and with what parameters.

The data section is split into a private and a public region, which supply the
library with secret and public inputs, respectively. The harness uses the
secrecy policy (see next) to decide which region each input field comes from.
For example, if the policy marks the key as private, the harness reads the key
data from the "Private" region.

## Requirement 2: The secrecy policy

MCFuzz expects the harness to also take a policy file as a second input.

The policy file is a small, static text file — written once by the user and held
fixed for the whole campaign — that classifies each named input field as
`public` or `private`.

The reference harness expects exactly three lines: key, iv, and plaintext.
Other harnesses may have more or fewer fields.

For example, a policy file may look like this:

```
key: private
plaintext: public
iv: public
```

The harness parses this file and, when constructing the library's inputs, draws
each field from the corresponding data region.

Marking a field `private` tells MCFuzz it may vary those bytes between
public-equivalent runs; a leak is reported only when varying private data
changes the trace. Changing the policy (for example, marking the key `public`)
changes what counts as a leak without touching the harness code.

## Requirement 3: Single, explicit entry point

MCFuzz expects the harness to have a single entry-point function that calls all APIs that
should be tested in a campaign. In the simplest case this could be `main`, but
it typically makes sense to use a separate function so that all initialization
and parsing happen outside the trace. This keeps the traced region shorter (and
thus faster to trace) and helps avoid non-determinism in the trace (see below).

We also recommend checking for malformed inputs outside the traced region, so
the harness can reject them early and avoid wasting time on invalid inputs
during the fuzzing stage.

By default, MCFuzz begins tracing at the `start_harness` function.
You can re-define the entry point this with the `tracing_entrypoint` config option.

## Requirement 4: Deterministic execution

MCFuzz compares traces by instruction and memory address, so two runs with
identical inputs must produce byte-identical traces. Any nondeterminism creates
false positives. The harness must remove all of it:

* **Deterministic randomness.** Replace the library's RNG with a deterministic,
  counter-based implementation so that fuzzer-supplied bytes fully determine
  execution. Never let the library draw real entropy.
* **Deterministic addresses.** Fix the layout the trace depends on. The
  reference harness allocates a fixed-size stack at a stable address (a
  "stabilizer") as its very first action and switches to it before the traced
  work begins. Address-space layout randomization must also be disabled system
  wide (`randomize_va_space = 0`, see the [Quick Start](quick-start.md)).
* **No other sources of variation.** Avoid wall-clock time, thread scheduling,
  file-system state, and uninitialized memory in anything that runs inside the
  traced region.

## See also

* [MCFuzz at a Glance](overview.md) — what MCFuzz does and why.
* [Quick Start](quick-start.md) — building a harness and running a first
  campaign end to end.
* [Speculation contract](../glossary.md#speculation-contract-aka-leakage-contract)
  — the leakage model the traces are compared against.
