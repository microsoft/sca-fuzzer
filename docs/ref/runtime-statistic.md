# Fuzzing Statistics

This document provides a complete reference on how to interpret the runtime statistics output of Revizor. These statistics are generated during fuzzing campaigns and provide insights into the performance and behavior of the fuzzer.

The runtime statistics are essentially printed twice: once during the fuzzing campaign, in a form of a continuously-updated progress log, and once at the end of the campaign, in a summarized report. The statistics in both places have the same meaning, but the final report includes cumulative totals for the entire campaign.

## Runtime Statistics Fields

A typical runtime statistics output looks like this:

```
17    ( 2%)| Stats: Cls:100/100,In:200,R:7,SF:10,OF:7,Fst:0,CN:0,CT:0,P1:0,CS:0,P2:0,V:0> Priming  27
```

This line is continuously updated on each iteration of the fuzzer (after each test case is executed).

The fields are as follows:

* `17    ( 2%)` - The current test case number and progress towards the total number of test cases.
* `Cls:100/100` - The average number of unique equivalence classes per test case. The left number is number of "effective" classes (those that have at least two hardware inputs), while the right number is total classes observed. In a well-functioning campaign, these numbers should be equal. See [contract equivalence class](../glossary.md#contract-equivalence-class) in the glossary.
* `In:200` - The number of inputs per test case. Normally, this number is equal to `-i` parameter passed times `inputs_per_class` configuration option.
* `R:7` - Average number of hardware tracing samples per input. See [Trace Analysis - Statistical Comparison](../topics/trace-analysis.md) for more details.
* `SF:10,OF:7,Fst:0,CN:0,CT:0,P1:0,CS:0,P2:0` - The number of test cases that have been filtered by each stage of the false-positive elimination pipeline.
    * `SF` - Number of test cases filtered by the speculation filter.
    * `OF` - Number of test cases filtered by the observation filter.
    * `Fst` - Number of test cases filtered after fast-path execution.
    * `CN` - Number of test cases filtered out when model nesting was increased from 1 (fast path) to `max_model_nesting`.
    * `CT` - Number of test cases that had taint mistakes.
    * `P1` - Number of test cases filtered out by priming stage with the minimal sample size.
    * `CS` - Number of test cases filtered out when the sample size was increased to a non-minimal value.
    * `P2` - Number of test cases filtered out by priming stage with the non-minimal sample size.
* `V:0` - The number of detected violations so far (can be non-zero when running with `--nonstop` flag).
* `Priming  27             ` - Current stage of the false-positive elimination pipeline.

## Final Summary Report

A typical final summary report looks like this:

```
================================ Statistics ===================================

Test Cases: 18
Inputs per test case: 200.0
Violations: 1
Effectiveness:
  Total Cls: 98.0
  Effective Cls: 98.0
Discarded Test Cases:
  Speculation Filter: 10
  Observation Filter: 7
  Fast Path: 0
  Max Nesting Check: 0
  Tainting Check: 0
  Early Priming Check: 0
  Large Sample Check: 0
  Priming Check: 0

Duration: 40.5
Finished at 15:40:23
```

This section summarizes overall statistics from the fuzzing campaign. The fields are similar to those explained in the runtime output section above:

* `Test Cases` - Total number of test cases executed during the campaign.
* `Inputs per test case` - Average number of inputs executed per test case.
* `Violations` - Total number of violations detected during the campaign (may >1 when running with `--nonstop` flag).
* `Effectiveness` - The average number of unique equivalence classes per test case. `Total Cls` is number of "effective" classes (those that have at least two hardware inputs), while `Effective Cls` is total classes observed. In a well-functioning campaign, these numbers should be equal. See [contract equivalence class](../glossary.md#contract-equivalence-class) in the glossary.
* `Discarded Test Cases` - The number of test cases that have been filtered by each stage of the false-positive elimination pipeline.
* `Duration` - Total duration of the fuzzing campaign in seconds.
* `Finished at` - Timestamp when the fuzzing campaign completed.
