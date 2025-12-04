# Minimization Passes

This document provides a detailed list of all available minimization features (passes) supported in the `minimize` execution mode of Revizor. These passes are used to simplify randomly generated violation artifacts to enable human analysis.

!!! note "Related Documentation"
    This document is intended as a reference; if you're looking for a practical guide on how to use the `minimize` mode, please refer to [How-To: Minimize Violation](../howto/minimize.md).

## Types of Passes

`minimize` mode supports three types of passes:

* program passes modify the program
* input passes modify the input sequence
* analysis passes provide additional information about the violation, usually by adding comments to the program.

## Program Passes

#### <a name="enable-instruction-pass"></a>`--enable-instruction-pass`

:   Enables the instruction minimization pass that iteratively removes instructions from the program while preserving the violation.

#### <a name="enable-simplification-pass"></a>`--enable-simplification-pass`

:   Enables the instruction simplification pass that replaces complex instructions with simpler ones while preserving the violation.

#### <a name="enable-nop-pass"></a>`--enable-nop-pass`

:   Enables the NOP replacement pass that iteratively replaces instructions with NOPs of the same size while preserving the violation.

#### <a name="enable-constant-pass"></a>`--enable-constant-pass`

:   Enables the constant simplification pass that replaces immediate arguments of instructions with 0s while preserving the violation.

#### <a name="enable-mask-pass"></a>`--enable-mask-pass`

:   Enables the mask simplification pass that reduces the size of the instrumentation masks while preserving the violation.

#### <a name="enable-label-pass"></a>`--enable-label-pass`

:   Enables the label removal pass that removes unused labels from the assembly file.

#### <a name="enable-fence-pass"></a>`--enable-fence-pass`

:   Enables the fence insertion pass that adds LFENCEs after instructions while preserving the violation.

## Input Passes

#### <a name="enable-input-seq-pass"></a>`--enable-input-seq-pass`

:   Enables the input sequence minimization pass that removes inputs from the original generated sequence while preserving the violation.

#### <a name="enable-input-diff-pass"></a>`--enable-input-diff-pass`

:   Enables the violating input difference minimization pass that operates on the pair of (contract-equivalent) inputs that triggered the violation and attempts to minimize the difference between the two inputs.
It does so by iterating over all bytes in the inputs, and (1) attempting to replace each byte with zero, and if it fails, (2) copying the byte from the first input to the second input.

## Analysis Passes

#### <a name="enable-source-analysis"></a>`--enable-source-analysis`

:   Enables the speculation source identification pass that analyzes the program to identify suspected sources of speculation, and adds the corresponding comments to the assembly file.
Note that the analysis is not guaranteed to be correct, and it may produce false results.

#### <a name="enable-comment-pass"></a>`--enable-comment-pass`

:   Enables the violation comment pass that adds comments to the assembly file with details about the violation.
