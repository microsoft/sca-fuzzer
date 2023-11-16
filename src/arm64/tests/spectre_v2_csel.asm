ISB  // instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:

# reduce the entropy of rax
AND X0, X0, #0b111111000000

# prepare jump targets. due to limitations of fuzzer, any instruction with a label
# is considered control flow, and therefore must terminate a basic block, which is
# why we add a branch to the next instruction.
ADR X2, .L1
B .L00
.L00:
ADR X3, .L2
B .L01
.L01:

# delay the jump
ADD X1, X1, X0
ADD X1, X1, #1
ADD X1, X1, X0
ADD X1, X1, #1
ADD X1, X1, X0
ADD X1, X1, #1
ADD X1, X1, X0
ADD X1, X1, #1
ADD X1, X1, X0
ADD X1, X1, #1
ADD X1, X1, X0
ADD X1, X1, #1
ADD X1, X1, X0
ADD X1, X1, #1
ADD X1, X1, X0
ADD X1, X1, #1

# reduce the entropy in X1
AND X1, X1, #0b1000000

# select a target based on the random value in X1
CMP X1, #0

# CSEL acts as barrier, so no violation will happen
CSEL X3, X3, X2, EQ

# make indirect jump to either .L1 or .L2,
# this is where the BTI misprediction happens
BR X3

.L1:
    ADD X2, X30, X0
    LDR X0, [X2], #0
    B .L2
.L2:

.bb_main.exit:
.test_case_exit:
ISB  // instrumentation
