ISB  // instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:

# reduce the entropy of X0
AND X0, X0, #0b111111000000

# delay the cond. jump
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

# misprediction
CMP X1, #0
B.EQ .L1

.L0:
# X1 != 0
    ADD X2, X30, X0
#   LDR X0, [X2], #0     <--- NO LDR, no violation should happen!
    B .L2
.L1:
# X1 == 0
.L2:

.bb_main.exit:
.test_case_exit:
ISB  // instrumentation
