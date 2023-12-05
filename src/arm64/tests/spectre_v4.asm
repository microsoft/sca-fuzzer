ISB  // instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:

# The AND makes X2 a multiple of 64 but not too big, so X2 ends up pointing
# to some different cache line in X30 each time
AND X2, X2, #0b1111000000
ADD X2, X30, X2

# Store address pointed by X2 at X30[0]
ADD X1, X30, #0
STR X2, [X1], #0

# Make sure X0=X30
ADD X0, X30, #0

# Create a delay to encourage speculative execution,
# without changing the value of X0.
# 33 ADD/SUB instuctions are the minimal amount of delay
# that produces speculation, empirically.
ADD X0, X0, #1
SUB X0, X0, #1
ADD X0, X0, #2
SUB X0, X0, #2
ADD X0, X0, #3
SUB X0, X0, #3
ADD X0, X0, #4
SUB X0, X0, #4
ADD X0, X0, #5
SUB X0, X0, #5
ADD X0, X0, #6
SUB X0, X0, #6
ADD X0, X0, #7
SUB X0, X0, #7
ADD X0, X0, #8
SUB X0, X0, #8
ADD X0, X0, #9
SUB X0, X0, #9
ADD X0, X0, #10
SUB X0, X0, #10
ADD X0, X0, #11
SUB X0, X0, #11
ADD X0, X0, #12
SUB X0, X0, #12
ADD X0, X0, #13
SUB X0, X0, #13
ADD X0, X0, #14
SUB X0, X0, #14
ADD X0, X0, #15
SUB X0, X0, #15
ADD X0, X0, #16
SUB X0, X0, #16
ADD X0, X0, #17
SUB X0, X0, #17

# Store at X30[0], but using X0 instead of X30 to not create dependency.
STR X1, [X0], #0

# The long computation of X0 encourages this load from X30[0] to happen 
# before the store to X30[0]
LDR X4, [X30], #0

# Make load dependency on the read value that hits the cache
LDR X5, [X4], #0

.bb_main.exit:
.test_case_exit:
ISB  // instrumentation
