.section .data.main
.function_main:

# reduce the entropy of x0
and x0, x0, #0b111111000000

# delay the cond. jump
add x1, x1, x0
add x1, x1, #1
add x1, x1, x0
add x1, x1, #1
add x1, x1, x0
add x1, x1, #1
add x1, x1, x0
add x1, x1, #1
add x1, x1, x0
add x1, x1, #1
add x1, x1, x0
add x1, x1, #1
add x1, x1, x0
add x1, x1, #1
add x1, x1, x0
add x1, x1, #1

# reduce the entropy in x1
and x1, x1, #0b1000000

# misprediction
cmp x1, #0
b.eq .l1

.l0:
# x1 != 0
    add x2, x20, x0
    ldr x0, [x2], #0
    b .l2
.l1:
# x1 == 0
.l2:

.test_case_exit:
