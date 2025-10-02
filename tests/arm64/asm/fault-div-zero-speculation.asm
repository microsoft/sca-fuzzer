.section .data.main

mov x2, #1
mov x1, #0
udiv x3, x2, x1

and x3, x3, #0b1111111111111
add x3, x3, #0x100
ldr x0, [x20, x3]

.test_case_exit:
