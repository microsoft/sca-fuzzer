.section .data.main

// base values
mov x4, #1
mov x5, #0

// flag check
csel x0, x4, x5, mi  // n == 1
csel x1, x4, x5, eq  // z == 1
csel x2, x4, x5, cs  // c == 1
csel x3, x4, x5, vs  // v == 1

.test_case_exit:
