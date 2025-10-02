.section .data.main

ldr x0, [x2]  // main page
ldr x1, [x20, 4096]  // faulty page
add x0, x0, x1

ldr x1, [x20, -8]  // underflow pad
ldr x2, [x20, 4096 + 4096 + 320]  // overflow pad
add x1, x1, x2

ldr x2, [x20, 4096 + 4096]  // reg init
ldr x3, [x20, 4096 + 4096 + 48]  // patched flags
ldr x4, [x20, 4096 + 4096 + 64]  // simd init
mov x5, x20

.test_case_exit:
