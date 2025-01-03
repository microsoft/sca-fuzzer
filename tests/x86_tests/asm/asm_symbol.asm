.intel_syntax noprefix
.section .data.main

.macro.measurement_start: nop qword ptr [rax + 0xff]

nop

.macro.measurement_end: nop qword ptr [rax + 0xff]

and rax, rax

.function_1:

nop

.section .data.guest_1
.function_2:
nop


.test_case_exit:
