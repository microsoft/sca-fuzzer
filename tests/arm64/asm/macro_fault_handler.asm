.section .data.main
.function_main_0:

ldr x0, [x20, #0x300]
mov x0, #0
brk #0x20
mov x1, #1

.macro.fault_handler:
ldr x2, [x20, #0x200]
ldr x2, [x20, #0xff8]
mov x2, #2


.test_case_exit:
