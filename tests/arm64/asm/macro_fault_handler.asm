.section .data.main
.function_main_0:

mov x0, #0
brk #0x20
mov x1, #1

.macro.fault_handler:
mov x2, #2

.test_case_exit:
