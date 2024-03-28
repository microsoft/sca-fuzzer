.intel_syntax noprefix
.test_case_enter:

.section .data.main
.function_main_0:

mov rbx, qword ptr [r14 + 0x300]
mov rax, qword ptr [r14 + 0x1000]
lfence

.macro.fault_handler:
mov rax, qword ptr [r14 + 0x200]


# ----------------------------- Exit    ------------------------------------------------------------
.test_case_exit:
