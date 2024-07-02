.intel_syntax noprefix
.test_case_enter:
.section .data.main
.byte 0xf1  # int1
mov rax, qword ptr [r14 + 256]
.test_case_exit:
