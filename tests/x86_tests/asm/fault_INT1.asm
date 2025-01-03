.intel_syntax noprefix
.section .data.main
.byte 0xf1  # int1
mov rax, qword ptr [r14 + 256]
.test_case_exit:
