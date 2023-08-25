.intel_syntax noprefix
.test_case_enter:
.section .data.0_host
INT3
MOV rax, qword ptr [r14 + 256]
.test_case_exit:
