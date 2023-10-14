.intel_syntax noprefix
.test_case_enter:
.section .data.main
MOV edx, 0
MOV ebx, 0
DIV ebx
XOR rax, rcx
AND rax, 0b111111111111 # instrumentation
MOV rax, qword ptr [r14 + rax + 128]
.test_case_exit:
