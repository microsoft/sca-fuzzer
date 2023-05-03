.intel_syntax noprefix
.test_case_enter:
MOV ebx, 0
DIV ebx
XOR rax, rcx
AND rax, 0b111111111111 # instrumentation
MOV rax, qword ptr [r14 + rax + 128]
.test_case_exit:
