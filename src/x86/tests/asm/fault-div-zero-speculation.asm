.intel_syntax noprefix
.test_case_enter:
.section .data.main
mov edx, 0
mov ebx, 0
div ebx
xor rax, rcx
and rax, 0b111111111111 # instrumentation
mov rax, qword ptr [r14 + rax + 128]
.test_case_exit:
