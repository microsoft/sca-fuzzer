.intel_syntax noprefix
.test_case_enter:
.section .data.main
mov rax, qword ptr [r14 + 4096]
xor rax, rcx
and rax, 0b111111111111 # instrumentation
mov rax, qword ptr [r14 + rax]
.test_case_exit:
