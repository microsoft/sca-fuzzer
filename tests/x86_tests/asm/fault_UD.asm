.intel_syntax noprefix
.test_case_enter:
.section .data.main
ud2
and rax, 0b111111111111 # instrumentation
mov rax, qword ptr [r14 + rax + 128]
.test_case_exit:
