.intel_syntax noprefix
.test_case_enter:
.section .data.main
mov rax, qword ptr [r14 + 4096 + 64]

# dependent memory access
and rbx, 0b111111111000 # instrumentation
mov rax, qword ptr [r14 + rbx]

# independent memory access
and rbx, 0b111111111000 # instrumentation
mov rax, qword ptr [r14 + rbx]
.test_case_exit:
