.intel_syntax noprefix
.test_case_enter:
.section .data.0_host

# empty - leaving initial reg values unchanged

MOV rax, qword ptr [r14]  # main page
MOV rbx, qword ptr [r14 + 4096 - 8]  # stack
MOV rcx, qword ptr [r14 + 4096]  # faulty page
MOV rdx, qword ptr [r14 + 4096 + 4096]  # reg init
MOV rsi, qword ptr [r14 + 4096 + 4096 + 64]  # simd init
MOV rdi, r14

.test_case_exit:
