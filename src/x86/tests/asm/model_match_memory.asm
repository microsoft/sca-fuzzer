.intel_syntax noprefix
.test_case_enter:
.section .data.main

MOV rax, qword ptr [r14]  # main page
ADD rax, qword ptr [r14 + 4096]  # faulty page

MOV rbx, qword ptr [r14 - 8]  # underflow pad
ADD rbx, qword ptr [r14 + 4096 + 4096 + 320]  # overflow pad

MOV rcx, qword ptr [r14 + 4096 + 4096]  # reg init
MOV rdx, qword ptr [r14 + 4096 + 4096 + 48]  # patched flags
MOV rsi, qword ptr [r14 + 4096 + 4096 + 64]  # simd init
MOV rdi, r14


# Uncomment the following to test the complete sandbox contents
# XOR rax, rax
# XOR rbx, rbx
# XOR rcx, rcx
# XOR rdx, rcx
# MOV rdi, 0xff8
# .l1:
# ADD rax, qword ptr [r14 + rdi]
# ADD rbx, qword ptr [r14 + rdi + 0x1000]
# ADD rcx, qword ptr [r14 + rdi + 0x2000]
# SUB rdi, 8
# JNZ .l1
# .l1_exit:

# MOV rdi, 0xef8
# .l2:
# ADD rdx, qword ptr [r14 + rdi - 0xf00]
# SUB rdi, 8
# JNZ .l2

.test_case_exit:
